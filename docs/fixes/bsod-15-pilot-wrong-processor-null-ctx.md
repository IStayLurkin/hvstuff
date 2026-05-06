# BSOD #15 Fix Log — Phase 2 pilot runs on wrong processor, NULL ctx → KPRCB corruption

**Date:** 2026-05-06  
**Bugcheck:** `IRQL_NOT_LESS_OR_EQUAL (0xA)` — IRQL=0xFF (KPRCB corruption), read from user-space address  
**P1:** `0x00007ffecfa6602a` (user-mode address — not a valid kernel pointer)  
**P2:** `0xFF` (corrupted IRQL field in KPRCB)  
**P4:** `dayzdriv+0x7043` = `VmxLaunchCore+0xd53` = `mov dword ptr [rsi+34h], eax`  
**Commit:** (this change)

---

## Root Cause

### Part 1: `KeSetSystemAffinityThreadEx` is group-relative

`KeSetSystemAffinityThreadEx((KAFFINITY)1)` pins the calling thread to bit 0 of the thread's **current processor group**, not to system-wide processor 0.

On a 32-logical-core Raptor Lake (i9-14900K: 16P + 16E), Windows creates two processor groups:
- Group 0: system-wide processors 0–15
- Group 1: system-wide processors 16–31

If the calling thread's current group is group 1, `KAFFINITY` bit 0 = system-wide processor **16**. `VmxLaunchCore` runs on processor 16. `KeGetCurrentProcessorNumberEx(NULL)` returns 16. `g_CoreCtx[16] = NULL` (only index 0 was set before the pilot call). `ctx = &g_CtxArray[16]` (correct ctx for that slot). `g_CoreCtx[16] = ctx` is set inside `VmxLaunchCore` before VMLAUNCH — that part is fine.

### Part 2: NULL `g_CoreCtx` slot → NULL deref in `AsmVmExitHandler`

`AsmVmExitHandler` is the CPU's `HOST_RIP`. On every VM-exit it does:

```asm
mov  eax, dword ptr gs:[1A4h]    ; system-wide processor number
lea  rcx, g_CoreCtx
mov  rcx, [rcx + rax*8]          ; rcx = g_CoreCtx[procNum]
pop  qword ptr [rcx + 90h]       ; GuestRegs.Rcx  ← CRASH if rcx=NULL
pop  qword ptr [rcx + 88h]       ; GuestRegs.Rax
```

During the pilot window, any other processor (e.g. processor 0) could receive an external interrupt or IPI that causes a VM-exit if it happened to have a VMCS loaded. In practice the most dangerous window is: the pilot runs on processor 16 (because of the group bug), sets `g_CoreCtx[16]`, but processors 0–15 still have `g_CoreCtx[0..15] = NULL`. If any exit fires on those processors, NULL-deref.

### Part 3: Corruption path to the observed crash

The NULL-deref writes 2 qwords (saved guest `rax`/`rcx`) into addresses `NULL+0x88` and `NULL+0x90` — low memory, which on Windows maps to user space. This corrupts the KPRCB of the crashing core (KPRCB starts at `gs:0`; writing to low addresses through a NULL GS-relative value corrupts KPRCB fields). `KPRCB.Irql` gets set to `0xFF`.

Subsequently, when `nvlddmkm` calls `ExFreePoolWithTag` and the memory manager fires a TLB shootdown IPI to that core, the IPI handler reads `KPRCB.Irql = 0xFF` and the kernel panics with `IRQL_NOT_LESS_OR_EQUAL (0xA)`.

The faulting IP `dayzdriv+0x7043` is in `VmxLaunchCore` — specifically `ctx->LaunchResult = AsmLaunchAndReturn(...)` — because `rsi` (the ctx pointer in the compiler's register allocation) was restored from `ctx->HostRsi` via `launch_resume`, which got its `rcx` from the corrupted ctx slot read via the wrong processor index.

---

## Fix

### 1. Use `KeSetSystemGroupAffinityThread` with explicit `GROUP_AFFINITY`

```c
GROUP_AFFINITY newAffinity = {0}, oldGroupAffinity = {0};
newAffinity.Group = 0;
newAffinity.Mask  = 1;   // processor 0 within group 0 = system-wide processor 0
KeSetSystemGroupAffinityThread(&newAffinity, &oldGroupAffinity);
VmxLaunchCore((ULONG_PTR)g_CtxArray);
KeRevertToUserGroupAffinityThread(&oldGroupAffinity);
```

This unambiguously pins to system-wide processor 0 regardless of the calling thread's current group.

### 2. Pre-populate all `g_CoreCtx` slots before the pilot

```c
for (ULONG i = 0; i < procCount; i++)
    g_CoreCtx[i] = &g_CtxArray[i];
```

Any core that receives an IPI or external interrupt during the pilot window and takes a VM-exit must find a valid ctx pointer. A NULL slot = guaranteed KPRCB corruption.

---

## Files Changed

| File | Change |
|---|---|
| `Vmx.c` | Phase 2 pilot: pre-populate all ctx slots; replace `KeSetSystemAffinityThreadEx` with `KeSetSystemGroupAffinityThread(Group=0,Mask=1)` |
| `CHANGELOG.md` | Added BSOD #15 entry |

---

## Invariant Going Forward

> **Never use `KeSetSystemAffinityThreadEx` to pin to a specific processor on multi-group systems.**  
> Always use `KeSetSystemGroupAffinityThread` with an explicit `GROUP_AFFINITY{Group, Mask}`.  
> `KAFFINITY` bit N is group-relative; `KPRCB.Number` (`gs:[1A4h]`) is system-wide.  
> Mismatching them silently runs code on a different processor than intended and leaves `g_CoreCtx` slots NULL.
