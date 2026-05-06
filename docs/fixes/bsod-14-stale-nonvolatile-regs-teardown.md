# BSOD #14 Fix Log — Stale non-volatile registers on teardown

**Date:** 2026-05-06  
**Bugcheck:** `DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1)` — corrupted non-volatile register (e.g. `rsi` = user-space address) causing bad memory access at IRQL=0xFF  
**Commit:** (this change)

---

## Root Cause

When the hypervisor is **resident** (launched on all 32 cores), later IPI callbacks executing on those logical processors are free to reuse the kernel thread stack frame that `AsmLaunchAndReturn` had set up before `VMLAUNCH`.  Specifically, the 8 non-volatile register saves (`push rbx/rbp/rsi/rdi/r12-r15`) at the top of `AsmLaunchAndReturn`, plus the shadow space below them, sit at `[HostResumeRsp+20h .. HostResumeRsp+60h]`.  Any IPI that allocates a new frame on that thread's stack and writes to it will overwrite those saved values.

On teardown, `launch_resume` was restoring registers by doing:

```asm
add  rsp, 20h     ; skip shadow space
pop  r15
pop  r14
...
pop  rbx
ret
```

— reading directly from the kernel thread stack, which by that point contained IPI-reused garbage.  One or more of `rsi`, `rdi`, `rbp`, etc. got a stale value (e.g. a user-space address `0x...`).  The first memory dereference through that register after returning to `VmxLaunchCore` triggered the bugcheck at `IRQL=0xFF` (still inside the IPI callback).

---

## Fix

Snapshot host non-volatile registers (and the return address) into `CORE_VMX_CONTEXT` **before** `VMLAUNCH`, while the values are still correct.  On teardown, restore from the struct — not from the kernel thread stack.

### `AsmLaunchAndReturn` (Arch.asm) — pre-launch snapshot

```asm
mov  [rdx + CTX_HOST_RBX], rbx
mov  [rdx + CTX_HOST_RBP], rbp
mov  [rdx + CTX_HOST_RSI], rsi
mov  [rdx + CTX_HOST_RDI], rdi
mov  [rdx + CTX_HOST_R12], r12
mov  [rdx + CTX_HOST_R13], r13
mov  [rdx + CTX_HOST_R14], r14
mov  [rdx + CTX_HOST_R15], r15
mov  rax, [rsp + 60h]               ; return address (past 8 pushes + 20h shadow)
mov  [rdx + CTX_HOST_RETADDR], rax
```

### `launch_resume` (Arch.asm) — restore from ctx, not from stack

```asm
; rcx = PCORE_VMX_CONTEXT (live from do_teardown / AsmVmExitHandler)
mov  rbx, [rcx + CTX_HOST_RBX]
mov  rbp, [rcx + CTX_HOST_RBP]
mov  rsi, [rcx + CTX_HOST_RSI]
mov  rdi, [rcx + CTX_HOST_RDI]
mov  r12, [rcx + CTX_HOST_R12]
mov  r13, [rcx + CTX_HOST_R13]
mov  r14, [rcx + CTX_HOST_R14]
mov  r15, [rcx + CTX_HOST_R15]
add  rsp, 20h                       ; skip shadow space (matching AsmLaunchAndReturn frame)
xor  eax, eax                       ; return 0 = success
jmp  qword ptr [rcx + CTX_HOST_RETADDR]
```

Using `jmp` instead of `ret` avoids consuming any stack slot — the return address comes from the struct, guaranteed valid regardless of stack reuse.

### `do_teardown` (Arch.asm)

The `vmxoff` path already passed `rcx = ctx` through to `launch_resume` via:

```asm
mov  rsp, qword ptr [rcx + CTX_RESUMERSP]
jmp  qword ptr [rcx + CTX_RESUMERIP]
```

No change needed here — `rcx` remains valid across `vmxoff`.

---

## Struct Changes

Added to `CORE_VMX_CONTEXT` (`Vmx.h`):

| Field | Offset | Contents |
|---|---|---|
| `HostRbx` | `+0x258` | pre-launch `rbx` |
| `HostRbp` | `+0x260` | pre-launch `rbp` |
| `HostRsi` | `+0x268` | pre-launch `rsi` |
| `HostRdi` | `+0x270` | pre-launch `rdi` |
| `HostR12` | `+0x278` | pre-launch `r12` |
| `HostR13` | `+0x280` | pre-launch `r13` |
| `HostR14` | `+0x288` | pre-launch `r14` |
| `HostR15` | `+0x290` | pre-launch `r15` |
| `HostRetAddr` | `+0x298` | return address of `AsmLaunchAndReturn` call site |

`C_ASSERT` static-size checks added for all nine offsets.

---

## Files Changed

| File | Change |
|---|---|
| `Arch.asm` | Added 9 CTX_HOST_* EQU constants; snapshot writes before vmlaunch; `launch_resume` restores from ctx, uses `jmp` not `ret`; updated `do_teardown` comments |
| `Vmx.h` | 9 new fields in `CORE_VMX_CONTEXT`; 9 new `C_ASSERT` offset checks |
| `CHANGELOG.md` | Added BSOD #14 entry |

---

## Invariant Going Forward

> **Never read non-volatile register saves off the kernel thread stack after a resident hypervisor launch.**  
> The stack may be reused by IPIs while the guest is running.  All teardown register restoration must go through `CORE_VMX_CONTEXT` fields written before `VMLAUNCH`.
