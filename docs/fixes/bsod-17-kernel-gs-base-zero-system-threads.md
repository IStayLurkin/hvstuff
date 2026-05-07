# BSOD #16/#17 — IA32_KERNEL_GS_BASE=0 on system threads

**Stop code**: `IRQL_NOT_LESS_OR_EQUAL` (0xA)  
**Failing module**: `dayzdriv.sys`  
**Date fixed**: 2026-05-07  

---

## Root Cause

Intel VMX does **not** save or restore `IA32_KERNEL_GS_BASE` (MSR 0xC0000102) across VM-exits
and VMRESUME transitions.  The guest kernel runs with the user-mode GS base (TEB address, or
zero for kernel/system threads) held in `KERNEL_GS_BASE` — whenever the kernel executes
`SWAPGS` it swaps `GS.base` ↔ `KERNEL_GS_BASE`, toggling between the KPCR and user mode.

### BSOD #16 (first attempt)

The original fix saved `IA32_KERNEL_GS_BASE` (0xC0000102) at `AsmLaunchAndReturn` time and
wrote that value back into `KERNEL_GS_BASE` on every VM-exit.

**Problem**: the IPI callback that calls `AsmLaunchAndReturn` runs on whichever logical
processor the kernel chooses.  That processor may be executing a **system thread** (kernel
worker, `CcAsyncLazywriteWorkerThread`, etc.).  System threads have no user-mode GS base
(there is no TEB), so `IA32_KERNEL_GS_BASE = 0` on those cores.

Storing 0 as the "safe host value" meant that on every VM-exit:
```
wrmsr(IA32_KERNEL_GS_BASE, 0)
```
An NMI that fired while in VMX root then executed `SWAPGS` → `GS.base` became 0 →
`gs:[0x1A4]` tried to read address `0x1A4` (KPRCB.Number field) → page fault at IRQL=HIGH →
`IRQL_NOT_LESS_OR_EQUAL`.

Diagnostic evidence: the probe log printed `KgsBase=0x0` for all 32 cores, confirming every
core's saved value was zero.

### BSOD #17 (correct fix)

Read `IA32_GS_BASE` (MSR 0xC0000101) instead.  In kernel mode:

| MSR | What it holds |
|-----|---------------|
| `IA32_GS_BASE` (0xC0000101) | Current `GS.base` = **KPCR virtual address** — always valid in kernel mode |
| `IA32_KERNEL_GS_BASE` (0xC0000102) | Saved-away value (user-mode GS base = TEB, or 0 for system threads) |

The KPCR address is **never zero** on any core.  With the KPCR address stored in both
`GS.base` and `KERNEL_GS_BASE` while in VMX root, any `SWAPGS` executed by an NMI handler
swaps `KPCR ↔ KPCR` — effectively a no-op.  The NMI handler's `gs:[]` accesses all hit the
real KPCR.

---

## Files Changed

### `Arch.asm`

1. Added `IA32_GS_BASE EQU 0C0000101h` constant alongside the existing
   `IA32_KERNEL_GS_BASE EQU 0C0000102h`.
2. In `AsmLaunchAndReturn`, changed the rdmsr that snapshots the host-safe value:
   ```asm
   ; Before (BSOD #17): captured KERNEL_GS_BASE which is 0 on system threads
   ; mov  ecx, IA32_KERNEL_GS_BASE

   ; After: capture GS.base = KPCR, always a valid kernel address
   mov  ecx, IA32_GS_BASE
   rdmsr
   shl  rdx, 32
   or   rax, rdx                       ; rax = full 64-bit KPCR address
   mov  [rbx + CTX_HOST_KGSBASE], rax  ; ctx->HostKernelGsBase = KPCR
   ```
3. Added `CTX_GUEST_KGSBASE EQU 2A0h` and `CTX_HOST_KGSBASE EQU 2A8h` offset constants.
4. In `AsmVmExitHandler`: save guest `KERNEL_GS_BASE` → `ctx->GuestKernelGsBase`, write
   `ctx->HostKernelGsBase` (KPCR) into `KERNEL_GS_BASE`.
5. Before `vmresume`: restore guest `KERNEL_GS_BASE` from `ctx->GuestKernelGsBase` so guest
   `SWAPGS` sequences remain coherent.

### `Vmx.h`

- Added `#define IA32_KERNEL_GS_BASE 0xC0000102` to MSR constants.
- Added `GuestKernelGsBase` (+0x2A0) and `HostKernelGsBase` (+0x2A8) fields to
  `CORE_VMX_CONTEXT`.  Added block comment explaining the BSOD root cause.
- Added `C_ASSERT` offset checks for both new fields.

### `Vmx.c`

- `LogCoreResult`: pilot launch now logs `KgsBase=0x<addr> (KPCR)` for passing cores so the
  next crash can immediately confirm whether the KPCR address looks sane
  (expect `0xFFFF...` kernel-space address, never `0x0`).
- Updated pilot log message text accordingly.

---

## SDM Reference

Intel SDM Vol. 3C §26.3 "Clearing Address-Space Identifiers" / §27.5 "Loading Host State":
MSRs `IA32_FS_BASE`, `IA32_GS_BASE` are written from VMCS HOST_FS_BASE / HOST_GS_BASE on
every VM-exit, but `IA32_KERNEL_GS_BASE` has **no** corresponding VMCS field — it is left
with whatever value the guest last wrote.
