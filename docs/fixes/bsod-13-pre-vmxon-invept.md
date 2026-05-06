# BSOD #13 Fix Log — Pre-VMXON INVEPT raises #UD

**Date:** 2026-05-06  
**Bugcheck:** `KMODE_EXCEPTION_NOT_HANDLED (0x1E)` — `STATUS_ILLEGAL_INSTRUCTION (0xC000001D)`  
**Commit:** `917d276`

---

## Root Cause

`INVEPT` is a VMX privileged instruction — it is only valid while the CPU is in **VMX root operation** (i.e., after `VMXON` has executed on that logical processor).  Executing `INVEPT` outside VMX root operation raises `#UD` (invalid opcode exception), which the Windows kernel converts to bugcheck `0x1E / 0xC000001D`.

Three call sites in the pre-launch EPT setup path were calling `EptInvalidate()`, which resolves to `AsmInveptSingleContext` → `INVEPT` instruction — all before the IPI that runs `VMXON` on each core:

| # | Call site | Location |
|---|---|---|
| 1 | `VmxIsolateInfrastructure` — after WP-table sort/registration | `Vmx.c` |
| 2 | `VmxInitialize` self-hiding block — after `EptHideRange` loop | `Vmx.c` |
| 3 | `EptSetPermissions` — inline flush at end of function | `Ept.c` |

`EptSetPermissions` is called by `EptHideRange`, which is called from `VmxInitialize` at driver-load time (PASSIVE_LEVEL, before any IPI). At that point `VMXON` has not executed anywhere.

---

## Fix

Replaced all three pre-VMXON `EptInvalidate` calls with:

```c
InterlockedExchange(&g_InveptPending, 1);
```

The `g_InveptPending` lazy-flush flag already existed (introduced for the BSOD #12 / IPI-broadcast fix). `VmExitDispatch` drains it on each core's first VM-exit:

```c
if (InterlockedCompareExchange(&g_InveptPending, 0, 1) == 1)
    EptInvalidate(g_Ept.Eptp);
```

At that point, VMX root operation is guaranteed active (we are inside a VM-exit handler). The EPT TLB is cold anyway at first `VMLAUNCH`, so deferring the flush to the first exit is not only safe but optimal — the flush was redundant at load time.

All remaining `EptInvalidate` calls in the codebase are inside VM-exit handlers where VMX root operation is always active.

---

## Linkage Change

`g_InveptPending` was declared `static volatile LONG` in `Vmx.c` — making it TU-private and inaccessible to `Ept.c`. To allow `EptSetPermissions` in `Ept.c` to set the flag directly:

- Removed `static` from the definition in `Vmx.c`
- Added `extern volatile LONG g_InveptPending;` to `Vmx.h`

---

## Files Changed

| File | Change |
|---|---|
| `Vmx.c` | Removed `static` from `g_InveptPending`; replaced 2× `EptInvalidate` + log message |
| `Ept.c` | Replaced `EptInvalidate` in `EptSetPermissions` with `InterlockedExchange`; added comment |
| `Vmx.h` | Added `extern volatile LONG g_InveptPending` declaration |
| `CHANGELOG.md` | Added BSOD #13 entry |

---

## Invariant Going Forward

> **Never call `EptInvalidate` (or any `INVEPT`-issuing function) outside a VM-exit handler.**  
> Any EPT modification made before `VMXON` must use `InterlockedExchange(&g_InveptPending, 1)` to defer the flush.
