# VMX Hardware Fault Reference

Source: Intel SDM Vol 3D, Table 30-1 "VM-Instruction Error Numbers" (rev. June 2023).

The `VMCS_VM_INSTRUCTION_ERROR` field (encoding `0x4400`) is written by the CPU
on a VMfailValid condition (RFLAGS.ZF=1 after a VMX instruction).  It is **not**
written on VMfailInvalid (RFLAGS.CF=1, no current VMCS) or on success.

In this driver the field is read by `LogVmxInstrError()` and decoded by
`VmxInstrErrorName()` in `Vmx.c`.

---

## Error Code Table

| Code | Mnemonic | Triggering condition |
|-----:|----------|----------------------|
|  0 | No error / VMCS not current | ZF was not set, or `VMREAD` returned 0 because there is no current VMCS |
|  1 | `VMCALL` in VMX root | `VMCALL` executed while already in VMX root operation |
|  2 | `VMCLEAR` bad PA | `VMCLEAR` operand is not a valid physical address (misaligned, out of range, or WB-uncacheable) |
|  3 | `VMCLEAR` with VMXON pointer | `VMCLEAR` operand equals the address of the current VMXON region |
|  4 | `VMLAUNCH` non-clear VMCS | `VMLAUNCH` attempted on a VMCS whose launch state is not "clear" — use `VMRESUME` instead, or `VMCLEAR` first |
|  5 | `VMRESUME` non-launched VMCS | `VMRESUME` attempted on a VMCS whose launch state is not "launched" — use `VMLAUNCH` first |
|  6 | `VMRESUME` after `VMXOFF` | `VMRESUME` executed after the VMXON region was deactivated |
|  7 | VM entry: invalid control fields | One or more VM-execution, VM-exit, or VM-entry control fields violate a consistency check.  **Most common cause: CR0 or CR4 bit violates IA32_VMX_CR0/CR4_FIXED0/FIXED1 masks.** See `[CR AUDIT]` log lines. |
|  8 | VM entry: invalid host-state | A host-state field (segment selector, base, RSP, RIP, CR0, CR4, etc.) fails a VMX consistency check |
|  9 | `VMPTRLD` bad PA | `VMPTRLD` operand is not a valid, WB-cacheable, 4KB-aligned physical address |
| 10 | `VMPTRLD` with VMXON pointer | `VMPTRLD` operand equals the VMXON region physical address |
| 11 | `VMPTRLD` revision ID mismatch | The VMCS revision identifier in the first 4 bytes of the target region does not match `IA32_VMX_BASIC[30:0]` |
| 12 | `VMREAD`/`VMWRITE` unsupported field | The VMCS component encoding is not recognized by this CPU |
| 13 | `VMWRITE` to read-only field | Attempted write to a read-only VMCS field (e.g. VM-exit reason, exit qualification) |
| 15 | `VMXON` in VMX root | `VMXON` executed when the processor is already in VMX root operation (VBS/Hyper-V conflict) |
| 16 | VM entry: invalid executive VMCS | The executive-VMCS pointer in a VMCS for an SMM dual-monitor is invalid |
| 17 | VM entry: non-launched executive VMCS | The executive VMCS has not been launched |
| 18 | VM entry: executive VMCS != VMXON pointer | Outside SMM, the VMCS link pointer does not equal the VMXON pointer |
| 19 | `VMCALL` with non-clear VMCS (dual-monitor) | `VMCALL` for SMM-transfer with VMCS not in clear state |
| 20 | `VMCALL` invalid VM-exit control fields | VM-exit control fields in the VMCS used for `VMCALL` in dual-monitor mode are invalid |
| 22 | `VMCALL` incorrect MSEG revision ID | MSEG header revision ID does not match `IA32_SMM_MONITOR_CTL[31:0]` |
| 23 | `VMXOFF` under dual-monitor | `VMXOFF` executed while dual-monitor treatment of SMIs and SMM is active |
| 24 | `VMCALL` invalid SMM-monitor features | MSEG header or SMM-monitor features field is invalid |
| 25 | VM entry: invalid exec control (executive VMCS) | VM-execution control in the executive VMCS is incompatible with the current processor state |
| 26 | VM entry: events blocked by MOV SS | VM entry attempted with events blocked by a `MOV SS` or `POP SS` in the guest-state area |
| 28 | Invalid operand to `INVEPT`/`INVVPID` | The invalidation type or descriptor passed to `INVEPT` or `INVVPID` is unsupported |

---

## Diagnostic Correlation

### Error 7 — Invalid control fields (most likely on 14900K)

This is the most common non-hang failure.  Check the `[CR AUDIT]` lines logged
by `VmxAuditCrValues()` immediately before the hang sentinel:

```
[CR AUDIT core=00] GUEST_CR0=0x...  GUEST_CR4=0x...  HOST_CR0=0x...  HOST_CR4=0x...
[CR AUDIT core=00] FIXED0: CR0=0x...  CR4=0x...  FIXED1: CR0=0x...  CR4=0x...
[CR AUDIT core=00] All CR0/CR4 values conform to FIXED masks — OK
```

If the audit reports violations, the bad bit mask is printed per-field.  Common
causes on Raptor Lake:

- `CR0.PE` (bit 0), `CR0.PG` (bit 31), `CR0.NE` (bit 5) — must be 1 (FIXED0).
- `CR4.VMXE` (bit 13) — must be 1 in host CR4 while in VMX root, but must be 0
  in the guest read-shadow (`VMCS_CR4_READ_SHADOW`) to hide VMX from the guest.
- `CR4.PAE` (bit 5) — must be 1 when long mode is active (FIXED0 on most CPUs).

### Error 8 — Invalid host-state

Check segment selectors: bits 2:0 (RPL and TI) must be 0 for all host selectors.
The code masks them with `& ~7U` before writing, so this should not occur.
If it does, check `AsmGetCs()` / `AsmGetTr()` return values in the log.

### Error 11 — VMCS revision ID mismatch (VMPTRLD)

The first DWORD of the VMCS region must match `IA32_VMX_BASIC[30:0]`.
`GetVmcsRevisionId()` reads this MSR.  A mismatch means either the MSR was read
before VMX was enabled (stale value), or the VMCS region was not initialized
before `VMPTRLD` (race between Phase A initialization and Phase B execution).

### VMfailInvalid (CF set, no error code)

`VMXON` and `VMPTRLD` with bad physical addresses set CF and produce no error code.
The log will show:

```
[VMXON FAIL core=00] __vmx_on returned 1 (CF=VMfailInvalid ...)
```

Verify `MmGetPhysicalAddress` returned a non-zero PA, and that the VMXON/VMCS
regions are 4KB-aligned non-paged allocations with WB memory type.

---

## EPT Physical-Page Aliasing — BSOD 0xA in `KeAccumulateTicks` (2026-05-16)

### Symptom

`IRQL_NOT_LESS_OR_EQUAL` (0xA), `Arg2: 0xFF` (HIGH_LEVEL), faulting address in
user-space range (e.g. `0x20a8592a000`).  Failure bucket: `AV_nt!KeAccumulateTicks`.

Stack: `KeBalanceSetManager` → `MiWorkingSetManager` → `MiAgeWorkingSet` →
`MiFlushTbList` → `KiIpiWaitForRequestBarrier` interrupted by clock ISR →
`KeClockInterruptNotify` → `KiUpdateRunTime` → `KeAccumulateTicks` → fault.

`KeAccumulateTicks` reads `KTHREAD.ApcState.Process`; the field contains a
user-space address, causing a read fault at IPI_LEVEL.

### Root Cause

The identity EPT map was built using 2MB large-page PDEs for the bulk of physical
RAM.  `EptMapPage4KB`, called from VMX root at HIGH_LEVEL during EPT violation
handling, split 2MB PDEs by calling `AllocEptTable` →
`MmAllocateContiguousMemorySpecifyCache` from inside the VMX root window.

`MmAllocateContiguousMemorySpecifyCache` is not safe at HIGH_LEVEL.  It can return
a physical page that is simultaneously registered in the guest's PFN database as
a live non-paged pool allocation (e.g. a `KTHREAD`).  Because the EPT identity map
covers all physical RAM (GPA == HPA), the EPT hardware then walks that page as a
PT — its 64-bit entries are interpreted as EPT page-table entries by the hypervisor
and as `KTHREAD` fields by the guest concurrently.  The `KTHREAD.ApcState.Process`
field offset lands on an EPT entry value that happens to be a low GPA (e.g.
`0x20a8592a000`), which the guest reads as a pointer and then dereferences at
IPI_LEVEL.

A `SplitLock` TAS primitive was added in a prior fix to prevent two cores from
racing the split.  It prevented the double-split race but did not address the
allocator-returns-live-pool-page hazard, so the BSOD recurred.

### Fix (2026-05-16)

`EptBuildIdentityMap` now maps all physical RAM at **4KB granularity from the
start** using `EptMap4KBLeaf`.  No 2MB large-page PDEs are created anywhere in
the identity map.

Consequences:
- `EptMapPage4KB` now only walks the already-populated PT and writes a leaf PTE.
  No allocation, no split, no lock — unconditionally safe from VMX root.
- `EptTryMerge2MB` (which could re-introduce large-page PDEs at runtime) is
  removed entirely.
- `EPT_CONTEXT.SplitLock` field removed — no longer needed.
- `EptFree` updated to walk all four levels (PML4 → PDPT → PD → PT) since every
  PDE now points to a PT rather than a large-page leaf.

Trade-off: `EptBuildIdentityMap` allocates significantly more PT pages up front
(one 4KB page per 2MB of physical RAM ≈ ~32 MB of EPT tables for a 64 GB system).
All allocations are made from `MmAllocateContiguousMemorySpecifyCache` at
PASSIVE_LEVEL before VMXON, where the allocator is safe.

---

## Log Line Quick Reference

| Log tag | Meaning |
|---------|---------|
| `[CR AUDIT core=NN]` | Pre-launch CR0/CR4 vs FIXED mask dump — logged unconditionally |
| `[VMX INSTR ERROR core=NN]` | ZF-path error after VMWRITE/VMLAUNCH — includes code + name |
| `[VMXON FAIL core=NN]` | CF-path VMXON failure — no error code available |
| `[VMPTRLD FAIL core=NN]` | CF-path VMPTRLD failure — no error code available |
| `[VMLAUNCH FAIL core=NN]` | VMLAUNCH fell through — includes exit reason + error code |
| `[VBS CONFLICT core=NN]` | CR4.VMXE already set at Phase B entry — Hyper-V/VBS active |
| `[VMINSTR DIAG core=NN]` | Phase sentinel trace — last tag before hang identifies killer |
