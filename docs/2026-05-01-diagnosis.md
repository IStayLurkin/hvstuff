# 2026-05-01 Crash Diagnosis

## Stop code reported: CRITICAL_STRUCTURE_CORRUPTION (0x109)

The 0x109 on the stop screen was from a **prior session's dump** (`043026-10406-01.dmp`), already fixed as BSOD #7. Today's new dump is a separate issue.

---

## Dumps analyzed

| File | Crash time | Bugcheck | Status |
|------|-----------|----------|--------|
| `C:\Windows\Minidump\043026-10406-01.dmp` | prior session | **0x109** Arg4=0x3 (GDT corruption) | Fixed — BSOD #7 |
| `C:\Windows\Minidump\043026-10562-01.dmp` | Thu Apr 30 08:29:59 | **0xD1** IRQL=0xE (IPI_LEVEL page fault) | Fixed — BSOD #9 (see below) |

---

## BSOD #9 — 0xD1, IRQL=0xE (IPI_LEVEL)

### Dump
`C:\Windows\Minidump\043026-10562-01.dmp`  
Crash time: `Thu Apr 30 08:29:59.856 2026` (UTC-7) — matches first EPT build timestamp exactly.

### Bugcheck parameters
- Arg1: `ffff8807d3892c08` — memory address written to
- Arg2: `0xE` — IRQL (IPI_LEVEL)
- Arg3: `0x1` — write operation
- Arg4: `fffff8063f758689` — faulting IP (Ntfs!NtfsChangeAttributeValue+0x6b9)

### Call stack (abridged)
```
nt!KeBugCheckEx
nt!KiBugCheckDispatch+0x69
nt!KiPageFault+0x468
Ntfs!NtfsChangeAttributeValue+0x6b9
Ntfs!NtfsAddAllocationForResidentWrite+0x1aa
Ntfs!NtfsCommonWrite+0x32b5
Ntfs!NtfsFsdWrite+0x584
nt!IopfCallDriver / nt!IofCallDriver
FLTMGR!FltpDispatch
nt!NtWriteFile+0x2d2
nt!KiSystemServiceCopyEnd+0x25
nt!KiServiceLinkage
dayzdriv!FreeCoreCxtArray+0x28    ← dayzdriv+0x13c8
...
dayzdriv!memcpy+0x1f0             ← dayzdriv+0x3298  (RtlCopyMemory)
```

### Root cause
The first EPT-enabled build (08:29:58) ran a version of `VmxLaunchCore` that still contained
pageable/filesystem calls inside the `KeIpiGenericCall` callback (running at IPI_LEVEL = 0xE).
`ExFreePoolWithTag` / `RtlCopyMemory` internally accessed paged metadata or paged pool,
triggering a page fault that cascaded into `NtWriteFile` → Ntfs — illegal above DISPATCH_LEVEL.

Same class as **BSOD #8** (same rule: never call ZwWriteFile or any pageable/filesystem API
above DISPATCH_LEVEL; IPI callbacks run at IPI_LEVEL).

### Fix
Already applied in subsequent builds: all `HvLog`, `ExFreePool`, and pageable calls were
removed from `VmxLaunchCore`. The IPI callback now contains only MSR reads, intrinsics,
VMCS operations, and non-paged memory accesses.

### Evidence fix works
Post-fix builds show no BSOD. Driver runs to 31/32 or 32/32 PASS with only the
pre-existing intermittent `exit=0x80000021` (invalid guest state) on a random core —
no crash, no dump generated.

---

## Remaining open issue (not a BSOD)

Intermittent `exit=0x80000021` (VM-entry failure, invalid guest state) on a single core per
run. Non-deterministic — different core each time (core 9 in the last captured run). Not
reproduced on every run. Suspected race or per-core VMCS state issue, not investigated yet.
