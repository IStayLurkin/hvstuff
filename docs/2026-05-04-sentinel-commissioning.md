# 2026-05-04 — Sentinel Commissioning & Architectural Isolation

## Summary

This session completed the user-mode management plane and kernel architectural
isolation layer. The hypervisor is now write-protected against guest tampering,
and a full commissioning pipeline exists to register target GPAs via hypercall.

---

## What was implemented

### Kernel side (Vmx.c / Ept.c / Vmx.h)

**VmxIsolateInfrastructure** (called from VmxInitialize, after self-hiding):

Three-pass write-protection of hypervisor control structures:
- Pass 1: VmcsRegion + VmxonRegion for all 32 cores
- Pass 2: EPT paging structures (PML4 + all PDPT + PD pages, walked live)
- Pass 3: Driver image pages (base from RtlPcToFileHeader, size from PE SizeOfImage)

Each protected GPA is inserted into `g_WpTable[256]` (sorted ascending for
O(log n) binary search) and its EPT PTE is set to `EPT_READ | EPT_EXEC`.
A single `INVEPT` at the end flushes all cores' EPT TLBs.

**HandleEptViolation — write-protection enforcement:**

Write faults on registered GPAs inject `#GP(0)` (vector 13, type 3, error-code 0)
instead of lazy-mapping. Logged as `[WP]` events.

**HandleEptViolation — MBEC user-execute guardrail:**

When `EPT_QUAL_EXEC_USER` (bit 11) is set and the leaf PTE does not have
`EPT_EXEC_USER` (bit 10), `#GP(0)` is injected. Logged as `[MBEC]` events.
`EptGetPteFlags` (new export in Ept.c) reads leaf PTE flags without modifying state.

**HV_CALL_WP_REGISTER (0x07):**

Runtime GPA registration: `VMCALL RAX=0x07, RBX=GPA`. Inserts into `g_WpTable`
with insertion-sort, sets EPT to `READ|EXEC`, issues INVEPT.
Returns `HV_STATUS_SUCCESS`, `HV_STATUS_BAD_ALIGNMENT`, `HV_STATUS_INVALID_CALL`,
or `HV_STATUS_NOT_SUPPORTED` (table full).

---

### User-mode side

**hvbridge/HvBridge.dll:**

User-mode DLL (x64, /MT, no CRT dep) with two MASM exports:
- `IssueHypercall(gpa, policy)` — HC 0x05
- `IssueHypercallRaw(id, arg0, arg1)` — any hypercall by ID

**spectre/hv_client.py — HvClient class:**

ctypes wrapper around HvBridge.dll. Methods: `set_ept_policy`, `protect_rx`,
`protect_ro`, `restore_rwx`, `sweep`, `wp_register`, `get_perf_counters`.
Input validation (`HvValidationError`) and HV status checking (`HvCallError`)
on every call.

**spectre/hv_client.py — Sentinel `__main__` entrypoint:**

When run directly:
1. Checks `logs/dayzdriv.log` for `RESIDENT HYPERVISOR LAUNCH BEGIN`
2. Reads `logs/sentinel_gpas.txt` (Label + 0xGPA per line, # comments ignored)
3. Calls `wp_register` for each GPA
4. Reports per-GPA pass/fail
5. Exits 0 on full success (`[*] Sentinel active — N/N GPAs write-protected`),
   exits 1 on any failure

---

### resolver/ — kernel physical address resolver

Standalone one-shot WDM driver (separate from dayzdriv.sys):

- `Resolver.c`: calls `MmGetSystemRoutineAddress` + `MmGetPhysicalAddress` for
  each entry in `g_Symbols[]`, writes `logs\sentinel_gpas.txt`, self-unloads
- `resolver.vcxproj`: WDM driver project, same WDK/toolchain as dayzdriv
- `build.bat`: compile + sign with DayZTestCert, output to `resolver\bin\resolver.sys`
- `run.bat`: `sc create` → `sc start` → 1s wait → `sc delete` → print output

Default symbol table:
- `KiSystemCall64`
- `NtCreateFile`
- `PsInitialSystemProcess`
- `MmSystemRangeStart`
- `ExAllocatePoolWithTag`

Unresolvable symbols are written as commented-out `# UNRESOLVED Label` lines
so the file is always valid for the Python parser.

---

## Commissioning sequence

```
1. resolver\build.bat          # requires elevated prompt + DayZTestCert
2. resolver\run.bat            # writes logs\sentinel_gpas.txt
3. sc.exe query dayz           # must show RUNNING
4. python spectre\hv_client.py # registers GPAs via HC 0x07
```

Expected output of step 4:
```
[*] dayzdriv Sentinel — commissioning tool
    repo : F:\vsprojs\dayzdriv
    dll  : F:\vsprojs\dayzdriv\bin\HvBridge.dll
    gpas : F:\vsprojs\dayzdriv\logs\sentinel_gpas.txt

[+] Hypervisor active (LAUNCH BEGIN seen in log).
[+] HvBridge.dll loaded.

    [+] KiSystemCall64               0x<GPA>  REGISTERED
    [+] NtCreateFile                 0x<GPA>  REGISTERED
    ...

[*] Sentinel active — N/N GPAs write-protected via HV_CALL_WP_REGISTER.
```

---

## Known gaps / next steps

1. **IPI-driven INVEPT broadcast** — `EptInvalidate` runs on calling core only.
   Other cores have stale EPT TLBs until next VM-exit. Fix: `KeIpiGenericCall`
   stub calling `EptInvalidate` after each `g_WpTable` insertion.

2. **IOCTL interface** — `IRP_MJ_DEVICE_CONTROL` not yet wired in `Driver.c`.
   Needed for usermode physical memory reads via `\\.\DayZLink`.

3. **Sentinel target expansion** — add DayZ-specific GPAs to `g_Symbols[]`
   in `resolver\Resolver.c` once the game process VA→GPA mapping is known.
