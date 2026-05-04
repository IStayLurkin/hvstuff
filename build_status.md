# Build Status — DayZ Hypervisor (dayzdriv)

**Target:** i9-14900K (Raptor Lake) / MSI MAG Z790 TOMAHAWK MAX WIFI / Windows 11 26100
**Toolchain:** VS2022 Build Tools G:\VS2022BT | WDK 10.0.26100.0 | ml64/cl/link HostX64\x64

---

## Current State: RESIDENT + ISOLATED — awaiting sentinel_gpas.txt population

---

## Files

| File | Status | Description |
|------|--------|-------------|
| `Arch.asm` | Done | GDT/IDT/selector getters, LAR/LSL, AsmLaunchAndReturn, AsmVmExitHandler, AsmInveptSingleContext |
| `Vmx.h` | Done | VMCS field constants, MSR indices, structs, prototypes, `C_ASSERT` offset checks |
| `Vmx.c` | Done | 3-phase launch (probe→pilot→full), VmxProbeCore, VmxLaunchCore, VmExitDispatch, EPT violation, teardown, HvLog |
| `Ept.c` | Done | 2MB identity map over all physical ranges, lazy 4KB split on EPT violation, EptFree |
| `Driver.c` | Done | DriverEntry, DriverUnload (calls VmxTeardown), CreateClose IRP handler |
| `build_dayz.bat` | Done | Full pipeline: stop→asm→compile→link→sign + numbered action menu |
| `hvbridge/HvBridge.dll` | Done | User-mode hypercall bridge: IssueHypercall + IssueHypercallRaw |
| `spectre/hv_client.py` | Done | Python HvClient wrapper + Sentinel commissioning entrypoint |
| `resolver/Resolver.c` | Done | One-shot WDM driver: resolves symbols → writes sentinel_gpas.txt |
| `resolver/build.bat` | Done | Compiles + signs resolver.sys with DayZTestCert |
| `resolver/run.bat` | Done | sc create → sc start → sc delete → prints sentinel_gpas.txt |

---

## Launch Pipeline

```
DriverEntry
  └─ VmxInitialize
       ├─ [Phase 1] VmxProbeCore IPI (all cores)
       │    VMXON → VMPTRLD → write all VMCS → readback critical fields → VMXOFF
       │    Abort if any field write or readback fails — logged before any VMLAUNCH
       │
       ├─ [Phase 2] VmxLaunchCore pinned to core 0
       │    Full VMLAUNCH on one core. If it BSODs, 31 cores are unaffected.
       │    Phase 1 log is already flushed to disk before this runs.
       │
       └─ [Phase 3] KeIpiGenericCall(VmxLaunchCore, all cores)
            Only reached after Phase 1 + Phase 2 both pass.
            All 32 cores go resident. Windows runs as guest.
```

---

## VM-exit Dispatch

| Exit Reason | Action |
|-------------|--------|
| CPUID (10) | Mask hypervisor bit; zero leaf 0x40000000 |
| RDMSR (31) | Pass through; return 0 for VMX capability MSRs |
| WRMSR (32) | Pass through; ignore writes to VMX capability MSRs |
| MOV CR (28) | Update VMCS guest CR + read shadow |
| EPT violation (48) | Lazy 4KB identity map via EptMapPage4KB + INVEPT |
| VMCALL (18) / HLT (12) | Set TeardownPending → VMXOFF on this exit |
| External INT (1) / Preemption (52) | Re-inject / resume |

---

## Safety Measures

| Measure | What it catches |
|---------|-----------------|
| `C_ASSERT` offsets in `Vmx.h` | ASM `CTX_*` EQU drift from C struct — build error |
| Phase 1 VMCS probe | Invalid VMCS state before VMLAUNCH — logged, no freeze |
| Phase 2 pilot launch | First-VMLAUNCH bugs isolated to core 0 — 31 cores safe |
| `LVMW` macro | Silent VMWRITE failure — logs field encoding, aborts |
| Shadow GDT per core | TR busy-bit write goes to shadow, not live GDT (PatchGuard 0x109) |
| `FILE_WRITE_THROUGH` log | Log survives hard freeze — last line is last known good state |
| `vmxoff` before `CR4.VMXE` clear | Correct VMX teardown order on failure path |
| `LaunchResult != 0` guard | No CR4 write on success/teardown path — was cause of hard freeze |

---

## Test Log

| Date | Result | Notes |
|------|--------|-------|
| 2026-04-29 | BSOD 0xD1 | VMLAUNCH ok, VM-exit clean, crash on DriverEntry return. IRQL=0xFF = host stack overflow. |
| 2026-04-29 | 32/32 PASS | Smoke test (no EPT). All cores vmlaunch+vmcall+vmxoff. |
| 2026-04-30 | 32/32 PASS | Smoke test with EPT identity map. All cores passed. |
| 2026-05-02 | 0/32 FAIL | Resident launch: VMLAUNCH invalid guest state (exit=0x80000021). |
| 2026-05-02 | HARD FREEZE | Resident launch: IPI fired, machine froze. Root cause: unconditional `CR4.VMXE` clear after `AsmLaunchAndReturn` — `#GP` in VMX non-root → triple fault. Fixed. |
| 2026-05-02 | AWAITING | 3-phase safety pipeline added. Ready to test with `build_dayz.bat → 1`. |
| 2026-05-04 | 32/32 PASS | Resident launch confirmed: all 32 cores probed OK, Phase 2 pilot started (log in logs\dayzdriv.log). |
| 2026-05-04 | BUILT | VmxIsolateInfrastructure, HV_CALL_WP_REGISTER (0x07), MBEC guardrail, HvBridge.dll, hv_client.py Sentinel, resolver/Resolver.c all added. Awaiting resolver\run.bat + python spectre\hv_client.py commissioning run. |

---

## Next Steps

1. `resolver\build.bat` — build resolver.sys (elevated prompt)
2. `resolver\run.bat` — writes `logs\sentinel_gpas.txt`
3. `sc.exe query dayz` — confirm hypervisor is RUNNING
4. `python spectre\hv_client.py` — register GPAs, confirm `[*] Sentinel active`
5. Monitor `logs\dayzdriv.log` for `[WP]` write violations and `[MBEC]` user-execute violations
6. Next kernel feature: IPI-driven INVEPT broadcast for full 32-core EPT TLB coherency
7. After that: IOCTL interface for usermode memory reads
