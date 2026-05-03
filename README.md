# dayzdriv — Bare-Metal VMX Hypervisor Driver

Windows kernel driver that virtualizes all logical processors using Intel VT-x (VMX) and EPT.
Targets i9-14900K / MSI MAG Z790 / Windows 11 26100.

---

## Build

Run `build_dayz.bat` from any terminal (VS dev env is loaded automatically).

The menu after a successful build:

```
1  Start driver   — sc create + sc start, auto-watches for crash dump (15s)
2  Stop driver    — sc stop + sc delete
3  Tail log       — last 40 lines of logs\dayzdriv.log
4  Analyze dump   — cdb !analyze on newest dump in dumps\
5  Exit
```

Manual one-shot build + sign without the menu:

```
build_dayz.bat
```

---

## Toolchain

| Component | Path |
|-----------|------|
| VS2022 Build Tools | `G:\VS2022BT` |
| WDK | `C:\Program Files (x86)\Windows Kits\10` (10.0.26100.0) |
| ml64 / cl / link | `G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64` |
| signtool | WDK `bin\10.0.26100.0\x64\signtool.exe` |

---

## Architecture

### Launch sequence (3-phase safety pipeline)

**Phase 1 — VMCS probe (no VMLAUNCH, all cores)**
Every core runs VMXON → VMPTRLD → writes all VMCS fields → reads back a
critical subset to verify → VMXOFF. No guest is ever entered. If any field
mismatches, the driver aborts with a logged field encoding before touching
the live kernel state. Build-time `C_ASSERT` checks enforce that every ASM
`CTX_*` offset matches the C struct layout.

**Phase 2 — Pilot launch (core 0 only)**
Core 0 runs a full VMLAUNCH. If it freezes or BSODs, only one core is
affected and the Phase 1 log is already on disk. This turns an all-cores
hard-freeze into a single-core diagnosable failure.

**Phase 3 — Full resident launch (all cores via IPI)**
Only reached after both Phase 1 and Phase 2 pass. All 32 cores go resident
simultaneously via `KeIpiGenericCall`. Windows runs as a guest from this
point until `DriverUnload`.

### MSR bitmap

A 4KB non-paged page is allocated per core and pointed to by `VMCS_MSR_BITMAP`.
`CPU_BASED_USE_MSR_BITMAPS` (bit 28) is set in the primary processor-based controls
so the CPU consults the bitmap instead of exiting on every MSR access.

Only `IA32_FEATURE_CONTROL` (0x3A) has its bits set:
- Offset `0x000` bit 2 — RDMSR exits
- Offset `0x800` bit 2 — WRMSR exits

All other MSR bits are zero (no exit), which eliminates the per-MSR overhead of
the unconditional RDMSR/WRMSR exit path.

### EPT memory isolation (Phase 3)

`EptSetPermissions(Ept, Gpa, ShadowVa, AccessMask)` protects a single 4KB guest-physical page:

1. Calls `EptMapPage4KB` to split any covering 2MB PDE and install a 4KB PTE with `AccessMask` permissions.
2. Records `{ Gpa, RealHpa, ShadowHpa }` in the fixed `g_EptShadowTable[64]`.
3. Calls `EptInvalidate` to flush hardware TLB caches.

`ShadowVa` is a caller-allocated non-paged 4KB buffer (content controlled by the caller). The driver derives its physical address via `MmGetPhysicalAddress`.

**Violation handler swap logic** (`EptHandleViolation`):

| Access type (exit qual bits 2:0) | PTE swapped to | Permissions set |
|---|---|---|
| Read or Write (bits 0/1) | `ShadowHpa` (decoy page) | R+W only — X still faults |
| Execute (bit 2) | `RealHpa` (original page) | X only — R/W still faults |

Each swap is followed by a Type 1 (Single-Context) `INVEPT`. `DbgPrint` emits the GPA, exit qualification, and target HPA on every intercept — visible in DebugView in real time.

GPAs not in the shadow table fall through to the existing lazy-map path (`EptMapPage4KB` identity UC).

### TSC latency masking

`VmExitDispatch` captures `__rdtsc()` on entry and subtracts the handler wall-time from `VMCS_TSC_OFFSET` before returning to the guest. The offset accumulates across exits so the guest's `RDTSC` view drifts by at most one exit's overhead rather than the sum of all exits.

### VM-exit dispatch

| Reason | Handler |
|--------|---------|
| CPUID | Masks hypervisor-present bit, clears leaf 0x40000000 |
| RDMSR `IA32_FEATURE_CONTROL` | Spoofs `0x05` (locked + VMXON-outside-SMX); logs via `DbgPrint` |
| WRMSR `IA32_FEATURE_CONTROL` | Swallows write silently; logs via `DbgPrint` |
| RDMSR / WRMSR (other) | Passes through; blocks VMX capability MSRs |
| MOV CR0/3/4 | Updates VMCS guest and read-shadow fields |
| EPT violation (protected GPA) | Shadow swap via `EptHandleViolation` + `DbgPrint` + INVEPT |
| EPT violation (unprotected GPA) | Lazy 4KB identity-map via `EptMapPage4KB` |
| VMCALL / HLT | Sets `TeardownPending` → VMXOFF on exit |
| External INT / Preemption timer | Re-injects / resumes |

### EPT

2MB large-page identity map built at load time over all physical memory
ranges reported by `MmGetPhysicalMemoryRanges`. EPT violations lazily
promote missed pages to 4KB mappings without splitting the entire map.

---

## Logging

- **File:** `logs\dayzdriv.log` (volume GUID path, `FILE_WRITE_THROUGH` — survives hard freeze)
- **Format:** `[QPC_ticks] !!! DayZHV: message`
- **DebugView:** mirrored via `DbgPrint`

---

## Safety measures

- `C_ASSERT` block in `Vmx.h` — compile error if ASM `CTX_*` offsets drift from C struct
- Phase 1 VMCS probe — catches invalid VMCS state before any VMLAUNCH
- Phase 2 single-core pilot — isolates first-launch failures to one core
- `LVMW` macro — every `VMWRITE` in `VmxLaunchCore` aborts on failure with field logged
- Shadow GDT per core — TR busy-bit write on VM-exit lands in shadow copy, not live GDT (prevents PatchGuard 0x109)
- Host stack: 64KB, RSP at midpoint — 32KB guard headroom below and above
- `CR4.VMXE` cleared only on genuine VMLAUNCH failure — not on success/teardown path (was root cause of prior hard freeze)
- `vmxoff` called before `CR4.VMXE` clear on failure path

---

## Issues fixed

| Date | Issue | Fix |
|------|-------|-----|
| 2026-04-28 | CR0 missing NE bit | `AdjustCr0` forces all FIXED0 bits |
| 2026-04-28 | Host state VMWRITE triple-fault | `SafeVmWrite` + `LVMW` macro abort |
| 2026-04-28 | Stack misalign on VM-exit | RSP = base + 0x8000 - 16, `& ~0xF` |
| 2026-04-28 | TSS64 base extraction | `GetTssBase` reads all 64 bits |
| 2026-04-29 | BSOD 0xD1 IRQL=0xFF | Host stack 32KB→64KB, RSP at midpoint |
| 2026-04-29 | No file log appearing | Volume GUID path for kernel-mode file I/O |
| 2026-04-29 | BSOD 0x109 PatchGuard | HOST_GDTR_BASE → shadow GDT, not live GDT |
| 2026-05-02 | Hard freeze on resident launch | `CR4.VMXE` cleared unconditionally after `AsmLaunchAndReturn` returned on success path — causes `#GP` in VMX non-root → triple fault. Fixed: guard with `LaunchResult != 0`, add missing `vmxoff` on failure path. |
| 2026-05-03 | All MSR accesses exited unconditionally | Added MSR bitmap (`VMCS_MSR_BITMAP`) with `CPU_BASED_USE_MSR_BITMAPS`; only `IA32_FEATURE_CONTROL` (0x3A) intercept bits set. `HandleRdmsr` spoofs `0x05`, `HandleWrmsr` swallows writes; both log via `DbgPrint`. |
| 2026-05-03 | No EPT memory isolation primitive | Added `EptSetPermissions` + `EptHandleViolation` + fixed shadow table (`g_EptShadowTable[64]`). R/W faults swap PTE to decoy `ShadowHpa`; X faults swap to `RealHpa`. Each swap followed by INVEPT + `DbgPrint`. TSC offset masking via `VMCS_TSC_OFFSET` hides handler latency from guest `RDTSC`. |
