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

### Scoped EPT self-hiding

`EptHideRange(Ept, Va, Bytes, DecoyVa)` walks a VA range page-by-page, calls `MmGetPhysicalAddress` on each page, and calls `EptSetPermissions` with `AccessMask=0` (no R/W/X). Any guest attempt to read those GPAs triggers an EPT violation; `EptHandleViolation` returns the zeroed `DecoyVa` page for R/W faults and the real HPA for X faults.

Called from `VmxInitialize` after EPT is built, before the Phase 1 probe, hiding:

| Range | Why hidden |
|---|---|
| `g_CtxArray` (all `CORE_VMX_CONTEXT` slots) | Per-core VMX state, guest register snapshots, pending injection fields |
| Per-core `MsrBitmap` | MSR intercept configuration |
| Per-core `IoBitmapA` / `IoBitmapB` | I/O port intercept configuration |

Not hidden: `VmxonRegion`, `VmcsRegion`, `HostStack` — these are accessed by CPU hardware in root mode and must remain at their physical addresses. The driver PE image is also left visible to avoid PatchGuard/loader interference.

A single zeroed `g_DecoyPage` (tag `HvDC`, 4KB) backs all hidden GPAs. Freed in `VmxTeardown` after `EptFree`.

### LSTAR syscall entry monitoring

`IA32_LSTAR` (0xC0000082) intercept bits are set in the MSR bitmap high-MSR region (read at offset 0x410 bit 2, write at 0xC10 bit 2). `HandleRdmsr` returns the real hardware value and `DbgPrint`s it. `HandleWrmsr` logs the new kernel entry point address and passes through — the kernel legitimately writes LSTAR during boot and S3 resume.

### Descriptor-table exiting

`SECONDARY_EXEC_DESC_TABLE_EXITING` (secondary bit 2) causes exits on `LGDT`, `LIDT`, `LLDT`, and `LTR`. Exit reason 46 covers GDTR/IDTR instructions; reason 47 covers LDTR/TR. `HandleDescriptorTable` decodes the instruction from exit qualification bits 1:0 and `DbgPrint`s the instruction name and qualification value, then advances RIP. Writes are passed through — blocking LGDT/LIDT would BSOD on S3 resume.

### Thermal and power MSR spoofing

`IA32_ENERGY_PERF_BIAS` (0x1B0) and `IA32_PACKAGE_THERM_STATUS` (0x1B1) are intercepted via MSR bitmap (low-MSR region, byte 0x36 bits 0–1). `HandleRdmsr` returns static nominal values: `ENERGY_PERF_BIAS = 0x6` (balanced, matching Windows default), `PACKAGE_THERM_STATUS = 0x0` (no thermal events). `HandleWrmsr` swallows writes silently. This prevents VM-exit–driven power oscillations from appearing in software thermal monitors.

### APIC base MSR intercept

`IA32_APIC_BASE` (0x1B) is intercepted via MSR bitmap (byte 0x03 bit 3). `HandleRdmsr` returns the real hardware value transparently. `HandleWrmsr` swallows any attempted guest remap — prevents the guest from relocating the APIC MMIO window to an unknown physical address without monitor knowledge.

### XSETBV extended-state synchronisation

`SECONDARY_EXEC_ENABLE_XSETBV` (secondary bit 13) intercepts `XSETBV`. `HandleXsetbv` reads `XCR[RCX]` index and `RDX:RAX` value from guest registers, `DbgPrint`s them, executes the real `_xsetbv` intrinsic to keep hardware state in sync, then advances RIP.

### Stateful interrupt-window event delivery

`InjectPendingException(Ctx)` now checks `VMCS_GUEST_INTERRUPTIBILITY` before injecting. If bits 0–1 are set (STI shadow or MOV SS shadow), it saves `PendingIntrInfo`/`PendingErrorCode` in `CORE_VMX_CONTEXT`, sets `PendingInjection=TRUE`, and enables `CPU_BASED_INTERRUPT_WINDOW_EXITING` (primary bit 2) by patching the live `VMCS_CPU_BASED_VM_EXEC_CONTROL` field.

On exit reason 7 (interrupt window), `HandleInterruptWindow` clears the bit, then calls `DoInject` to deliver the saved event. The bit is only set for the duration of one deferred injection, preventing the exit flood that permanent enablement would cause.

`CORE_VMX_CONTEXT` gains three new fields at `+0x128`: `PendingInjection` (BOOLEAN), `PendingIntrInfo` (ULONG), `PendingErrorCode` (ULONG), with `C_ASSERT` layout checks.

### CR register state consistency

`CR4_GUEST_HOST_MASK` owns bit 13 (`VMXE`). Guest `MOV from CR4` returns `CR4_READ_SHADOW`, which has `VMXE=0`, so the guest never sees the hypervisor's VMX-enable bit. `CR0_GUEST_HOST_MASK` is 0 — no CR0 bits owned. Both values verified by the Phase 1 VMCS probe PVMR readback.

### Exception re-injection

`InjectPendingException()` is called from the `default:` branch of `VmExitDispatch` for any exit reason not explicitly handled. It reads `VMCS_VM_EXIT_INTR_INFO` (0x4404); if bit 31 is set and the type field indicates a hardware exception (type=3), it re-writes the event into `VMCS_VM_ENTRY_INTR_INFO_FIELD` with the error code (if present) so the guest's IDT handles it naturally. Only if there is no valid interruption info does the handler fall through to `TeardownPending`.

### I/O bitmap — PCI config port monitoring

Two 4KB non-paged I/O bitmaps (`IoBitmapA`/`IoBitmapB`) are allocated per core with `CPU_BASED_USE_IO_BITMAPS` (bit 25) set in primary proc controls. Ports `0xCF8–0xCFF` (PCI CONFIG_ADDRESS / CONFIG_DATA) have their bitmap bits set in bitmap A. `HandleIoAccess` executes the real `IN`/`OUT` on behalf of the guest (hardware continuity preserved), restores the result into guest RAX for reads, then `DbgPrint`s port, direction, size, and value.

### EPT accessed/dirty (A/D) bit tracking

`SECONDARY_EXEC_ENABLE_EPT_AD` (bit 21 of secondary controls) is set in `cpu2Ctls`. `EPT_AD_ENABLE` (EPTP bit 6) is set in `EptBuildIdentityMap`. This enables hardware-managed A/D bit updates in EPT leaf entries, mirroring bare-metal page-metadata behaviour so the guest memory manager does not observe discrepancies.

### VM-exit dispatch

| Reason | Handler |
|--------|---------|
| CPUID | Masks hypervisor-present bit, clears leaf 0x40000000 |
| RDMSR `IA32_FEATURE_CONTROL` | Spoofs `0x05` (locked + VMXON-outside-SMX); logs via `DbgPrint` |
| WRMSR `IA32_FEATURE_CONTROL` | Swallows write silently; logs via `DbgPrint` |
| RDMSR / WRMSR (other) | Passes through; blocks VMX capability MSRs |
| MOV CR0/3/4 | Updates VMCS guest and read-shadow fields |
| I/O access (0xCF8–0xCFF) | Executes real IN/OUT, logs port+value via `DbgPrint` |
| GDTR/IDTR access (reason 46) | Logs instruction + qualification, advances RIP |
| LDTR/TR access (reason 47) | Logs instruction + qualification, advances RIP |
| XSETBV (reason 55) | Executes real `_xsetbv`, logs XCR index + value |
| Interrupt window (reason 7) | Clears window bit, delivers deferred injection |
| EPT violation (protected GPA) | Shadow swap via `EptHandleViolation` + `DbgPrint` + INVEPT |
| EPT violation (unprotected GPA) | Lazy 4KB identity-map via `EptMapPage4KB` |
| VMCALL / HLT | Sets `TeardownPending` → VMXOFF on exit |
| External INT / Preemption timer | Re-injects / resumes |
| Unhandled (hardware exception) | Re-injected via `VM_ENTRY_INTR_INFO_FIELD` |
| Unhandled (no exception info) | `TeardownPending` |

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
| 2026-05-03 | Hypervisor control pages scannable by guest | `EptHideRange` hides `CORE_VMX_CONTEXT`, `MsrBitmap`, `IoBitmapA/B` via `EptSetPermissions(mask=0)`. Decoy zero page (`g_DecoyPage`, tag `HvDC`) returned for R/W faults. |
| 2026-05-03 | Thermal/power MSRs reveal VM-exit overhead | `IA32_ENERGY_PERF_BIAS` spoofed to 0x6, `IA32_PACKAGE_THERM_STATUS` to 0x0. Writes swallowed. MSR bitmap bits at byte 0x36 bits 0–1. |
| 2026-05-03 | Guest could remap APIC base undetected | `IA32_APIC_BASE` (0x1B) intercepted via bitmap byte 0x03 bit 3. Reads pass through; writes swallowed with DbgPrint. |
| 2026-05-03 | No LSTAR visibility | MSR bitmap bits 0x410/0xC10 set for 0xC0000082; RDMSR logs+passes through; WRMSR logs new entry point address. |
| 2026-05-03 | No descriptor-table exiting | `SECONDARY_EXEC_DESC_TABLE_EXITING` (secondary bit 2); reasons 46/47 handled with DbgPrint, RIP advanced. |
| 2026-05-03 | XSETBV unhandled, fell to teardown | `SECONDARY_EXEC_ENABLE_XSETBV` (secondary bit 13); `HandleXsetbv` executes real `_xsetbv` and advances RIP. |
| 2026-05-03 | Exception injection dropped if guest non-interruptible | `InjectPendingException` checks interruptibility; defers via `PendingInjection` + interrupt-window exiting (primary bit 2). `HandleInterruptWindow` (reason 7) delivers and clears the bit. |
| 2026-05-03 | CR4.VMXE visible to guest | `CR4_GUEST_HOST_MASK` owns bit 13; `CR4_READ_SHADOW` has VMXE=0. Guest `MOV from CR4` returns shadow. |
| 2026-05-03 | Unhandled exceptions caused teardown | `InjectPendingException` re-injects hardware exceptions (type=3) via `VM_ENTRY_INTR_INFO_FIELD` before falling back to teardown. |
| 2026-05-03 | No I/O interception | I/O bitmaps (`IoBitmapA`/`B`, tag `HvIA`/`HvIB`) with `CPU_BASED_USE_IO_BITMAPS`; ports 0xCF8–0xCFF intercepted. `HandleIoAccess` passes through real hardware and logs. |
| 2026-05-03 | EPT A/D bits not tracked by hardware | `SECONDARY_EXEC_ENABLE_EPT_AD` (bit 21) added to secondary controls; `EPT_AD_ENABLE` (bit 6) set in EPTP. |
| 2026-05-03 | No EPT memory isolation primitive | Added `EptSetPermissions` + `EptHandleViolation` + fixed shadow table (`g_EptShadowTable[64]`). R/W faults swap PTE to decoy `ShadowHpa`; X faults swap to `RealHpa`. Each swap followed by INVEPT + `DbgPrint`. TSC offset masking via `VMCS_TSC_OFFSET` hides handler latency from guest `RDTSC`. |
