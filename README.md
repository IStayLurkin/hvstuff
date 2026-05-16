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

### Cache coherency — `__wbinvd` requirement on 14th Gen

On Intel Core 14th Gen (Raptor Lake / i9-14900K), the split ring bus between
P-core clusters means that code pages committed to DRAM by one execution engine
may not be coherent in the I-Cache of a second engine at the time of the first
fetch.  Under KDMapper this window is larger than normal because the mapper
writes the payload into a non-paged pool allocation without issuing any
architectural serializing sequence afterward.

**Rule:** Any call site that crosses from the mapper's load sequence into VMX
initialization code — specifically `DriverEntry` before `PsCreateSystemThread`
and `VmxLaunchCore` at IPI entry — must issue `__wbinvd()` followed by
`__cpuid(_, 0)` before proceeding.

- `__wbinvd` (WBINVD instruction, SDM Vol 2B §4.3): writes back all modified
  lines in all cache levels to main memory and invalidates all cache lines and
  TLB entries on the issuing logical processor.
- `__cpuid(_, 0)` (CPUID instruction, SDM Vol 3A §8.3): full serializing
  instruction — all prior µops are retired and the store buffer is drained
  before any instruction after CPUID is fetched or executed.

Without this sequence, the CPU may speculatively fetch I-Cache lines for
`HvInitThread` or Phase A of `VmxLaunchCore` from a stale pre-relocation copy
of the payload, producing an instruction stream that does not match the
relocated addresses — observed as an immediate hang at the Phase A alignment
log line on 14900K.

### KDMapper compatibility — `/GS-` (stack security check disabled)

This driver is optimized for KDMapper manual mapping. KDMapper maps the PE image
without processing the Load Config directory, which means:

- The `__security_cookie` global and `__security_check_cookie` export are **not
  initialized** at the mapped base address.
- Any function compiled with `/GS` (stack buffer security check) will corrupt
  the uninitialized cookie and fault at the stack-check epilogue.

**All source files are compiled with `/GS-`** to disable buffer security checks.
This is correct and intentional for a freestanding kernel environment loaded via
manual mapper — the WDK's structured exception handler table (`_pdata`, `_xdata`)
is still present and functional for the CPU; only the CRT-level cookie check is
absent.

Consequence: all critical VMX-path locals in `VmxLaunchCore` are explicitly
initialized on the stack at declaration; no variable relies on BSS zero-init or
a prior global write that may not be visible under the mapper's load model.

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

> **14th Gen scheduling bypass (2026-05-15):** On i9-14900K under KDMapper,
> kernel scheduling mitigations were intercepting the `PsCreateSystemThread`
> dispatch before the pilot thread could enter its execution context.  The
> launch path is now **synchronous**: `DriverEntry` calls `VmxInitialize()`
> directly (Phase 1 + 2 + 3) before returning, using its own execution context
> rather than a scheduler-dispatched system thread.  The WBINVD + CPUID(0)
> serialization fence immediately precedes the call.  `HvRemainingCoresThread`
> is retained in the source for future use but is not spawned in this path.

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

### Architectural isolation — write-protection (`VmxIsolateInfrastructure`)

Called once from `VmxInitialize` after self-hiding and before Phase 1 probe.
Protects hypervisor control structures against guest writes in three passes:

| Pass | What is protected |
|------|-------------------|
| 1 | `VmcsRegion` + `VmxonRegion` for all 32 cores |
| 2 | EPT paging structures: PML4 + all PDPT + all PD pages (walked live) |
| 3 | Driver image pages (base from `RtlPcToFileHeader`, size from PE `SizeOfImage`) |

Each protected GPA is inserted (sorted, binary-search dedup) into `g_WpTable[256]`
and its EPT PTE is set to `EPT_READ | EPT_EXEC` (write stripped).
A single `INVEPT` at the end flushes all cores' EPT TLBs.

Any subsequent guest write to a registered GPA triggers `#GP(0)` injection
(vector 13, type 3, error-code 0) instead of lazy-mapping the access through.
The fault is logged as a `[WP]` event.

**Known gap:** `EptInvalidate` runs on the calling core only. Other cores get
stale TLB entries until their next VM-exit. Fixing this requires an IPI-driven
`EptInvalidate` broadcast (not yet implemented).

### HV_CALL_WP_REGISTER (0x07)

Runtime registration: a trusted guest can add any 4KB-aligned GPA to
`g_WpTable` via `VMCALL` with `RAX=0x07`, `RBX=GPA`.

Return codes in guest `RAX`:

| Code | Meaning |
|------|---------|
| `HV_STATUS_SUCCESS` (0x00) | Registered (or already registered) |
| `HV_STATUS_BAD_ALIGNMENT` (0x03) | GPA not 4KB-aligned |
| `HV_STATUS_INVALID_CALL` (0x01) | GPA out of range |
| `HV_STATUS_NOT_SUPPORTED` (0x02) | `g_WpTable` full (256 entries max) |

### MBEC user-execute guardrail

When MBEC is active and `EPT_QUAL_EXEC_USER` (qualification bit 11) is set in
an EPT violation, `HandleEptViolation` reads the leaf PTE flags via
`EptGetPteFlags`. If `EPT_EXEC_USER` (bit 10) is not set in the PTE, `#GP(0)`
is injected and the event is logged as `[MBEC]`. This enforces the policy that
user-mode code cannot execute from supervisor-only EPT pages.

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

## User-mode management plane

### HvBridge.dll (`hvbridge/`)

User-mode DLL that exposes two exports:

| Export | Signature | Purpose |
|--------|-----------|---------|
| `IssueHypercall` | `uint64_t(uint64_t gpa, uint64_t policy)` | Issue HC 0x05 (SET_EPT_POLICY) |
| `IssueHypercallRaw` | `uint64_t(uint64_t id, uint64_t arg0, uint64_t arg1)` | Issue any hypercall by ID |

Built with VS2022 v143 toolset, `/MT` (no CRT DLL), output to `bin\HvBridge.dll`.

Build:
```
msbuild hvbridge\HvBridge.vcxproj /p:Configuration=Release /p:Platform=x64
```

### spectre/hv_client.py

Python ctypes wrapper around `HvBridge.dll`. Provides `HvClient` class with:

| Method | Hypercall | Description |
|--------|-----------|-------------|
| `set_ept_policy(gpa, policy)` | 0x05 | Set EPT permission bits on a 4KB GPA |
| `protect_rx(gpa)` | 0x05 | Strip write bit (READ \| EXEC) |
| `protect_ro(gpa)` | 0x05 | Strip write + execute bits |
| `restore_rwx(gpa)` | 0x05 | Restore full access |
| `sweep(base, count, policy)` | 0x05 | Apply policy to contiguous page range |
| `wp_register(gpa)` | 0x07 | Add GPA to kernel write-protection table |
| `get_perf_counters()` | 0x03 | Read MPERF/APERF exit-overhead counters |

### Sentinel commissioning (`python spectre\hv_client.py`)

When run directly, `hv_client.py` acts as a commissioning tool ("Sentinel"):

1. Verifies hypervisor is resident (`RESIDENT HYPERVISOR LAUNCH BEGIN` in `logs\dayzdriv.log`)
2. Reads `logs\sentinel_gpas.txt` — one `Label  0xGPA` entry per line, `#` lines ignored
3. Calls `wp_register` for each GPA via HC 0x07
4. Reports `[+] Label  0xGPA  REGISTERED` per entry, or `[!] ... ERROR` on failure
5. Prints `[*] Sentinel active — N/N GPAs write-protected` on full success

### resolver/ — kernel physical address resolver

Standalone one-shot WDM driver that resolves ntoskrnl exported symbols to
physical addresses and writes `logs\sentinel_gpas.txt` automatically.

**Build and run (elevated prompt):**
```
resolver\build.bat
resolver\run.bat
```

`run.bat` creates the service, starts it (driver writes the file and exits),
deletes the service, then prints the file contents.

To add or remove target symbols, edit the `g_Symbols[]` table in `resolver\Resolver.c`.

### Full commissioning sequence

```
1. resolver\build.bat          # build resolver.sys
2. resolver\run.bat            # writes logs\sentinel_gpas.txt
3. sc.exe query dayz           # confirm hypervisor is RUNNING
4. python spectre\hv_client.py # register GPAs via HC 0x07
```

Expected final output:
```
[*] Sentinel active — N/N GPAs write-protected via HV_CALL_WP_REGISTER.
```

---

## Logging

- **File:** `logs\dayzdriv.log` (volume GUID path, `FILE_WRITE_THROUGH` — survives hard freeze)
- **Format:** `[QPC_ticks] !!! DayZHV: message`
- **DebugView:** mirrored via `DbgPrint`

### Memory-buffered hardware audit (`g_VmxDiag`)

During the synchronous `DriverEntry` execution path (KDMapper freestanding
environment), all file I/O inside `VmxLaunchCore`'s Phase A / VMXON window is
prohibited.  `ZwWriteFile` serializes on an internal I/O mutex that is already
held by the kernel I/O subsystem during the APC-driven load path — calling it
deadlocks KDMapper completely, producing a silent freeze with no log output.

The driver allocates a 4KB-aligned `VMX_DIAG_BUFFER` struct from non-paged pool
in `VmxInitialize` (pool tag `HvDB`) and writes hardware diagnostic state
directly to it in zero-overhead memory writes before and after each critical
threshold:

| Field | Populated at |
|-------|-------------|
| `EflagsBefore` / `EflagsAfter` | Immediately before / after `__vmx_on` |
| `Cr0Value` / `Cr4Value` | Live reads right before `__vmx_on` (VMXE already set) |
| `Fixed0Cr0` / `Fixed1Cr0` | IA32_VMX_CR0_FIXED0/1 MSR values |
| `VmxonResult` | Return value of `__vmx_on` (0=OK, 1=CF, 2=ZF) |
| `LaunchResult` | `ctx->LaunchResult` sentinel at last milestone |
| `StepIndicator` | VMX_STEP_ENTRY → CACHE_FLUSH → CR_AUDIT → VMXON_ATTEMPT |

The `Magic` field (`0xDEADBEEF900D`) allows a kernel debugger to locate the
struct by physical address scan even without symbol files:

```
0: kd> s -q 0 L? 0xffffffff`ffffffff 0xDEADBEEF900D0000
```

`g_VmxDiag` is a global pointer exported from `Vmx.c`; its KVA is also
accessible via the `IOCTL_HV_READ_MEMORY` interface once the device node is live.

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
| 2026-05-03 | MBEC implemented | Mode-Based Execute Control: `EPT_EXEC` (bit 2) = supervisor-execute, `EPT_EXEC_USER` (bit 10) = user-execute. Identity map built with both bits set (`EPT_RWX_MBEC`). |
| 2026-05-04 | No write-protection of hypervisor control structures | `VmxIsolateInfrastructure` added: 3-pass walk protects VMCS/VMXON regions, EPT paging structures, and driver image pages. `g_WpTable[256]` sorted for O(log n) lookup. Write faults inject `#GP(0)` (`[WP]` events). |
| 2026-05-04 | No runtime GPA registration from usermode | `HV_CALL_WP_REGISTER` (0x07) added: inserts GPA into `g_WpTable` with insertion-sort, sets EPT to `READ\|EXEC`, issues INVEPT. |
| 2026-05-04 | MBEC user-execute faults not enforced | `HandleEptViolation` checks `EPT_QUAL_EXEC_USER` (bit 11) + `EptGetPteFlags`; injects `#GP(0)` if `EPT_EXEC_USER` not set in PTE (`[MBEC]` events). |
| 2026-05-04 | No user-mode hypercall bridge | `hvbridge/HvBridge.dll` + `VmCall.asm`: exports `IssueHypercall` and `IssueHypercallRaw`. Python `HvClient` wraps both via ctypes. |
| 2026-05-04 | No sentinel commissioning tool | `spectre/hv_client.py` `__main__` block: reads `sentinel_gpas.txt`, calls `wp_register` per GPA, reports pass/fail. |
| 2026-05-04 | No physical address resolver | `resolver/Resolver.c`: one-shot WDM driver calls `MmGetSystemRoutineAddress` + `MmGetPhysicalAddress` for each symbol in `g_Symbols[]`, writes `sentinel_gpas.txt`. |
| 2026-05-15 | Silent VMXON hang on 14900K (VBS/Hyper-V conflict) | Pre-Phase-B `CR4.VMXE` check: if already set, `__vmx_off()` + hard warning logged. Serialized `__writecr4` + `CPUID(0)` to flush pipeline before VMXON. |
| 2026-05-15 | VMX failure paths had no error-code visibility | Added `VmxInstrErrorName()` (full SDM Table 30-1 decode table), `LogVmxInstrError()` (reads `VMCS_VM_INSTRUCTION_ERROR` and logs code + name), and `VmxAuditCrValues()` (dumps GUEST/HOST CR0/CR4 vs. FIXED0/FIXED1 MSR masks). Wired into VMWRITE batch failure, VMLAUNCH fall-through, and VMPTRLD ZF path. CR audit runs in Phase A before IRQL raise so `HvLog`/`ZwWriteFile` is legal. |
| 2026-05-15 | VMXON hang persists after first CPUID flush | Added second `CPUID(0)` immediately before `__vmx_on` to drain any micro-arch state accumulated after `__writecr3`. `FATAL: CRx bit violation:` format added to `VmxAuditCrValues` for grep-friendly log triage. `ZwFlushBuffersFile` after `>>> VMXON pending` sentinel guarantees the line is on SSD before CPU enters VMX root. Documented VT-d DISABLED requirement for Z790 Tomahawk in README and `14th_gen_notes.md`. |
| 2026-05-15 | KDMapper freestanding environment not fully handled | `DriverEntry` gains a `CPUID(0)` hardware fence between device/symlink publication and `PsCreateSystemThread` to serialize all prior stores. `VmxLaunchCore` VMXON block: `vmxonRet` explicitly pre-initialized to sentinel `0xFF` (no BSS zero-init reliance); VMXON failure log now includes PA. README documents `/GS-` rationale and its consequences. `docs/mapping_notes.md` records entry point offset and allocation pattern for 14900K. |
| 2026-05-15 | Synchronous `ZwWriteFile` inside `DriverEntry` deadlocks KDMapper | All `HvLog`/`ZwFlushBuffersFile` calls in Phase A and the VMXON/VMPTRLD window of `VmxLaunchCore` removed. Replaced with lockless memory writes to `g_VmxDiag` (`VMX_DIAG_BUFFER`, pool tag `HvDB`). Magic field `0xDEADBEEF900D` allows WinDbg physical-scan recovery when no log exists. `StepIndicator` (1–4) and live CR0/CR4 captures bracket the VMXON attempt. |

---

## Known Hardware Issues

### i9-14900K / Z790 — Silent VMXON hang

**Symptom:** Core hangs between the `[TRACE] VMXON pending` sentinel and the next log line. No BSOD, no error code, no `LaunchResult` update — the IPI worker simply never returns.

**Root causes identified:**

1. **VBS / Hyper-V conflict** — If Windows boots with Hyper-V or Virtualization-Based Security enabled, `CR4.VMXE` is already set on every logical core. Issuing `VMXON` when a peer hypervisor is already in VMX root mode produces a silent architectural failure on Raptor Lake. The CPU does not generate a visible `#GP`; it simply stalls.

   **Fix:** `VmxLaunchCore` reads `CR4` in Phase A (before the IRQL raise) and logs a `[VBS CONFLICT]` warning if `VMXE` is already set. It calls `__vmx_off()` to attempt a clean state before proceeding. If the hang persists, disable Hyper-V in firmware or via:
   ```
   bcdedit /set hypervisorlaunchtype off
   ```
   Then reboot.

2. **CR4 write not serialized** — The `MOV CR4, reg` instruction is not architecturally serializing on all Raptor Lake microcode revisions. Out-of-order speculative fetches may observe the old CR4 value (VMXE=0) during the subsequent VMXON, causing the instruction to fault silently.

   **Fix:** `__writecr4(cr4WithVmxe)` is immediately followed by `__cpuid(_, 0)` inside the `cli` window. A second `CPUID` is inserted immediately before `__vmx_on` to drain any micro-architectural state accumulated between the CR4 write and the actual VMXON opcode. `CPUID` is a full serializing instruction (SDM Vol 3A §8.3) that retires all prior uops and drains the store buffer.

3. **VT-d (IOMMU) conflict — Z790 Tomahawk builds** — Intel VT-d enables the IOMMU, which installs a DMA-remapping hypervisor layer in VMX root on certain Z790 firmware versions. If VT-d is active, a second agent already occupies VMX root when our driver executes VMXON, producing the same silent hang as a VBS conflict. **VT-d must be DISABLED in BIOS** for this driver to load on Z790 Tomahawk hardware.

   **BIOS path (MSI MAG Z790 Tomahawk):** Advanced → CPU Configuration → Intel VT-d → **Disabled**. Reboot required.

   Verify after reboot: `dayzdriv.log` must show `IA32_FEATURE_CONTROL` lock bit set and no `[VBS CONFLICT]` line.

**GDT/IDT alignment status:** Shadow GDT and IDT base are confirmed 16-byte aligned (`OK(16B)`) on this platform — not the cause of the hang.
