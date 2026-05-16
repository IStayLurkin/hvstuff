# KDMapper — Load Model and 14900K Observations

Platform: Intel Core i9-14900K (Raptor Lake), MSI MAG Z790, Windows 11 26100.
Mapper: KDMapper (manual PE mapping, no DSE bypass required — test-signing off).

---

## Load model

KDMapper allocates a non-paged pool region, copies the PE image sections, applies
base relocations, resolves imports against the live kernel export table, and then
calls the entry point directly via a kernel APC on a system thread.

Key differences from a standard `MmLoadSystemImage` load:

| Property | Normal driver load | KDMapper load |
|---|---|---|
| `DriverObject` | Real WDM object | Pointer to mapper-supplied stub (invalid for Object Manager) |
| `RegistryPath` | Valid registry path | NULL or mapper stub |
| Load Config directory | Processed — `__security_cookie` initialized | **Skipped** — cookie not initialized |
| PE header visibility | Mapped at image base | **Header page skipped** — `ImageBase` offset 0x0 may be inaccessible |
| PatchGuard awareness | Driver in `PsLoadedModuleList` | **Not listed** — invisible to PG module checks |
| Unload | `DriverUnload` called by SCM | Must be triggered manually (IOCTL teardown or `DriverUnload` pointer patch) |

---

## Entry point offset — 14900K observations

On 14900K / Z790 with Windows 11 26100 the mapped allocation consistently
lands in the `0xFFFF...` high-canonical region (non-paged pool above
`MmSystemRangeStart`).  The entry point offset within the image is **0x4C0**
(relative to the section-mapped base, not the PE `AddressOfEntryPoint` field
which is relative to `ImageBase`).

```
Mapped base:    0xFFFF<pool-tag-region>0000   (4KB-aligned, non-paged pool)
Entry point VA: MappedBase + 0x4C0
```

This offset is stable across reboots on this platform for the current build.
It will shift if new code is added before `DriverEntry` in the link order.
Verify with: `dumpbin /HEADERS dayz.sys | findstr "entry point"`.

The header page (offset 0x0, the MZ/PE headers) is **not mapped** by KDMapper —
any code that walks backwards from an export to find `IMAGE_DOS_HEADER` must use
`__try`/`__except` around the `0x5A4D` ('MZ') check.  `KernelScanPattern` in
`Driver.c` already does this.

---

## /GS- — stack security check disabled

KDMapper does not initialize the `__security_cookie` global (it skips the Load
Config directory).  Any function compiled with `/GS` will:

1. Read the uninitialized (or zero) cookie at function entry.
2. XOR it with RSP to form a frame cookie on the stack.
3. At function exit, re-read the global, re-XOR with RSP, and compare.
4. If `__security_cookie` is 0 and the frame cookie is 0^RSP = RSP, the check
   passes coincidentally — but if the linker placed `__security_cookie` at an
   address that was not zeroed by the pool allocator, the comparison fires
   `__report_gsfailure` → bug-check.

**All source files use `/GS-`** (project property: C/C++ → Code Generation →
Buffer Security Check → No).  This is the only safe option for manual-mapped
drivers.

---

## Freestanding environment invariants

Because the Load Config directory is skipped, the following must hold in all
code paths that execute before or during `DriverEntry` (including functions
called from `DriverEntry`):

1. **No `/GS` stack cookies** — enforced by `/GS-` build flag.
2. **No static initializers** — `DriverEntry` is the first C code to run;
   global constructors are not called by KDMapper.  Use explicit initialization
   in `DriverEntry` or the first call site.
3. **No CRT startup** — `memset`, `memcpy`, `RtlCopyMemory` are safe (kernel
   exports); CRT functions like `printf`, `malloc` are not linked and must not
   be called.
4. **Explicit local initialization** — do not rely on BSS zero-init for
   variables whose value matters before assignment.  KDMapper zeros the `.bss`
   section in practice (pool allocation is zeroed), but this is a mapper
   implementation detail, not a guarantee.

The VMX launch path (`VmxLaunchCore`) follows rule 4 explicitly: all
return-value variables from VMX instructions (`vmxonRet`, `vmptrldRet`,
`vmwStat`, `launchRet`) are assigned an explicit sentinel before use.

---

## I-Cache / D-Cache desynchronization — 14900K anomaly

**Symptom:** Machine hangs immediately after the Phase A alignment log line in
`VmxLaunchCore` (the first `HvLog` call in the function body), or hangs
immediately after `DriverEntry` returns but before `HvInitThread` logs its
start message.  No BSOD, no error code — the processor simply stops retiring
instructions.

**Root cause:** Under KDMapper's freestanding payload footprint, the mapped
image is written into a non-paged pool region without any architectural
serializing sequence after the final relocation patch.  On the i9-14900K's
Raptor Lake microarchitecture, the P-core ring bus operates with split I-Cache
and D-Cache domains.  A logical processor that fetches `HvInitThread` or
`VmxLaunchCore` immediately after the pool write may observe a stale I-Cache
line that holds the pre-relocation opcode stream, while the D-Cache (and DRAM)
already holds the correct relocated image.  The divergence produces undefined
instruction behavior — observed as a silent hang at the first I-fetch across
the boundary.

**Fix applied (2026-05-15):**

Two serialization points were added:

1. **`DriverEntry`** — immediately before `PsCreateSystemThread`:
   ```c
   __wbinvd();          // write-back + invalidate all caches and TLBs
   __cpuid(_fence, 0);  // full pipeline serialization (SDM §8.3)
   ```

2. **`VmxLaunchCore`** — absolute first statements in the function body,
   before any log call or sub-function dispatch:
   ```c
   __wbinvd();
   __cpuid(_s, 0);
   ```

`__wbinvd` forces all modified D-cache lines to DRAM and invalidates all
I-Cache and TLB entries on the issuing logical processor, eliminating the
stale-line window.  The subsequent `CPUID(0)` prevents speculative I-fetch
of any instruction past the serializing point.

**Inline CR audit (Phase A):** The `VmxAuditCrValues()` sub-function call was
also removed from Phase A.  Under the manual-map environment, nested stack
frames that branch to a separate function symbol risk re-entering the stale
I-Cache window if the function's text page was not yet flushed.  The audit
logic is now expanded inline using direct `__readcr0()` / `__readcr4()`
intrinsics, eliminating the out-of-segment branch.

## Synchronous thread bypass protocol — 14th Gen (2026-05-15)

**Problem:** On i9-14900K under KDMapper, the asynchronous `PsCreateSystemThread`
dispatch was being intercepted or frozen by kernel scheduling mitigations before
the spawned system thread could enter its execution context.  The symptoms were
identical to the I-Cache/D-Cache desynchronization hang: the log recorded
`[ENTRY] DriverEntry complete` but neither `[THREAD] HvInitThread started` nor
any Phase A diagnostic ever appeared — the thread never got a quantum.

**Root cause:** Under KDMapper's freestanding load model the driver is invisible
to `PsLoadedModuleList`.  On 14th Gen platforms Windows 11's scheduler hardening
(Code Integrity Guard / Kernel Sensitive Data Protection) may flag or deprioritize
system thread callbacks whose backing image is not in the module list, preventing
the scheduler from dispatching the new thread before the KDMapper process exits
and its APC cleanup fires.

**Fix applied (2026-05-15):**

`DriverEntry` now executes `VmxInitialize()` directly and synchronously
**before returning**, using the calling thread's own execution context on
Core 0.  This eliminates the scheduler hand-off entirely for the pilot:

```c
// Serialization fence — WBINVD + CPUID(0) before VmxInitialize.
__wbinvd();
__cpuid(_fence, 0);

// Synchronous pilot: runs Phase 1 (probe) + Phase 2 (Core 0 VMLAUNCH)
// + Phase 3 (full IPI) directly in DriverEntry before returning.
NTSTATUS pilotStatus = VmxInitialize();
if (!NT_SUCCESS(pilotStatus)) { /* abort and return error */ }
```

If the synchronous pilot passes, `DriverEntry` maps the IPC page and starts the
DPC latency harness inline, then returns `STATUS_SUCCESS` with the hypervisor
already resident.  No background thread is spawned for the initial launch.

**Invariants maintained:**
- The WBINVD + CPUID(0) serialization fence is still issued immediately before
  `VmxInitialize` so the I-Cache/D-Cache coherency requirement is satisfied.
- `VmxInitialize` is called at PASSIVE_LEVEL from `DriverEntry`, which is the
  same IRQL at which system threads run — no new constraint is introduced.
- KDMapper still returns immediately after `DriverEntry` exits; the pilot
  completes within `DriverEntry` itself, not inside a kernel APC.

## Diagnostic correlation

If the driver hangs immediately after `DriverEntry` returns (KDMapper exit):

- `dayzdriv.log` will contain `[ENTRY] DriverEntry complete` but **not**
  `[THREAD] HvInitThread started` — the system thread was not scheduled before
  KDMapper's process exited.  This is benign; the thread runs independently.

If `[THREAD] HvInitThread started` appears but `VmxInitialize` does not:

- Check that `HvLogOpen` succeeded (log file exists and has content).
- Verify IRQL is PASSIVE_LEVEL at thread start (it always is for system threads).

If the machine hard-freezes with no log output at all:

- The entry point offset may have shifted.  Verify with `dumpbin` as above.
- The pool allocation may have landed in a region where the PE sections are not
  fully committed.  Re-map and retry.

---

## Synchronous I/O deadlock anomaly — KDMapper freestanding context (2026-05-15)

**Symptom:** KDMapper freezes completely with no log file output.  The process
does not exit; no BSOD is generated.  The driver's `DriverEntry` never returns.

**Root cause:** Under KDMapper's manual-map APC dispatch, the kernel I/O
serialization mutex (`IopSynchronousServiceTail` / `IopCompleteRequest` path)
is already held at the point `DriverEntry` receives control.  Calling
`ZwWriteFile` — even with `FILE_SYNCHRONOUS_IO_NONALERT` and
`FILE_WRITE_THROUGH` — blocks indefinitely on that mutex.  The APC thread
cannot make forward progress; KDMapper's wait on the APC completion object
never fires.  The result is a hard, silent freeze with zero log output.

Any `HvLog` call in the `DriverEntry` → `VmxInitialize` → `VmxLaunchCore`
call chain that executes before the first context switch fires this deadlock.

**Fix applied (2026-05-15):** All `HvLog` (i.e. `ZwWriteFile`) and
`ZwFlushBuffersFile` calls inside `VmxLaunchCore`'s Phase A pre-flight and
the VMXON / VMPTRLD / VMWRITE window have been removed.  They are replaced
with zero-overhead writes to `g_VmxDiag`, a `VMX_DIAG_BUFFER` allocated from
non-paged pool before the IPI (pool tag `HvDB`).

### `VMX_DIAG_BUFFER` layout

```c
typedef struct _VMX_DIAG_BUFFER {
    ULONG64 Magic;          // 0xDEADBEEF900D — locator sentinel for WinDbg
    ULONG64 EflagsBefore;   // RFLAGS immediately before __vmx_on
    ULONG64 EflagsAfter;    // RFLAGS immediately after  __vmx_on
    ULONG64 Cr0Value;       // __readcr0() right before __vmx_on
    ULONG64 Cr4Value;       // __readcr4() right before __vmx_on (VMXE set)
    ULONG64 Fixed0Cr0;      // IA32_VMX_CR0_FIXED0 MSR
    ULONG64 Fixed1Cr0;      // IA32_VMX_CR0_FIXED1 MSR
    ULONG   VmxonResult;    // __vmx_on return: 0=OK, 1=CF (VMfailInvalid), 2=ZF
    ULONG   LaunchResult;   // ctx->LaunchResult sentinel at last update
    ULONG   StepIndicator;  // last milestone: 1=Entry 2=CacheFlush 3=CrAudit 4=VmxonAttempt
} VMX_DIAG_BUFFER;
```

**Reading the buffer from WinDbg after a freeze:**

```
0: kd> s -q 0 L? 0xffffffffffffffff 0x0000BEEF900D0000
<finds PA containing Magic>
0: kd> dt nt!_VMX_DIAG_BUFFER <addr>
```

If `StepIndicator` == 4 and `VmxonResult` == 0xFF the CPU hung inside
`__vmx_on` before it returned.  If `VmxonResult` == 1 (CF), the VMXON region
PA or CR4 state was invalid.

---

## 0x109 Arg4:1 — Function modification on `nt!NtAddAtom` (2026-05-15)

### Bugcheck signature

```
CRITICAL_STRUCTURE_CORRUPTION (109)
Arg1: <PatchGuard context VA>
Arg2: <hash mismatch detail>
Arg3: <protected structure VA>  ← points inside nt!NtAddAtom or adjacent Nt* function
Arg4: 0x0000000000000001       ← type 1 = function body modification detected
```

`Arg4 = 1` is PatchGuard's "modified kernel function" category.  It fires when the
byte content of a page that backs a protected kernel routine (`nt!Nt*`, `nt!Zw*`,
`nt!Ps*`, etc.) differs from the stored reference hash.  `nt!NtAddAtom` is a common
trigger because it is a short leaf function whose prologue bytes are frequently targeted
by in-memory patch techniques.

### Root cause in the VMX launch sequence

If any driver code writes to an `nt!` function page — even a single byte — **before**
`VmxInitialize` has completed and the EPT identity map is live, PatchGuard's scan
thread will detect the raw modification on bare metal.  There is no EPT shadow yet to
intercept PatchGuard's read and return the original bytes.

The dangerous window is:

```
DriverEntry enters
  │
  ├─ [SAFE] IoCreateDevice / IoCreateSymbolicLink  — no kernel text modified
  │
  ├─ [DANGER ZONE] ── any write to kernel .text before VmxInitialize ──
  │   PatchGuard reads bare metal → sees modified bytes → BSOD 0x109 Arg4:1
  │
  └─ VmxInitialize() returns → EPT live → hypervisor intercepts PG reads
       [SAFE] modifications here are shadowed transparently
```

### Fix enforced in this driver

`DriverEntry` issues no write to any kernel page before `VmxInitialize()` returns.
The load sequence is:

1. `HvLogOpen()` — writes to the driver's own log file only.
2. `ObReferenceObjectByName` / `IoCreateDevice` / `IoCreateSymbolicLink` — Object
   Manager and I/O Manager bookkeeping; no kernel text pages modified.
3. `devDrv->MajorFunction[...]` patches — writes to `\Driver\Null`'s **IRP dispatch
   table** (a data structure in non-paged pool), not to any kernel function body.
4. `__wbinvd()` / `__cpuid(_, 0)` — serialization only; no memory write.
5. **`VmxInitialize()`** — EPT built and live before this returns.
6. `IpcMapPage()` / `DpcLatencyStart()` — housekeeping after hypervisor is resident.

Steps 1–4 are PatchGuard-safe.  No `nt!Nt*` function byte is touched at any point.

### Diagnosis checklist for 0x109 Arg4:1

| Check | How |
|-------|-----|
| Is `VmxInitialize` the first substantive call in `DriverEntry`? | Read `Driver.c` — only device/symlink setup precedes it |
| Does any loaded payload (via `IOCTL_HV_LOAD_MODULE`) write kernel text at load time? | Audit `Loader.c` — `ManualLoad` only patches the **payload's own IAT**, not `ntoskrnl` |
| Is there a timing gap between driver load and PG scan? | 0x109 typically fires 30–120 s after load; if it fires immediately, a write happened in `DriverEntry` itself |
| Is the EPT shadow table registered for the target GPA before the write? | `g_EptShadowTable` must have an entry for every GPA that will be modified |

### Log correlation

After a 0x109 Arg4:1 bugcheck the driver log (`logs\dayzdriv.log`) should contain:

```
[ENTRY] Synchronous VmxInitialize returned 0x0  IRQL=0
[ENTRY] DriverEntry complete — hypervisor resident  IRQL=0
```

If those two lines are present and the crash still occurs, the modification is happening
**after** `DriverEntry` — most likely in a payload loaded via `IOCTL_HV_LOAD_MODULE` or
in a deferred work item.  Use `!analyze -v` in WinDbg: `Arg3` will point at the modified
function; cross-reference with `ln <Arg3>` to identify the target.
