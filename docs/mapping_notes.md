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

## Synchronous `DriverEntry` deadlock — Raptor Lake boundary (2026-05-16)

**Symptom:** Machine crashes immediately and catastrophically (no log, no BSOD
code visible) when `VmxInitialize()` is called synchronously from `DriverEntry`
on an i9-14900K under KDMapper.

**Root cause — execution context boundary violation:**

KDMapper dispatches the driver entry point via a kernel APC on one of its system
threads.  On Raptor Lake (14th Gen) this APC executes in a highly constrained
context: the kernel I/O subsystem's internal serialization mutex
(`IopSynchronousServiceTail`) is already held by the calling path.  Any code
inside `VmxInitialize()` that invokes `ZwWriteFile` (including every `HvLog`
call in Phase A through Phase 3) attempts to re-acquire that mutex on the same
thread — an immediate recursive deadlock.

On prior Windows builds this manifested as a silent, permanent freeze of KDMapper
with zero log output (see "Synchronous I/O deadlock anomaly" section below).  On
14th Gen with current 26100 patch level the result is an immediate catastrophic
machine crash rather than a quiet hang, likely due to a watchdog timeout or
stricter APC-context enforcement in the updated kernel.

The critical constraint: **`VmxInitialize` must never execute on the same thread
that holds the kernel I/O serialization mutex** — i.e., it must not run
synchronously inside the KDMapper APC dispatch.

**Fix restored (2026-05-16): asynchronous system thread dispatch**

`DriverEntry` spawns `HvRemainingCoresThread` via `PsCreateSystemThread` and
returns `STATUS_SUCCESS` immediately, fully decoupling the VMX initialization
path from KDMapper's APC thread quantum:

```c
// WBINVD + CPUID(0) fence first — I-Cache coherency on 14900K ring bus.
__wbinvd();
__cpuid(_fence, 0);

HANDLE threadHandle = NULL;
PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
                     NULL, NULL, NULL,
                     HvRemainingCoresThread, NULL);
ZwClose(threadHandle);
return STATUS_SUCCESS;
```

The system thread runs at PASSIVE_LEVEL outside any APC context.  `HvLog` /
`ZwWriteFile` are legal there.  KDMapper exits cleanly after `DriverEntry`
returns; the VMX thread completes independently.

**WBINVD + CPUID fence retained:** The serialization fence before
`PsCreateSystemThread` is still required to address the I-Cache/D-Cache
desynchronization window on the 14900K ring bus (documented in the section
above).  It must precede the thread spawn, not precede `VmxInitialize`, so
that the new thread's first I-fetch sees the relocated image correctly.

## EPT table allocator — user-mode PA leak (2026-05-16)

**Symptom:** Immediate BSOD on driver load under KDMapper. Bugcheck Arg1 contains
a user-mode address in the range `0x00007ff...` — visible in the crash dump as the
faulting address in a `PAGE_FAULT_IN_NONPAGED_AREA` (0x50) or `MEMORY_MANAGEMENT`
(0x1A) bugcheck with Arg1 pointing into user space.

**Root cause — `AllocEptTable` physical address upper bound:**

`AllocEptTable` in `Ept.c` called `MmAllocateContiguousMemorySpecifyCache` with:

```c
hi.QuadPart = 0x7FFFFFFFFFFFF000LL;   // BUG: top of user-mode 47-bit VA space
```

The `hi` parameter is a *physical* address upper bound, not a virtual address.
However, `0x7FFF_FFFF_FFFF_F000` happens to equal the highest possible user-mode
canonical virtual address (47-bit signed range, `MmHighestUserAddress`).

On a memory layout where low physical RAM is covered by the direct physical mapping,
some physical addresses below that bound have their `MmGetVirtualForPhysical`
reverse-mapping point into the direct-map region.  On certain NUMA or memory-hole
configurations the direct-map VA for a low physical page is absent from the PFN
database, and `MmGetVirtualForPhysical` returns NULL or a garbage VA.  In the worst
case — seen on this platform — the PFN entry for the allocated contiguous page
resolves to a user-mode virtual address.

`EptBuildIdentityMap` then calls `MmGetVirtualForPhysical` on the physical address
embedded in each EPT entry to obtain the VA of the next-level table.  If that VA is
in user space, the EPT walker immediately faults at kernel privilege — Arg1 of the
crash is that user-mode address.

**Fix applied (2026-05-16):**

```c
hi.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFF;   // no upper bound
```

With no upper bound, `MmAllocateContiguousMemorySpecifyCache` allocates from the
non-paged pool's preferred physical range.  All returned pages are registered in the
PFN database with a well-known kernel-space virtual address, and
`MmGetVirtualForPhysical` always returns a high-canonical kernel VA.

**Secondary guards added:**

1. `EptBuildIdentityMap` validates each physical range returned by
   `MmGetPhysicalMemoryRanges`: if `base >= 0x000FFFFFFFFFFFFF`, the build aborts
   with `STATUS_INVALID_PARAMETER`.  This catches any future allocator regression
   before the EPT walk begins.

2. `EptMapPage4KB` validates alignment (`GPA & 0xFFF == 0`, `HPA & 0xFFF == 0`)
   and 52-bit physical address bounds (`< 0x000FFFFFFFFFFFFF`) on both GPA and HPA
   before entering the table-walk path.  Invalid inputs return silently without
   touching any EPT structure.

---

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
