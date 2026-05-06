# Changelog

## [Unreleased] — 2026-05-06  fix: unhandled VM-exit tears down one core while 31 others run live

### Kernel (Vmx.c)

- **Root cause**: The `default:` case in `VmExitDispatch` called
  `InjectPendingException` and, if that returned FALSE, set
  `Ctx->TeardownPending = TRUE`.  On any exit reason not explicitly handled
  (EPT misconfiguration, APIC-access, triple-fault, or any future unrecognised
  exit), one core would tear down via `do_teardown` → `vmxoff` while the
  remaining 31 cores were still live in VMX non-root, using the shared
  `g_CtxArray` and EPT.  `VmxTeardown` frees `g_CtxArray` and the EPT after
  signalling all cores, but at that point the 31 active cores had already
  resumed — they would VMRESUME against freed/repurposed memory
  (use-after-free → guaranteed BSOD on next exit).

- **Fix**: Replace the teardown with a `#UD` injection.  An unhandled exit
  reason is surfaced to the guest as `#UD` (invalid opcode), which the guest
  kernel's own exception handler will report cleanly.  The hypervisor stays
  fully resident and all 32 cores continue running.  The exit reason and guest
  RIP are logged via `DbgPrint` (safe at any IRQL; `HvLog`/`ZwWriteFile` is
  illegal above `DISPATCH_LEVEL`).

---

## [Unreleased] — 2026-05-06  BSOD #15: Phase 2 pilot runs on wrong processor (NULL ctx → KPRCB corruption)

### Kernel (Vmx.c)

- **Root cause**: `KeSetSystemAffinityThreadEx((KAFFINITY)1)` takes a *group-relative*
  bitmask, not a system-wide processor number.  On a 32-core Raptor Lake system Windows
  creates two processor groups (0–15, 16–31).  If the calling thread's current group is
  group 1, bit 0 = system-wide processor 16.  `VmxLaunchCore` runs on processor 16,
  `KeGetCurrentProcessorNumberEx` returns 16, and `g_CoreCtx[16]` was NULL (only index 0
  was populated).  On the first VM-exit `AsmVmExitHandler` reads `g_CoreCtx[gs:[1A4h]]`
  = `g_CoreCtx[16]` = NULL, then does `pop qword ptr [rcx+90h]` through NULL — writing
  2 guest register saves into low memory, corrupting the KPRCB.  Observed as
  `IRQL_NOT_LESS_OR_EQUAL (0xA)` with IRQL=0xFF and faulting IP at
  `dayzdriv!VmxLaunchCore+0xd53` (`mov [rsi+34h],eax`) after `launch_resume` restored
  `rsi` from the NULL-deref-sourced garbage ctx slot.

- **Fix**:
  1. Replace `KeSetSystemAffinityThreadEx((KAFFINITY)1)` /
     `KeRevertToUserAffinityThreadEx` with `KeSetSystemGroupAffinityThread` /
     `KeRevertToUserGroupAffinityThread` using an explicit `GROUP_AFFINITY{Group=0,Mask=1}`
     — unambiguously pins to system-wide processor 0 regardless of the calling thread's
     current group.
  2. Pre-populate **all** `g_CoreCtx[i]` slots before the pilot launch.  Any core that
     receives an IPI or external interrupt during the pilot window and takes a VM-exit
     must find a valid ctx pointer; a NULL slot causes the same KPRCB-corruption crash.

---

## [Unreleased] — 2026-05-06  BSOD #14: stale non-volatile registers on teardown

### Kernel (Arch.asm / Vmx.h)

- **Root cause**: When the hypervisor is resident, subsequent IPI callbacks on the same
  logical processor reuse the kernel thread stack frame that `AsmLaunchAndReturn` set up
  before `VMLAUNCH`.  The 8 non-volatile register saves (`push rbx/rbp/rsi/rdi/r12-r15`)
  at offsets `[HostResumeRsp+20h..60h]` could be overwritten by any IPI that allocates a
  new frame there.  On teardown, `launch_resume` was doing `add rsp,20h; pop r15..rbx; ret`
  — restoring from the now-stale kernel thread stack — giving one or more registers a
  garbage value (e.g. `rsi` = user-space address).  The first dereference through the
  corrupted register fired `0xD1` at `IRQL=0xFF`.

- **Fix**: snapshot all 8 host non-volatile registers **and** the return address into
  `CORE_VMX_CONTEXT` immediately before `VMLAUNCH` (while values are still correct).
  `launch_resume` now restores from the struct (via `rcx = ctx`, which `do_teardown`
  keeps live across `vmxoff`) and uses `jmp [rcx+CTX_HOST_RETADDR]` instead of `ret`.
  The kernel thread stack is never read during teardown.

- **`CORE_VMX_CONTEXT`**: 9 new fields added at offsets `+0x258`–`+0x298`:
  `HostRbx/Rbp/Rsi/Rdi/R12/R13/R14/R15` + `HostRetAddr`.  9 new `C_ASSERT` offset
  checks added to `Vmx.h`.

- **`Arch.asm`**: 9 new `CTX_HOST_*` EQU constants; pre-launch snapshot writes; reworked
  `launch_resume` to restore from ctx + `jmp`; updated `do_teardown` comments.

---

## [Unreleased] — 2026-05-06  BSOD #13: pre-VMXON INVEPT raises #UD

### Kernel (Ept.c / Vmx.c / Vmx.h)

- **Root cause**: `INVEPT` is a VMX instruction; executing it outside VMX root operation
  (before `VMXON`) raises `#UD` → `KMODE_EXCEPTION_NOT_HANDLED (0x1E)` /
  `STATUS_ILLEGAL_INSTRUCTION (0xC000001D)`.  Three call sites in the pre-launch
  EPT-setup path were calling `EptInvalidate` (→ `AsmInveptSingleContext` →
  `INVEPT`) before the IPI that runs `VMXON`:
  1. `VmxIsolateInfrastructure` — direct `EptInvalidate` after WP-table sort
  2. `VmxInitialize` self-hiding block — `EptInvalidate` after `EptHideRange` calls
  3. `EptSetPermissions` — inline `EptInvalidate` called by `EptHideRange`

- **Fix**: replaced all three pre-VMXON `EptInvalidate` calls with
  `InterlockedExchange(&g_InveptPending, 1)`.  The lazy-flush flag already drains
  in `VmExitDispatch` on each core's first exit — which is the correct flush point
  (EPT TLB is cold at `VMLAUNCH`).  All `EptInvalidate` calls that remain are
  inside VM-exit handlers (EPT violation, hypercall dispatch, `g_InveptPending`
  drain) where VMX root operation is guaranteed active.

- **`g_InveptPending`**: promoted from `static` in `Vmx.c` to a non-static
  definition + `extern volatile LONG g_InveptPending` declaration in `Vmx.h` so
  `Ept.c` can set it directly.

---

## [Unreleased] — 2026-05-04  Python bridge + IOCTL_HV_READ_MEMORY

### Kernel (Driver.c / Vmx.h)

- **New IOCTL: `IOCTL_HV_READ_MEMORY` (0x00222404)**
  - `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)`
  - Input: `{ ULONG64 Kva; ULONG Length; }` — 12 bytes, little-endian
  - Output: raw bytes copied from the kernel virtual address
  - Ceiling: 65 536 bytes per call (`HV_READ_MAX_LENGTH`)
  - Safety: `RtlCopyMemory` wrapped in `__try/__except` at `PASSIVE_LEVEL`; unmapped/guard-page faults return the exception code rather than bugchecking
  - Input struct copied out of `SystemBuffer` before `RtlCopyMemory` overwrites it (METHOD_BUFFERED overlap fix)
- **`Vmx.h`**: promoted `IOCTL_HV_READ_MEMORY` from comment to `#define CTL_CODE(...)`; added `HV_READ_MAX_LENGTH` constant and `HV_READ_REQUEST` struct

### Python — `spectre/`

#### `hv_constants.py`
- Added `IOCTL_HV_READ_MEMORY = 0x00222404`
- Added `HV_READ_MAX_LENGTH = 65536`

#### `hv_interface.py`
- Added `HVInterface.read_memory(kva, length) -> bytes`
  - Validates `1 ≤ length ≤ HV_READ_MAX_LENGTH`
  - Packs 12-byte `struct '<QI'` input buffer with exact size (no null-terminator appended)
  - Raises `HVError` on IOCTL failure

#### `spectre_memory.py` (new)
- `SpectreMemory` — typed read abstraction over `HVInterface.read_memory`
  - `read_raw(kva, length) -> bytes`
  - `read_uint64 / read_uint32 / read_float / read_vec3 / read_string / read_struct`
  - All typed reads go through a single `_unpack` helper; short reads raise `ValueError`

#### `memory_worker.py` (new)
- `MemoryWorker(QObject)` — runs `build_fn()` on a `QThread`, emits results via signals
  - `scene_ready = pyqtSignal(object)` — emitted with the built scene on success
  - `error = pyqtSignal(str)` — emitted with `traceback.format_exc()` on exception
  - `stop_requested = pyqtSignal()` — thread-safe cross-thread stop (connected to `QTimer.stop`)
  - `start()` / `stop()` — same-thread timer lifecycle
  - Default interval: 16 ms (~60 Hz)

#### `test_read.py` (new)
- Hardware smoke test: opens `\\.\DayZHV`, runs pattern scan, reads 8 bytes via `IOCTL_HV_READ_MEMORY`, exercises `SpectreMemory.read_uint64`
- Prints `[+]`/`[!]` per step with actionable failure messages

#### `Features/esp.py`
- **`SpectreMemoryInterface`** — adapter satisfying the `MemoryInterface` duck type over `SpectreMemory`
  - `read / read_u64 / read_u32 / read_u8 / read_u16 / read_f32 / read_vec3 / read_wstring`
  - `write` / `write_vec3` return `False` (HV bridge has no write primitive)
  - `close()` calls `HVInterface.close()` — guaranteed handle release on shutdown
- **`DayZGame.attach()`** — tries HV bridge first, falls back to Win32 RPM on `HVError`
- **`ESPOverlay`** — wires `MemoryWorker` when HV bridge is active:
  - `_start_worker_thread()` — moves worker onto `QThread`, connects `scene_ready → set_scene`
  - `_build_scene_hv()` — worker's `build_fn`; runs full `ESPMemoryHelper.build_scene` off the main thread
  - `_tick_hotkeys()` — 30 Hz main-thread timer for `process_hotkeys` + OBS protection (hotkeys must stay on main thread)
  - `closeEvent()` — emits `stop_requested`, joins worker thread with 2 s timeout before overlay closes
  - Falls back to original `QTimer._tick` path when HV bridge is unavailable

### Tests (`tests/`)
- `test_hv_constants.py` — asserts `IOCTL_HV_READ_MEMORY == 0x00222404`, `HV_READ_MAX_LENGTH == 65536`
- `test_hv_interface_read.py` — 4 tests: happy path (asserts `in_len == 12`), zero length, overlength, IOCTL failure → `HVError`
- `test_spectre_memory.py` — 9 tests covering all typed read methods, delegation, short-read error
- `test_memory_worker.py` — 2 tests: `scene_ready` emission, `error` emission on exception; guarded with `pytest.importorskip('PyQt5')`
- `conftest.py` (new) — root-level `sys.path` injection so all tests import from `spectre/` without per-file hacks

**Total: 17 tests, all passing.**

---

## Prior — kernel hypervisor (see git log)

- IOCTL_HV_SCAN_PATTERN (0x00222400): pattern scanner, HVInterface, hv_client sentinel pipeline
- HV_CALL_WP_REGISTER (0x07): write-protection table, EPT R|X enforcement
- HV_CALL_LOCK_LSTAR (0x06): WRMSR IA32_LSTAR rejection
- SMEP/SMAP baseline enforcement via CR4 guest/host mask
- Resident hypervisor: 32/32 logical core launch, EPT identity map, VM-exit dispatch, shadow GDT, TSS busy-bit restore, DPC latency harness
