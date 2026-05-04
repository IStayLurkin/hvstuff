# Changelog

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
