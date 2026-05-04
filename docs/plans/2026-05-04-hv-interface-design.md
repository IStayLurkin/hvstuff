# HV Interface — Python/Kernel Pattern Scanner Design
**Date:** 2026-05-04  
**Hardware:** Intel i9-14900K / Z790, Windows 11

---

## Goal

A Python user-mode controller that issues pattern-scan requests to `dayzdriv.sys` via a custom IOCTL. The driver searches kernel virtual address space and returns the KVA of the first match. Python stores all results in a `dict[str, int]` at startup (single-shot) and reads from that dict at runtime — no repeated IOCTL calls in the hot path.

---

## IOCTL Contract

```c
#define IOCTL_HV_SCAN_PATTERN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Resolves to: 0x00222400  (0x801 is already IOCTL_DISK_READ_MEMORY)
```

| Field | Value |
|---|---|
| Method | `METHOD_BUFFERED` — I/O manager copies buffers; no MDL needed |
| Access | `FILE_ANY_ACCESS` |
| Device | `\\.\DayZHV` |

**Input buffer:** null-terminated ASCII pattern string, max 256 bytes.  
`"48 8B 05 ? ? ? ? 48 8B"` — IDA/SigMaker format, spaces between bytes, `?` or `??` as wildcards.

**Output buffer:** 8 bytes — `UINT64` kernel virtual address of first match, or `0` on no-match/error.

### Driver-side handler (METHOD_BUFFERED)

```c
case IOCTL_HV_SCAN_PATTERN: {
    SIZE_T inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    if (inputLen < 2 || inputLen > 256) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
    }
    // Force null-termination — ctypes may not guarantee trailing null
    ((char*)Irp->AssociatedIrp.SystemBuffer)[inputLen - 1] = '\0';

    const char* pattern = (const char*)Irp->AssociatedIrp.SystemBuffer;
    UINT64 result = KernelScanPattern(pattern);

    *(UINT64*)Irp->AssociatedIrp.SystemBuffer = result;
    Irp->IoStatus.Information = sizeof(UINT64);
    status = STATUS_SUCCESS;
    break;
}
```

**IRQL note:** The IRP dispatch routine runs at `PASSIVE_LEVEL`. `KernelScanPattern` must stay at `PASSIVE_LEVEL` for its full execution — no raising to `DISPATCH_LEVEL` for extended periods, or `CLOCK_WATCHDOG_TIMEOUT` risk on large scan ranges. Keep the scan region bounded.

---

## Python Architecture

Three files under `spectre/`:

```
spectre/
  hv_constants.py      — control code, device path, buffer limits
  hv_interface.py      — HVInterface class (handle lifetime + IOCTL call)
  pattern_scanner.py   — pattern map + single-shot startup scan
```

### hv_constants.py

Single source of truth for all magic values shared between the Python files and the driver header.

```python
DEVICE_PATH           = r"\\.\DayZHV"
IOCTL_HV_SCAN_PATTERN = 0x00222400  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, ...)
PATTERN_BUFFER_SIZE   = 256         # must match driver MAX_PATTERN_LEN
```

### hv_interface.py — HVInterface

Owns the Win32 device handle. Context-manager so `with HVInterface() as hv:` guarantees `CloseHandle` on exit.

**`__init__`:** `CreateFileW(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)` — raises `HVError` if handle is `INVALID_HANDLE_VALUE`.

**`scan_pattern(pattern: str) -> int`:**
- Encodes pattern as ASCII into a 256-byte `create_string_buffer` (zero-filled tail → guaranteed null terminator)
- Calls `DeviceIoControl` synchronously (`lpOverlapped=None`)
- Unpacks output with `struct.unpack_from('<Q', out_buf)[0]`
- Returns KVA (`int`), or `0` on no-match
- Raises `HVError(OSError)` on Win32 failure or short read (`bytes_returned != 8`)

**Error type:**
```python
class HVError(OSError):
    def __init__(self, msg: str, win32_error: int = 0):
        super().__init__(win32_error, msg)
        self.win32_error = win32_error
```

### pattern_scanner.py — single-shot scan

Pattern map is a plain `dict[str, str]` at module level. At startup, `scan_all(hv: HVInterface) -> dict[str, int]` iterates it **sequentially** — no parallelism. Rationale: avoids flooding the driver's IRP queue at the exact moment the game is loading; on a 32-core machine the sequential scan still completes in microseconds.

Zero results are stored in the dict (not dropped) so callers can detect which patterns missed.

```python
PATTERNS: dict[str, str] = {
    "Target_1": "48 8B 05 ? ? ? ? 48 8B",
    "Target_2": "E8 ? ? ? ? 48 8B D8",
}

def scan_all(hv: HVInterface) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for name, pattern in PATTERNS.items():
        offsets[name] = hv.scan_pattern(pattern)
    return offsets
```

---

## Data Flow

```
startup
  pattern_scanner.scan_all(hv)
    └─ sequential loop over PATTERNS
         └─ hv.scan_pattern("48 8B 05 ? ? ? ? 48 8B")
              └─ DeviceIoControl → dayzdriv.sys IOCTL_HV_SCAN_PATTERN
                   └─ KernelScanPattern() → KVA (uint64)
              └─ returns int (0 = miss)
    └─ { "Target_1": 0xfffff80412345678, "Target_2": 0 }

runtime
  read from offsets dict — no IOCTL in hot path
```

---

## Error Policy

| Condition | Behaviour |
|---|---|
| `CreateFileW` fails | Raise `HVError` with `GetLastError()` |
| `DeviceIoControl` returns 0 | Raise `HVError` with `GetLastError()` |
| `bytes_returned != 8` | Raise `HVError("short read")` |
| Result KVA == 0 | Log warning; store 0 in dict; caller decides if fatal |
| Pattern > 255 chars | Raise `ValueError` before any IOCTL |
