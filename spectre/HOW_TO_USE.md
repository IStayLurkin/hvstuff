# HV Interface — How to Use

## Prerequisites

- 64-bit Python 3.8+
- `dayzdriv.sys` loaded and running (`sc start dayzdriv` succeeded)
- The device `\\.\DayZHV` must be accessible (confirms the driver is live)

---

## File Overview

```
spectre/
  hv_constants.py     — shared constants (device path, IOCTL code, buffer size)
  hv_interface.py     — HVInterface class (Win32 device handle + IOCTL call)
  pattern_scanner.py  — pattern map + single-shot startup scan
```

---

## Step 1 — Add Your Patterns

Open `pattern_scanner.py` and edit the `PATTERNS` dict at the top of the file.
Keys are human-readable names. Values are SigMaker-style byte patterns — space-separated hex bytes, `?` or `??` for wildcards.

```python
PATTERNS: dict[str, str] = {
    "Target_1": "48 8B 05 ? ? ? ? 48 8B",
    "Target_2": "E8 ? ? ? ? 48 8B D8",
}
```

Pattern rules:
- Bytes are two hex digits: `48`, `8B`, `E8`, etc.
- Single wildcard: `?`
- Double wildcard: `??` (treated identically to `?`)
- Maximum pattern length: 255 bytes (driver cap)

---

## Step 2 — Run the Scan

The scan is designed to run once at startup. Call `scan_all` with an open `HVInterface`:

```python
from hv_interface import HVInterface, HVError
from pattern_scanner import scan_all

with HVInterface() as hv:
    offsets = scan_all(hv)

print(offsets)
# {'Target_1': 18446735277682955384, 'Target_2': 0}
```

`scan_all` returns a `dict[str, int]`:
- Non-zero value — kernel virtual address (KVA) of the first match in ntoskrnl `.text`
- `0` — pattern not found or driver returned no match (a warning is logged)

---

## Step 3 — Use the Results at Runtime

Read from the `offsets` dict in your hot path. Do **not** call `scan_all` or `hv.scan_pattern` in a loop — the IOCTL is a blocking kernel call and is intended for one-shot initialization only.

```python
target_kva = offsets.get("Target_1", 0)
if target_kva == 0:
    print("Target_1 not found — check pattern or driver state")
else:
    print(f"Target_1 at 0x{target_kva:016X}")
```

---

## Error Reference

| Exception | Cause |
|---|---|
| `HVError` (Win32 error 2) | Device not found — driver not loaded or `\\.\DayZHV` not created |
| `HVError` (Win32 error 5) | Access denied — run as Administrator |
| `HVError("short read")` | Driver returned fewer than 8 bytes — version mismatch |
| `ValueError` | Pattern string exceeds 255 bytes |
| `HVError` (Win32 error 87) | `STATUS_INVALID_BUFFER_SIZE` — pattern < 2 bytes or output buffer too small |

---

## IOCTL Reference

| Field | Value |
|---|---|
| Control code | `0x00222400` |
| Input | ASCII pattern string, null-terminated, max 256 bytes |
| Output | 8-byte little-endian `uint64` KVA (0 = miss) |
| Method | `METHOD_BUFFERED` |
| Device | `\\.\DayZHV` (symlink → `\Device\DayZHV`) |

---

## Troubleshooting

**`HVError: [WinError 2]`** — The driver is not running. Run `sc query dayzdriv` and confirm `STATE: 4 RUNNING`. If not, check `logs\dayzdriv.log` for the failure reason.

**All offsets return `0`** — The pattern did not match in ntoskrnl `.text`. Verify the pattern against the currently loaded kernel version with a disassembler. Patterns are version-specific.

**`WinError 5` (Access Denied)** — The script must run as Administrator to open the kernel device handle.

**Build mismatch** — If you update `IOCTL_HV_SCAN_PATTERN` in `Vmx.h`, update the matching constant in `hv_constants.py` to the same value. Current value: `0x00222400`.
