# SpectreMemory Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the Win32 user-mode memory access layer in Project Spectre with a `SpectreMemory` class that reads kernel virtual addresses via a new `IOCTL_HV_READ_MEMORY` IOCTL on the `\\.\DayZHV` device, and expose a `MemoryWorker` QThread-compatible worker for non-blocking PyQt5 integration.

**Architecture:** `HVInterface` (existing) owns the device handle and issues raw `DeviceIoControl` calls. `SpectreMemory` wraps it — all typed read methods (`read_uint64`, `read_float`, `read_vec3`, `read_string`, `read_struct`) delegate to one internal `read_raw(kva, length)` method which uses the new `IOCTL_HV_READ_MEMORY` (0x00222404) control code. `MemoryWorker(QObject)` lives on a `QThread`, calls `SpectreMemory` in a loop, and emits an `ESPScene` signal; the main thread connects to that signal and repaints.

**Tech Stack:** Python 3.11+ (64-bit), ctypes, struct, PyQt5, pytest, existing `HVInterface` / `hv_constants` / `pattern_scanner`.

---

### Task 1: Add IOCTL_HV_READ_MEMORY constant

**Files:**
- Modify: `spectre/hv_constants.py`

**Step 1: Write the failing test**

Create `tests/test_hv_constants.py`:

```python
from spectre.hv_constants import IOCTL_HV_READ_MEMORY

def test_ioctl_read_memory_value():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x901, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    # = (0x22 << 16) | (0x901 << 2) | 0 | 0 = 0x00222404
    assert IOCTL_HV_READ_MEMORY == 0x00222404
```

**Step 2: Run test to verify it fails**

```
cd F:\vsprojs\dayzdriv
pytest tests/test_hv_constants.py::test_ioctl_read_memory_value -v
```
Expected: `ImportError` or `AttributeError` — `IOCTL_HV_READ_MEMORY` does not exist yet.

**Step 3: Add the constant**

In `spectre/hv_constants.py`, append:
```python
IOCTL_HV_READ_MEMORY  = 0x00222404  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
HV_READ_MAX_LENGTH    = 65536       # driver enforces this ceiling (64 KB)
```

**Step 4: Run test to verify it passes**

```
pytest tests/test_hv_constants.py::test_ioctl_read_memory_value -v
```
Expected: `PASSED`

**Step 5: Commit**

```
git add spectre/hv_constants.py tests/test_hv_constants.py
git commit -m "feat: add IOCTL_HV_READ_MEMORY constant (0x00222404)"
```

---

### Task 2: Add read_memory to HVInterface

**Files:**
- Modify: `spectre/hv_interface.py`
- Test: `tests/test_hv_interface_read.py`

**Step 1: Write the failing test**

Create `tests/test_hv_interface_read.py`:

```python
import ctypes
import struct
from unittest.mock import patch, MagicMock
from spectre.hv_interface import HVInterface
from spectre.hv_constants import IOCTL_HV_READ_MEMORY

def _make_hv() -> HVInterface:
    """Construct HVInterface without touching the real device."""
    hv = HVInterface.__new__(HVInterface)
    hv._handle = 0xDEAD  # fake non-zero handle
    return hv

def test_read_memory_returns_bytes():
    hv = _make_hv()
    fake_data = struct.pack('<Q', 0xCAFEBABEDEADBEEF)

    def fake_ioctl(handle, code, in_buf, in_len, out_buf, out_len, bytes_ret, overlapped):
        ctypes.memmove(out_buf, fake_data, len(fake_data))
        bytes_ret._obj.value = len(fake_data)
        return 1  # TRUE

    with patch('spectre.hv_interface._kernel32.DeviceIoControl', side_effect=fake_ioctl):
        result = hv.read_memory(0xFFFFF80012345678, 8)

    assert result == fake_data

def test_read_memory_raises_on_length_zero():
    hv = _make_hv()
    import pytest
    with pytest.raises(ValueError):
        hv.read_memory(0xFFFFF80012345678, 0)

def test_read_memory_raises_on_length_over_cap():
    hv = _make_hv()
    import pytest
    with pytest.raises(ValueError):
        hv.read_memory(0xFFFFF80012345678, 65537)

def test_read_memory_raises_hverror_on_ioctl_fail():
    hv = _make_hv()
    import pytest

    def fail_ioctl(*args, **kwargs):
        return 0  # FALSE

    with patch('spectre.hv_interface._kernel32.DeviceIoControl', side_effect=fail_ioctl):
        with patch('spectre.hv_interface._kernel32.GetLastError', return_value=5):
            with pytest.raises(Exception):
                hv.read_memory(0xFFFFF80012345678, 8)
```

**Step 2: Run test to verify it fails**

```
pytest tests/test_hv_interface_read.py -v
```
Expected: `AttributeError: 'HVInterface' object has no attribute 'read_memory'`

**Step 3: Implement `read_memory` in `HVInterface`**

Add the following import at the top of `spectre/hv_interface.py` (already present: `ctypes`, `struct`). Then add this method inside `HVInterface`, after `scan_pattern`:

```python
def read_memory(self, kva: int, length: int) -> bytes:
    from hv_constants import HV_READ_MAX_LENGTH, IOCTL_HV_READ_MEMORY
    if length <= 0 or length > HV_READ_MAX_LENGTH:
        raise ValueError(
            f"length must be 1..{HV_READ_MAX_LENGTH}, got {length}"
        )
    # Input: packed little-endian { uint64 kva, uint32 length }
    in_buf = ctypes.create_string_buffer(struct.pack('<QI', kva, length))
    out_buf = ctypes.create_string_buffer(length)
    bytes_returned = ctypes.c_ulong(0)

    ok = _kernel32.DeviceIoControl(
        self._handle,
        IOCTL_HV_READ_MEMORY,
        in_buf,  ctypes.sizeof(in_buf),
        out_buf, ctypes.sizeof(out_buf),
        ctypes.byref(bytes_returned),
        None,
    )
    if not ok:
        err = _kernel32.GetLastError()
        raise HVError(f"read_memory(kva=0x{kva:X}, len={length}) failed", err)
    return bytes(out_buf.raw[:bytes_returned.value])
```

**Step 4: Run tests to verify they pass**

```
pytest tests/test_hv_interface_read.py -v
```
Expected: all 4 tests `PASSED`

**Step 5: Commit**

```
git add spectre/hv_interface.py tests/test_hv_interface_read.py
git commit -m "feat: add HVInterface.read_memory via IOCTL_HV_READ_MEMORY"
```

---

### Task 3: Create SpectreMemory with typed read methods

**Files:**
- Create: `spectre/spectre_memory.py`
- Create: `tests/test_spectre_memory.py`

**Step 1: Write the failing tests**

Create `tests/test_spectre_memory.py`:

```python
import struct
from unittest.mock import MagicMock
import pytest
from spectre.spectre_memory import SpectreMemory

KVA = 0xFFFFF80012345678

def _mem(raw: bytes) -> SpectreMemory:
    hv = MagicMock()
    hv.read_memory.return_value = raw
    return SpectreMemory(hv)

def test_read_uint64():
    m = _mem(struct.pack('<Q', 0xDEADBEEFCAFEBABE))
    assert m.read_uint64(KVA) == 0xDEADBEEFCAFEBABE

def test_read_uint32():
    m = _mem(struct.pack('<I', 0xDEADBEEF))
    assert m.read_uint32(KVA) == 0xDEADBEEF

def test_read_float():
    m = _mem(struct.pack('<f', 3.14))
    assert abs(m.read_float(KVA) - 3.14) < 1e-5

def test_read_vec3():
    m = _mem(struct.pack('<fff', 1.0, 2.0, 3.0))
    assert m.read_vec3(KVA) == pytest.approx((1.0, 2.0, 3.0))

def test_read_string_utf8():
    raw = b'Hello\x00' + b'\x00' * 58
    m = _mem(raw)
    assert m.read_string(KVA) == 'Hello'

def test_read_string_no_null_truncates():
    raw = b'A' * 64
    m = _mem(raw)
    assert m.read_string(KVA) == 'A' * 64

def test_read_struct_returns_raw():
    raw = b'\x01\x02\x03\x04'
    m = _mem(raw)
    assert m.read_struct(KVA, 4) == raw

def test_read_raw_delegates_to_hv():
    hv = MagicMock()
    hv.read_memory.return_value = b'\xFF' * 8
    m = SpectreMemory(hv)
    result = m.read_raw(KVA, 8)
    hv.read_memory.assert_called_once_with(KVA, 8)
    assert result == b'\xFF' * 8

def test_read_uint64_on_short_read_raises():
    m = _mem(b'\x01\x02\x03')  # only 3 bytes, need 8
    with pytest.raises(ValueError):
        m.read_uint64(KVA)
```

**Step 2: Run tests to verify they fail**

```
pytest tests/test_spectre_memory.py -v
```
Expected: `ModuleNotFoundError: No module named 'spectre.spectre_memory'`

**Step 3: Implement `spectre/spectre_memory.py`**

Create `spectre/spectre_memory.py`:

```python
from __future__ import annotations
import struct
from hv_interface import HVInterface


class SpectreMemory:
    def __init__(self, hv: HVInterface) -> None:
        self._hv = hv

    def read_raw(self, kva: int, length: int) -> bytes:
        return self._hv.read_memory(kva, length)

    def _unpack(self, kva: int, fmt: str) -> tuple:
        size = struct.calcsize(fmt)
        data = self.read_raw(kva, size)
        if len(data) < size:
            raise ValueError(
                f"Short read at 0x{kva:X}: expected {size} bytes, got {len(data)}"
            )
        return struct.unpack_from(fmt, data)

    def read_uint64(self, kva: int) -> int:
        return self._unpack(kva, '<Q')[0]

    def read_uint32(self, kva: int) -> int:
        return self._unpack(kva, '<I')[0]

    def read_float(self, kva: int) -> float:
        return self._unpack(kva, '<f')[0]

    def read_vec3(self, kva: int) -> tuple[float, float, float]:
        return self._unpack(kva, '<fff')

    def read_string(self, kva: int, max_len: int = 64) -> str:
        data = self.read_raw(kva, max_len)
        null = data.find(b'\x00')
        raw = data[:null] if null != -1 else data
        return raw.decode('utf-8', errors='replace')

    def read_struct(self, kva: int, length: int) -> bytes:
        return self.read_raw(kva, length)
```

**Step 4: Run tests to verify they pass**

```
pytest tests/test_spectre_memory.py -v
```
Expected: all 9 tests `PASSED`

**Step 5: Commit**

```
git add spectre/spectre_memory.py tests/test_spectre_memory.py
git commit -m "feat: add SpectreMemory with typed read methods"
```

---

### Task 4: Add MemoryWorker QThread worker

**Files:**
- Create: `spectre/memory_worker.py`
- Create: `tests/test_memory_worker.py`

**Step 1: Write the failing tests**

Create `tests/test_memory_worker.py`:

```python
import pytest
from unittest.mock import MagicMock, patch

# Guard: skip entire module if PyQt5 is not installed
pytest.importorskip('PyQt5')

from PyQt5.QtCore import QCoreApplication
import sys

@pytest.fixture(scope='module')
def qt_app():
    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    yield app

def test_memory_worker_emits_scene(qt_app):
    from spectre.memory_worker import MemoryWorker
    fake_scene = object()
    build_fn = MagicMock(return_value=fake_scene)

    worker = MemoryWorker(build_fn=build_fn, interval_ms=0)
    received = []
    worker.scene_ready.connect(lambda s: received.append(s))

    worker._run_once()

    assert received == [fake_scene]
    build_fn.assert_called_once()

def test_memory_worker_emits_error_on_exception(qt_app):
    from spectre.memory_worker import MemoryWorker

    def explode():
        raise RuntimeError("boom")

    worker = MemoryWorker(build_fn=explode, interval_ms=0)
    errors = []
    worker.error.connect(lambda e: errors.append(e))

    worker._run_once()

    assert len(errors) == 1
    assert 'boom' in errors[0]
```

**Step 2: Run tests to verify they fail**

```
pytest tests/test_memory_worker.py -v
```
Expected: `ModuleNotFoundError: No module named 'spectre.memory_worker'`

**Step 3: Implement `spectre/memory_worker.py`**

Create `spectre/memory_worker.py`:

```python
from __future__ import annotations
import traceback
from typing import Callable, Any
from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal


class MemoryWorker(QObject):
    """
    Runs build_fn() on a QThread, emits scene_ready with the result.
    
    Usage:
        worker = MemoryWorker(build_fn=lambda: memory.build_scene(...))
        thread = QThread()
        worker.moveToThread(thread)
        worker.scene_ready.connect(overlay.update_scene)
        thread.started.connect(worker.start)
        thread.start()
    """

    scene_ready = pyqtSignal(object)
    error       = pyqtSignal(str)

    def __init__(self, build_fn: Callable[[], Any], interval_ms: int = 16) -> None:
        super().__init__()
        self._build_fn   = build_fn
        self._interval   = interval_ms
        self._timer: QTimer | None = None
        self._running    = False

    def start(self) -> None:
        self._running = True
        self._timer = QTimer(self)
        self._timer.setInterval(self._interval)
        self._timer.timeout.connect(self._run_once)
        self._timer.start()

    def stop(self) -> None:
        self._running = False
        if self._timer:
            self._timer.stop()

    def _run_once(self) -> None:
        try:
            scene = self._build_fn()
            self.scene_ready.emit(scene)
        except Exception:
            self.error.emit(traceback.format_exc())
```

**Step 4: Run tests to verify they pass**

```
pytest tests/test_memory_worker.py -v
```
Expected: all 2 tests `PASSED`

**Step 5: Commit**

```
git add spectre/memory_worker.py tests/test_memory_worker.py
git commit -m "feat: add MemoryWorker QThread worker with scene_ready signal"
```

---

### Task 5: Wire MemoryWorker into the kernel driver (C side stub)

**Files:**
- Modify: `Vmx.h` (add IOCTL code comment only — actual handler is in the kernel driver source, outside this repo)

**Step 1: Document the kernel contract**

This task is a reminder that `IOCTL_HV_READ_MEMORY` (0x00222404) must be handled in the kernel driver (`DayZHV`). The Python layer is complete; this task tracks the kernel side obligation.

The kernel handler must:
1. Accept input buffer: `{ ULONG64 Kva; ULONG Length; }` (12 bytes)
2. Validate `Length > 0 && Length <= 65536`
3. Validate `Kva` is a non-null canonical kernel address (bits 63:48 all 1 for KVA)
4. Use `__try / __except` around `RtlCopyMemory(OutputBuffer, (PVOID)Kva, Length)`
5. Set `Irp->IoStatus.Information = Length` on success

**Step 2: Add comment to Vmx.h**

Find the section in `Vmx.h` where IOCTL codes are documented (or top-of-file comment block) and add:

```c
// IOCTL_HV_READ_MEMORY  0x00222404
//   Input:  { ULONG64 Kva; ULONG Length; }   (12 bytes, METHOD_BUFFERED)
//   Output: raw bytes copied from Kva         (max 65536 bytes)
//   Status: STATUS_INVALID_PARAMETER if Length == 0 || Length > 65536
//           STATUS_ACCESS_VIOLATION  if Kva is unmapped (caught via __try)
```

**Step 3: Commit**

```
git add Vmx.h
git commit -m "docs: document IOCTL_HV_READ_MEMORY kernel contract in Vmx.h"
```

---

### Task 6: Run full test suite and verify

**Step 1: Run all tests**

```
cd F:\vsprojs\dayzdriv
pytest tests/ -v
```
Expected: all tests `PASSED`, no warnings about missing imports other than optional PyQt5 skip guard.

**Step 2: Verify imports work from spectre/ directory**

```
cd F:\vsprojs\dayzdriv\spectre
python -c "from spectre_memory import SpectreMemory; print('OK')"
python -c "from hv_constants import IOCTL_HV_READ_MEMORY; print(hex(IOCTL_HV_READ_MEMORY))"
```
Expected: `OK` and `0x222404`

**Step 3: Commit if any fixups were needed**

```
git add -u
git commit -m "fix: post-integration cleanup"
```
