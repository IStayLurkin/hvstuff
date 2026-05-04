from __future__ import annotations
import ctypes
import ctypes.wintypes
import struct
from hv_constants import DEVICE_PATH, IOCTL_HV_SCAN_PATTERN, PATTERN_BUFFER_SIZE, IOCTL_HV_READ_MEMORY, HV_READ_MAX_LENGTH

_kernel32 = ctypes.windll.kernel32

GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
OPEN_EXISTING   = 3
INVALID_HANDLE  = ctypes.wintypes.HANDLE(-1).value


class HVError(OSError):
    def __init__(self, msg: str, win32_error: int = 0) -> None:
        super().__init__(win32_error, msg)
        self.win32_error = win32_error


class HVInterface:
    def __init__(self) -> None:
        handle = _kernel32.CreateFileW(
            DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE or handle == 0:
            err = _kernel32.GetLastError()
            raise HVError(f"CreateFileW({DEVICE_PATH!r}) failed", err)
        self._handle = handle

    def scan_pattern(self, pattern: str) -> int:
        encoded = pattern.encode('ascii')
        if len(encoded) >= PATTERN_BUFFER_SIZE:
            raise ValueError(
                f"Pattern too long ({len(encoded)} bytes, max {PATTERN_BUFFER_SIZE - 1}): {pattern!r}"
            )

        # create_string_buffer zero-fills to PATTERN_BUFFER_SIZE — guarantees null terminator
        in_buf  = ctypes.create_string_buffer(encoded, PATTERN_BUFFER_SIZE)
        out_buf = ctypes.create_string_buffer(8)
        bytes_returned = ctypes.c_ulong(0)

        ok = _kernel32.DeviceIoControl(
            self._handle,
            IOCTL_HV_SCAN_PATTERN,
            in_buf,  ctypes.sizeof(in_buf),
            out_buf, ctypes.sizeof(out_buf),
            ctypes.byref(bytes_returned),
            None,
        )
        if not ok:
            err = _kernel32.GetLastError()
            raise HVError(f"DeviceIoControl failed for pattern {pattern!r}", err)
        if bytes_returned.value != 8:
            raise HVError(
                f"DeviceIoControl short read: expected 8 bytes, got {bytes_returned.value}"
            )

        (kva,) = struct.unpack_from('<Q', out_buf)
        return kva

    def read_memory(self, kva: int, length: int) -> bytes:
        if length <= 0 or length > HV_READ_MAX_LENGTH:
            raise ValueError(
                f"length must be 1..{HV_READ_MAX_LENGTH}, got {length}"
            )
        in_buf = ctypes.create_string_buffer(struct.pack('<QI', kva, length), 12)
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

    def close(self) -> None:
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> 'HVInterface':
        return self

    def __exit__(self, *_) -> None:
        self.close()
