import ctypes
import struct
import pytest
from unittest.mock import patch
from hv_interface import HVInterface, HVError
from hv_constants import IOCTL_HV_READ_MEMORY

def _make_hv() -> HVInterface:
    hv = HVInterface.__new__(HVInterface)
    hv._handle = 0xDEAD
    return hv

def test_read_memory_returns_bytes():
    hv = _make_hv()
    fake_data = struct.pack('<Q', 0xCAFEBABEDEADBEEF)

    def fake_ioctl(handle, code, in_buf, in_len, out_buf, out_len, bytes_ret, overlapped):
        assert in_len == 12, f"input buffer must be 12 bytes, got {in_len}"
        ctypes.memmove(out_buf, fake_data, len(fake_data))
        bytes_ret._obj.value = len(fake_data)
        return 1  # TRUE

    with patch('hv_interface._kernel32.DeviceIoControl', side_effect=fake_ioctl):
        result = hv.read_memory(0xFFFFF80012345678, 8)

    assert result == fake_data

def test_read_memory_raises_on_length_zero():
    hv = _make_hv()
    with pytest.raises(ValueError):
        hv.read_memory(0xFFFFF80012345678, 0)

def test_read_memory_raises_on_length_over_cap():
    hv = _make_hv()
    with pytest.raises(ValueError):
        hv.read_memory(0xFFFFF80012345678, 65537)

def test_read_memory_raises_hverror_on_ioctl_fail():
    hv = _make_hv()

    def fail_ioctl(*args, **kwargs):
        return 0

    with patch('hv_interface._kernel32.DeviceIoControl', side_effect=fail_ioctl):
        with patch('hv_interface._kernel32.GetLastError', return_value=5):
            with pytest.raises(HVError):
                hv.read_memory(0xFFFFF80012345678, 8)
