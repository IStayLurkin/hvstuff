import struct
from unittest.mock import MagicMock
import pytest
from spectre_memory import SpectreMemory

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
