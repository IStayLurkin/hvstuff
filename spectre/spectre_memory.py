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
