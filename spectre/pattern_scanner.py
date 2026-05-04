from __future__ import annotations
import logging
from hv_interface import HVInterface

_log = logging.getLogger(__name__)

PATTERNS: dict[str, str] = {
    "Target_1": "48 8B 05 ? ? ? ? 48 8B",
    "Target_2": "E8 ? ? ? ? 48 8B D8",
}


def scan_all(hv: HVInterface) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for name, pattern in PATTERNS.items():
        kva = hv.scan_pattern(pattern)
        if kva == 0:
            _log.warning("Pattern miss: %s (%r)", name, pattern)
        else:
            _log.debug("Pattern hit:  %s -> 0x%016X", name, kva)
        offsets[name] = kva
    return offsets
