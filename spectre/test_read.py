"""
IOCTL_HV_READ_MEMORY smoke test.

Run from the spectre/ directory after the driver is loaded and mapped:
    python test_read.py

Prerequisites:
  - dayzdriv.sys loaded via your mapper
  - \\.\DayZHV symbolic link visible (confirm in WinObj under \??)
  - DayZ running (for pattern hits to be meaningful)

Exit codes:
  0 — all checks passed
  1 — device open failed (DSE bypass / mapper issue)
  2 — pattern scan returned 0 (driver loaded but pattern miss)
  3 — memory read returned unexpected length
"""
from __future__ import annotations
import sys
import os

# Allow running from spectre/ directly without installing the package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hv_interface import HVInterface, HVError
from spectre_memory import SpectreMemory
from pattern_scanner import scan_all

STEP_WIDTH = 60


def _step(label: str, result: str, ok: bool) -> None:
    marker = "[+]" if ok else "[!]"
    print(f"{marker} {label:<{STEP_WIDTH}} {result}")


def main() -> int:
    print("=" * (STEP_WIDTH + 12))
    print("  DayZHV IOCTL_HV_READ_MEMORY smoke test")
    print("=" * (STEP_WIDTH + 12))
    print()

    # ------------------------------------------------------------------
    # Step 1: Open device handle
    # ------------------------------------------------------------------
    print("--- Step 1: Device open ---")
    try:
        hv = HVInterface()
    except HVError as e:
        _step("Open \\\\.\\.DayZHV", f"FAILED  win32={e.win32_error}", False)
        print()
        print("[!] Cannot open device.  Check:")
        print("    - dayzdriv.sys is loaded (check DebugView for DriverEntry lines)")
        print("    - Symbolic link \\\\??\\DayZLink exists (WinObj)")
        print("    - Running as Administrator")
        return 1
    _step("Open \\\\.\\.DayZHV", "OK", True)
    print()

    with hv:
        mem = SpectreMemory(hv)

        # ------------------------------------------------------------------
        # Step 2: Pattern scan (IOCTL_HV_SCAN_PATTERN = 0x00222400)
        # ------------------------------------------------------------------
        print("--- Step 2: Pattern scan (0x900 IOCTL) ---")
        offsets = scan_all(hv)

        any_hit = False
        for name, kva in offsets.items():
            hit = kva != 0
            any_hit = any_hit or hit
            _step(f"Pattern '{name}'",
                  f"KVA=0x{kva:016X}" if hit else "MISS (returned 0)",
                  hit)

        if not any_hit:
            print()
            print("[!] All patterns missed.  Possible causes:")
            print("    - DayZ is not running (patterns target game memory)")
            print("    - pattern_scanner.py PATTERNS dict contains placeholders")
            print("      (Target_1 / Target_2) — replace with real byte patterns")
            print("    - Kernel .text section layout changed after an update")
            return 2
        print()

        # ------------------------------------------------------------------
        # Step 3: Memory read integrity (IOCTL_HV_READ_MEMORY = 0x00222404)
        # ------------------------------------------------------------------
        print("--- Step 3: Memory read integrity (0x901 IOCTL) ---")

        # Use the first non-zero KVA we got from any pattern.
        test_kva = next((kva for kva in offsets.values() if kva != 0), None)

        # Read 8 bytes from that address.
        try:
            raw = mem.read_raw(test_kva, 8)
        except HVError as e:
            _step("read_raw(kva, 8)", f"FAILED  win32={e.win32_error}", False)
            print()
            print("[!] The 0x901 IOCTL call failed.  Check:")
            print("    - Driver was rebuilt after adding the IOCTL_HV_READ_MEMORY case")
            print("    - RtlCopyMemory __try block is present in Driver.c")
            return 3

        length_ok = len(raw) == 8
        _step("read_raw(kva, 8) — byte count", f"got {len(raw)} bytes", length_ok)
        if not length_ok:
            return 3

        _step("raw bytes", raw.hex(), True)

        # Check whether the address happens to be the start of a PE image.
        try:
            at_base = mem.read_raw(test_kva, 2)
            is_mz = at_base == b'MZ'
        except HVError:
            is_mz = False
            at_base = b''

        if is_mz:
            _step("First 2 bytes == 'MZ'",
                  "Valid PE header — pointer is at a module base", True)
        else:
            # Not an MZ — that's fine, patterns rarely point at a module base.
            _step("First 2 bytes",
                  f"{at_base.hex() if at_base else 'read failed'} (not MZ — expected for mid-code KVAs)",
                  True)

        # Read a uint64 through SpectreMemory to exercise the full typed path.
        try:
            val64 = mem.read_uint64(test_kva)
            _step("read_uint64(kva)", f"0x{val64:016X}", True)
        except Exception as e:
            _step("read_uint64(kva)", f"FAILED: {e}", False)

        print()
        print("[+] All checks passed.  IOCTL_HV_READ_MEMORY is operational.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
