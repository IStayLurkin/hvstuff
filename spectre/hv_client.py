from __future__ import annotations
import ctypes
import os
from typing import Optional

# ---------------------------------------------------------------------------
# EPT permission bit constants (mirrors Vmx.h / HvBridge.cpp).
# ---------------------------------------------------------------------------
EPT_READ      = 1 << 0
EPT_WRITE     = 1 << 1
EPT_EXEC      = 1 << 2   # supervisor-mode execute
EPT_EXEC_USER = 1 << 10  # user-mode execute (MBEC only)

EPT_RO  = EPT_READ                          # read-only
EPT_RX  = EPT_READ | EPT_EXEC              # read + supervisor-execute
EPT_RWX = EPT_READ | EPT_WRITE | EPT_EXEC  # full access

_VALID_POLICY_MASK = EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER

# Hypercall IDs (mirrors Vmx.h).
HV_CALL_GET_PERF_COUNTERS = 0x03
HV_CALL_SET_EPT_POLICY    = 0x05
HV_CALL_LOCK_LSTAR        = 0x06
HV_CALL_WP_REGISTER       = 0x07

# HV_STATUS codes returned by IssueHypercall / IssueHypercallRaw.
HV_STATUS_SUCCESS        = 0x00
HV_STATUS_INVALID_CALL   = 0x01
HV_STATUS_NOT_SUPPORTED  = 0x02
HV_STATUS_BAD_ALIGNMENT  = 0x03

_STATUS_NAMES = {
    HV_STATUS_SUCCESS:       "HV_STATUS_SUCCESS",
    HV_STATUS_INVALID_CALL:  "HV_STATUS_INVALID_CALL",
    HV_STATUS_NOT_SUPPORTED: "HV_STATUS_NOT_SUPPORTED",
    HV_STATUS_BAD_ALIGNMENT: "HV_STATUS_BAD_ALIGNMENT",
}

# Maximum 48-bit physical address (i9-14900K physical address width).
_MAX_PHYSICAL_ADDRESS = (1 << 48) - 1

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HvCallError(Exception):
    """Raised when the hypervisor returns a non-success status code."""
    def __init__(self, status: int, gpa: int, policy: int) -> None:
        name = _STATUS_NAMES.get(status, f"0x{status:02X}")
        super().__init__(
            f"Hypercall failed: {name} (GPA=0x{gpa:016X} policy=0x{policy:X})"
        )
        self.status = status
        self.gpa    = gpa
        self.policy = policy


class HvValidationError(ValueError):
    """Raised when a GPA or policy value fails pre-call validation."""


# ---------------------------------------------------------------------------
# DLL path resolution — bin\HvBridge.dll relative to this file.
# ---------------------------------------------------------------------------

def _dll_path() -> str:
    here    = os.path.dirname(os.path.abspath(__file__))
    repo    = os.path.dirname(here)                        # spectre\ -> repo root
    candidate = os.path.join(repo, "bin", "HvBridge.dll")
    return candidate


# ---------------------------------------------------------------------------
# HvClient
# ---------------------------------------------------------------------------

class HvClient:
    """
    User-mode paravirtualization client for the dayzdriv hypervisor.

    Loads HvBridge.dll from bin\ and wraps IssueHypercall for runtime
    EPT policy adjustment via hypercall 0x05 (HV_CALL_SET_EPT_POLICY).

    Usage:
        hv = HvClient()
        hv.set_ept_policy(0x1_0000_0000, EPT_READ | EPT_EXEC)
    """

    def __init__(self, dll_path: Optional[str] = None) -> None:
        path = dll_path or _dll_path()
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"HvBridge.dll not found at '{path}'. "
                "Build the hvbridge project and copy the output to bin\\."
            )
        self._dll = ctypes.CDLL(path)

        fn = self._dll.IssueHypercall
        fn.restype  = ctypes.c_uint64
        fn.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
        self._issue = fn

        fn_raw = self._dll.IssueHypercallRaw
        fn_raw.restype  = ctypes.c_uint64
        fn_raw.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
        self._issue_raw = fn_raw

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_gpa(gpa: int) -> None:
        if not isinstance(gpa, int) or gpa < 0:
            raise HvValidationError(
                f"GPA must be a non-negative integer, got {gpa!r}"
            )
        if gpa == 0:
            raise HvValidationError(
                "GPA 0x0 is the real-mode IVT page and must not be modified."
            )
        if gpa > _MAX_PHYSICAL_ADDRESS:
            raise HvValidationError(
                f"GPA 0x{gpa:X} exceeds the 48-bit physical address limit "
                f"(0x{_MAX_PHYSICAL_ADDRESS:X}) of the i9-14900K."
            )
        if gpa & 0xFFF:
            raise HvValidationError(
                f"GPA 0x{gpa:X} is not 4KB-aligned. "
                f"Use 0x{gpa & ~0xFFF:X} (aligned down) or 0x{(gpa + 0xFFF) & ~0xFFF:X} (aligned up)."
            )

    @staticmethod
    def _validate_policy(policy: int) -> None:
        if not isinstance(policy, int) or policy < 0:
            raise HvValidationError(
                f"Policy must be a non-negative integer, got {policy!r}"
            )
        stray = policy & ~_VALID_POLICY_MASK
        if stray:
            raise HvValidationError(
                f"Policy 0x{policy:X} contains invalid bits 0x{stray:X}. "
                f"Valid bits: EPT_READ(1) | EPT_WRITE(2) | EPT_EXEC(4) | EPT_EXEC_USER(0x400)."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_ept_policy(self, gpa: int, policy: int) -> int:
        """
        Issue HV_CALL_SET_EPT_POLICY (0x05) to the hypervisor.

        Args:
            gpa:    4KB-aligned guest physical address.
            policy: Combination of EPT_READ / EPT_WRITE / EPT_EXEC /
                    EPT_EXEC_USER.  Pass 0 to trap all accesses.

        Returns:
            HV_STATUS_SUCCESS (0) on success.

        Raises:
            HvValidationError: if gpa or policy fail pre-call checks.
            HvCallError:       if the hypervisor returns a non-zero status.
        """
        self._validate_gpa(gpa)
        self._validate_policy(policy)

        status = int(self._issue(ctypes.c_uint64(gpa), ctypes.c_uint64(policy)))
        if status != HV_STATUS_SUCCESS:
            raise HvCallError(status, gpa, policy)
        return status

    def protect_rx(self, gpa: int) -> int:
        """Convenience: set a page read+supervisor-execute only (clear write bit)."""
        return self.set_ept_policy(gpa, EPT_READ | EPT_EXEC)

    def protect_ro(self, gpa: int) -> int:
        """Convenience: set a page read-only (clear write and execute bits)."""
        return self.set_ept_policy(gpa, EPT_READ)

    def restore_rwx(self, gpa: int) -> int:
        """Convenience: restore full read/write/execute access to a page."""
        return self.set_ept_policy(gpa, EPT_RWX)

    def sweep(self, base_gpa: int, page_count: int, policy: int) -> list[int]:
        """
        Apply policy to a contiguous range of pages.

        Returns a list of HV_STATUS codes, one per page.
        Validation is performed once on base_gpa and policy before the loop;
        each per-page GPA is validated individually so a single bad page does
        not silently abort the sweep.

        Raises HvValidationError on base_gpa / policy / any per-page GPA.
        Raises HvCallError on the first non-success hypervisor response.
        """
        if not isinstance(page_count, int) or page_count <= 0:
            raise HvValidationError(
                f"page_count must be a positive integer, got {page_count!r}"
            )
        self._validate_policy(policy)
        results: list[int] = []
        for i in range(page_count):
            gpa = base_gpa + i * 0x1000
            results.append(self.set_ept_policy(gpa, policy))
        return results

    def wp_register(self, gpa: int) -> int:
        """
        Issue HV_CALL_WP_REGISTER (0x07) to dynamically add a GPA to the
        hypervisor's write-protection table (g_WpTable).

        After registration the kernel will:
          - Set the page's EPT permissions to EPT_READ | EPT_EXEC (strip write).
          - On any subsequent guest write to this GPA: inject #GP(0) and log
            a [WP] event rather than lazy-mapping the access through.

        Args:
            gpa: 4KB-aligned guest physical address to protect.

        Returns:
            HV_STATUS_SUCCESS (0) on success, or if already registered.

        Raises:
            HvValidationError: if gpa fails pre-call checks.
            HvCallError:       if the kernel returns a non-zero status
                               (HV_STATUS_NOT_SUPPORTED if table is full).
        """
        self._validate_gpa(gpa)
        status = int(self._issue_raw(
            ctypes.c_uint64(HV_CALL_WP_REGISTER),
            ctypes.c_uint64(gpa),
            ctypes.c_uint64(0)
        ))
        if status != HV_STATUS_SUCCESS:
            raise HvCallError(status, gpa, 0)
        return status

    def get_perf_counters(self) -> tuple[int, int]:
        """
        Issue HV_CALL_GET_PERF_COUNTERS (0x03).

        Returns:
            (mperf_offset, aper_offset) — accumulated MPERF/APERF ticks
            consumed by VM-exit handlers on the calling core since boot.
            Both values are zero until the guest first reads IA32_MPERF or
            IA32_APERF (which arms the AperMperfActive flag in the kernel).
        """
        status = int(self._issue_raw(
            ctypes.c_uint64(HV_CALL_GET_PERF_COUNTERS),
            ctypes.c_uint64(0),
            ctypes.c_uint64(0)
        ))
        # For HC 0x03: RAX = MperfOffset, RBX = AperOffset.
        # IssueHypercallRaw only returns RAX. AperOffset (RBX) is not
        # retrievable from user-mode without a dedicated out-parameter export.
        # This returns (mperf_offset, 0) until the DLL gains RBX pass-through.
        return (status, 0)
