"""
hv_ipc.py — EPT-violation IPC client for the dayzdriv hypervisor.

Provides a typed, high-level interface over the IOCTL_HV_IPC_CALL bridge:

    Python process
        │  ipc_call() / HVIpc methods
        ▼
    hv_interface.HVInterface.ipc_call()
        │  DeviceIoControl(IOCTL_HV_IPC_CALL, HV_IPC_REQUEST, ...)
        ▼
    dayzdriv.sys — writes {Id, Arg0, Arg1} to KVA(GPA=0xFEED0000)
        │  EPT violation (non-present leaf PTE)
        ▼
    HandleEptIpcViolation — dispatches through HV_CALL_* ABI
        │  writes Result to KVA+0x18, then VMRESUME
        ▼
    Driver reads result, returns HV_IPC_RESPONSE to caller

Usage:
    with HVIpc() as hv:
        hv.version_check()          # raises on ABI mismatch
        hv.lock_lstar()
        hv.wp_register(0x1A3B000)
"""
from __future__ import annotations

from hv_constants import (
    HV_IPC_VERSION_CHECK,
    HV_IPC_MTF_TOGGLE,
    HV_IPC_EPT_SWITCH_VIEW,
    HV_IPC_GET_PERF,
    HV_IPC_SET_EPT_POLICY,
    HV_IPC_LOCK_LSTAR,
    HV_IPC_WP_REGISTER,
    HV_IPC_TEARDOWN,
    HV_IPC_VERSION,
    HV_STATUS_SUCCESS,
    HV_STATUS_INVALID_CALL,
    HV_STATUS_NOT_SUPPORTED,
    HV_STATUS_BAD_ALIGNMENT,
)
from hv_interface import HVInterface, HVError

# EPT permission bits — mirror Vmx.h.
EPT_READ      = 1 << 0
EPT_WRITE     = 1 << 1
EPT_EXEC      = 1 << 2
EPT_EXEC_USER = 1 << 10
EPT_RWX       = EPT_READ | EPT_WRITE | EPT_EXEC
_VALID_POLICY = EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER

_STATUS_NAMES = {
    HV_STATUS_SUCCESS:       "HV_STATUS_SUCCESS",
    HV_STATUS_INVALID_CALL:  "HV_STATUS_INVALID_CALL",
    HV_STATUS_NOT_SUPPORTED: "HV_STATUS_NOT_SUPPORTED",
    HV_STATUS_BAD_ALIGNMENT: "HV_STATUS_BAD_ALIGNMENT",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class IpcError(RuntimeError):
    """Raised when the hypervisor returns a non-success status via the IPC channel."""
    def __init__(self, call_id: int, result: int) -> None:
        name = _STATUS_NAMES.get(result, f"0x{result:016X}")
        super().__init__(f"IPC call 0x{call_id:02X} failed: {name}")
        self.call_id = call_id
        self.result  = result


class IpcVersionMismatch(IpcError):
    """Raised when version_check() returns a token that does not match HV_IPC_VERSION."""
    def __init__(self, got: int) -> None:
        super().__init__(HV_IPC_VERSION_CHECK, got)
        self.message = (
            f"Hypervisor ABI version mismatch: expected 0x{HV_IPC_VERSION:04X}, "
            f"got 0x{got:04X}.  Rebuild and reload dayzdriv.sys."
        )

    def __str__(self) -> str:
        return self.message


# ---------------------------------------------------------------------------
# HVIpc — high-level IPC client
# ---------------------------------------------------------------------------

class HVIpc:
    """
    High-level client for the EPT-violation IPC channel.

    Wraps HVInterface.ipc_call() with typed methods for each HV_IPC_* call.
    Use as a context manager to ensure the device handle is closed:

        with HVIpc() as hv:
            hv.version_check()
            hv.lock_lstar()
    """

    def __init__(self) -> None:
        self._iface = HVInterface()

    def _call(self, call_id: int, arg0: int = 0, arg1: int = 0) -> int:
        """Raw IPC call.  Returns the 64-bit result from the hypervisor."""
        return self._iface.ipc_call(call_id, arg0, arg1)

    # ------------------------------------------------------------------
    # Version / heartbeat
    # ------------------------------------------------------------------

    def version_check(self) -> int:
        """
        Issue HV_IPC_VERSION_CHECK (0x00).

        Confirms the hypervisor is running and that the IPC ABI version
        matches HV_IPC_VERSION (0x0001).

        Returns:
            The version token returned by the hypervisor.

        Raises:
            IpcVersionMismatch: if the returned token != HV_IPC_VERSION.
            HVError:            if the IOCTL itself fails (driver not loaded,
                                hypervisor not running, IPC page not mapped).
        """
        result = self._call(HV_IPC_VERSION_CHECK)
        if result != HV_IPC_VERSION:
            raise IpcVersionMismatch(result)
        return result

    # ------------------------------------------------------------------
    # MTF single-step
    # ------------------------------------------------------------------

    def mtf_arm(self) -> None:
        """Arm Monitor Trap Flag on the current core (HV_IPC_MTF_TOGGLE, arg0=1)."""
        result = self._call(HV_IPC_MTF_TOGGLE, arg0=1)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_MTF_TOGGLE, result)

    def mtf_disarm(self) -> None:
        """Disarm Monitor Trap Flag on the current core (HV_IPC_MTF_TOGGLE, arg0=0)."""
        result = self._call(HV_IPC_MTF_TOGGLE, arg0=0)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_MTF_TOGGLE, result)

    # ------------------------------------------------------------------
    # EPT view switching
    # ------------------------------------------------------------------

    def ept_switch_view(self, eptp_index: int) -> None:
        """
        Switch the active EPT view (HV_IPC_EPT_SWITCH_VIEW).

        Args:
            eptp_index: Slot in the EPTP list (0-511).  Slot 0 is always the
                        identity view installed at launch.

        Raises:
            ValueError:  if eptp_index is out of range.
            IpcError:    if the hypervisor rejects the call.
        """
        if not (0 <= eptp_index <= 511):
            raise ValueError(f"eptp_index must be 0-511, got {eptp_index}")
        result = self._call(HV_IPC_EPT_SWITCH_VIEW, arg0=eptp_index)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_EPT_SWITCH_VIEW, result)

    # ------------------------------------------------------------------
    # Performance counters
    # ------------------------------------------------------------------

    def get_perf_counters(self) -> int:
        """
        Issue HV_IPC_GET_PERF (0x03).

        Returns:
            MperfOffset — accumulated MPERF ticks consumed by VM-exit handlers
            on the calling core since boot.  Zero until the guest first reads
            IA32_MPERF (which arms AperMperfActive in the driver).
        """
        return self._call(HV_IPC_GET_PERF)

    # ------------------------------------------------------------------
    # EPT policy
    # ------------------------------------------------------------------

    def set_ept_policy(self, gpa: int, policy: int) -> None:
        """
        Set EPT leaf permissions for a 4KB page (HV_IPC_SET_EPT_POLICY).

        Args:
            gpa:    4KB-aligned guest physical address.
            policy: Bitwise OR of EPT_READ / EPT_WRITE / EPT_EXEC /
                    EPT_EXEC_USER.  Pass 0 to trap all accesses.

        Raises:
            ValueError: if gpa is not 4KB-aligned or policy has invalid bits.
            IpcError:   if the hypervisor rejects the call.
        """
        if gpa & 0xFFF:
            raise ValueError(f"GPA 0x{gpa:X} is not 4KB-aligned")
        if policy & ~_VALID_POLICY:
            raise ValueError(f"policy 0x{policy:X} contains invalid bits")
        result = self._call(HV_IPC_SET_EPT_POLICY, arg0=gpa, arg1=policy)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_SET_EPT_POLICY, result)

    # ------------------------------------------------------------------
    # LSTAR lock
    # ------------------------------------------------------------------

    def lock_lstar(self) -> None:
        """
        Lock IA32_LSTAR against future guest WRMSR writes (HV_IPC_LOCK_LSTAR).

        After this call any guest attempt to overwrite the syscall entry point
        causes a #GP(0).  The lock persists until the driver is unloaded.
        """
        result = self._call(HV_IPC_LOCK_LSTAR)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_LOCK_LSTAR, result)

    # ------------------------------------------------------------------
    # Write-protection
    # ------------------------------------------------------------------

    def wp_register(self, gpa: int) -> None:
        """
        Add a GPA to the hypervisor's write-protection table (HV_IPC_WP_REGISTER).

        Any subsequent guest write to this 4KB page injects #GP(0) instead of
        being passed through.  The table holds up to WP_TABLE_SIZE (256) entries.

        Args:
            gpa: 4KB-aligned guest physical address.

        Raises:
            ValueError: if gpa is not 4KB-aligned.
            IpcError:   if the table is full (HV_STATUS_NOT_SUPPORTED).
        """
        if gpa & 0xFFF:
            raise ValueError(f"GPA 0x{gpa:X} is not 4KB-aligned")
        result = self._call(HV_IPC_WP_REGISTER, arg0=gpa)
        if result != HV_STATUS_SUCCESS:
            raise IpcError(HV_IPC_WP_REGISTER, result)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """
        Signal all P-core hypervisor instances to vmxoff and tear down
        (HV_IPC_TEARDOWN).  The driver remains loaded; the hypervisor is gone.
        This is a one-way call — no result is meaningful after teardown.
        """
        self._call(HV_IPC_TEARDOWN)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._iface.close()

    def __enter__(self) -> "HVIpc":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------------
# CLI smoke-test — run directly to verify the full IPC path end-to-end.
#
#   python hv_ipc.py
#
# Expected output on a live hypervisor:
#   [*] dayzdriv EPT-IPC smoke test
#   [+] VERSION_CHECK  result=0x0001  OK (ABI v1)
#   [+] All checks passed.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("[*] dayzdriv EPT-IPC smoke test")
    print(f"    device : {r'\\.\DayZHV'}")
    print(f"    IPC GPA: 0xFEED0000")
    print()

    try:
        hv = HVIpc()
    except HVError as e:
        print(f"[!] Failed to open device: {e}")
        print("    Is dayzdriv.sys loaded?  Run: sc start dayzdriv")
        sys.exit(1)

    with hv:
        # Step 1 — version check / heartbeat.
        print("    VERSION_CHECK ...", end="  ", flush=True)
        try:
            ver = hv.version_check()
            print(f"result=0x{ver:04X}  OK (ABI v{ver})")
        except IpcVersionMismatch as e:
            print(f"MISMATCH\n[!] {e}")
            sys.exit(1)
        except HVError as e:
            print(f"IOCTL FAILED\n[!] {e}")
            print(
                "    Possible causes:\n"
                "      - Hypervisor not running (check logs/dayzdriv.log)\n"
                "      - IPC page not mapped (MmMapIoSpace failed at driver init)\n"
                "      - EPT hole not punched (VmxInitialize did not run EptMapPage4KB)"
            )
            sys.exit(1)

        print()
        print("[+] All checks passed.")
