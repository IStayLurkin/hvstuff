from __future__ import annotations

DEVICE_PATH           = r"\\.\DayZHV"
IOCTL_HV_SCAN_PATTERN = 0x00222400  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
PATTERN_BUFFER_SIZE   = 256         # must match driver-side MAX_PATTERN_LEN
IOCTL_HV_READ_MEMORY  = 0x00222404  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
HV_READ_MAX_LENGTH    = 65536       # driver enforces this ceiling (64 KB)
IOCTL_HV_IPC_CALL     = 0x00222408  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

# EPT-violation IPC call identifiers — mirror HV_IPC_* in Vmx.h.
HV_IPC_VERSION_CHECK  = 0x00  # heartbeat; returns HV_IPC_VERSION in result
HV_IPC_MTF_TOGGLE     = 0x01  # arg0: 1=arm, 0=disarm Monitor Trap Flag
HV_IPC_EPT_SWITCH_VIEW= 0x02  # arg0: EPTP list index (0-511)
HV_IPC_GET_PERF       = 0x03  # returns MperfOffset
HV_IPC_SET_EPT_POLICY = 0x05  # arg0: GPA, arg1: EPT permission bits
HV_IPC_LOCK_LSTAR     = 0x06  # lock IA32_LSTAR against guest writes
HV_IPC_WP_REGISTER    = 0x07  # arg0: GPA to write-protect
HV_IPC_TEARDOWN       = 0xFF  # clean hypervisor teardown

HV_IPC_VERSION        = 0x0001  # ABI version token returned by VERSION_CHECK

# HV_STATUS codes (returned in HV_IPC_RESPONSE.Result for error cases).
HV_STATUS_SUCCESS       = 0x00
HV_STATUS_INVALID_CALL  = 0x01
HV_STATUS_NOT_SUPPORTED = 0x02
HV_STATUS_BAD_ALIGNMENT = 0x03
