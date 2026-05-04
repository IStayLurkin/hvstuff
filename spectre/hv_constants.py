from __future__ import annotations

DEVICE_PATH           = r"\\.\DayZHV"
IOCTL_HV_SCAN_PATTERN = 0x00222400  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
PATTERN_BUFFER_SIZE   = 256         # must match driver-side MAX_PATTERN_LEN
