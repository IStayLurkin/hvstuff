from hv_constants import IOCTL_HV_READ_MEMORY, HV_READ_MAX_LENGTH

def test_ioctl_read_memory_value():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x901, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    # = (0x22 << 16) | (0x901 << 2) | 0 | 0 = 0x00222404
    assert IOCTL_HV_READ_MEMORY == 0x00222404

def test_hv_read_max_length():
    assert HV_READ_MAX_LENGTH == 65536
