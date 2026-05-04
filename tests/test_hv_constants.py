import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spectre'))
from hv_constants import IOCTL_HV_READ_MEMORY

def test_ioctl_read_memory_value():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x901, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    # = (0x22 << 16) | (0x901 << 2) | 0 | 0 = 0x00222404
    assert IOCTL_HV_READ_MEMORY == 0x00222404
