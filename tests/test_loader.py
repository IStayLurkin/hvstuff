import ctypes
import ctypes.wintypes as wt

GENERIC_READ    = 0x80000000
OPEN_EXISTING   = 3
FILE_SHARE_READ = 1
INVALID_HANDLE  = ctypes.c_void_p(-1).value

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x902, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
# = (0x22 << 16) | (0x902 << 2) = 0x00222408
IOCTL_HV_LOAD_MODULE = 0x00222408

def open_device():
    h = ctypes.windll.kernel32.CreateFileW(
        r"\\.\DayZLink", GENERIC_READ, FILE_SHARE_READ,
        None, OPEN_EXISTING, 0, None)
    assert h != INVALID_HANDLE, f"CreateFile failed: {ctypes.GetLastError()}"
    return h

def load_module(h, path: str):
    buf = ctypes.create_unicode_buffer(path)
    out = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.DeviceIoControl(
        h, IOCTL_HV_LOAD_MODULE,
        buf, len(buf) * 2,
        None, 0,
        ctypes.byref(out), None)
    err = ctypes.GetLastError()
    return ok, err

if __name__ == "__main__":
    payload_path = r"\\??\F:\vsprojs\dayzdriv\bin\payload\payload.sys"
    h = open_device()
    ok, err = load_module(h, payload_path)
    print(f"DeviceIoControl: ok={ok}  GetLastError={err:#010x}")
    ctypes.windll.kernel32.CloseHandle(h)
