# Manual PE Loader Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a kernel-mode manual PE loader in `Loader.c`/`Loader.h` that reads a `.sys` from disk, maps it into non-paged executable pool, applies relocations, resolves ntoskrnl + HAL imports, and calls its entry point.

**Architecture:** Three new files — `Loader.h` (types + prototypes), `Loader.c` (all five phases), and a trivial test payload `tests\payload\Payload.c`. The loader is wired into `Driver.c` via a new IOCTL (`IOCTL_HV_LOAD_MODULE`) so it can be triggered from Python without a reboot. Teardown is called from `DriverUnload` before device cleanup.

**Tech Stack:** WDK 10.0.26100.0, MSVC cl.exe, ntddk.h, no CRT. Build via existing `build_dayz.bat` pipeline.

---

### Task 1: Add Loader.h — types and prototypes

**Files:**
- Create: `Loader.h`
- Modify: `Vmx.h` (add IOCTL code)

**Step 1: Create Loader.h**

```c
// Loader.h
#pragma once
#include <ntddk.h>

#define LOADER_POOL_TAG 'daoL'

typedef struct _MANUAL_MODULE {
    PVOID          Base;
    SIZE_T         Size;
    PMDL           Mdl;           // NULL if POOL_FLAG_EXECUTABLE was sufficient
    PDRIVER_UNLOAD UnloadRoutine; // payload's DriverUnload, or NULL
    DRIVER_OBJECT  FakeDriver;
} MANUAL_MODULE, *PMANUAL_MODULE;

// Load a .sys from disk path (e.g. L"\\??\\C:\\path\\payload.sys").
// Allocates, maps, relocates, resolves imports, calls entry point.
// Caller must call ManualUnload when done.
NTSTATUS ManualLoad(_In_ PCWSTR ImagePath, _Out_ PMANUAL_MODULE* Module);

// Call payload DriverUnload (if any), free MDL and pool.
VOID ManualUnload(_In_ PMANUAL_MODULE Module);

// Internal helpers — exposed for unit testing only.
PVOID FindModuleBase(_In_ PCWSTR Name);
PVOID ResolveExport(_In_ PVOID ModuleBase, _In_ const char* Name);
```

**Step 2: Add IOCTL to Vmx.h**

Add after the existing `IOCTL_HV_READ_MEMORY` line:

```c
#define IOCTL_HV_LOAD_MODULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Input:  null-terminated wchar_t path (e.g. L"\\??\\C:\\payload.sys")
// Output: none
// Status: STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_FOUND,
//         STATUS_ENTRYPOINT_NOT_FOUND, STATUS_INVALID_IMAGE_FORMAT
#define HV_LOAD_PATH_MAX        520  // 260 wchars * 2 bytes
```

**Step 3: Commit**

```
git add Loader.h Vmx.h
git commit -m "feat: add Loader.h types and IOCTL_HV_LOAD_MODULE declaration"
```

---

### Task 2: Implement FindModuleBase and ResolveExport

**Files:**
- Create: `Loader.c`

**Step 1: Create Loader.c with the two helpers**

```c
#include <ntddk.h>
#include "Loader.h"

// Walk PsLoadedModuleList to find a loaded module by name (case-insensitive).
PVOID FindModuleBase(_In_ PCWSTR Name)
{
    extern PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY head = PsLoadedModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY* mod =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (mod->BaseDllName.Buffer &&
            _wcsicmp(mod->BaseDllName.Buffer, Name) == 0)
            return mod->DllBase;
    }
    return NULL;
}

// Walk the PE export directory of a loaded module to find a named export.
// ordinals[i] is a direct index into AddressOfFunctions — do NOT subtract Base.
PVOID ResolveExport(_In_ PVOID ModuleBase, _In_ const char* Name)
{
    UINT8* b = (UINT8*)ModuleBase;
    IMAGE_DOS_HEADER*       dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS*       nt  = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY*   dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(b + dir->VirtualAddress);

    UINT32* nameRvas = (UINT32*)(b + exp->AddressOfNames);
    UINT16* ordinals = (UINT16*)(b + exp->AddressOfNameOrdinals);
    UINT32* funcRvas = (UINT32*)(b + exp->AddressOfFunctions);

    for (UINT32 i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((const char*)(b + nameRvas[i]), Name) == 0)
            return (PVOID)(b + funcRvas[ordinals[i]]);
    }
    return NULL;
}
```

**Step 2: Verify it compiles — add Loader.c to the build**

In `build_dayz.bat`, find the cl.exe invocation and add `Loader.c` to the source list. Confirm no errors on `build_dayz.bat` run (sc start not required yet — compile-only check is fine).

**Step 3: Commit**

```
git add Loader.c build_dayz.bat
git commit -m "feat: implement FindModuleBase + ResolveExport in Loader.c"
```

---

### Task 3: Implement ReadFileToPool — disk read into temp buffer

**Files:**
- Modify: `Loader.c`

**Step 1: Add ReadFileToPool**

```c
// Read entire file at Path into a non-paged pool buffer.
// Caller frees with ExFreePoolWithTag(..., LOADER_POOL_TAG).
static NTSTATUS ReadFileToPool(
    _In_  PCWSTR   Path,
    _Out_ PVOID*   Buffer,
    _Out_ SIZE_T*  Length)
{
    *Buffer = NULL;
    *Length = 0;

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, Path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    HANDLE           hFile  = NULL;
    IO_STATUS_BLOCK  iosb   = {0};
    NTSTATUS status = ZwCreateFile(
        &hFile, GENERIC_READ, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    FILE_STANDARD_INFORMATION fsi = {0};
    status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) { ZwClose(hFile); return status; }

    SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
    PVOID  buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize, LOADER_POOL_TAG);
    if (!buf) { ZwClose(hFile); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER offset = {0};
    status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, buf,
                        (ULONG)fileSize, &offset, NULL);
    ZwClose(hFile);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, LOADER_POOL_TAG);
        return status;
    }

    *Buffer = buf;
    *Length = fileSize;
    return STATUS_SUCCESS;
}
```

**Step 2: Verify compile — build_dayz.bat, compile pass only**

**Step 3: Commit**

```
git add Loader.c
git commit -m "feat: add ReadFileToPool (ZwCreateFile/ZwReadFile into non-paged pool)"
```

---

### Task 4: Implement MapSections

**Files:**
- Modify: `Loader.c`

**Step 1: Add MapSections**

```c
// Validate DOS/NT headers. Returns pointer to NT headers or NULL.
static IMAGE_NT_HEADERS* ValidateHeaders(_In_ PVOID FileBuffer)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)FileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((UINT8*)FileBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;
    return nt;
}

// Allocate SizeOfImage pool, copy headers, map each section by VirtualAddress.
// Returns zero-initialized destination base or NULL on failure.
static PVOID MapSections(
    _In_  PVOID             FileBuffer,
    _In_  IMAGE_NT_HEADERS* Nt,
    _Out_ PMDL*             OutMdl)
{
    *OutMdl = NULL;
    IMAGE_OPTIONAL_HEADER* opt = &Nt->OptionalHeader;

    PVOID base = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_EXECUTABLE,
        opt->SizeOfImage,
        LOADER_POOL_TAG);
    if (!base) return NULL;
    RtlZeroMemory(base, opt->SizeOfImage);

    // Copy PE headers
    RtlCopyMemory(base, FileBuffer, opt->SizeOfHeaders);

    // Map sections
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(Nt);
    for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        RtlCopyMemory(
            (UINT8*)base + sec[i].VirtualAddress,
            (UINT8*)FileBuffer + sec[i].PointerToRawData,
            sec[i].SizeOfRawData);
    }

    return base;
}
```

**Step 2: Verify compile**

**Step 3: Commit**

```
git add Loader.c
git commit -m "feat: add ValidateHeaders + MapSections (section-by-VirtualAddress mapping)"
```

---

### Task 5: Implement ApplyRelocations

**Files:**
- Modify: `Loader.c`

**Step 1: Add ApplyRelocations**

```c
static NTSTATUS ApplyRelocations(
    _In_ PVOID              Base,
    _In_ IMAGE_NT_HEADERS*  Nt)
{
    IMAGE_OPTIONAL_HEADER* opt = &Nt->OptionalHeader;
    UINT64 delta = (UINT64)Base - opt->ImageBase;
    if (delta == 0) return STATUS_SUCCESS;

    IMAGE_DATA_DIRECTORY* dir =
        &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->VirtualAddress == 0) return STATUS_SUCCESS;

    IMAGE_BASE_RELOCATION* block =
        (IMAGE_BASE_RELOCATION*)((UINT8*)Base + dir->VirtualAddress);

    while (block->VirtualAddress != 0 && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        UINT8*  pageBase = (UINT8*)Base + block->VirtualAddress;
        UINT16* entries  = (UINT16*)((UINT8*)block + sizeof(IMAGE_BASE_RELOCATION));
        ULONG   count    =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

        for (ULONG i = 0; i < count; i++) {
            UINT8  type   = entries[i] >> 12;
            UINT16 offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64)
                *(UINT64*)(pageBase + offset) += delta;
            // IMAGE_REL_BASED_ABSOLUTE (0) = padding, skip
        }

        block = (IMAGE_BASE_RELOCATION*)((UINT8*)block + block->SizeOfBlock);
    }

    return STATUS_SUCCESS;
}
```

**Step 2: Verify compile**

**Step 3: Commit**

```
git add Loader.c
git commit -m "feat: add ApplyRelocations (IMAGE_REL_BASED_DIR64 fixup pass)"
```

---

### Task 6: Implement ResolveImports

**Files:**
- Modify: `Loader.c`

**Step 1: Add ResolveImports**

```c
static NTSTATUS ResolveImports(
    _In_ PVOID              Base,
    _In_ IMAGE_NT_HEADERS*  Nt)
{
    PVOID ntos = FindModuleBase(L"ntoskrnl.exe");
    PVOID hal  = FindModuleBase(L"hal.dll");
    if (!ntos) return STATUS_NOT_FOUND;

    IMAGE_DATA_DIRECTORY* dir =
        &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0) return STATUS_SUCCESS;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)((UINT8*)Base + dir->VirtualAddress);

    for (; imp->Name != 0; imp++) {
        const char* dllName = (const char*)((UINT8*)Base + imp->Name);

        PVOID resolveFrom = NULL;
        if (_stricmp(dllName, "ntoskrnl.exe") == 0) resolveFrom = ntos;
        else if (_stricmp(dllName, "hal.dll")  == 0) resolveFrom = hal;
        else {
            HvLog("!!! Loader: unknown import module: %s", dllName);
            return STATUS_NOT_FOUND;
        }

        IMAGE_THUNK_DATA* iat  =
            (IMAGE_THUNK_DATA*)((UINT8*)Base + imp->FirstThunk);
        IMAGE_THUNK_DATA* int_ =
            (IMAGE_THUNK_DATA*)((UINT8*)Base + imp->OriginalFirstThunk);

        for (; int_->u1.AddressOfData != 0; iat++, int_++) {
            PVOID resolved = NULL;

            if (IMAGE_SNAP_BY_ORDINAL64(int_->u1.Ordinal)) {
                UINT8* rb = (UINT8*)resolveFrom;
                IMAGE_DOS_HEADER* rdos = (IMAGE_DOS_HEADER*)rb;
                IMAGE_NT_HEADERS* rnt  = (IMAGE_NT_HEADERS*)(rb + rdos->e_lfanew);
                IMAGE_EXPORT_DIRECTORY* rexp = (IMAGE_EXPORT_DIRECTORY*)(rb +
                    rnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                UINT16  ord    = (UINT16)(int_->u1.Ordinal & 0xFFFF);
                UINT32* rfuncs = (UINT32*)(rb + rexp->AddressOfFunctions);
                resolved = (PVOID)(rb + rfuncs[ord - rexp->Base]);
            } else {
                IMAGE_IMPORT_BY_NAME* ibn =
                    (IMAGE_IMPORT_BY_NAME*)((UINT8*)Base + int_->u1.AddressOfData);
                resolved = ResolveExport(resolveFrom, ibn->Name);
                if (!resolved) {
                    HvLog("!!! Loader: unresolved import: %s!%s", dllName, ibn->Name);
                    return STATUS_ENTRYPOINT_NOT_FOUND;
                }
            }

            iat->u1.Function = (UINT64)resolved;
        }
    }

    return STATUS_SUCCESS;
}
```

**Step 2: Verify compile**

**Step 3: Commit**

```
git add Loader.c
git commit -m "feat: add ResolveImports (ntoskrnl + HAL IAT patching)"
```

---

### Task 7: Implement ManualLoad and ManualUnload

**Files:**
- Modify: `Loader.c`

**Step 1: Add ManualLoad and ManualUnload**

```c
NTSTATUS ManualLoad(_In_ PCWSTR ImagePath, _Out_ PMANUAL_MODULE* OutModule)
{
    *OutModule = NULL;

    PVOID  fileBuf  = NULL;
    SIZE_T fileSize = 0;
    NTSTATUS status = ReadFileToPool(ImagePath, &fileBuf, &fileSize);
    if (!NT_SUCCESS(status)) return status;

    IMAGE_NT_HEADERS* nt = ValidateHeaders(fileBuf);
    if (!nt) {
        ExFreePoolWithTag(fileBuf, LOADER_POOL_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PMDL  mdl  = NULL;
    PVOID base = MapSections(fileBuf, nt, &mdl);
    ExFreePoolWithTag(fileBuf, LOADER_POOL_TAG);  // file buffer no longer needed
    if (!base) return STATUS_INSUFFICIENT_RESOURCES;

    // Re-derive NT headers from mapped image
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    nt = (IMAGE_NT_HEADERS*)((UINT8*)base + dos->e_lfanew);

    status = ApplyRelocations(base, nt);
    if (!NT_SUCCESS(status)) goto fail;

    status = ResolveImports(base, nt);
    if (!NT_SUCCESS(status)) goto fail;

    // Allocate and populate module record
    PMANUAL_MODULE mod = (PMANUAL_MODULE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(MANUAL_MODULE), LOADER_POOL_TAG);
    if (!mod) { status = STATUS_INSUFFICIENT_RESOURCES; goto fail; }
    RtlZeroMemory(mod, sizeof(MANUAL_MODULE));

    mod->Base = base;
    mod->Size = nt->OptionalHeader.SizeOfImage;
    mod->Mdl  = mdl;

    // Fabricate DRIVER_OBJECT
    mod->FakeDriver.DriverSize  = sizeof(DRIVER_OBJECT);
    mod->FakeDriver.DriverStart = base;
    mod->FakeDriver.DriverInit  = (PDRIVER_INITIALIZE)(
        (UINT8*)base + nt->OptionalHeader.AddressOfEntryPoint);
    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\ManualLoad");
    mod->FakeDriver.DriverName = driverName;

    // Call entry point at PASSIVE_LEVEL
    typedef NTSTATUS (*PDRIVER_ENTRY)(PDRIVER_OBJECT, PUNICODE_STRING);
    PDRIVER_ENTRY entry = (PDRIVER_ENTRY)(
        (UINT8*)base + nt->OptionalHeader.AddressOfEntryPoint);
    UNICODE_STRING regPath = {0};

    HvLog("!!! Loader: calling entry point at %p", entry);
    status = entry(&mod->FakeDriver, &regPath);
    HvLog("!!! Loader: entry point returned 0x%X", status);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(mod, LOADER_POOL_TAG);
        goto fail;
    }

    mod->UnloadRoutine = mod->FakeDriver.DriverUnload;
    *OutModule = mod;
    return STATUS_SUCCESS;

fail:
    if (mdl) IoFreeMdl(mdl);
    ExFreePoolWithTag(base, LOADER_POOL_TAG);
    return status;
}

VOID ManualUnload(_In_ PMANUAL_MODULE Module)
{
    if (!Module) return;
    if (Module->UnloadRoutine)
        Module->UnloadRoutine(&Module->FakeDriver);
    if (Module->Mdl)
        IoFreeMdl(Module->Mdl);
    ExFreePoolWithTag(Module->Base, LOADER_POOL_TAG);
    ExFreePoolWithTag(Module, LOADER_POOL_TAG);
}
```

**Step 2: Verify compile**

**Step 3: Commit**

```
git add Loader.c
git commit -m "feat: implement ManualLoad + ManualUnload (full PE loader pipeline)"
```

---

### Task 8: Wire IOCTL_HV_LOAD_MODULE into Driver.c

**Files:**
- Modify: `Driver.c`

**Step 1: Add include and global module handle at top of Driver.c**

After `#include "Vmx.h"` add:

```c
#include "Loader.h"
static PMANUAL_MODULE g_LoadedModule = NULL;
```

**Step 2: Add case to DispatchDeviceControl switch**

After the `IOCTL_HV_READ_MEMORY` case block:

```c
case IOCTL_HV_LOAD_MODULE: {
    SIZE_T inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    if (inputLen < sizeof(WCHAR) || inputLen > HV_LOAD_PATH_MAX) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
    }
    // Ensure null-terminated path
    WCHAR* pathBuf = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
    pathBuf[inputLen / sizeof(WCHAR) - 1] = L'\0';

    if (g_LoadedModule) {
        ManualUnload(g_LoadedModule);
        g_LoadedModule = NULL;
    }

    status = ManualLoad(pathBuf, &g_LoadedModule);
    HvLog("!!! DayZHV: [LOAD] ManualLoad(%S) = 0x%X", pathBuf, status);
    break;
}
```

**Step 3: Call ManualUnload in DriverUnload before VmxTeardown**

In `DriverUnload`, before `DpcLatencyStop()`:

```c
if (g_LoadedModule) {
    ManualUnload(g_LoadedModule);
    g_LoadedModule = NULL;
}
```

**Step 4: Full build + sc start**

Run `build_dayz.bat`. Confirm 0 errors, driver loads, log shows `[ENTRY] DriverEntry returning status=0x0`.

**Step 5: Commit**

```
git add Driver.c
git commit -m "feat: wire IOCTL_HV_LOAD_MODULE into Driver.c dispatch + DriverUnload teardown"
```

---

### Task 9: Build a minimal test payload

**Files:**
- Create: `tests\payload\Payload.c`
- Create: `tests\payload\build_payload.bat`

**Step 1: Create Payload.c**

```c
#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "!!! Payload: DriverEntry called — manual load succeeded\n");
    return STATUS_SUCCESS;
}
```

**Step 2: Create build_payload.bat**

```bat
@echo off
setlocal

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10
set INC=/I "%WDK%\Include\10.0.26100.0\km" /I "%WDK%\Include\10.0.26100.0\shared"
set LIBS="%WDK%\Lib\10.0.26100.0\km\x64\ntoskrnl.lib"

"%MSVC%\cl.exe" /nologo /kernel /GS- /GR- /EHs-c- /Zi /W3 /WX ^
    %INC% /D_AMD64_ /DAMD64 /D_WIN64 ^
    /Fo bin\payload\ /Fd bin\payload\ ^
    tests\payload\Payload.c /link /NODEFAULTLIB /SUBSYSTEM:NATIVE ^
    /DRIVER /ENTRY:DriverEntry /BASE:0x10000 ^
    /OUT:bin\payload\payload.sys %LIBS%

echo Payload build done: bin\payload\payload.sys
```

**Step 3: Build payload**

```
mkdir bin\payload
build_payload.bat
```

Confirm `bin\payload\payload.sys` exists.

**Step 4: Commit**

```
git add tests\payload\Payload.c tests\payload\build_payload.bat
git commit -m "test: add minimal DriverEntry payload for manual loader smoke test"
```

---

### Task 10: Smoke test via Python

**Files:**
- Create: `tests\test_loader.py`

**Step 1: Create test_loader.py**

```python
import ctypes
import ctypes.wintypes as wt

GENERIC_READ    = 0x80000000
OPEN_EXISTING   = 3
FILE_SHARE_READ = 1
INVALID_HANDLE  = ctypes.c_void_p(-1).value

IOCTL_HV_LOAD_MODULE = 0x00222408  # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x902, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)

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
```

**Step 2: Compute correct IOCTL code**

`CTL_CODE(0x22, 0x902, 0, 0)` = `(0x22 << 16) | (0x902 << 2)` = `0x00222408`. Verify against `Vmx.h`.

**Step 3: Run test**

```
python tests\test_loader.py
```

Expected: `DeviceIoControl: ok=1  GetLastError=0x00000000`

Check `logs\dayzdriv.log` for:
```
!!! Loader: calling entry point at 0x...
!!! Loader: entry point returned 0x0
!!! DayZHV: [LOAD] ManualLoad(\\??\F:\...\payload.sys) = 0x0
```

Check kernel debugger / DbgView for:
```
!!! Payload: DriverEntry called — manual load succeeded
```

**Step 4: Commit**

```
git add tests\test_loader.py
git commit -m "test: add Python smoke test for IOCTL_HV_LOAD_MODULE"
```

---

## Summary

| Task | What it adds |
|---|---|
| 1 | `Loader.h` types + IOCTL declaration |
| 2 | `FindModuleBase` + `ResolveExport` |
| 3 | `ReadFileToPool` (disk → pool) |
| 4 | `ValidateHeaders` + `MapSections` |
| 5 | `ApplyRelocations` |
| 6 | `ResolveImports` |
| 7 | `ManualLoad` + `ManualUnload` (full pipeline) |
| 8 | IOCTL dispatch + teardown wiring in `Driver.c` |
| 9 | Minimal test payload `.sys` |
| 10 | Python smoke test |
