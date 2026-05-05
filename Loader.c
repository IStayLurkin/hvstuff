#include <ntddk.h>
#include <ntimage.h>
#include "Loader.h"
#include "Vmx.h"

// Minimal LDR_DATA_TABLE_ENTRY — only the fields we need.
// The full structure is undocumented; these first three fields are stable
// across all x64 Windows versions since Vista.
typedef struct _LDR_DATA_TABLE_ENTRY_MIN {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_MIN, *PLDR_DATA_TABLE_ENTRY_MIN;

// Walk PsLoadedModuleList to find a loaded module by name (case-insensitive).
PVOID FindModuleBase(_In_ PCWSTR Name)
{
    extern PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY head = PsLoadedModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY_MIN mod =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY_MIN, InLoadOrderLinks);
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
    // Reject empty files and files too large for a single ZwReadFile call (ULONG limit).
    if (fileSize == 0 || fileSize > (SIZE_T)MAXULONG) {
        ZwClose(hFile);
        return STATUS_FILE_TOO_LARGE;
    }

    PVOID  buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize, LOADER_POOL_TAG);
    if (!buf) { ZwClose(hFile); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER offset = {0};
    iosb = (IO_STATUS_BLOCK){0};
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

// Validate DOS/NT headers. Returns pointer to NT headers or NULL.
static IMAGE_NT_HEADERS* ValidateHeaders(_In_ PVOID FileBuffer, _In_ SIZE_T FileSize)
{
    if (FileSize < sizeof(IMAGE_DOS_HEADER)) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)FileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > FileSize) return NULL;
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
        POOL_FLAG_NON_PAGED_EXECUTE,
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
    UINT8* relocEnd = (UINT8*)Base + dir->VirtualAddress + dir->Size;

    while ((UINT8*)block + sizeof(IMAGE_BASE_RELOCATION) <= relocEnd &&
           block->VirtualAddress != 0 &&
           block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        if ((ULONG64)block->VirtualAddress >= (ULONG64)Nt->OptionalHeader.SizeOfImage)
            break;
        UINT8*  pageBase = (UINT8*)Base + block->VirtualAddress;
        UINT16* entries  = (UINT16*)((UINT8*)block + sizeof(IMAGE_BASE_RELOCATION));
        ULONG   count    =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

        for (ULONG i = 0; i < count; i++) {
            UINT8  type   = entries[i] >> 12;
            UINT16 offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                if ((ULONG64)block->VirtualAddress + offset + sizeof(UINT64) > (ULONG64)Nt->OptionalHeader.SizeOfImage)
                    continue;
                *(UINT64*)(pageBase + offset) += delta;
            }
            // IMAGE_REL_BASED_ABSOLUTE (0) = padding, skip
        }

        block = (IMAGE_BASE_RELOCATION*)((UINT8*)block + block->SizeOfBlock);
    }

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// ResolveImports
// Walk the import directory of the mapped image and patch the IAT.
// Only ntoskrnl.exe and hal.dll are supported; any other DLL causes a hard
// failure with STATUS_NOT_FOUND.
// Must be called at PASSIVE_LEVEL (ExAcquireResourceSharedLite requirement).
// ---------------------------------------------------------------------------
static NTSTATUS ResolveImports(
    _In_ PVOID              Base,
    _In_ IMAGE_NT_HEADERS*  Nt)
{
    // Lock PsLoadedModuleList for shared access while querying module bases.
    extern ERESOURCE PsLoadedModuleResource;
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, TRUE);
    PVOID ntos = FindModuleBase(L"ntoskrnl.exe");
    PVOID hal  = FindModuleBase(L"hal.dll");
    ExReleaseResourceLite(&PsLoadedModuleResource);
    KeLeaveCriticalRegion();

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

        if (!resolveFrom) {
            HvLog("!!! Loader: module base not found for %s", dllName);
            return STATUS_NOT_FOUND;
        }

        IMAGE_THUNK_DATA* iat  =
            (IMAGE_THUNK_DATA*)((UINT8*)Base + imp->FirstThunk);
        IMAGE_THUNK_DATA* int_ =
            imp->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA*)((UINT8*)Base + imp->OriginalFirstThunk)
                : iat;

        for (; int_->u1.AddressOfData != 0; iat++, int_++) {
            PVOID resolved = NULL;

            if (IMAGE_SNAP_BY_ORDINAL64(int_->u1.Ordinal)) {
                // Ordinal-based import: index directly into AddressOfFunctions,
                // adjusting for the export base ordinal.
                UINT8* rb = (UINT8*)resolveFrom;
                IMAGE_DOS_HEADER* rdos = (IMAGE_DOS_HEADER*)rb;
                IMAGE_NT_HEADERS* rnt  = (IMAGE_NT_HEADERS*)(rb + rdos->e_lfanew);
                IMAGE_EXPORT_DIRECTORY* rexp = (IMAGE_EXPORT_DIRECTORY*)(rb +
                    rnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                UINT16  ord    = (UINT16)(int_->u1.Ordinal & 0xFFFF);
                UINT32* rfuncs = (UINT32*)(rb + rexp->AddressOfFunctions);
                if (ord < rexp->Base || (UINT32)(ord - rexp->Base) >= rexp->NumberOfFunctions) {
                    HvLog("!!! Loader: ordinal %u out of range for %s", (UINT32)ord, dllName);
                    return STATUS_ENTRYPOINT_NOT_FOUND;
                }
                UINT32 idx = (UINT32)(ord - rexp->Base);
                resolved = (PVOID)(rb + rfuncs[idx]);
            } else {
                // Name-based import: look up via export name table.
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

// ---------------------------------------------------------------------------
// ManualLoad
// Full PE loader pipeline: read file → validate → map sections → relocate →
// resolve imports → call entry point.  On success writes *OutModule which the
// caller must eventually pass to ManualUnload.
// ---------------------------------------------------------------------------
NTSTATUS ManualLoad(_In_ PCWSTR ImagePath, _Out_ PMANUAL_MODULE* OutModule)
{
    *OutModule = NULL;

    // Phase 1: Read the on-disk image into a temporary non-paged buffer.
    PVOID  fileBuf  = NULL;
    SIZE_T fileSize = 0;
    NTSTATUS status = ReadFileToPool(ImagePath, &fileBuf, &fileSize);
    if (!NT_SUCCESS(status)) return status;

    // Phase 2: Validate PE headers before doing any mapping.
    IMAGE_NT_HEADERS* nt = ValidateHeaders(fileBuf, fileSize);
    if (!nt) {
        ExFreePoolWithTag(fileBuf, LOADER_POOL_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Phase 3: Allocate executable pool and copy sections.
    // After MapSections the file buffer is no longer needed.
    PMDL  mdl  = NULL;
    PVOID base = MapSections(fileBuf, nt, &mdl);
    ExFreePoolWithTag(fileBuf, LOADER_POOL_TAG);
    fileBuf = NULL;
    if (!base) return STATUS_INSUFFICIENT_RESOURCES;

    // Re-derive NT headers from the mapped image (file buffer is gone).
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    nt = (IMAGE_NT_HEADERS*)((UINT8*)base + dos->e_lfanew);

    // Phase 4: Apply base relocations.
    status = ApplyRelocations(base, nt);
    if (!NT_SUCCESS(status)) goto fail_base;

    // Phase 5: Patch the import address table.
    status = ResolveImports(base, nt);
    if (!NT_SUCCESS(status)) goto fail_base;

    // Allocate the module descriptor from non-paged pool so it outlives
    // the IOCTL call.
    PMANUAL_MODULE mod = (PMANUAL_MODULE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(MANUAL_MODULE), LOADER_POOL_TAG);
    if (!mod) { status = STATUS_INSUFFICIENT_RESOURCES; goto fail_base; }
    RtlZeroMemory(mod, sizeof(MANUAL_MODULE));

    mod->Base = base;
    mod->Size = nt->OptionalHeader.SizeOfImage;
    mod->Mdl  = mdl;

    // Fabricate a minimal DRIVER_OBJECT.  This struct is embedded by value in
    // MANUAL_MODULE and must NEVER be passed to IoCreateDevice, Object Manager,
    // or any other PatchGuard-visible API — it is only passed to the payload's
    // own DriverEntry / DriverUnload which are code we control.
    mod->FakeDriver.DriverSize  = sizeof(DRIVER_OBJECT);
    mod->FakeDriver.DriverStart = base;
    mod->FakeDriver.DriverInit  = (PDRIVER_INITIALIZE)(
        (UINT8*)base + nt->OptionalHeader.AddressOfEntryPoint);
    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\ManualLoad");
    mod->FakeDriver.DriverName = driverName;

    // Phase 6: Call the payload entry point at PASSIVE_LEVEL.
    typedef NTSTATUS (*PDRIVER_ENTRY)(PDRIVER_OBJECT, PUNICODE_STRING);
    PDRIVER_ENTRY entry = (PDRIVER_ENTRY)(
        (UINT8*)base + nt->OptionalHeader.AddressOfEntryPoint);
    UNICODE_STRING regPath = {0};

    HvLog("!!! Loader: calling entry point at %p", entry);
    status = entry(&mod->FakeDriver, &regPath);
    HvLog("!!! Loader: entry point returned 0x%X", status);

    if (!NT_SUCCESS(status)) {
        // Entry point failed — free the module descriptor; fall through to
        // fail_base to free the mapped image as well.
        ExFreePoolWithTag(mod, LOADER_POOL_TAG);
        goto fail_base;
    }

    // Capture any DriverUnload the payload registered.
    mod->UnloadRoutine = mod->FakeDriver.DriverUnload;
    *OutModule = mod;
    return STATUS_SUCCESS;

fail_base:
    if (mdl) IoFreeMdl(mdl);
    ExFreePoolWithTag(base, LOADER_POOL_TAG);
    return status;
}

// ---------------------------------------------------------------------------
// ManualUnload
// Call the payload's DriverUnload (if any), then release all resources.
// Safe to call with a NULL Module pointer.
// ---------------------------------------------------------------------------
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
