# Manual PE Loader — Design Document

**Date:** 2026-05-04  
**Context:** Kernel-mode manual loader for modular `.sys` extensions in dayzdriv/hvstuff.  
**Scope:** Ring-0 loader running inside an existing driver. Loads another `.sys` from disk into non-paged executable pool. No PsLoadedModuleList entry. Imports limited to ntoskrnl.exe and hal.dll.

---

## Constraints

- **HVCI incompatibility:** If HVCI (Hypervisor-Protected Code Integrity) is active, arbitrary executable pool allocation is blocked at the EPT/SLAT level. No MDL workaround recovers from this. Detect early and fail with `STATUS_ACCESS_DENIED` rather than silently loading non-executable code. On dayzdriv (VMX resident), EPT execute permission could theoretically be granted manually — out of scope for this loader.
- **IRQL:** All loader phases run at `PASSIVE_LEVEL`. Entry point invocation must also be at `PASSIVE_LEVEL` — the payload may call `IoCreateDevice`, register callbacks, or touch pageable memory.
- **x86-64 instruction cache coherence:** No software cache flush required after writing code pages. The x64 architecture guarantees coherent instruction fetches across all logical processors (P-cores and E-cores included) for fresh page writes.

---

## Pipeline

```
1. Allocate + Copy     ZwCreateFile/ZwReadFile → temp buffer; ExAllocatePool2(SizeOfImage) → dest
2. Map Sections        copy headers + each section by VirtualAddress into dest
3. Relocate            walk IMAGE_BASE_RELOCATION, apply delta to every DIR64 fixup
4. Resolve Imports     walk IMAGE_IMPORT_DESCRIPTOR, patch IAT against ntoskrnl + HAL export dirs
5. [Set Executable]    MmProtectMdlSystemAddress if not already executable
6. Invoke Entry Point  call AddressOfEntryPoint at PASSIVE_LEVEL with fabricated DRIVER_OBJECT
7. Store Handle        keep MANUAL_MODULE for teardown
```

---

## Phase 1: Allocation and Section Mapping

```c
// Allocate destination — zero-initialized (handles BSS)
PVOID base = ExAllocatePool2(
    POOL_FLAG_NON_PAGED | POOL_FLAG_EXECUTABLE,
    optionalHeader->SizeOfImage,
    'daoL');
if (!base) return STATUS_INSUFFICIENT_RESOURCES;
RtlZeroMemory(base, optionalHeader->SizeOfImage);

// Copy headers
RtlCopyMemory(base, fileBuffer, optionalHeader->SizeOfHeaders);

// Map each section
IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    if (sections[i].SizeOfRawData == 0) continue;
    RtlCopyMemory(
        (UINT8*)base + sections[i].VirtualAddress,
        (UINT8*)fileBuffer + sections[i].PointerToRawData,
        sections[i].SizeOfRawData);
}
```

**Invariants:**
- Destination size is `SizeOfImage` (virtual layout), not file size.
- Zero-init before section copy ensures `VirtualSize > SizeOfRawData` gaps (BSS) are zeroed.
- Source (file buffer) and destination never alias — safe to copy section by section.

---

## Phase 2: Relocation

```c
UINT64 delta = (UINT64)base - optionalHeader->ImageBase;
if (delta == 0) goto skip_reloc;

IMAGE_DATA_DIRECTORY* relocDir =
    &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
IMAGE_BASE_RELOCATION* block =
    (IMAGE_BASE_RELOCATION*)((UINT8*)base + relocDir->VirtualAddress);

while (block->VirtualAddress != 0 && block->SizeOfBlock != 0) {
    UINT8*  pageBase = (UINT8*)base + block->VirtualAddress;
    UINT16* entries  = (UINT16*)((UINT8*)block + sizeof(IMAGE_BASE_RELOCATION));
    ULONG   count    = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

    for (ULONG i = 0; i < count; i++) {
        UINT8  type   = entries[i] >> 12;
        UINT16 offset = entries[i] & 0x0FFF;

        if (type == IMAGE_REL_BASED_DIR64) {       // 0xA — only type in x64 images
            *(UINT64*)(pageBase + offset) += delta;
        }
        // IMAGE_REL_BASED_ABSOLUTE (0) is padding — skip silently
    }

    block = (IMAGE_BASE_RELOCATION*)((UINT8*)block + block->SizeOfBlock);
}
skip_reloc:;
```

**Invariants:**
- `delta` is the difference between actual load address and the linker's preferred `ImageBase`.
- Each block's `VirtualAddress` is page-aligned; the 12-bit `offset` within each entry is always `<= 0xFFF` — never crosses page boundary.
- Each patched slot contains an absolute VA baked at link time using `ImageBase`; adding `delta` adjusts it to the actual allocation.
- `SizeOfBlock` includes the 8-byte block header — subtract before dividing to get entry count.
- `SizeOfBlock` is always a multiple of 4 (entries are 2 bytes, padded with `ABSOLUTE` entries to maintain alignment). Advancing by `SizeOfBlock` bytes is always correct.

---

## Phase 3: Import Resolution

### 3a. Find module bases via PsLoadedModuleList

```c
extern PLIST_ENTRY PsLoadedModuleList;

PVOID FindModuleBase(PCWSTR name) {
    PLIST_ENTRY head = PsLoadedModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY* mod =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (_wcsicmp(mod->BaseDllName.Buffer, name) == 0)
            return mod->DllBase;
    }
    return NULL;
}

PVOID ntos = FindModuleBase(L"ntoskrnl.exe");
PVOID hal  = FindModuleBase(L"hal.dll");
```

### 3b. Export resolver (GetProcAddress equivalent)

```c
PVOID ResolveExport(PVOID moduleBase, const char* name) {
    UINT8* b = (UINT8*)moduleBase;
    IMAGE_DOS_HEADER*       dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS*       nt  = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY*   dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(b + dir->VirtualAddress);

    UINT32* nameRvas = (UINT32*)(b + exp->AddressOfNames);
    UINT16* ordinals = (UINT16*)(b + exp->AddressOfNameOrdinals);
    UINT32* funcRvas = (UINT32*)(b + exp->AddressOfFunctions);

    for (UINT32 i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((const char*)(b + nameRvas[i]), name) == 0) {
            return (PVOID)(b + funcRvas[ordinals[i]]);
            // ordinals[i] is a direct index into funcRvas — do NOT subtract exp->Base
        }
    }
    return NULL;
}
```

**Critical:** `ordinals[i]` indexes directly into `AddressOfFunctions`. Do **not** subtract `exp->Base` — that adjustment applies only when resolving by ordinal number, not by the name→ordinal→function indirection used here.

### 3c. Walk IMAGE_IMPORT_DESCRIPTOR and patch IAT

```c
IMAGE_DATA_DIRECTORY* impDir =
    &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
IMAGE_IMPORT_DESCRIPTOR* imp =
    (IMAGE_IMPORT_DESCRIPTOR*)((UINT8*)base + impDir->VirtualAddress);

for (; imp->Name != 0; imp++) {
    const char* dllName = (const char*)((UINT8*)base + imp->Name);

    PVOID resolveFrom = NULL;
    if (_stricmp(dllName, "ntoskrnl.exe") == 0) resolveFrom = ntos;
    else if (_stricmp(dllName, "hal.dll")  == 0) resolveFrom = hal;
    else return STATUS_NOT_FOUND;  // unknown module — hard fail

    IMAGE_THUNK_DATA* iat  = (IMAGE_THUNK_DATA*)((UINT8*)base + imp->FirstThunk);
    IMAGE_THUNK_DATA* int_ = (IMAGE_THUNK_DATA*)((UINT8*)base + imp->OriginalFirstThunk);

    for (; int_->u1.AddressOfData != 0; iat++, int_++) {
        PVOID resolved = NULL;

        if (IMAGE_SNAP_BY_ORDINAL64(int_->u1.Ordinal)) {
            // Ordinal import
            UINT8* rb = (UINT8*)resolveFrom;
            IMAGE_DOS_HEADER* rdos = (IMAGE_DOS_HEADER*)rb;
            IMAGE_NT_HEADERS* rnt  = (IMAGE_NT_HEADERS*)(rb + rdos->e_lfanew);
            IMAGE_EXPORT_DIRECTORY* rexp = (IMAGE_EXPORT_DIRECTORY*)(rb +
                rnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            UINT16 ord = (UINT16)(int_->u1.Ordinal & 0xFFFF);
            UINT32* rfuncs = (UINT32*)(rb + rexp->AddressOfFunctions);
            resolved = (PVOID)(rb + rfuncs[ord - rexp->Base]);
        } else {
            IMAGE_IMPORT_BY_NAME* ibn =
                (IMAGE_IMPORT_BY_NAME*)((UINT8*)base + int_->u1.AddressOfData);
            resolved = ResolveExport(resolveFrom, ibn->Name);
        }

        if (!resolved) return STATUS_ENTRYPOINT_NOT_FOUND;
        iat->u1.Function = (UINT64)resolved;
    }
}
```

**Invariants:**
- Walk `OriginalFirstThunk` (INT) for names/ordinals; write resolved addresses into `FirstThunk` (IAT).
- Use `IMAGE_SNAP_BY_ORDINAL64` (tests bit 63) — not the 32-bit variant.
- IAT slots are in your writable pool allocation — no page protection change needed at this stage.

---

## Phase 4: Entry Point Invocation

```c
// Optional: make pages executable via MDL if ExAllocatePool2 POOL_FLAG_EXECUTABLE insufficient
// Skip entirely if HVCI is active — will fail silently or fault.
PMDL mdl = IoAllocateMdl(base, (ULONG)optionalHeader->SizeOfImage, FALSE, FALSE, NULL);
MmBuildMdlForNonPagedPool(mdl);
MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);

// Fabricate DRIVER_OBJECT
DRIVER_OBJECT fakeDriver  = {0};
fakeDriver.DriverSize     = sizeof(DRIVER_OBJECT);
fakeDriver.DriverStart    = base;
fakeDriver.DriverInit     = (PDRIVER_INITIALIZE)(
    (UINT8*)base + optionalHeader->AddressOfEntryPoint);
UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\ManualLoad");
fakeDriver.DriverName     = driverName;

// Call entry point at PASSIVE_LEVEL
typedef NTSTATUS (*PDRIVER_ENTRY)(PDRIVER_OBJECT, PUNICODE_STRING);
PDRIVER_ENTRY entry = (PDRIVER_ENTRY)(
    (UINT8*)base + optionalHeader->AddressOfEntryPoint);

UNICODE_STRING regPath = {0};
NTSTATUS status = entry(&fakeDriver, &regPath);
```

**Note:** Inspect the payload's `DriverEntry` before deciding whether to pass `&fakeDriver` or `NULL`. Payloads that call `IoCreateDevice` need a non-NULL `DriverObject`. Payloads that only register callbacks may tolerate `NULL`.

---

## Phase 5: Teardown

```c
typedef struct _MANUAL_MODULE {
    PVOID           Base;
    SIZE_T          Size;
    PMDL            Mdl;            // NULL if MDL path not used
    PDRIVER_UNLOAD  UnloadRoutine;  // fakeDriver.DriverUnload if payload set it
    DRIVER_OBJECT   FakeDriver;
} MANUAL_MODULE;

void ManualUnload(MANUAL_MODULE* mod) {
    if (mod->UnloadRoutine)
        mod->UnloadRoutine(&mod->FakeDriver);
    if (mod->Mdl) {
        IoFreeMdl(mod->Mdl);
    }
    ExFreePoolWithTag(mod->Base, 'daoL');
}
```

Call `ManualUnload` from the outer driver's `DriverUnload` before device cleanup — same ordering as dayzdriv's existing `VmxTeardown` call.

---

## Summary Table

| Phase | Key invariant |
|---|---|
| Allocation | Size = `SizeOfImage`, zero-init before section copy |
| Section map | Copy by `VirtualAddress`/`PointerToRawData`, not flat file copy |
| Relocation | `delta = allocBase - ImageBase`; only patch `IMAGE_REL_BASED_DIR64` (0xA) entries |
| Export resolve | `ordinals[i]` is a direct funcRvas index — do not subtract `exp->Base` |
| Import walk | Write to FirstThunk (IAT); read from OriginalFirstThunk (INT) |
| Entry point | Must be called at `PASSIVE_LEVEL` |
| Teardown | Loader owns the allocation — nothing frees it automatically |
