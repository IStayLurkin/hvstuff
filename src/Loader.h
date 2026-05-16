// Loader.h
#pragma once
#include <ntddk.h>

#define LOADER_POOL_TAG 'daoL'

typedef struct _MANUAL_MODULE {
    PVOID          Base;
    SIZE_T         Size;
    PMDL           Mdl;           // NULL for pool-allocated images (POOL_FLAG_NON_PAGED_EXECUTE)
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
// Caller must hold PsLoadedModuleResource shared (via ExAcquireResourceSharedLite).
PVOID FindModuleBase(_In_ PCWSTR Name);
PVOID ResolveExport(_In_ PVOID ModuleBase, _In_ const char* Name);
