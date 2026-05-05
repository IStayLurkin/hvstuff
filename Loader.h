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
