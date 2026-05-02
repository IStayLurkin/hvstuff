#include <ntddk.h>
#include "Vmx.h"

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    HvLog("!!! DayZHV: [UNLOAD] DriverUnload entered.  IRQL=%u", (ULONG)KeGetCurrentIrql());

    // Tear down the resident hypervisor on all cores before freeing resources.
    VmxTeardown();

    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DayZLink");
    IoDeleteSymbolicLink(&symName);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
    HvLog("!!! DayZHV: [UNLOAD] Driver unloaded cleanly.  IRQL=%u", (ULONG)KeGetCurrentIrql());
    HvLogClose();
}

static NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DayZHV");
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DayZLink");
    PDEVICE_OBJECT devObj  = NULL;

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        // Stale \Device\DayZHV from a prior failed load — open it by name,
        // delete it, then retry. IoGetDeviceObjectPointer gives us the pointer.
        FILE_OBJECT   *fileObj  = NULL;
        DEVICE_OBJECT *staleDev = NULL;
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&devName, FILE_READ_DATA,
                                                &fileObj, &staleDev))) {
            // fileObj is a reference on the file object; release it first.
            // The device object itself stays alive until we delete it.
            ObDereferenceObject(fileObj);
            IoDeleteSymbolicLink(&symName);
            IoDeleteDevice(staleDev);
        }
        status = IoCreateDevice(DriverObject, 0, &devName,
                                FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    }
    if (!NT_SUCCESS(status)) {
        HvLogOpen();
        HvLog("!!! DayZHV: [FAIL] IoCreateDevice status=0x%X", status);
        HvLogClose();
        return status;
    }

    IoCreateSymbolicLink(&symName, &devName);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = CreateClose;
    DriverObject->DriverUnload                  = DriverUnload;

    // VmxInitialize opens the log internally and keeps it open on success.
    status = VmxInitialize();

    HvLog("!!! DayZHV: [ENTRY] DriverEntry returning status=0x%X  IRQL=%u",
          status, (ULONG)KeGetCurrentIrql());

    if (!NT_SUCCESS(status)) {
        HvLogClose();
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj);
    }
    // On success: log stays open, VM is running, DriverEntry returns STATUS_SUCCESS.

    return status;
}
