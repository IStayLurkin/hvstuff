#include <ntddk.h>
#include "Vmx.h"

// ---------------------------------------------------------------------------
// DPC latency harness
// Fires a DPC every 10 ms and measures how far off schedule it arrives.
// Tracks the running worst-case jitter and logs every 1000 firings via HvLog.
// ---------------------------------------------------------------------------
#define DPC_INTERVAL_MS     10
#define DPC_LOG_INTERVAL    1000

static KTIMER   g_DpcTimer;
static KDPC     g_DpcObject;
static ULONG64  g_DpcLastFire   = 0;   // interrupt-time units (100 ns) of last fire
static ULONG64  g_DpcMaxJitter  = 0;   // peak absolute jitter in 100-ns units
static ULONG64  g_DpcFireCount  = 0;
static BOOLEAN  g_DpcRunning    = FALSE;

static void DpcCallback(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ULONG64 now = KeQueryInterruptTime();  // 100-ns units, monotonic

    if (g_DpcLastFire != 0) {
        ULONG64 expected = g_DpcLastFire + (ULONG64)DPC_INTERVAL_MS * 10000ULL;
        ULONG64 jitter   = (now > expected) ? (now - expected) : (expected - now);
        if (jitter > g_DpcMaxJitter)
            g_DpcMaxJitter = jitter;
    }
    g_DpcLastFire = now;
    g_DpcFireCount++;

    if (g_DpcFireCount % DPC_LOG_INTERVAL == 0) {
        // Jitter in microseconds (100-ns units / 10).
        HvLog("!!! DayZHV: [DPC] fires=%llu  peak_jitter=%llu us",
              g_DpcFireCount, g_DpcMaxJitter / 10);
    }

    // Re-arm for the next interval.
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)DPC_INTERVAL_MS * 10000LL;  // relative, 100-ns units
    KeSetTimer(&g_DpcTimer, due, &g_DpcObject);
}

void DpcLatencyStart(void)
{
    if (g_DpcRunning) return;
    g_DpcFireCount = 0;
    g_DpcMaxJitter = 0;
    g_DpcLastFire  = 0;
    KeInitializeTimer(&g_DpcTimer);
    KeInitializeDpc(&g_DpcObject, DpcCallback, NULL);
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)DPC_INTERVAL_MS * 10000LL;
    KeSetTimer(&g_DpcTimer, due, &g_DpcObject);
    g_DpcRunning = TRUE;
    HvLog("!!! DayZHV: [DPC] latency harness started (%d ms interval)", DPC_INTERVAL_MS);
}

void DpcLatencyStop(void)
{
    if (!g_DpcRunning) return;
    KeCancelTimer(&g_DpcTimer);
    g_DpcRunning = FALSE;
    HvLog("!!! DayZHV: [DPC] latency harness stopped  fires=%llu  peak_jitter=%llu us",
          g_DpcFireCount, g_DpcMaxJitter / 10);
}

// ---------------------------------------------------------------------------
// IRP_MJ_POWER handler — teardown before S3/S4 sleep, re-launch on resume.
// ---------------------------------------------------------------------------
static NTSTATUS DispatchPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MinorFunction == IRP_MN_SET_POWER &&
        stack->Parameters.Power.Type == SystemPowerState) {

        SYSTEM_POWER_STATE state = stack->Parameters.Power.State.SystemState;

        if (state == PowerSystemWorking) {
            // Resume from S3: re-initialise the hypervisor on all cores.
            HvLog("!!! DayZHV: [POWER] S3 resume — re-launching hypervisor");
            VmxInitialize();
            DpcLatencyStart();
        } else if (state >= PowerSystemSleeping1) {
            // S3/S4/S5 entry: tear down cleanly before firmware takes control.
            HvLog("!!! DayZHV: [POWER] sleep/hibernate entry (state=%u) — teardown", state);
            DpcLatencyStop();
            VmxTeardown();
        }
    }

    PoStartNextPowerIrp(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    HvLog("!!! DayZHV: [UNLOAD] DriverUnload entered.  IRQL=%u", (ULONG)KeGetCurrentIrql());

    DpcLatencyStop();
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
    DriverObject->MajorFunction[IRP_MJ_POWER]  = DispatchPower;
    DriverObject->DriverUnload                  = DriverUnload;

    // Tell the power manager this device handles its own power IRPs.
    devObj->Flags |= DO_POWER_PAGABLE;

    // VmxInitialize opens the log internally and keeps it open on success.
    status = VmxInitialize();

    HvLog("!!! DayZHV: [ENTRY] DriverEntry returning status=0x%X  IRQL=%u",
          status, (ULONG)KeGetCurrentIrql());

    if (!NT_SUCCESS(status)) {
        HvLogClose();
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj);
    } else {
        // VM is running — start the latency measurement harness.
        DpcLatencyStart();
    }

    return status;
}
