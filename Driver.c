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

// ---------------------------------------------------------------------------
// KernelScanPattern — scan loaded kernel image for a SigMaker-style pattern.
// Pattern format: space-separated hex bytes, '?' or '??' for wildcards.
// Returns the KVA of the first match, or 0 on no-match / error.
// Runs at PASSIVE_LEVEL (called from IRP dispatch). Keep scan region bounded.
// ---------------------------------------------------------------------------
UINT64 KernelScanPattern(const char *Pattern)
{
    // Resolve ntoskrnl base via MmGetSystemRoutineAddress on a known export.
    UNICODE_STRING  routineName = RTL_CONSTANT_STRING(L"MmGetSystemRoutineAddress");
    PVOID           routinePtr  = MmGetSystemRoutineAddress(&routineName);
    if (!routinePtr) return 0;

    // Walk down from the export to the PE header (MZ signature).
    ULONG_PTR base = (ULONG_PTR)routinePtr & ~(ULONG_PTR)0xFFF;
    for (ULONG i = 0; i < 0x1000; ++i, base -= PAGE_SIZE) {
        __try {
            if (*(USHORT *)base == 0x5A4D) break;  // 'MZ'
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }
    if (*(USHORT *)base != 0x5A4D) return 0;

    // Resolve the .text section bounds.
    IMAGE_DOS_HEADER     *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64   *nt  = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    ULONG_PTR scanBase  = base + nt->OptionalHeader.BaseOfCode;
    SIZE_T    scanSize  = nt->OptionalHeader.SizeOfCode;

    // Parse the pattern string into byte/mask arrays.
    UCHAR  bytes[MAX_PATTERN_LEN];
    BOOLEAN mask[MAX_PATTERN_LEN];
    ULONG  patLen = 0;

    const char *p = Pattern;
    while (*p && patLen < MAX_PATTERN_LEN) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (p[0] == '?' ) {
            bytes[patLen] = 0;
            mask[patLen]  = FALSE;
            ++patLen;
            if (p[1] == '?') ++p;
            ++p;
        } else {
#define HEX_DIGIT(c) ((c) >= '0' && (c) <= '9' ? (c) - '0' : \
                      (c) >= 'a' && (c) <= 'f' ? (c) - 'a' + 10 : \
                      (c) >= 'A' && (c) <= 'F' ? (c) - 'A' + 10 : 0)
            bytes[patLen] = (UCHAR)((HEX_DIGIT(p[0]) << 4) | HEX_DIGIT(p[1]));
#undef HEX_DIGIT
            mask[patLen]  = TRUE;
            ++patLen;
            p += 2;
        }
    }
    if (patLen == 0) return 0;

    // Linear scan.
    for (SIZE_T i = 0; i + patLen <= scanSize; ++i) {
        BOOLEAN match = TRUE;
        __try {
            for (ULONG j = 0; j < patLen; ++j) {
                if (mask[j] && ((UCHAR *)(scanBase + i))[j] != bytes[j]) {
                    match = FALSE;
                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (match) return (UINT64)(scanBase + i);
    }
    return 0;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack  = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR          info   = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_HV_SCAN_PATTERN: {
        SIZE_T inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        SIZE_T outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inputLen < 2 || inputLen > MAX_PATTERN_LEN || outputLen < sizeof(UINT64)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        char *buf = (char *)Irp->AssociatedIrp.SystemBuffer;

        // Force null-termination — Python's ctypes may not guarantee a trailing null.
        buf[inputLen - 1] = '\0';

        UINT64 kva = KernelScanPattern(buf);

        *(UINT64 *)Irp->AssociatedIrp.SystemBuffer = kva;
        info   = sizeof(UINT64);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_HV_READ_MEMORY: {
        SIZE_T inputLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        SIZE_T outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inputLen < sizeof(HV_READ_REQUEST)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        HV_READ_REQUEST req;
        RtlCopyMemory(&req, Irp->AssociatedIrp.SystemBuffer, sizeof(req));

        if (req.Length == 0 || req.Length > HV_READ_MAX_LENGTH ||
            outputLen < req.Length) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Kva is a kernel virtual address resolved by KernelScanPattern.
        // No cross-process copy is needed — both source and destination are
        // in kernel VA space. The __try catches unmapped or guard-page faults.
        __try {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                          (PVOID)req.Kva,
                          req.Length);
            info   = req.Length;
            status = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status    = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
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
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_POWER]          = DispatchPower;
    DriverObject->DriverUnload                          = DriverUnload;

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
