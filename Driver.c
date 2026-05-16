#include <ntddk.h>
#include <ntimage.h>
#include "Vmx.h"
#include "Loader.h"
static PMANUAL_MODULE g_LoadedModule = NULL;
static PDEVICE_OBJECT g_DeviceObject  = NULL;   // our device; not owned by DriverObject

// ---------------------------------------------------------------------------
// EPT-violation IPC page mapping.
//
// The hypervisor punched GPA 0xFEED0000 non-present in the EPT.  To trigger
// the EPT violation from ring 0 we need a KVA whose guest-physical address
// resolves to exactly that GPA.  MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached)
// maps a physical address into kernel VA space; on a type-1 hypervisor the
// guest-physical address equals the host-physical address in the identity map,
// so mapping PA 0xFEED0000 gives us a KVA that hits GPA 0xFEED0000.
//
// The mapping is created once after VmxInitialize succeeds (hypervisor live,
// EPT hole already punched) and freed in DriverUnload.
// ---------------------------------------------------------------------------
static PVOID g_IpcKva = NULL;   // KVA that maps GPA/PA HV_IPC_GPA

static NTSTATUS IpcMapPage(void)
{
    if (g_IpcKva) return STATUS_SUCCESS;   // already mapped

    PHYSICAL_ADDRESS pa = {0};
    pa.QuadPart = (LONGLONG)(HV_IPC_GPA & HV_IPC_GPA_MASK);

    // MmMapIoSpace maps a physical address into the kernel's non-paged VA space.
    // MmNonCached matches the UC leaf the identity EPT would have used; more
    // importantly the cache attribute does not affect whether the CPU walks the
    // EPT — any store to this VA will trigger the non-present EPT violation.
    g_IpcKva = MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
    if (!g_IpcKva) {
        HvLog("!!! DayZHV: [IPC] MmMapIoSpace(0x%llX) failed", pa.QuadPart);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    HvLog("!!! DayZHV: [IPC] IPC page mapped: PA=0x%llX KVA=%p", pa.QuadPart, g_IpcKva);
    return STATUS_SUCCESS;
}

static void IpcUnmapPage(void)
{
    if (g_IpcKva) {
        MmUnmapIoSpace(g_IpcKva, PAGE_SIZE);
        g_IpcKva = NULL;
    }
}

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
    UNREFERENCED_PARAMETER(DriverObject);
    HvLog("!!! DayZHV: [UNLOAD] DriverUnload entered.  IRQL=%u", (ULONG)KeGetCurrentIrql());

    if (g_LoadedModule) {
        ManualUnload(g_LoadedModule);
        g_LoadedModule = NULL;
    }

    DpcLatencyStop();
    IpcUnmapPage();   // unmap before teardown — hypervisor frees EPT structures
    VmxTeardown();

    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DayZLink");
    IoDeleteSymbolicLink(&symName);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
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

    case IOCTL_HV_LOAD_MODULE: {
        SIZE_T inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inputLen < sizeof(WCHAR) || inputLen > HV_LOAD_PATH_MAX) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
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

    case IOCTL_HV_IPC_CALL: {
        SIZE_T inputLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        SIZE_T outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inputLen < sizeof(HV_IPC_REQUEST) || outputLen < sizeof(HV_IPC_RESPONSE)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        // Lazy-map the IPC page if not already done.  This handles the case
        // where a caller issues the IOCTL without waiting for VmxInitialize to
        // map it explicitly (e.g. during testing with the HV not running).
        if (!g_IpcKva) {
            status = IpcMapPage();
            if (!NT_SUCCESS(status)) {
                status = STATUS_DEVICE_NOT_READY;
                break;
            }
        }

        // Copy the request out of the METHOD_BUFFERED system buffer before
        // the write clobbers it (input and output share the same buffer).
        HV_IPC_REQUEST req;
        RtlCopyMemory(&req, Irp->AssociatedIrp.SystemBuffer, sizeof(req));

        HvLog("!!! DayZHV: [IPC] IOCTL IPC call  id=0x%llX arg0=0x%llX arg1=0x%llX",
              req.Id, req.Arg0, req.Arg1);

        // IPC page layout (all slots at g_IpcKva offsets):
        //   +00h  Id     — faulting store; EPT violation fires here
        //   +08h  Arg0
        //   +10h  Arg1
        //   +18h  Result — hypervisor writes GuestRegs.Rax here before VMRESUME
        //
        // Write order: Arg0/Arg1 first (so the 24-byte struct is complete when
        // the hypervisor reads it on the Id fault), then Id last.
        // The hypervisor's HandleEptIpcViolation writes the dispatch result
        // into ipc[3] (+18h) so we can read it back after the store returns.
        volatile ULONG64 *ipc = (volatile ULONG64 *)g_IpcKva;
        ipc[3] = 0xDEADDEADDEADDEADULL;  // sentinel — detects missed writes
        ipc[1] = req.Arg0;
        ipc[2] = req.Arg1;
        KeMemoryBarrier();
        ipc[0] = req.Id;                  // triggers EPT violation; handler runs
                                          // synchronously before this store retires

        // After VMRESUME the store has committed and ipc[3] holds the result.
        ULONG64 result = ipc[3];

        HvLog("!!! DayZHV: [IPC] result=0x%llX", result);

        HV_IPC_RESPONSE resp = { result };
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &resp, sizeof(resp));
        info   = sizeof(HV_IPC_RESPONSE);
        status = STATUS_SUCCESS;
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

// ---------------------------------------------------------------------------
// HvRemainingCoresThread — spawned after the synchronous Core 0 pilot passes.
// Calls VmxInitialize again to run Phase 3 (full IPI resident launch on all
// remaining cores).  Keeping this off DriverEntry lets the mapper unblock
// while the multi-core IPI barrier resolves.
// ---------------------------------------------------------------------------
static VOID HvRemainingCoresThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    HvLog("!!! DayZHV: [THREAD] HvRemainingCoresThread started on core %u — launching remaining cores",
          KeGetCurrentProcessorNumberEx(NULL));

    NTSTATUS status = VmxInitialize();
    HvLog("!!! DayZHV: [THREAD] VmxInitialize (remaining cores) status=0x%X", status);

    if (!NT_SUCCESS(status)) {
        HvLogClose();
        PsTerminateSystemThread(status);
        return;
    }

    NTSTATUS ipcStatus = IpcMapPage();
    if (!NT_SUCCESS(ipcStatus))
        HvLog("!!! DayZHV: [WARN] IPC page eager-map failed 0x%X — lazy fallback active", ipcStatus);

    DpcLatencyStart();

    HvLog("!!! DayZHV: [THREAD] Hypervisor fully online — all cores resident.");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    // Under manual mapping (kdmapper) both DriverObject and RegistryPath are
    // invalid — DriverObject is not a real WDK object and will fault in the
    // Object Manager's reference-count path (ObfReferenceObjectWithTag) if
    // passed to IoCreateDevice before we supply a valid object.
    //
    // Strategy:
    //  1. Borrow \Driver\Null — a genuine kernel object IoCreateDevice accepts.
    //  2. Create the device node and symlink so usermode can open the handle
    //     immediately after DriverEntry returns.
    //  3. Spawn a system thread to call VmxInitialize asynchronously so
    //     DriverEntry returns STATUS_SUCCESS right away, unblocking KDMapper.
    //
    // DriverObject / RegistryPath from the mapper are never dereferenced.
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    HvLogOpen();
    HvLog("!!! DayZHV: [ENTRY] DriverEntry entered  IRQL=%u", (ULONG)KeGetCurrentIrql());

    // --- Step 1: obtain a real DRIVER_OBJECT to pass to IoCreateDevice -------
    UNICODE_STRING nullDrvName = RTL_CONSTANT_STRING(L"\\Driver\\Null");
    PDRIVER_OBJECT borrowedDrv = NULL;
    NTSTATUS status = ObReferenceObjectByName(&nullDrvName,
                                              OBJ_CASE_INSENSITIVE,
                                              NULL,
                                              0,
                                              *IoDriverObjectType,
                                              KernelMode,
                                              NULL,
                                              (PVOID *)&borrowedDrv);
    if (!NT_SUCCESS(status)) {
        HvLog("!!! DayZHV: [FAIL] ObReferenceObjectByName(\\Driver\\Null) 0x%X", status);
        HvLogClose();
        return status;
    }

    // --- Step 2: create the device node -------------------------------------
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DayZHV");
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\DayZLink");

    status = IoCreateDevice(borrowedDrv, 0, &devName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        // Stale \Device\DayZHV from a prior failed load — delete it and retry.
        FILE_OBJECT   *fileObj  = NULL;
        DEVICE_OBJECT *staleDev = NULL;
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&devName, FILE_READ_DATA,
                                                &fileObj, &staleDev))) {
            ObDereferenceObject(fileObj);
            IoDeleteSymbolicLink(&symName);
            IoDeleteDevice(staleDev);
        }
        status = IoCreateDevice(borrowedDrv, 0, &devName,
                                FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    }

    ObDereferenceObject(borrowedDrv);

    if (!NT_SUCCESS(status)) {
        HvLog("!!! DayZHV: [FAIL] IoCreateDevice status=0x%X", status);
        HvLogClose();
        return status;
    }

    // Patch the MajorFunction slots the device inherits from \Driver\Null.
    DRIVER_OBJECT *devDrv = g_DeviceObject->DriverObject;
    devDrv->MajorFunction[IRP_MJ_CREATE]         = CreateClose;
    devDrv->MajorFunction[IRP_MJ_CLOSE]          = CreateClose;
    devDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    devDrv->MajorFunction[IRP_MJ_POWER]          = DispatchPower;
    devDrv->DriverUnload                          = DriverUnload;

    g_DeviceObject->Flags |= DO_POWER_PAGABLE;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    IoCreateSymbolicLink(&symName, &devName);

    // Hardware fence before spawning the VMX thread.
    // Ensures the mapped image's code pages are coherent in I-Cache on the
    // issuing P-core before the scheduler delivers the first quantum to the
    // new system thread.  Without this, the 14900K's split ring bus can serve
    // stale pre-relocation I-Cache lines to the thread's first fetch.
    __wbinvd();
    {
        int _fence[4];
        __cpuid(_fence, 0);
    }

    // --- Step 3: asynchronous VMX initialization ----------------------------
    // Spawn a system thread to call VmxInitialize so DriverEntry returns
    // STATUS_SUCCESS immediately, decoupling our runtime from KDMapper's APC
    // thread quantum.  Calling VmxInitialize synchronously here would execute
    // inside KDMapper's APC context, which holds the kernel I/O serialization
    // mutex — any ZwWriteFile call (including HvLog) in that path deadlocks
    // the mapper process permanently with no BSOD and no log output.
    HANDLE threadHandle = NULL;
    NTSTATUS threadStatus = PsCreateSystemThread(&threadHandle,
                                                  THREAD_ALL_ACCESS,
                                                  NULL, NULL, NULL,
                                                  HvRemainingCoresThread,
                                                  NULL);
    if (!NT_SUCCESS(threadStatus)) {
        HvLog("!!! DayZHV: [FAIL] PsCreateSystemThread 0x%X", threadStatus);
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        HvLogClose();
        return threadStatus;
    }
    ZwClose(threadHandle);

    HvLog("!!! DayZHV: [ENTRY] DriverEntry complete — VMX thread spawned  IRQL=%u",
          (ULONG)KeGetCurrentIrql());
    return STATUS_SUCCESS;
}
