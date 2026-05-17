#include <ntddk.h>
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "Vmx.h"

// Define HV_VERBOSE to enable per-exit DbgPrint tracing (RDMSR, WRMSR, CR3,
// IO, DR, EPT lazy-map, etc.).  Off by default — these fire thousands of times
// per second on a live guest and drown out signal in DebugView.
// #define HV_VERBOSE

#ifdef HV_VERBOSE
#define HV_VERBOSE_LOG(fmt, ...) DbgPrint("DayZHV: " fmt "\n", ##__VA_ARGS__)
#else
#define HV_VERBOSE_LOG(fmt, ...) ((void)0)
#endif

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
// Per-core context pointer array — indexed by processor number.
// Written by VmxLaunchCore before vmlaunch, read by AsmVmExitHandler on exit.
PCORE_VMX_CONTEXT g_CoreCtx[MAX_LOGICAL_PROCESSORS] = {0};

// Driver-lifetime allocations — kept alive while the VM is running.
static PCORE_VMX_CONTEXT g_CtxArray  = NULL;
static ULONG             g_ProcCount = 0;
static PVOID             g_DecoyPage = NULL;   // zeroed page backing all hidden GPAs
EPT_CONTEXT              g_Ept       = {0};

// Pre-VMXON CPUID calibration cache — populated in VmxInitialize before VMXON.
CPUID_CACHE g_CpuidCache = {0};

// IPI checkin counter — tracks how many P-cores have finished Phase A.
// Reset to 0 before each KeIpiGenericCall; each core increments on arrival
// then spins until all g_ProcCount P-cores have checked in before Phase B.
static volatile LONG g_PcoreCheckin = 0;

// Lockless hardware diagnostic buffer — populated during the pre-VMXON window
// before the IRQL raise where ZwWriteFile is unsafe.  Allocated from non-paged
// pool in VmxInitialize; freed in VmxTeardown.  NULL until allocated.
PVMX_DIAG_BUFFER g_VmxDiag = NULL;

// LSTAR lock — set via HV_CALL_LOCK_LSTAR once the guest has completed boot.
// When TRUE, any guest WRMSR to IA32_LSTAR is rejected and logged.
// Intentionally not per-core: LSTAR is a system-wide MSR, one value shared
// across all logical processors; locking it is a global decision.
static volatile BOOLEAN  g_LstarLocked = FALSE;

// Set to 1 whenever any core modifies the EPT (WP_REGISTER, SET_EPT_POLICY,
// shadow-table swap). Checked at the top of VmExitDispatch on every core; the
// first exit on each core after the flag is set issues INVEPT and clears it.
// InterlockedCompareExchange64 ensures a clean read-modify-write; the flag
// stays set until every core has flushed (each core clears only its own read).
// Using LONG (32-bit) for Interlocked* compatibility.
volatile LONG            g_InveptPending = 0;

// ---------------------------------------------------------------------------
// Write-protection table — sorted ascending GPAs set by VmxIsolateInfrastructure.
// Any EPT write fault on a listed GPA injects #GP(0) instead of lazy-mapping.
// ---------------------------------------------------------------------------
#define WP_TABLE_SIZE 256
static ULONG64 g_WpTable[WP_TABLE_SIZE] = {0};
static ULONG   g_WpCount                = 0;

static BOOLEAN WpTableContains(ULONG64 Gpa)
{
    Gpa &= ~0xFFFULL;
    if (g_WpCount == 0) return FALSE;
    ULONG lo = 0, hi = g_WpCount - 1;
    while (lo <= hi) {
        ULONG mid = lo + (hi - lo) / 2;
        if (g_WpTable[mid] == Gpa) return TRUE;
        if (g_WpTable[mid] <  Gpa) lo = mid + 1;
        else {
            if (mid == 0) break;
            hi = mid - 1;
        }
    }
    return FALSE;
}


// ---------------------------------------------------------------------------
// File logging — writes timestamped lines to logs\dayzdriv.log
// FILE_WRITE_THROUGH bypasses the FS write cache so each HvLog() call is
// durable on disk before returning — survives a hard freeze mid-sequence.
// ---------------------------------------------------------------------------
static HANDLE g_LogHandle = NULL;

void HvLogOpen(void)
{
    UNICODE_STRING    path = RTL_CONSTANT_STRING(
        L"\\??\\Volume{543eab83-c5fe-4513-8f15-4e9e71493a23}\\vsprojs\\dayzdriv\\logs\\dayzdriv.log");
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ZwCreateFile(&g_LogHandle, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ,
                 FILE_OPEN_IF,
                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
                 NULL, 0);
}

// HvLog — durable file log.  Every call survives a hard freeze (FILE_WRITE_THROUGH).
// Use for lifecycle events: launch, teardown, PASS/FAIL, stats, alloc errors.
// NOT mirrored to DebugView — keeps DbgPrint output clean for active debugging.
void HvLog(const char *fmt, ...)
{
    if (!g_LogHandle) return;

    // __rdtsc() is a bare intrinsic — no OS call, no rdtscp, cannot #UD.
    // KeQueryPerformanceCounter crashes after IPI-based VMXON/VMXOFF because
    // it uses rdtscp, which faults if the HAL timer state was disturbed.
    ULONG64 tsc = __rdtsc();

    char buf[512];
    char prefix[32];
    RtlStringCbPrintfA(prefix, sizeof(prefix), "[%llu] ", tsc);
    SIZE_T prefixLen = strlen(prefix);

    RtlStringCbCopyA(buf, sizeof(buf), prefix);

    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);

    SIZE_T len = strlen(buf);
    if (len < sizeof(buf) - 1 && buf[len-1] != '\n') {
        buf[len]   = '\n';
        buf[len+1] = '\0';
        len++;
    }

    IO_STATUS_BLOCK iosb;
    ZwWriteFile(g_LogHandle, NULL, NULL, NULL, &iosb, buf, (ULONG)len, NULL, NULL);
}

// HvLogDbg — DebugView-only log (DbgPrint wrapper with consistent prefix).
// Use for diagnostic paths that fire infrequently but are not lifecycle events:
// unhandled exits, injection, hypercall errors.  Does NOT write to the file.
// Safe above DISPATCH_LEVEL (DbgPrint is safe; ZwWriteFile is not).
static void HvLogDbg(const char *fmt, ...)
{
    char buf[256];
    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(buf, sizeof(buf), fmt, args);
    va_end(args);
    DbgPrint("DayZHV: %s\n", buf);
}

void HvLogClose(void)
{
    if (g_LogHandle) {
        ZwClose(g_LogHandle);
        g_LogHandle = NULL;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Read the 32-bit VMCS revision identifier from IA32_VMX_BASIC[30:0].
static ULONG GetVmcsRevisionId(void)
{
    return (ULONG)(__readmsr(IA32_VMX_BASIC) & 0x7FFFFFFF);
}

// Apply Intel's fixed-bit rule: (current | fixed0) & fixed1.
static ULONG64 AdjustCr0(ULONG64 Cr0)
{
    Cr0 |=  __readmsr(IA32_VMX_CR0_FIXED0);
    Cr0 &=  __readmsr(IA32_VMX_CR0_FIXED1);
    return Cr0;
}

static ULONG64 AdjustCr4(ULONG64 Cr4)
{
    Cr4 |=  __readmsr(IA32_VMX_CR4_FIXED0);
    Cr4 &=  __readmsr(IA32_VMX_CR4_FIXED1);
    return Cr4;
}

// Adjust a VMX control field using the allowed-0/allowed-1 encoding in the MSR.
// Low 32 bits = bits that must be 1 (Fixed0), high 32 bits = bits allowed to be 1 (Fixed1).
static ULONG AdjustControls(ULONG Requested, ULONG MsrIndex)
{
    ULONGLONG msr = __readmsr(MsrIndex);
    ULONG fixed0  = (ULONG)(msr & 0xFFFFFFFF);
    ULONG fixed1  = (ULONG)(msr >> 32);
    return (Requested | fixed0) & fixed1;
}

// Extract the 64-bit base of a TSS (16-byte) descriptor from the GDT.
static ULONG64 GetTssBase(ULONG64 GdtBase, USHORT TrSelector)
{
    // TrSelector index selects a 16-byte entry; strip RPL/TI bits.
    ULONG index = (TrSelector & ~7U);
    PSEGMENT_DESCRIPTOR_64 desc =
        (PSEGMENT_DESCRIPTOR_64)(GdtBase + index);

    ULONG64 base =
        ((ULONG64)desc->BaseLow)                |
        ((ULONG64)desc->BaseMiddle  << 16)       |
        ((ULONG64)desc->BaseHigh    << 24)       |
        ((ULONG64)desc->BaseUpper   << 32);

    return base;
}

// Decode a VM-instruction error code (from VMCS_VM_INSTRUCTION_ERROR) to a
// human-readable string.  These are the 28 error codes defined in SDM Vol 3D
// Table 30-1 "VM-Instruction Error Numbers".  Code 0 means no error was
// recorded (ZF was not set, or the VMCS was not current).
static const char *VmxInstrErrorName(ULONG64 Code)
{
    switch (Code) {
    case  0: return "No error / VMCS not current";
    case  1: return "VMCALL in VMX root operation";
    case  2: return "VMCLEAR with invalid physical address";
    case  3: return "VMCLEAR with VMXON pointer";
    case  4: return "VMLAUNCH with non-clear VMCS";
    case  5: return "VMRESUME with non-launched VMCS";
    case  6: return "VMRESUME after VMXOFF";
    case  7: return "VM entry with invalid control field(s)";
    case  8: return "VM entry with invalid host-state field(s)";
    case  9: return "VMPTRLD with invalid physical address";
    case 10: return "VMPTRLD with VMXON pointer";
    case 11: return "VMPTRLD with incorrect VMCS revision ID";
    case 12: return "VMREAD/VMWRITE from/to unsupported VMCS component";
    case 13: return "VMWRITE to read-only VMCS component";
    case 15: return "VMXON in VMX root operation";
    case 16: return "VM entry with invalid executive-VMCS pointer";
    case 17: return "VM entry with non-launched executive VMCS";
    case 18: return "VM entry with executive-VMCS != VMXON pointer (not in SMM)";
    case 19: return "VMCALL with non-clear VMCS (in VMX root, dual-monitor)";
    case 20: return "VMCALL with invalid VM-exit control fields";
    case 22: return "VMCALL with incorrect MSEG revision ID";
    case 23: return "VMXOFF under dual-monitor treatment of SMIs and SMM";
    case 24: return "VMCALL with invalid SMM-monitor features";
    case 25: return "VM entry with invalid VM-execution control in executive VMCS";
    case 26: return "VM entry with events blocked by MOV SS";
    case 28: return "Invalid operand to INVEPT/INVVPID";
    default: return "Unknown/reserved error code";
    }
}

// Log a VM-instruction error code by number and name.  Call this immediately
// after any VMX instruction that set ZF (VMfailValid), while the VMCS is still
// current.  CF (VMfailInvalid) means no current VMCS — do NOT call this then.
static void LogVmxInstrError(ULONG ProcNum, const char *InstrName)
{
    ULONG64 errCode = 0;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errCode);
    HvLog("!!! DayZHV: [VMX INSTR ERROR core=%02u] %s: code=%llu (%s)",
          ProcNum, InstrName, errCode, VmxInstrErrorName(errCode));
}

// Log raw GUEST and HOST CR0/CR4 as they will be written to the VMCS, checked
// against the IA32_VMX_CR0/CR4_FIXED MSR masks.  A mismatch with FIXED0 (must-1)
// or FIXED1 (must-0) will cause VM-instruction error 7 at VMLAUNCH time.
// Called in Phase A (before IRQL raise) so HvLog/ZwWriteFile is legal.
static void VmxAuditCrValues(ULONG ProcNum,
                              ULONG64 GuestCr0, ULONG64 GuestCr4,
                              ULONG64 HostCr0,  ULONG64 HostCr4)
{
    ULONG64 cr0f0 = __readmsr(IA32_VMX_CR0_FIXED0);
    ULONG64 cr0f1 = __readmsr(IA32_VMX_CR0_FIXED1);
    ULONG64 cr4f0 = __readmsr(IA32_VMX_CR4_FIXED0);
    ULONG64 cr4f1 = __readmsr(IA32_VMX_CR4_FIXED1);

    // Bits set in (value & ~FIXED1) must be 0 but are 1 — violates allowed-1.
    // Bits set in (~value & FIXED0) must be 1 but are 0  — violates allowed-0.
    ULONG64 gCr0Bad = (GuestCr0 & ~cr0f1) | (~GuestCr0 & cr0f0);
    ULONG64 gCr4Bad = (GuestCr4 & ~cr4f1) | (~GuestCr4 & cr4f0);
    ULONG64 hCr0Bad = (HostCr0  & ~cr0f1) | (~HostCr0  & cr0f0);
    ULONG64 hCr4Bad = (HostCr4  & ~cr4f1) | (~HostCr4  & cr4f0);

    HvLog("!!! DayZHV: [CR AUDIT core=%02u] GUEST_CR0=0x%llX  GUEST_CR4=0x%llX  "
          "HOST_CR0=0x%llX  HOST_CR4=0x%llX",
          ProcNum, GuestCr0, GuestCr4, HostCr0, HostCr4);
    HvLog("!!! DayZHV: [CR AUDIT core=%02u] FIXED0: CR0=0x%llX  CR4=0x%llX  "
          "FIXED1: CR0=0x%llX  CR4=0x%llX",
          ProcNum, cr0f0, cr4f0, cr0f1, cr4f1);

    if (gCr0Bad || gCr4Bad || hCr0Bad || hCr4Bad) {
        HvLog("!!! DayZHV: [CR AUDIT core=%02u] FIXED MASK VIOLATIONS DETECTED — "
              "VMLAUNCH will fail with error 7 (invalid control fields)",
              ProcNum);
        if (gCr0Bad) HvLog("!!! DayZHV: FATAL: CR0 bit violation: 0x%llX (core=%02u GUEST)", gCr0Bad, ProcNum);
        if (gCr4Bad) HvLog("!!! DayZHV: FATAL: CR4 bit violation: 0x%llX (core=%02u GUEST)", gCr4Bad, ProcNum);
        if (hCr0Bad) HvLog("!!! DayZHV: FATAL: CR0 bit violation: 0x%llX (core=%02u HOST)",  hCr0Bad, ProcNum);
        if (hCr4Bad) HvLog("!!! DayZHV: FATAL: CR4 bit violation: 0x%llX (core=%02u HOST)",  hCr4Bad, ProcNum);
    } else {
        HvLog("!!! DayZHV: [CR AUDIT core=%02u] All CR0/CR4 values conform to FIXED masks — OK",
              ProcNum);
    }
}

// Write a VMCS field and check RFLAGS for CF=1 (error) or ZF=1 (no-current-VMCS).
// Returns FALSE and logs on failure so the caller can abort cleanly.
static BOOLEAN SafeVmWrite(ULONG Field, ULONG64 Value)
{
    unsigned char result = __vmx_vmwrite(Field, Value);
    if (result != 0) {
        HvLog("!!! DayZHV: VMWRITE FAILED field=0x%04X value=0x%llX result=%u",
              Field, Value, (ULONG)result);
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// BIOS / CPU capability checks
// ---------------------------------------------------------------------------
BOOLEAN IsVmxSupported(void)
{
    int cpuid[4] = {0};
    __cpuid(cpuid, 1);
    return (cpuid[2] & (1 << 5)) != 0;   // ECX bit 5 = VMX
}

BOOLEAN IsVmxEnabledInBios(void)
{
    ULONGLONG fc = __readmsr(IA32_FEATURE_CONTROL);
    HvLog("!!! DayZHV: [MSR 0x3A] IA32_FEATURE_CONTROL raw=0x%llX  Lock=%u  EnableVmxOutsideSmx=%u",
          fc, (ULONG)(fc & 1), (ULONG)((fc >> 2) & 1));

    if (!(fc & 0x1)) {
        // Not locked — attempt to lock with bit 0 (Lock) and bit 2 (Enable VMX outside SMX).
        ULONGLONG newFc = (fc & ~0x7ULL) | 0x5ULL;   // preserve upper bits, set Lock+EnableVmxOutsideSmx
        __writemsr(IA32_FEATURE_CONTROL, newFc);
        fc = __readmsr(IA32_FEATURE_CONTROL);
        HvLog("!!! DayZHV: [MSR 0x3A] Wrote lock bits. Re-read=0x%llX  Lock=%u  EnableVmxOutsideSmx=%u",
              fc, (ULONG)(fc & 1), (ULONG)((fc >> 2) & 1));
        if (!(fc & 0x1) || !(fc & 0x4)) {
            HvLog("!!! DayZHV: [MSR 0x3A] FATAL — WRMSR accepted but lock/enable bits did not stick. BIOS hard-blocked.");
            return FALSE;
        }
        return TRUE;
    }

    // Already locked. Bit 2 (Enable VMX outside SMX) MUST be set.
    if (!(fc & 0x4)) {
        HvLog("!!! DayZHV: [MSR 0x3A] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        HvLog("!!! DayZHV: [MSR 0x3A] FATAL: IA32_FEATURE_CONTROL is LOCKED but EnableVmxOutsideSmx (bit 2) is CLEAR.");
        HvLog("!!! DayZHV: [MSR 0x3A] BIOS has hard-blocked VMXON.  Cannot unlock at runtime.");
        HvLog("!!! DayZHV: [MSR 0x3A] DIAGNOSIS: BIOS VMX setting may be disabled or limited to SMX-only mode.");
        HvLog("!!! DayZHV: [MSR 0x3A] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Per-core region alloc / free
// ---------------------------------------------------------------------------
static void FreeCoreCxtArray(PCORE_VMX_CONTEXT arr, ULONG count)
{
    for (ULONG i = 0; i < count; i++) {
        if (arr[i].HostStack)   ExFreePoolWithTag(arr[i].HostStack,   'HvHS');
        if (arr[i].GuestStack)  ExFreePoolWithTag(arr[i].GuestStack,  'HvGS');
        if (arr[i].VmcsRegion)  ExFreePoolWithTag(arr[i].VmcsRegion,  'HvVC');
        if (arr[i].VmxonRegion) ExFreePoolWithTag(arr[i].VmxonRegion, 'HvVO');
        if (arr[i].ShadowGdt)   ExFreePoolWithTag(arr[i].ShadowGdt,   'HvGD');
        if (arr[i].MsrBitmap)   ExFreePoolWithTag(arr[i].MsrBitmap,   'HvMB');
        if (arr[i].IoBitmapA)   ExFreePoolWithTag(arr[i].IoBitmapA,   'HvIA');
        if (arr[i].IoBitmapB)   ExFreePoolWithTag(arr[i].IoBitmapB,   'HvIB');
        // XSaveArea is allocated as (buf + 63) and stored as the aligned interior
        // pointer. Free by subtracting the stored offset hidden just before the
        // aligned pointer. We use a simpler scheme: store the raw allocation pointer
        // in the byte just before the aligned pointer via a prefix PVOID slot.
        // See AllocCoreCtxArray for the layout. The raw pointer is at XSaveArea[-1].
        if (arr[i].XSaveArea) {
            PVOID raw = ((PVOID*)arr[i].XSaveArea)[-1];
            ExFreePoolWithTag(raw, 'HvXS');
        }
        if (arr[i].MsrLoadPageRaw) ExFreePoolWithTag(arr[i].MsrLoadPageRaw, 'HvML');
        if (arr[i].EptpListPage)   ExFreePoolWithTag(arr[i].EptpListPage,   'HvEL');
        if (arr[i].ShadowVmcsPage) ExFreePoolWithTag(arr[i].ShadowVmcsPage, 'HvSV');
        if (arr[i].VmreadBitmap)   ExFreePoolWithTag(arr[i].VmreadBitmap,   'HvVR');
        if (arr[i].VmwriteBitmap)  ExFreePoolWithTag(arr[i].VmwriteBitmap,  'HvVW');
        if (arr[i].SppTablePage)   ExFreePoolWithTag(arr[i].SppTablePage,   'HvSP');
    }
}

// Query XSAVE compacted size and the user-state component mask.
// Returns FALSE if XSAVEC is not supported (CR4.OSXSAVE or CPUID check fails).
static BOOLEAN QueryXSaveInfo(ULONG *outSize, ULONG64 *outMask)
{
    int regs[4];

    // CPUID[1].ECX bit 26 = XSAVE supported; bit 27 = OSXSAVE (CR4.OSXSAVE set).
    __cpuid(regs, 1);
    if (!((regs[2] >> 26) & 1) || !((regs[2] >> 27) & 1)) return FALSE;

    // CPUID[0xD, 0]: EBX = current XSAVE area size, ECX = compacted (XSAVEC) size.
    __cpuidex(regs, 0xD, 0);
    ULONG compactedSize = (ULONG)regs[2];
    if (compactedSize == 0) return FALSE;

    // Cap at 8KB — AMX TILE data is 8KB, AVX-512 + opmask + PKRU is ~2.7KB.
    if (compactedSize > 0x2000) compactedSize = 0x2000;

    // User-state mask: XCR0 (all OS-enabled components).
    // XGETBV(0) returns EDX:EAX = XCR0.
    ULONG64 xcr0 = _xgetbv(0);

    *outSize = compactedSize;
    *outMask = xcr0;
    return TRUE;
}

static NTSTATUS AllocCoreCtxArray(PCORE_VMX_CONTEXT arr, ULONG count)
{
    // Determine XSAVE buffer size once — same on all cores.
    ULONG   xsaveSize = 0;
    ULONG64 xsaveMask = 0;
    BOOLEAN xsaveOk   = QueryXSaveInfo(&xsaveSize, &xsaveMask);

    for (ULONG i = 0; i < count; i++) {
        arr[i].VmxonRegion  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVO');
        arr[i].VmcsRegion   = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVC');
        arr[i].HostStack    = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000,   'HvHS');
        arr[i].GuestStack   = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000,    'HvGS');
        arr[i].ShadowGdt    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvGD');
        arr[i].MsrBitmap    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvMB');
        arr[i].IoBitmapA    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvIA');
        arr[i].IoBitmapB    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvIB');
        // MSR-load page: must be physically 4KB page-aligned (SDM §26.2.1.3).
        // ExAllocatePool2 does not guarantee page-aligned VAs even for PAGE_SIZE requests.
        // Allocate 2*PAGE_SIZE, align the VA up to the next page boundary, store the
        // raw pointer for ExFreePoolWithTag.
        {
            PVOID raw = ExAllocatePool2(POOL_FLAG_NON_PAGED, 2 * PAGE_SIZE, 'HvML');
            if (raw) {
                ULONG_PTR aligned = ((ULONG_PTR)raw + PAGE_SIZE - 1) & ~(ULONG_PTR)(PAGE_SIZE - 1);
                arr[i].MsrLoadPageRaw = raw;
                arr[i].MsrLoadPage    = (PVOID)aligned;
                RtlZeroMemory((PVOID)aligned, PAGE_SIZE);
            }
        }
        arr[i].ExitReason   = 0xFFFFFFFF;
        arr[i].LaunchResult = 0xFF;
        arr[i].Passed       = FALSE;
        // DR shadow: initialise to hardware reset state.
        // DR6 reset = 0xFFFF0FF0 (all status bits set, BD/BS/BT clear).
        // DR7 reset = 0x400 (local enable bits clear, GE/LE=0, no conditions armed).
        arr[i].GuestDr[6]    = 0xFFFF0FF0ULL;
        arr[i].GuestDr[7]    = 0x400ULL;
        // Shadow IA32_XSS with the current hardware value so the guest sees
        // whatever the OS configured before we launched the hypervisor.
        arr[i].GuestXss           = __readmsr(IA32_XSS);
        arr[i].GuestRtitCtl       = 0;   // PT disabled at hypervisor launch
        arr[i].LbrVirtEnabled     = FALSE;
        arr[i].GuestPerfGlobalCtrl = __readmsr(IA32_PERF_GLOBAL_CTRL);

        // EPTP list: slot 0 = identity EPTP (written after EptBuildIdentityMap).
        arr[i].EptpListPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvEL');
        if (arr[i].EptpListPage)
            RtlZeroMemory(arr[i].EptpListPage, PAGE_SIZE);

        // VMCS shadowing: shadow VMCS page + read/write bitmaps.
        // Shadow VMCS must have VMCS revision ID written before use (done in launch core).
        arr[i].ShadowVmcsPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvSV');
        arr[i].VmreadBitmap   = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVR');
        arr[i].VmwriteBitmap  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVW');
        if (arr[i].ShadowVmcsPage) RtlZeroMemory(arr[i].ShadowVmcsPage, PAGE_SIZE);
        if (arr[i].VmreadBitmap)   RtlZeroMemory(arr[i].VmreadBitmap,   PAGE_SIZE);
        if (arr[i].VmwriteBitmap)  RtlZeroMemory(arr[i].VmwriteBitmap,  PAGE_SIZE);

        // SPP table: all-ones = all 32 sub-pages within each 4KB page are writable.
        arr[i].SppTablePage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvSP');
        if (arr[i].SppTablePage)
            RtlFillMemory(arr[i].SppTablePage, PAGE_SIZE, 0xFF);

        // XSAVE area: allocate (size + sizeof(PVOID) + 63) bytes so we can align
        // the buffer to 64 bytes (required by XSAVEC/XRSTOR) and store the raw
        // allocation pointer in the slot immediately before the aligned region
        // for retrieval in FreeCoreCxtArray.
        if (xsaveOk) {
            SIZE_T rawBytes = xsaveSize + sizeof(PVOID) + 63;
            PVOID  raw      = ExAllocatePool2(POOL_FLAG_NON_PAGED, rawBytes, 'HvXS');
            if (raw) {
                RtlZeroMemory(raw, rawBytes);
                // Aligned start: advance past the PVOID prefix slot, then round up.
                ULONG_PTR aligned = ((ULONG_PTR)raw + sizeof(PVOID) + 63) & ~(ULONG_PTR)63;
                // Store raw pointer in the PVOID slot just before the aligned area.
                ((PVOID*)aligned)[-1] = raw;
                arr[i].XSaveArea = (PVOID)aligned;
                arr[i].XSaveSize = xsaveSize;
                arr[i].XSaveMask = xsaveMask;
            }
        }

        // Log optional-feature allocation failures — these don't abort the driver
        // but silently degrade capability (VMFUNC, VMCS shadowing, SPP, XSAVE).
        if (!arr[i].EptpListPage)
            HvLog("!!! DayZHV: [WARN] Core %u EptpListPage alloc failed — VMFUNC will be disabled", i);
        if (!arr[i].ShadowVmcsPage || !arr[i].VmreadBitmap || !arr[i].VmwriteBitmap)
            HvLog("!!! DayZHV: [WARN] Core %u shadow-VMCS alloc failed (ShadowVmcs=%p VmrdBmp=%p VmwrBmp=%p) — VMCS shadowing disabled",
                  i, arr[i].ShadowVmcsPage, arr[i].VmreadBitmap, arr[i].VmwriteBitmap);
        if (!arr[i].SppTablePage)
            HvLog("!!! DayZHV: [WARN] Core %u SppTablePage alloc failed — SPP disabled", i);
        if (xsaveOk && !arr[i].XSaveArea)
            HvLog("!!! DayZHV: [WARN] Core %u XSaveArea alloc failed (size=%u) — guest extended state NOT saved/restored on VM-exit",
                  i, xsaveSize);

        if (!arr[i].VmxonRegion || !arr[i].VmcsRegion ||
            !arr[i].HostStack   || !arr[i].GuestStack  ||
            !arr[i].ShadowGdt   || !arr[i].MsrBitmap   ||
            !arr[i].IoBitmapA   || !arr[i].IoBitmapB) {
            HvLog("!!! DayZHV: [FAIL] Core %u critical alloc failed: vmxon=%p vmcs=%p hstk=%p gstk=%p gdt=%p msr=%p ioA=%p ioB=%p",
                  i, arr[i].VmxonRegion, arr[i].VmcsRegion, arr[i].HostStack, arr[i].GuestStack,
                  arr[i].ShadowGdt, arr[i].MsrBitmap, arr[i].IoBitmapA, arr[i].IoBitmapB);
            FreeCoreCxtArray(arr, i + 1);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(arr[i].VmxonRegion, PAGE_SIZE);
        RtlZeroMemory(arr[i].VmcsRegion,  PAGE_SIZE);
        RtlZeroMemory(arr[i].HostStack,   0x10000);
        RtlZeroMemory(arr[i].GuestStack,  0x8000);

        // MSR bitmap: 4KB, four 1KB regions (SDM Vol 3C §24.6.9).
        // All zeroes = no intercept. Set bit 2 (MSR 0x3A) in:
        //   byte 0 of region 0 (offset 0x000) — read intercept for low MSRs
        //   byte 0 of region 2 (offset 0x800) — write intercept for low MSRs
        RtlZeroMemory(arr[i].MsrBitmap, PAGE_SIZE);
        ((UCHAR*)arr[i].MsrBitmap)[0x000] |= (1 << 2);   // RDMSR 0x3A exits
        ((UCHAR*)arr[i].MsrBitmap)[0x800] |= (1 << 2);   // WRMSR 0x3A exits
        // IA32_MPERF (0xE7): byte 0x1C, bit 7
        ((UCHAR*)arr[i].MsrBitmap)[0x01C] |= (1 << 7);   // RDMSR 0xE7 exits
        ((UCHAR*)arr[i].MsrBitmap)[0x81C] |= (1 << 7);   // WRMSR 0xE7 exits (inject #GP)
        // IA32_APERF (0xE8): byte 0x1D, bit 0
        ((UCHAR*)arr[i].MsrBitmap)[0x01D] |= (1 << 0);   // RDMSR 0xE8 exits
        ((UCHAR*)arr[i].MsrBitmap)[0x81D] |= (1 << 0);   // WRMSR 0xE8 exits (inject #GP)
        // IA32_APIC_BASE (0x1B): byte 0x03, bit 3
        ((UCHAR*)arr[i].MsrBitmap)[0x003] |= (1 << 3);   // RDMSR 0x1B exits
        ((UCHAR*)arr[i].MsrBitmap)[0x803] |= (1 << 3);   // WRMSR 0x1B exits
        // IA32_DEBUGCTL (0x1D9): byte 0x3B, bit 1
        ((UCHAR*)arr[i].MsrBitmap)[0x03B] |= (1 << 1);   // RDMSR 0x1D9 exits
        ((UCHAR*)arr[i].MsrBitmap)[0x83B] |= (1 << 1);   // WRMSR 0x1D9 exits
        // IA32_ENERGY_PERF_BIAS (0x1B0): byte 0x36, bit 0
        // IA32_PACKAGE_THERM_STATUS (0x1B1): byte 0x36, bit 1
        ((UCHAR*)arr[i].MsrBitmap)[0x036] |= (1 << 0) | (1 << 1);   // RDMSR exits
        ((UCHAR*)arr[i].MsrBitmap)[0x836] |= (1 << 0) | (1 << 1);   // WRMSR exits
        // LSTAR (0xC0000082): high-MSR range, index = 0x82
        // Read intercept: offset 0x400 + 0x82/8 = 0x410, bit 0x82%8 = 2
        // Write intercept: offset 0xC00 + 0x82/8 = 0xC10, bit 2
        ((UCHAR*)arr[i].MsrBitmap)[0x410] |= (1 << 2);   // RDMSR LSTAR exits
        ((UCHAR*)arr[i].MsrBitmap)[0xC10] |= (1 << 2);   // WRMSR LSTAR exits
        // IA32_RTIT_CTL (0x570): byte 0xAE, bit 0 — Intel PT control intercept
        ((UCHAR*)arr[i].MsrBitmap)[0x0AE] |= (1 << 0);   // RDMSR 0x570 exits
        ((UCHAR*)arr[i].MsrBitmap)[0x8AE] |= (1 << 0);   // WRMSR 0x570 exits
        // IA32_XSS (0xDA0): byte 0x1B5, bit 0 — supervisor XSAVE state mask
        ((UCHAR*)arr[i].MsrBitmap)[0x1B5] |= (1 << 0);   // RDMSR 0xDA0 exits
        ((UCHAR*)arr[i].MsrBitmap)[0x9B5] |= (1 << 0);   // WRMSR 0xDA0 exits
        // IA32_PERF_GLOBAL_CTRL (0x38F): byte 0x71, bit 7 — PMU isolation
        ((UCHAR*)arr[i].MsrBitmap)[0x071] |= (1 << 7);   // RDMSR 0x38F exits
        ((UCHAR*)arr[i].MsrBitmap)[0x871] |= (1 << 7);   // WRMSR 0x38F exits
        // IA32_PERF_GLOBAL_STATUS (0x38E): byte 0x71, bit 6
        ((UCHAR*)arr[i].MsrBitmap)[0x071] |= (1 << 6);   // RDMSR 0x38E exits
        ((UCHAR*)arr[i].MsrBitmap)[0x871] |= (1 << 6);   // WRMSR 0x38E exits

        // I/O bitmaps: all zeroes = no intercept (SDM Vol 3C §24.6.4).
        // Set bits for ports 0xCF8-0xCFF (PCI config address/data).
        // Bitmap A covers ports 0x0000-0x7FFF; port P -> byte P/8, bit P%8.
        RtlZeroMemory(arr[i].IoBitmapA, PAGE_SIZE);
        RtlZeroMemory(arr[i].IoBitmapB, PAGE_SIZE);
        for (USHORT port = 0xCF8; port <= 0xCFF; port++)
            ((UCHAR*)arr[i].IoBitmapA)[port / 8] |= (UCHAR)(1 << (port % 8));
    }
    return STATUS_SUCCESS;
}


// ---------------------------------------------------------------------------
// VM-exit dispatch
// ---------------------------------------------------------------------------

static void AdvanceGuestRip(void);
static void HandlePmuRdmsr(PCORE_VMX_CONTEXT Ctx);
static void HandlePmuWrmsr(PCORE_VMX_CONTEXT Ctx);

// Execute an I/O instruction on behalf of the guest and log it.
// Exit qual bits 2:0 = access size (0=byte,1=word,3=dword), bit 3 = direction (1=IN).
// Bits 31:16 = port number (SDM Vol 3C Table 27-5).
static void HandleIoAccess(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);

    USHORT port      = (USHORT)((qual >> 16) & 0xFFFF);
    BOOLEAN isIn     = (qual >> 3) & 1;
    ULONG   sizeMinus1 = (ULONG)(qual & 0x7);   // 0=byte, 1=word, 3=dword

    if (isIn) {
        ULONG val = 0;
        switch (sizeMinus1) {
        case 0: val = __inbyte(port);  break;
        case 1: val = __inword(port);  break;
        case 3: val = __indword(port); break;
        }
        // Return value in guest RAX (low bits only, high bits preserved per ABI).
        ULONG mask = (sizeMinus1 == 3) ? 0xFFFFFFFF :
                     (sizeMinus1 == 1) ? 0xFFFF : 0xFF;
        Ctx->GuestRegs.Rax = (Ctx->GuestRegs.Rax & ~(ULONG64)mask) | (val & mask);
        HV_VERBOSE_LOG("IO IN  port=0x%04X size=%u val=0x%X", port, sizeMinus1 + 1, val);
    } else {
        ULONG val = (ULONG)(Ctx->GuestRegs.Rax);
        switch (sizeMinus1) {
        case 0: __outbyte(port,  (UCHAR)val);  break;
        case 1: __outword(port,  (USHORT)val); break;
        case 3: __outdword(port, val);         break;
        }
        HV_VERBOSE_LOG("IO OUT port=0x%04X size=%u val=0x%X", port, sizeMinus1 + 1, val);
    }

    AdvanceGuestRip();
}

// Deliver entryInfo+errorCode into the VMCS injection fields right now.
// Caller must have already verified interruptibility state allows delivery.
static void DoInject(PCORE_VMX_CONTEXT Ctx, ULONG entryInfo, ULONG errorCode)
{
    if (entryInfo & (1UL << 11))
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, errorCode);
    __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, entryInfo);
    __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);
    Ctx->PendingInjection = FALSE;
    HvLogDbg("[INJECT] vec=0x%02X info=0x%08X ec=0x%X", entryInfo & 0xFF, entryInfo, errorCode);
}

// Disable interrupt-window exiting by clearing bit 2 of the live CPU-based controls.
static void ClearInterruptWindowExiting(void)
{
    ULONG64 cpu = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpu);
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpu & ~(ULONG64)CPU_BASED_INTERRUPT_WINDOW_EXITING);
}

// Enable interrupt-window exiting so we get an exit as soon as IF=1 and no blocking.
static void SetInterruptWindowExiting(void)
{
    ULONG64 cpu = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpu);
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpu | CPU_BASED_INTERRUPT_WINDOW_EXITING);
}

// Called when an exit reason has no explicit handler. Reads exit-interruption info;
// if it's a valid hardware exception (type=3), attempts immediate injection.
// If the guest is in a non-interruptible state, saves the event and arms the
// interrupt window so delivery is retried as soon as the guest can accept it.
// Returns TRUE if the event was handled (injected or deferred), FALSE to teardown.
static BOOLEAN InjectPendingException(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 intrInfo = 0;
    __vmx_vmread(VMCS_VM_EXIT_INTR_INFO, &intrInfo);

    if (!(intrInfo & (1UL << 31))) return FALSE;        // no valid event
    ULONG type = (ULONG)((intrInfo >> 8) & 0x7);
    if (type != 3) return FALSE;                        // only hardware exceptions

    ULONG entryInfo = (ULONG)(intrInfo & 0xFFFF) | (1UL << 31);
    ULONG errorCode = 0;
    if (intrInfo & (1UL << 11)) {
        ULONG64 ec = 0;
        __vmx_vmread(VMCS_VM_EXIT_INTR_ERROR_CODE, &ec);
        errorCode = (ULONG)ec;
        entryInfo |= (1UL << 11);
    }

    // Check guest interruptibility: STI shadow, MOV SS shadow, or NMI blocking.
    ULONG64 interruptibility = 0;
    __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY, &interruptibility);

    if (interruptibility & 0x3) {
        // Guest cannot accept the event right now — defer it.
        Ctx->PendingInjection  = TRUE;
        Ctx->PendingIntrInfo   = entryInfo;
        Ctx->PendingErrorCode  = errorCode;
        SetInterruptWindowExiting();
        HvLogDbg("[INJECT] deferred vec=0x%02X (interruptibility=0x%llX)", entryInfo & 0xFF, interruptibility);
    } else {
        DoInject(Ctx, entryInfo, errorCode);
    }
    return TRUE;
}

// Exit reason 7: guest is now interruptible. Re-attempt the deferred injection.
static void HandleInterruptWindow(PCORE_VMX_CONTEXT Ctx)
{
    ClearInterruptWindowExiting();
    if (Ctx->PendingInjection)
        DoInject(Ctx, Ctx->PendingIntrInfo, Ctx->PendingErrorCode);
}

static void AdvanceGuestRip(void)
{
    ULONG64 rip = 0, len = 0, ar = 0;
    __vmx_vmread(VMCS_GUEST_RIP,              &rip);
    __vmx_vmread(VMCS_VM_EXIT_INSTRUCTION_LEN, &len);
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS,  &ar);

    ULONG64 newRip = rip + len;

    // Access-rights L-bit (bit 13) = 1 → 64-bit CS (IA-32e mode): no truncation.
    // L-bit = 0, D-bit (bit 14) = 1 → 32-bit CS (compatibility mode): truncate to 32.
    // L-bit = 0, D-bit = 0 → 16-bit CS: truncate to 16.
    BOOLEAN lBit = (ar >> 13) & 1;
    BOOLEAN dBit = (ar >> 14) & 1;
    if (!lBit) {
        if (dBit)
            newRip &= 0xFFFFFFFFULL;   // 32-bit compatibility
        else
            newRip &= 0xFFFFULL;       // 16-bit real/protected
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, newRip);
}

// Enable RDTSC_EXITING for exactly one guest RDTSC after a CPUID exit.
static void ArmRdtscTrap(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 cpu = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpu);
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpu | CPU_BASED_RDTSC_EXITING);
    Ctx->RdtscPending = TRUE;
}

static void DisarmRdtscTrap(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 cpu = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpu);
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpu & ~(ULONG64)CPU_BASED_RDTSC_EXITING);
    Ctx->RdtscPending = FALSE;
}

// 48-char brand string split across three 16-byte leaves (0x80000002/3/4).
// Each leaf returns 16 bytes as four little-endian DWORDs in EAX/EBX/ECX/EDX.
// "Intel(R) Core(TM) i9-14900K CPU @ 3.20GHz" — padded to exactly 48 bytes with NULs.
static const char g_BrandString[48] =
    "Intel(R) Core(TM) i9-14900K CPU @ 3.20GHz\0\0\0\0\0";

static void HandleCpuid(PCORE_VMX_CONTEXT Ctx)
{
    ULONG leaf = (ULONG)Ctx->GuestRegs.Rax;
    int regs[4] = {0};

    // Hypervisor-range [0x40000000, 0x4FFFFFFF]: return the pre-VMXON calibrated
    // bare-metal values verbatim. On bare metal these all return zero — returning
    // anything else would fingerprint the hypervisor.
    if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
        ULONG idx = leaf - 0x40000000;
        if (idx < CPUID_CACHE_HV_LEAVES) {
            Ctx->GuestRegs.Rax = g_CpuidCache.HvRange[idx].Eax;
            Ctx->GuestRegs.Rbx = g_CpuidCache.HvRange[idx].Ebx;
            Ctx->GuestRegs.Rcx = g_CpuidCache.HvRange[idx].Ecx;
            Ctx->GuestRegs.Rdx = g_CpuidCache.HvRange[idx].Edx;
        } else {
            Ctx->GuestRegs.Rax = Ctx->GuestRegs.Rbx =
            Ctx->GuestRegs.Rcx = Ctx->GuestRegs.Rdx = 0;
        }
        AdvanceGuestRip();
        ArmRdtscTrap(Ctx);
        return;
    }

    // Beyond-max standard leaf: return the cached bare-metal response for
    // the first 8 out-of-range leaves; zero for anything farther out.
    if (leaf > g_CpuidCache.MaxStdLeaf && leaf < 0x40000000) {
        ULONG idx = leaf - (g_CpuidCache.MaxStdLeaf + 1);
        if (idx < CPUID_CACHE_BEYOND_MAX) {
            Ctx->GuestRegs.Rax = g_CpuidCache.BeyondMax[idx].Eax;
            Ctx->GuestRegs.Rbx = g_CpuidCache.BeyondMax[idx].Ebx;
            Ctx->GuestRegs.Rcx = g_CpuidCache.BeyondMax[idx].Ecx;
            Ctx->GuestRegs.Rdx = g_CpuidCache.BeyondMax[idx].Edx;
        } else {
            Ctx->GuestRegs.Rax = Ctx->GuestRegs.Rbx =
            Ctx->GuestRegs.Rcx = Ctx->GuestRegs.Rdx = 0;
        }
        AdvanceGuestRip();
        ArmRdtscTrap(Ctx);
        return;
    }

    // Normal leaf: execute on hardware and apply stealth patches.
    __cpuidex(regs, (int)leaf, (int)Ctx->GuestRegs.Rcx);

    if (leaf == 1)
        regs[2] &= ~(1 << 31);     // clear hypervisor present bit (ECX[31])

    if (leaf == 0x80000002 || leaf == 0x80000003 || leaf == 0x80000004) {
        const ULONG *p = (const ULONG *)(g_BrandString + (leaf - 0x80000002) * 16);
        regs[0] = p[0]; regs[1] = p[1]; regs[2] = p[2]; regs[3] = p[3];
    }

    Ctx->GuestRegs.Rax = (ULONG64)(ULONG)regs[0];
    Ctx->GuestRegs.Rbx = (ULONG64)(ULONG)regs[1];
    Ctx->GuestRegs.Rcx = (ULONG64)(ULONG)regs[2];
    Ctx->GuestRegs.Rdx = (ULONG64)(ULONG)regs[3];
    AdvanceGuestRip();
    ArmRdtscTrap(Ctx);
}

// Exit reason 16: RDTSC fired because we armed RDTSC_EXITING after a CPUID.
// Return a TSC value that is monotonic but accounts for the VM-exit overhead,
// matching what the guest would have observed on bare metal. Immediately
// disarm RDTSC_EXITING so subsequent RDTSC instructions pass through freely.
static void HandleRdtsc(PCORE_VMX_CONTEXT Ctx)
{
    // Read hardware TSC, then subtract the calibrated bare-metal CPUID cost.
    // This gives the guest a value consistent with "CPUID ran, then RDTSC ran
    // right after" without the VM-exit latency inflating the measurement.
    ULONG64 tsc = __rdtsc();
    if (tsc > g_CpuidCache.CpuidExitCost)
        tsc -= g_CpuidCache.CpuidExitCost;

    Ctx->GuestRegs.Rax = tsc & 0xFFFFFFFFULL;
    Ctx->GuestRegs.Rdx = (tsc >> 32) & 0xFFFFFFFFULL;

    DisarmRdtscTrap(Ctx);
    AdvanceGuestRip();
}

static void HandleRdmsr(PCORE_VMX_CONTEXT Ctx)
{
    ULONG msr = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val = 0;

    if (msr == IA32_MPERF) {
        // Arm offset tracking on first guest access; subsequent exits will
        // snapshot MPERF/APERF and accumulate the overhead.
        Ctx->AperMperfActive = TRUE;
        val = __readmsr(IA32_MPERF) - Ctx->MperfOffset;
    } else if (msr == IA32_APERF) {
        Ctx->AperMperfActive = TRUE;
        val = __readmsr(IA32_APERF) - Ctx->AperOffset;
    } else if (msr == IA32_FEATURE_CONTROL) {
        // Firmware-Locked stealth: Lock=1, EnableVmxOutsideSmx=0.
        // Guest sees hardware as VMX-capable (CPUID.1.ECX[5]=1) but firmware
        // locked before enabling VMXON, identical to a machine with VMX off in
        // BIOS. A correct VMX-presence check bails out here and never tries VMXON.
        // Preserve bits [14:8] (SENTER/GETSEC) so VBS/Hyper-V capability checks
        // that cross-reference CPUID against FEATURE_CONTROL still pass.
        val = (__readmsr(IA32_FEATURE_CONTROL) & ~0x7ULL)  // clear Lock + SMX + non-SMX bits
            | 0x1ULL;                                        // set Lock only
        HV_VERBOSE_LOG("RDMSR IA32_FEATURE_CONTROL -> 0x%llX (locked)", val);
    } else if (msr == IA32_APIC_BASE) {
        val = __readmsr(IA32_APIC_BASE);
        HV_VERBOSE_LOG("RDMSR IA32_APIC_BASE -> 0x%llX", val);
    } else if (msr == IA32_ENERGY_PERF_BIAS) {
        val = 0x6;   // balanced — nominal Windows default, hides exit-driven power oscillation
        HV_VERBOSE_LOG("RDMSR IA32_ENERGY_PERF_BIAS -> 0x%llX (spoofed)", val);
    } else if (msr == IA32_PACKAGE_THERM_STATUS) {
        val = 0x0;   // all status/log bits clear — no thermal events reported
        HV_VERBOSE_LOG("RDMSR IA32_PACKAGE_THERM_STATUS -> 0x%llX (spoofed)", val);
    } else if (msr == IA32_LSTAR) {
        // Return the per-core shadow, not the live hardware value.
        // The shadow is seeded at VMLAUNCH time and updated by every unlocked
        // WRMSR IA32_LSTAR, so it always equals what the guest last wrote.
        val = Ctx->GuestLstar;
        HV_VERBOSE_LOG("RDMSR IA32_LSTAR -> 0x%llX (shadow)", val);
    } else if (msr == IA32_DEBUGCTL) {
        val = __readmsr(IA32_DEBUGCTL);
        HV_VERBOSE_LOG("RDMSR IA32_DEBUGCTL -> 0x%llX", val);
    } else if (msr == IA32_RTIT_CTL) {
        // Return the guest's shadow value; the hardware register has TraceEn=0
        // while in VMX-root so the host's own execution is never traced.
        val = Ctx->GuestRtitCtl;
        HV_VERBOSE_LOG("RDMSR IA32_RTIT_CTL -> shadow=0x%llX", val);
    } else if (msr == IA32_XSS) {
        val = Ctx->GuestXss;
        HV_VERBOSE_LOG("RDMSR IA32_XSS -> shadow=0x%llX", val);
    } else if (msr == IA32_LBR_CTL) {
        // If hardware Arch-LBR auto-swap is active the guest state is in the
        // hardware register (CPU restores it on VM-entry); read it directly.
        val = Ctx->LbrVirtEnabled ? __readmsr(IA32_LBR_CTL) : 0;
        HV_VERBOSE_LOG("RDMSR IA32_LBR_CTL -> 0x%llX", val);
    } else if (msr == IA32_PERF_GLOBAL_CTRL ||
               msr == IA32_PERF_GLOBAL_STATUS ||
               msr == IA32_PERF_GLOBAL_OVF_CTRL ||
               msr == IA32_FIXED_CTR_CTRL) {
        HandlePmuRdmsr(Ctx);
        return;   // HandlePmuRdmsr calls AdvanceGuestRip itself
    } else if (msr == IA32_VMX_BASIC || (msr >= 0x481 && msr <= 0x48B)) {
        val = 0;
    } else if (msr >= 0x40000000 && msr <= 0x400000FF) {
        // Hypervisor-synthetic MSR range: return all zeros.
        // Prevents guests from detecting Hyper-V enlightenment protocols.
        val = 0;
    } else {
        val = __readmsr(msr);
        HV_VERBOSE_LOG("RDMSR 0x%X -> 0x%llX", msr, val);
    }

    Ctx->GuestRegs.Rax = val & 0xFFFFFFFF;
    Ctx->GuestRegs.Rdx = (val >> 32) & 0xFFFFFFFF;
    AdvanceGuestRip();
}

static void HandleWrmsr(PCORE_VMX_CONTEXT Ctx)
{
    ULONG msr = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val = ((Ctx->GuestRegs.Rdx & 0xFFFFFFFF) << 32) |
                  (Ctx->GuestRegs.Rax & 0xFFFFFFFF);

    if (msr == IA32_MPERF || msr == IA32_APERF) {
        // MPERF and APERF are read-only on Intel — WRMSR causes #GP(0) on
        // bare metal. Inject it to match real hardware behaviour.
        ULONG gpInfo = 0x0D | (3UL << 8) | (1UL << 31);  // #GP, hw exception, valid
        __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, gpInfo);
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
        __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 2);  // WRMSR is 2 bytes
        HV_VERBOSE_LOG("WRMSR MPERF/APERF 0x%X -> #GP (read-only)", msr);
        return;
    }
    if (msr == IA32_FEATURE_CONTROL) {
        HV_VERBOSE_LOG("WRMSR IA32_FEATURE_CONTROL swallowed val=0x%llX", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_APIC_BASE) {
        HV_VERBOSE_LOG("WRMSR IA32_APIC_BASE swallowed remap to 0x%llX", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_ENERGY_PERF_BIAS || msr == IA32_PACKAGE_THERM_STATUS) {
        HV_VERBOSE_LOG("WRMSR thermal/power 0x%X swallowed val=0x%llX", msr, val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_LSTAR) {
        if (g_LstarLocked) {
            // Lock is set — reject the write. Inject #GP(0) so the guest gets a
            // deterministic architectural fault rather than a silent discard.
            // A legitimate OS never writes LSTAR after boot; only a rootkit or
            // exploit targeting the syscall entry point does.
            ULONG64 current = __readmsr(IA32_LSTAR);
            HvLog("!!! DayZHV: [LSTAR] LOCKED write rejected: attempted=0x%llX current=0x%llX  core=%u",
                  val, current, KeGetCurrentProcessorNumberEx(NULL));
            ULONG gpInfo = (13UL << 8) | (3UL << 8) | (1UL << 31) | (1UL << 11);
            // #GP vector=13, type=hardware exception (3), error-code valid (bit 11), valid (bit 31)
            __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD,
                          13UL | (3UL << 8) | (1UL << 11) | (1UL << 31));
            __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
            __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 2); // WRMSR is 2 bytes
            UNREFERENCED_PARAMETER(gpInfo);
            return; // do not advance RIP — exception delivery re-executes from faulting RIP
        }
        // Lock not yet set — pass through and update the per-core shadow so
        // subsequent RDMSR and the pre-VMRESUME restore both see the new value.
        HV_VERBOSE_LOG("WRMSR IA32_LSTAR -> 0x%llX (unlocked)", val);
        Ctx->GuestLstar = val;
        __writemsr(IA32_LSTAR, val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_DEBUGCTL) {
        HV_VERBOSE_LOG("WRMSR IA32_DEBUGCTL -> 0x%llX", val);
        // Pass through; the host must not hold stale LBR/BTS state that leaks
        // into VMX-root mode and confuses the guest's debug view.
        __writemsr(IA32_DEBUGCTL, val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_RTIT_CTL) {
        // Save the full guest intent, but strip TraceEn (bit 0) before writing
        // to hardware. The CPU will not record VMX-root execution in the guest's
        // trace buffer. When the guest eventually VMRESUMEs, TraceEn remains
        // clear in hardware — the guest's trace picks up only after the next
        // WRMSR that re-enables it (which will re-enter this handler).
        Ctx->GuestRtitCtl = val;
        __writemsr(IA32_RTIT_CTL, val & ~1ULL);  // TraceEn=0 while in VMX-root
        HV_VERBOSE_LOG("WRMSR IA32_RTIT_CTL shadow=0x%llX hw=0x%llX", val, val & ~1ULL);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_XSS) {
        // XSS audit (M4): IA32_XSS controls supervisor-state XSAVE components
        // (XSAVES/XRSTORS, not XSAVEC/XRSTOR). Our AsmVmExitHandler uses
        // XSAVEC64/XRSTOR64, which are governed by XCR0 (XSaveMask), not XSS.
        // Therefore the guest's XSS value does not affect our save/restore path
        // and is safe to pass through to hardware without masking. Shadow is
        // maintained in GuestXss for RDMSR transparency.
        Ctx->GuestXss = val;
        __writemsr(IA32_XSS, val);
        HV_VERBOSE_LOG("WRMSR IA32_XSS -> 0x%llX", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_LBR_CTL) {
        // If Arch-LBR auto-swap is active, write directly — the CPU saves/restores
        // the full LBR stack automatically on VM-exit/entry so there is no host
        // pollution. If not active, swallow (guest LBR not fully virtualized).
        if (Ctx->LbrVirtEnabled)
            __writemsr(IA32_LBR_CTL, val);
        HV_VERBOSE_LOG("WRMSR IA32_LBR_CTL -> 0x%llX active=%u", val, Ctx->LbrVirtEnabled);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_PERF_GLOBAL_CTRL ||
        msr == IA32_PERF_GLOBAL_STATUS ||
        msr == IA32_PERF_GLOBAL_OVF_CTRL ||
        msr == IA32_FIXED_CTR_CTRL) {
        HandlePmuWrmsr(Ctx);
        return;
    }
    if (msr == IA32_VMX_BASIC || (msr >= 0x481 && msr <= 0x48B)) {
        AdvanceGuestRip();
        return;
    }
    if (msr >= 0x40000000 && msr <= 0x400000FF) {
        // Synthetic MSR range: writes are illegal on bare metal — inject #GP(0).
        // Do NOT advance RIP; #GP delivers the faulting instruction address.
        ULONG gpInfo = (0x0D) |    // vector 13 = #GP
                       (3UL << 8)  | // type 3 = hardware exception
                       (1UL << 31);  // valid
        __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, gpInfo);
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
        __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 2); // WRMSR is 2 bytes
        HV_VERBOSE_LOG("WRMSR synthetic 0x%X -> #GP", msr);
        return;
    }
    HV_VERBOSE_LOG("WRMSR 0x%X = 0x%llX", msr, val);
    __writemsr(msr, val);
    AdvanceGuestRip();
}

// DR read helpers — no intrinsic for DR0-DR3/DR6/DR7 reads in MSVC kernel mode.
static ULONG64 ReadDr(ULONG n) {
    switch (n) {
    case 0: return __readdr(0);
    case 1: return __readdr(1);
    case 2: return __readdr(2);
    case 3: return __readdr(3);
    case 6: return __readdr(6);
    case 7: return __readdr(7);
    default: return 0;
    }
}
static void WriteDr(ULONG n, ULONG64 v) {
    switch (n) {
    case 0: __writedr(0, v); break;
    case 1: __writedr(1, v); break;
    case 2: __writedr(2, v); break;
    case 3: __writedr(3, v); break;
    case 6: __writedr(6, v); break;
    case 7: __writedr(7, v); break;
    }
}

// GPR byte offsets inside GUEST_REGS — indexed by exit-qualification bits 11:8.
static const SIZE_T GprOffsets[16] = {
    FIELD_OFFSET(GUEST_REGS, Rax), FIELD_OFFSET(GUEST_REGS, Rcx),
    FIELD_OFFSET(GUEST_REGS, Rdx), FIELD_OFFSET(GUEST_REGS, Rbx),
    FIELD_OFFSET(GUEST_REGS, Rsp), FIELD_OFFSET(GUEST_REGS, Rbp),
    FIELD_OFFSET(GUEST_REGS, Rsi), FIELD_OFFSET(GUEST_REGS, Rdi),
    FIELD_OFFSET(GUEST_REGS, R8),  FIELD_OFFSET(GUEST_REGS, R9),
    FIELD_OFFSET(GUEST_REGS, R10), FIELD_OFFSET(GUEST_REGS, R11),
    FIELD_OFFSET(GUEST_REGS, R12), FIELD_OFFSET(GUEST_REGS, R13),
    FIELD_OFFSET(GUEST_REGS, R14), FIELD_OFFSET(GUEST_REGS, R15),
};

static void HandleCrAccess(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);

    ULONG cr      = (ULONG)(qual & 0xF);
    ULONG type    = (ULONG)((qual >> 4) & 0x3);
    ULONG gpr_idx = (ULONG)((qual >> 8) & 0xF);

    ULONG64 *gpr = (ULONG64*)((UCHAR*)&Ctx->GuestRegs + GprOffsets[gpr_idx]);

    if (type == 0) {  // MOV to CR
        switch (cr) {
        case 0:
            __vmx_vmwrite(VMCS_GUEST_CR0,       *gpr);
            __vmx_vmwrite(VMCS_CR0_READ_SHADOW,  *gpr);
            HV_VERBOSE_LOG("MOV CR0 <- 0x%llX", *gpr);
            break;
        case 3:
            __vmx_vmwrite(VMCS_GUEST_CR3, *gpr);
            HV_VERBOSE_LOG("MOV CR3 <- 0x%llX", *gpr);
            break;
        case 4: {
            ULONG64 requested = *gpr;
            ULONG64 enforced = (requested | CR4_SMEP | CR4_SMAP) & ~CR4_VMXE;
            __vmx_vmwrite(VMCS_GUEST_CR4,       enforced);
            __vmx_vmwrite(VMCS_CR4_READ_SHADOW, requested & ~CR4_VMXE);
            // Log CR4 writes that clear SMEP/SMAP — always visible, not gated.
            if ((requested & (CR4_SMEP | CR4_SMAP)) != (CR4_SMEP | CR4_SMAP))
                HvLogDbg("[CR4] guest cleared SMEP/SMAP: req=0x%llX enforced=0x%llX",
                         requested, enforced);
            else
                HV_VERBOSE_LOG("MOV CR4 <- req=0x%llX enforced=0x%llX", requested, enforced);
            break;
        }
        }
    } else if (type == 1) {  // MOV from CR
        ULONG64 val = 0;
        switch (cr) {
        case 0: __vmx_vmread(VMCS_GUEST_CR0, &val); break;
        case 3: __vmx_vmread(VMCS_GUEST_CR3, &val); break;
        case 4: __vmx_vmread(VMCS_GUEST_CR4, &val); break;
        }
        *gpr = val;
    }

    AdvanceGuestRip();
}

// Exit reason 29: MOV DRn, GPR  or  MOV GPR, DRn.
// Maintain a per-core guest DR shadow so the guest sees a consistent bare-metal
// debug register state. DR4/DR5 alias DR6/DR7 when CR4.DE=0 (the Windows default).
static void HandleDrAccess(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);

    ULONG dr      = (ULONG)(qual & 0x7);
    ULONG dir     = (ULONG)((qual >> 4) & 0x1);  // 0=write to DR, 1=read from DR
    ULONG gpr_idx = (ULONG)((qual >> 8) & 0xF);

    // DR4/DR5 alias DR6/DR7 when CR4.DE=0.
    if (dr == 4) dr = 6;
    if (dr == 5) dr = 7;

    ULONG64 *gpr = (ULONG64*)((UCHAR*)&Ctx->GuestRegs + GprOffsets[gpr_idx]);

    if (dir == 0) {
        // MOV DR, GPR — guest writing a debug register.
        // AsmVmExitHandler loaded guest shadow into hardware on entry; write the
        // new value to the shadow. The ASM stub flushes hardware back to shadow
        // after dispatch returns, so DR0-DR3/DR6 hardware are kept in sync.
        // DR7 is VMCS-managed (not in the hardware flush path) — write it directly.
        Ctx->GuestDr[dr] = *gpr;
        Ctx->DrDirty = TRUE;
        if (dr == 7)
            __vmx_vmwrite(VMCS_GUEST_DR7, *gpr);
        HV_VERBOSE_LOG("MOV DR%u <- 0x%llX", dr, *gpr);
    } else {
        // MOV GPR, DR — guest reading a debug register.
        *gpr = Ctx->GuestDr[dr];
        HV_VERBOSE_LOG("MOV GPR <- DR%u val=0x%llX", dr, *gpr);
    }

    AdvanceGuestRip();
}

static void HandleXsetbv(PCORE_VMX_CONTEXT Ctx)
{
    ULONG   xcr   = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val   = ((Ctx->GuestRegs.Rdx & 0xFFFFFFFF) << 32) |
                     (Ctx->GuestRegs.Rax & 0xFFFFFFFF);
    HV_VERBOSE_LOG("XSETBV XCR%u=0x%llX", xcr, val);
    _xsetbv(xcr, val);
    AdvanceGuestRip();
}

static void HandleDescriptorTable(PCORE_VMX_CONTEXT Ctx, ULONG reason)
{
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
    ULONG instr = (ULONG)(qual & 0x3);

    static const char* const gdtrIdtrNames[] = { "SGDT", "SIDT", "LGDT", "LIDT" };
    static const char* const ldtrTrNames[]   = { "SLDT", "STR",  "LLDT", "LTR"  };

    const char *name = (reason == VMX_EXIT_REASON_GDTR_IDTR)
                       ? gdtrIdtrNames[instr] : ldtrTrNames[instr];

    HV_VERBOSE_LOG("DESC-TABLE %s qual=0x%llX", name, qual);

    AdvanceGuestRip();
}

// Forward declaration — HandleHypercall is defined later in this TU but
// called by HandleEptIpcViolation which precedes it.
static void HandleHypercall(PCORE_VMX_CONTEXT Ctx);

// ---------------------------------------------------------------------------
// HandleEptIpcViolation — EPT-violation IPC channel dispatch.
//
// Called when a guest write lands on HV_IPC_GPA (the sentinel non-present
// page).  The guest encodes the request by storing a 24-byte struct at the
// faulting linear address:
//
//   +00h  ULONG64  id    — hypercall ID (one of HV_CALL_*)
//   +08h  ULONG64  arg0  — same semantics as RBX in the VMCALL ABI
//   +10h  ULONG64  arg1  — same semantics as RCX in the VMCALL ABI
//
// The handler reads the struct from the guest linear address (valid kernel VA
// in the same physical address space as the host), dispatches through the
// same logic as HandleHypercall, advances RIP, and returns.
//
// The IPC GPA remains non-present after dispatch — no leaf PTE is installed —
// so every future write triggers a new violation.
// ---------------------------------------------------------------------------
typedef struct _IPC_PAYLOAD {
    ULONG64 Id;
    ULONG64 Arg0;
    ULONG64 Arg1;
} IPC_PAYLOAD;

static void HandleEptIpcViolation(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 gla = 0;
    __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &gla);

    // gla is a kernel VA valid in this address space — direct read is safe
    // because the IPC caller must have mapped the page.  An unmapped VA here
    // would mean a guest bug; we guard with __try so a bad GLA doesn't tear down.
    IPC_PAYLOAD payload = {0};
    __try {
        RtlCopyMemory(&payload, (PVOID)gla, sizeof(payload));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HvLogDbg("[IPC] EPT-IPC: bad guest linear address 0x%llX — ignored", gla);
        AdvanceGuestRip();
        return;
    }

    HvLogDbg("[IPC] EPT-IPC: id=0x%llX arg0=0x%llX arg1=0x%llX gla=0x%llX",
             payload.Id, payload.Arg0, payload.Arg1, gla);

    // Synthesise the same register state HandleHypercall reads from GuestRegs
    // so we can re-use the existing hypercall dispatch table.
    ULONG64 savedRax = Ctx->GuestRegs.Rax;
    ULONG64 savedRbx = Ctx->GuestRegs.Rbx;
    ULONG64 savedRcx = Ctx->GuestRegs.Rcx;

    Ctx->GuestRegs.Rax = payload.Id;
    Ctx->GuestRegs.Rbx = payload.Arg0;
    Ctx->GuestRegs.Rcx = payload.Arg1;

    // Borrow HandleHypercall's dispatch — it calls AdvanceGuestRip internally.
    // We must NOT call AdvanceGuestRip again after this.
    HandleHypercall(Ctx);

    // Write the result back to ipc[3] (+18h from the faulting GLA) so the
    // ring-0 driver can read it synchronously after the store retires.
    // Guard with __try: the GLA is a non-paged KVA mapped by MmMapIoSpace,
    // but be defensive against a teardown race.
    ULONG64 result = Ctx->GuestRegs.Rax;
    __try {
        *(volatile ULONG64 *)(gla + 0x18) = result;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HvLogDbg("[IPC] EPT-IPC: failed to write result to GLA+18h=0x%llX", gla + 0x18);
    }

    // Restore caller's RBX/RCX; leave RAX as the result (VMCALL ABI convention).
    Ctx->GuestRegs.Rbx = savedRbx;
    Ctx->GuestRegs.Rcx = savedRcx;
    (void)savedRax;
}

static void HandleEptViolation(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 gpa  = 0;
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION,     &qual);

    // EPT-violation IPC channel: write to the sentinel non-present GPA.
    // Dispatch through the hypercall ABI without emitting a VMCALL instruction.
    if ((gpa & HV_IPC_GPA_MASK) == (HV_IPC_GPA & HV_IPC_GPA_MASK) &&
        (qual & EPT_QUAL_WRITE)) {
        HandleEptIpcViolation(Ctx);
        return;
    }

    ULONG shadowResult = EptHandleViolation(&g_Ept, gpa, qual);

    if (shadowResult == EPT_VIOLATION_HANDLED) {
        // R/W on a hidden page — decoy served and INVEPT done inside Ept.c.
        // Faulting access re-executes against the now-mapped decoy PTE.
        InterlockedExchange(&g_InveptPending, 1);  // signal other cores to flush
        return;
    }

    if (shadowResult == EPT_VIOLATION_EXEC) {
        // Execute fault on a hidden data page.
        // Inject #PF(0): vector 14, type 3 (hardware exception), error-code
        // valid (bit 11), valid (bit 31). Error code 0 = non-present, no write,
        // supervisor fetch — matches a normal not-present page fault.
        // Guest RIP is NOT advanced; #PF re-delivers from the faulting instruction.
        __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD,
                      0x0EUL | (3UL << 8) | (1UL << 11) | (1UL << 31));
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
        __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);
        return;
    }

    // Write-integrity check: guest tried to write a hypervisor-protected GPA.
    // Inject #GP(0) — architecturally correct for a write to a read-only page.
    if ((qual & EPT_QUAL_WRITE) && WpTableContains(gpa)) {
        HvLog("!!! DayZHV: [WP] Write on protected GPA=0x%llX qual=0x%llX -> #GP(0)",
              gpa & ~0xFFFULL, qual);
        __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD,
                      0x0DUL | (3UL << 8) | (1UL << 11) | (1UL << 31));
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
        __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);
        return;
    }

    // MBEC user-execute fault on an untracked page.
    // This page is a normal OS code page that the guest mapped user-executable
    // but whose 4KB PTE (after a prior split) lost EPT_EXEC_USER. Lazy-grant it
    // rather than injecting #GP — nothing on bare metal injects #GP for a valid
    // user-mode code fetch, and doing so is itself a detection surface.
    if (g_MbecEnabled && (qual & EPT_QUAL_EXEC_USER)) {
        ULONG64 aligned = gpa & ~0xFFFULL;
        ULONG64 hpa     = aligned;   // identity map

        // Split any covering 2MB page and set both supervisor and user execute bits.
        EptMapPage4KB(&g_Ept, aligned, hpa,
                      EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER | EPT_MEMTYPE_WB);
        EptInvalidate(g_Ept.Eptp);
        InterlockedExchange(&g_InveptPending, 1);  // signal other cores to flush
        // No AdvanceGuestRip — faulting fetch re-executes after PTE is fixed.
        return;
    }

    // Unprotected GPA (MMIO hole or lazy-map gap): identity-map 4KB UC and retry.
    HV_VERBOSE_LOG("EPT lazy-map GPA=0x%llX qual=0x%llX", gpa & ~0xFFFULL, qual);
    EptMapPage4KB(&g_Ept, gpa & ~0xFFFULL, gpa & ~0xFFFULL, EPT_RWX | EPT_MEMTYPE_UC);
    EptInvalidate(g_Ept.Eptp);
    InterlockedExchange(&g_InveptPending, 1);  // signal other cores to flush
}

// ---------------------------------------------------------------------------
// MTF arm / disarm — Monitor Trap Flag single-step API.
// Writes directly into the currently-loaded VMCS via VMWRITE. Must only be
// called from within a VM-exit handler (VMCS is guaranteed current).
// ---------------------------------------------------------------------------
void MtfArm(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 cpuCtl = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpuCtl);
    cpuCtl |= CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpuCtl);
    Ctx->MtfArmed = TRUE;
    HvLogDbg("[MTF] core=%02u armed", KeGetCurrentProcessorNumberEx(NULL));
}

void MtfDisarm(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 cpuCtl = 0;
    __vmx_vmread(VMCS_CPU_BASED_VM_EXEC_CONTROL, &cpuCtl);
    cpuCtl &= ~(ULONG64)CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpuCtl);
    Ctx->MtfArmed = FALSE;
}

// ---------------------------------------------------------------------------
// HandleMtf — EXIT_REASON_MTF (37)
// Fires after every guest instruction while MTF is set in CPU-based controls.
// Logs the current guest RIP and key register state, then self-disarms.
// Callers re-arm via MtfArm for continued single-stepping.
// ---------------------------------------------------------------------------
static void HandleMtf(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 rip = 0;
    __vmx_vmread(VMCS_GUEST_RIP, &rip);
    HvLogDbg("[MTF] RIP=0x%llX RAX=0x%llX RBX=0x%llX RCX=0x%llX RDX=0x%llX",
             rip, Ctx->GuestRegs.Rax, Ctx->GuestRegs.Rbx,
             Ctx->GuestRegs.Rcx, Ctx->GuestRegs.Rdx);
    // MTF auto-clears after each exit — we just clear our tracking flag.
    // The bit in CPU-based controls persists; we clear it here so single-step
    // is one-shot per MtfArm() call. Callers re-arm explicitly to continue.
    MtfDisarm(Ctx);
}

// ---------------------------------------------------------------------------
// HandleException — EXIT_REASON_EXCEPTION_NMI (0)
// Dispatches #DB (vector 1) and #PF (vector 14) exits from the exception bitmap.
// Other intercepted vectors are re-injected transparently.
// ---------------------------------------------------------------------------
static void HandleException(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 intrInfo = 0;
    __vmx_vmread(VMCS_VM_EXIT_INTR_INFO, &intrInfo);

    ULONG vector    = (ULONG)(intrInfo & 0xFF);
    ULONG intrType  = (ULONG)((intrInfo >> 8) & 0x7);   // 3 = hw exception
    BOOLEAN hasErr  = (intrInfo >> 11) & 1;
    ULONG64 errCode = 0;
    if (hasErr) __vmx_vmread(VMCS_VM_EXIT_INTR_ERROR_CODE, &errCode);

    if (vector == 1) {
        // #DB — Debug exception.
        // Read DR6 to distinguish single-step (BS bit) from breakpoint (B0-B3).
        ULONG64 dr6 = __readdr(6);
        ULONG64 rip = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &rip);
        HV_VERBOSE_LOG("[#DB] RIP=0x%llX DR6=0x%llX", rip, dr6);
    } else if (vector == 14) {
        ULONG64 cr2 = 0, rip = 0;
        __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &cr2);
        __vmx_vmread(VMCS_GUEST_RIP, &rip);
        HV_VERBOSE_LOG("[#PF] RIP=0x%llX CR2=0x%llX err=0x%llX", rip, cr2, errCode);
    } else {
        ULONG64 rip = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &rip);
        HvLogDbg("[EXC] vec=%u type=%u err=0x%llX RIP=0x%llX", vector, intrType, errCode, rip);
    }

    // Re-inject the exception into the guest. The VM-entry interruption-info
    // field uses the same encoding as the exit interruption-info field, so we
    // can forward it directly (masking reserved bits per SDM §26.2.1.3).
    ULONG64 injectInfo = (intrInfo & 0x80000FFF);  // valid + type + vector + hasErr
    __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, injectInfo);
    if (hasErr) {
        __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, errCode);
    }
    // Instruction length: required for software exceptions; for hw exceptions
    // the CPU ignores this field, but write 0 to keep the VMCS clean.
    __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);
    // No AdvanceGuestRip — the exception re-delivers at the faulting RIP.
    UNREFERENCED_PARAMETER(Ctx);
}

// ---------------------------------------------------------------------------
// ProbeHlat — CPUID[0x20,0].EBX bit 0 signals HLAT support.
// Returns FALSE on every current Raptor Lake desktop SKU.
// ---------------------------------------------------------------------------
BOOLEAN ProbeHlat(void)
{
    int regs[4];
    // First check CPUID max leaf — leaf 0x20 is only valid on Sapphire Rapids+.
    __cpuid(regs, 0);
    if ((ULONG)regs[0] < CPUID_HLAT_LEAF) {
        HvLog("!!! DayZHV: [HLAT] Not available: CPUID max leaf=0x%X < 0x%X (Raptor Lake)",
              (ULONG)regs[0], CPUID_HLAT_LEAF);
        return FALSE;
    }
    __cpuidex(regs, CPUID_HLAT_LEAF, 0);
    BOOLEAN present = (regs[1] & 1) != 0;
    HvLog("!!! DayZHV: [HLAT] CPUID[0x20,0].EBX=0x%X  supported=%u", (ULONG)regs[1], present);
    if (!present) {
        HvLog("!!! DayZHV: [HLAT] Not present on this CPU. Nearest Raptor Lake analogue: "
              "EPT A/D bits (Phase 2, already active) for hardware-tracked access patterns. "
              "Full HLAT (HLATP prefix table, IA32_VMX_TERTIARY bit 1) requires Sapphire "
              "Rapids Xeon (2023) or later.");
    }
    return present;
}

// ---------------------------------------------------------------------------
// HandleHypercall — EXIT_REASON_VMCALL hypercall dispatcher.
//
// Calling convention (Ring 0 guest driver executes VMCALL):
//   RAX = hypercall ID
//   RBX = arg0
//   RCX = arg1  (RCX is saved in GuestRegs before the exit)
//   RDX = arg2
//
// On return, guest RAX holds the status code. Other registers are unchanged.
// RIP is advanced past the VMCALL instruction by AdvanceGuestRip().
// ---------------------------------------------------------------------------
static void HandleHypercall(PCORE_VMX_CONTEXT Ctx)
{
    ULONG64 id   = Ctx->GuestRegs.Rax;
    ULONG64 arg0 = Ctx->GuestRegs.Rbx;
    ULONG64 result = HV_STATUS_SUCCESS;

    switch (id) {

    case 0x00ULL:
        // Version / heartbeat check.  Returns HV_IPC_VERSION so the caller can
        // confirm the hypervisor ABI version before issuing more complex calls.
        result = HV_IPC_VERSION;
        break;

    case HV_CALL_MTF_TOGGLE:
        // arg0: 1 = arm MTF, 0 = disarm.
        if (arg0)
            MtfArm(Ctx);
        else
            MtfDisarm(Ctx);
        HvLogDbg("[HC 0x01] MTF %s", arg0 ? "armed" : "disarmed");
        break;

    case HV_CALL_EPT_SWITCH_VIEW: {
        // arg0: EPTP list index (0-511). Validates range and that the slot is
        // non-zero before writing the new EPTP into VMCS_EPT_POINTER directly.
        // This is the software fallback for VMFUNC; hardware VMFUNC (leaf 0)
        // never exits so this path handles explicit out-of-guest requests.
        if (!Ctx->EptpListPage || arg0 >= 512) {
            result = HV_STATUS_NOT_SUPPORTED;
            break;
        }
        ULONG64 newEptp = ((ULONG64*)Ctx->EptpListPage)[arg0];
        if (newEptp == 0) {
            result = HV_STATUS_INVALID_CALL;
            break;
        }
        __vmx_vmwrite(VMCS_EPT_POINTER, newEptp);
        EptInvalidate(newEptp);
        HvLogDbg("[HC 0x02] EPT view switch slot=%llu EPTP=0x%llX", arg0, newEptp);
        break;
    }

    case HV_CALL_GET_PERF_COUNTERS:
        // Return MperfOffset in RAX and AperOffset in RBX.
        // The caller reads these to determine how many MPERF/APERF ticks were
        // consumed by hypervisor exits during the measurement window.
        result = Ctx->MperfOffset;
        Ctx->GuestRegs.Rbx = Ctx->AperOffset;
        HvLogDbg("[HC 0x03] Mperf=%llu Aper=%llu", Ctx->MperfOffset, Ctx->AperOffset);
        break;

    case HV_CALL_SET_EPT_POLICY: {
        ULONG64 gpa    = Ctx->GuestRegs.Rbx;
        ULONG64 policy = Ctx->GuestRegs.Rcx;

        // GPA must be 4KB-aligned.
        if (gpa & 0xFFFULL) {
            result = HV_STATUS_BAD_ALIGNMENT;
            HvLogDbg("[HC 0x05] SET_EPT_POLICY rejected: GPA=0x%llX not 4KB-aligned", gpa);
            break;
        }
        // Strip any bits outside the valid policy mask to prevent EPT entry corruption.
        policy &= HV_EPT_POLICY_MASK;

        // EPT_EXEC_USER (bit 10) is only meaningful when MBEC is active.
        // Reject rather than silently ignore so the caller knows the hardware
        // does not support the requested policy granularity.
        if ((policy & EPT_EXEC_USER) && !g_MbecEnabled) {
            result = HV_STATUS_NOT_SUPPORTED;
            HvLogDbg("[HC 0x05] SET_EPT_POLICY rejected: MBEC not active");
            break;
        }

        // Identity map: GPA == HPA. EptMapPage4KB splits any covering 2MB PDE
        // automatically before installing the 4KB PTE with the requested policy.
        EptMapPage4KB(&g_Ept, gpa, gpa, policy | EPT_MEMTYPE_WB);
        EptInvalidate(g_Ept.Eptp);  // flush this core immediately
        InterlockedExchange(&g_InveptPending, 1);  // signal other cores to flush

        HvLogDbg("[HC 0x05] SET_EPT_POLICY GPA=0x%llX R=%u W=%u SX=%u UX=%u",
                 gpa,
                 (policy & EPT_READ)      ? 1 : 0,
                 (policy & EPT_WRITE)     ? 1 : 0,
                 (policy & EPT_EXEC)      ? 1 : 0,
                 (policy & EPT_EXEC_USER) ? 1 : 0);
        break;
    }

    case HV_CALL_LOCK_LSTAR: {
        ULONG64 current = __readmsr(IA32_LSTAR);
        if (g_LstarLocked) {
            HvLogDbg("[HC 0x06] LOCK_LSTAR: already locked at 0x%llX", current);
        } else {
            g_LstarLocked = TRUE;
            HvLog("!!! DayZHV: [LSTAR] Locked at 0x%llX — subsequent WRMSR will #GP", current);
        }
        result = HV_STATUS_SUCCESS;
        break;
    }

    case HV_CALL_WP_REGISTER: {
        ULONG64 gpa = arg0 & ~0xFFFULL;   // arg0 = RBX = GPA

        if (arg0 & 0xFFFULL) {
            result = HV_STATUS_BAD_ALIGNMENT;
            HvLogDbg("[HC 0x07] WP_REGISTER rejected: GPA=0x%llX not 4KB-aligned", arg0);
            break;
        }
        if (gpa == 0 || gpa > 0xFFFFFFFFFFFFULL) {
            result = HV_STATUS_INVALID_CALL;
            HvLogDbg("[HC 0x07] WP_REGISTER rejected: GPA=0x%llX out of range", gpa);
            break;
        }
        if (g_WpCount >= WP_TABLE_SIZE) {
            result = HV_STATUS_NOT_SUPPORTED;
            HvLogDbg("[HC 0x07] WP_REGISTER rejected: table full (%u entries)", g_WpCount);
            break;
        }

        // Dedup: if already registered return success without duplicating.
        if (WpTableContains(gpa)) {
            HvLogDbg("[HC 0x07] WP_REGISTER GPA=0x%llX already registered", gpa);
            result = HV_STATUS_SUCCESS;
            break;
        }

        // Insert maintaining ascending sort order (insertion sort: one new element).
        ULONG pos = g_WpCount;
        while (pos > 0 && g_WpTable[pos - 1] > gpa) {
            g_WpTable[pos] = g_WpTable[pos - 1];
            pos--;
        }
        g_WpTable[pos] = gpa;
        g_WpCount++;

        // Set the page to EPT_READ | EPT_EXEC (strip write) to match the WP invariant.
        // EptMapPage4KB splits any covering 2MB PDE automatically.
        EptMapPage4KB(&g_Ept, gpa, gpa, EPT_READ | EPT_EXEC | EPT_MEMTYPE_WB);
        EptInvalidate(g_Ept.Eptp);  // flush this core immediately
        InterlockedExchange(&g_InveptPending, 1);  // signal other cores to flush

        HvLog("!!! DayZHV: [HC 0x07] WP_REGISTER GPA=0x%llX -> slot %u / %u. EPT set R+SX.",
              gpa, g_WpCount - 1, WP_TABLE_SIZE);
        result = HV_STATUS_SUCCESS;
        break;
    }

    case HV_CALL_TEARDOWN:
        Ctx->Passed = TRUE;
        Ctx->TeardownPending = TRUE;
        HvLogDbg("[HC 0xFF] Teardown via hypercall");
        return;   // do not advance RIP — teardown path does not resume guest

    default:
        result = HV_STATUS_INVALID_CALL;
        HvLogDbg("[HC] Unknown ID=0x%llX", id);
        break;
    }

    Ctx->GuestRegs.Rax = result;
    AdvanceGuestRip();
}

// ---------------------------------------------------------------------------
// HandleVmfunc — EXIT_REASON_VMFUNC (59)
// VMFUNC exits only if the leaf (EAX) is unsupported or the ECX index is
// out of range (>= 512). Leaf 0 with a valid ECX is handled in hardware
// without a VM-exit. We handle the error cases here by injecting #UD —
// an unsupported VMFUNC leaf is architecturally undefined behavior.
// ---------------------------------------------------------------------------
static void HandleVmfunc(PCORE_VMX_CONTEXT Ctx)
{
    ULONG leaf  = (ULONG)Ctx->GuestRegs.Rax;
    ULONG index = (ULONG)Ctx->GuestRegs.Rcx;
    HvLogDbg("[VMFUNC] unsupported leaf=%u index=%u -> #UD", leaf, index);
    // Inject #UD (vector 6, hw exception, no error code).
    ULONG udInfo = 6 | (3UL << 8) | (1UL << 31);
    __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, udInfo);
    __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
    __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 3);  // VMFUNC = F3 0F 01 D4 (4B)
    // Do NOT advance RIP — exception delivery re-executes from the faulting RIP.
}

// ---------------------------------------------------------------------------
// HandlePmuRdmsr / HandlePmuWrmsr — IA32_PERF_GLOBAL_CTRL and STATUS
// The "load IA32_PERF_GLOBAL_CTRL" VM-exit/entry controls handle the
// hardware save/restore automatically. The MSR bitmap intercepts give us
// visibility so we keep GuestPerfGlobalCtrl in sync with what the guest set.
// ---------------------------------------------------------------------------
static void HandlePmuRdmsr(PCORE_VMX_CONTEXT Ctx)
{
    ULONG msr = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val = 0;
    if (msr == IA32_PERF_GLOBAL_CTRL) {
        // Return the guest's shadow — the hardware register holds the host's
        // zero value (all counters off in VMX-root) after the VM-exit restore.
        val = Ctx->GuestPerfGlobalCtrl;
    } else {
        // STATUS, OVF_CTRL, FIXED_CTR_CTRL — pass through hardware.
        val = __readmsr(msr);
    }
    HV_VERBOSE_LOG("PMU RDMSR 0x%X -> 0x%llX", msr, val);
    Ctx->GuestRegs.Rax = val & 0xFFFFFFFF;
    Ctx->GuestRegs.Rdx = (val >> 32) & 0xFFFFFFFF;
    AdvanceGuestRip();
}

static void HandlePmuWrmsr(PCORE_VMX_CONTEXT Ctx)
{
    ULONG msr = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val = ((Ctx->GuestRegs.Rdx & 0xFFFFFFFF) << 32) |
                  (Ctx->GuestRegs.Rax & 0xFFFFFFFF);

    if (msr == IA32_PERF_GLOBAL_CTRL) {
        // Save the guest's intended counter enable mask. The VMCS
        // VMCS_GUEST_PERF_GLOBAL_CTRL field will be loaded on the next
        // VM-entry, restoring exactly this value into hardware for the guest.
        Ctx->GuestPerfGlobalCtrl = val;
        __vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, val);
        HV_VERBOSE_LOG("PMU WRMSR IA32_PERF_GLOBAL_CTRL = 0x%llX", val);
    } else {
        // STATUS writes are typically clears (MOV to MSR with clear bits).
        // Pass through; the guest manages its own overflow state.
        __writemsr(msr, val);
        HV_VERBOSE_LOG("PMU WRMSR 0x%X = 0x%llX", msr, val);
    }
    AdvanceGuestRip();
}

// ---------------------------------------------------------------------------
// ExitReasonName — map VM-exit reason code to a short human-readable string.
// Covers the common reasons; unknown codes return "REASON_N".
// ---------------------------------------------------------------------------
static const char *ExitReasonName(ULONG reason)
{
    switch (reason) {
    case  0: return "EXT_INT";
    case  1: return "NMI_WIN";
    case  2: return "NMI";
    case  3: return "INIT";
    case  4: return "SIPI";
    case  7: return "INTR_WIN";
    case  8: return "NMI_WINDOW";
    case  9: return "TASK_SWITCH";
    case 10: return "CPUID";
    case 12: return "HLT";
    case 14: return "INVD";
    case 15: return "INVLPG";
    case 18: return "VMCALL";
    case 19: return "VMCLEAR";
    case 20: return "VMLAUNCH";
    case 21: return "VMPTRLD";
    case 22: return "VMPTRST";
    case 23: return "VMREAD";
    case 24: return "VMRESUME";
    case 25: return "VMWRITE";
    case 26: return "VMXOFF";
    case 27: return "VMXON";
    case 28: return "CR_ACCESS";
    case 29: return "DR_ACCESS";
    case 30: return "IO";
    case 31: return "RDMSR";
    case 32: return "WRMSR";
    case 33: return "ENTRY_FAIL_GUEST";
    case 34: return "ENTRY_FAIL_MSR";
    case 36: return "MWAIT";
    case 37: return "MTF";
    case 39: return "MONITOR";
    case 40: return "PAUSE";
    case 41: return "ENTRY_FAIL_MC";
    case 43: return "TPR_THRESHOLD";
    case 44: return "APIC_ACCESS";
    case 45: return "VIRT_EOI";
    case 46: return "GDTR_IDTR";
    case 47: return "LDTR_TR";
    case 48: return "EPT_VIOLATION";
    case 49: return "EPT_MISCONFIG";
    case 50: return "INVEPT";
    case 51: return "RDTSCP";
    case 52: return "PREEMPT_TIMER";
    case 53: return "INVVPID";
    case 54: return "WBINVD";
    case 55: return "XSETBV";
    case 56: return "APIC_WRITE";
    case 57: return "RDRAND";
    case 58: return "INVPCID";
    case 59: return "VMFUNC";
    case 60: return "ENCLS";
    case 61: return "RDSEED";
    case 62: return "PML_FULL";
    case 63: return "XSAVES";
    case 64: return "XRSTORS";
    case 67: return "UMWAIT";
    case 68: return "TPAUSE";
    default: {
        // Thread-local static buffer — single-core call path only, safe.
        static char unk[16];
        RtlStringCbPrintfA(unk, sizeof(unk), "REASON_%u", reason);
        return unk;
    }
    }
}

// ---------------------------------------------------------------------------
// HandleVmxInstruction — handles all VMX instruction exits when the guest is
// not in VMX operation (our hypervisor does not expose nested VMX capability).
//
// Strategy: inject #UD for all VMX instructions. This is correct because:
//   1. IA32_FEATURE_CONTROL is spoofed with Lock=1, EnableVmxOutsideSmx=0
//      (firmware-locked model), so a correct guest aborts before VMXON.
//   2. Even if the guest tries, VMX instructions outside VMX operation cause
//      #UD per SDM Vol 3C §23.8 — we replicate that behavior exactly.
//   3. VMXON exit reason 28 fires when the guest executes VMXON while in
//      VMX non-root: the CPU exits to us rather than causing a nested fault.
//      We inject #UD so the guest's VMXON fails as it would on locked hardware.
// ---------------------------------------------------------------------------
static void HandleVmxInstruction(PCORE_VMX_CONTEXT Ctx, ULONG reason)
{
    UNREFERENCED_PARAMETER(Ctx);
    HvLogDbg("[VMX-INSTR] reason=%u (%s) — injecting #UD", reason, ExitReasonName(reason));
    ULONG udInfo = 6 | (3UL << 8) | (1UL << 31);  // #UD, hw exception, valid
    __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, udInfo);
    __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
    __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 3);
    // No AdvanceGuestRip — exception re-delivers from the faulting instruction.
}

void VmExitDispatch(PCORE_VMX_CONTEXT Ctx)
{
    ULONG reason = Ctx->ExitReason & 0xFFFF;

    // Fast path for the two highest-frequency no-op exits.
    // EXTERNAL_INT and PREEMPTION require no state change — just return to
    // VMRESUME. Skip the TSC/counter snapshot entirely; the handful of cycles
    // spent in this function are below measurement noise for these exits.
    // Telemetry is still counted so the exit-rate measurement is accurate.
    if (reason == VMX_EXIT_REASON_EXTERNAL_INT) {
        Ctx->Stats.ExternalInt++;
        Ctx->Stats.TotalExits++;
        return;
    }
    if (reason == VMX_EXIT_REASON_PREEMPTION) {
        Ctx->Stats.Preemption++;
        Ctx->Stats.TotalExits++;
        return;
    }

    Ctx->Stats.TotalExits++;

    // IPI-broadcast INVEPT: if any other core modified the EPT (WP_REGISTER,
    // SET_EPT_POLICY, shadow-table swap) it set g_InveptPending. Flush this
    // core's EPT TLB and clear the flag — each core that reads it as 1 does
    // its own INVEPT, which is safe and idempotent (extra flushes never hurt).
    // InterlockedExchange ensures the read is atomic and the write is ordered,
    // but we do NOT use CompareExchange-to-0 because multiple cores may clear
    // concurrently — that is intentional (each just flushes and moves on).
    if (InterlockedExchange(&g_InveptPending, 0)) {
        EptInvalidate(g_Ept.Eptp);
    }

    // Capture hardware DR6 into the guest shadow on every exit. The CPU writes
    // DR6 status bits (BS/BD/BT and breakpoint hits) autonomously on debug events,
    // so we must sync it here before the handler runs, not just on MOV DR exits.
    Ctx->GuestDr[6] = __readdr(6);

    // Snapshot TSC and counters before dispatch. APERF/MPERF reads are ~40
    // cycles each; only pay that cost once the guest has actually read those
    // MSRs (AperMperfActive tracks first RDMSR of either counter).
    ULONG64 tscEntry   = __rdtsc();
    ULONG64 mperfEntry = 0, aperfEntry = 0;
    if (Ctx->AperMperfActive) {
        mperfEntry = __readmsr(IA32_MPERF);
        aperfEntry = __readmsr(IA32_APERF);
    }

    switch (reason) {
    case VMX_EXIT_REASON_EXCEPTION_NMI:
        Ctx->Stats.Exception++;
        HandleException(Ctx);
        break;
    case VMX_EXIT_REASON_MTF:
        Ctx->Stats.Mtf++;
        HandleMtf(Ctx);
        break;
    case VMX_EXIT_REASON_RDTSC:
        HandleRdtsc(Ctx);
        break;
    case VMX_EXIT_REASON_CPUID:
        Ctx->Stats.Cpuid++;
        HandleCpuid(Ctx);
        break;
    case VMX_EXIT_REASON_RDMSR:
        Ctx->Stats.Rdmsr++;
        HandleRdmsr(Ctx);
        break;
    case VMX_EXIT_REASON_WRMSR:
        Ctx->Stats.Wrmsr++;
        HandleWrmsr(Ctx);
        break;
    case VMX_EXIT_REASON_EPT_VIOLATION:
        Ctx->Stats.EptViolation++;
        HandleEptViolation(Ctx);
        break;
    case VMX_EXIT_REASON_DR_ACCESS:     HandleDrAccess(Ctx);     break;
    case VMX_EXIT_REASON_CR_ACCESS:     HandleCrAccess(Ctx);     break;
    case VMX_EXIT_REASON_IO_ACCESS:     HandleIoAccess(Ctx);     break;
    case VMX_EXIT_REASON_GDTR_IDTR:
    case VMX_EXIT_REASON_LDTR_TR:       HandleDescriptorTable(Ctx, reason); break;
    case VMX_EXIT_REASON_XSETBV:        HandleXsetbv(Ctx);       break;
    case VMX_EXIT_REASON_INTERRUPT_WINDOW: HandleInterruptWindow(Ctx); break;
    case VMX_EXIT_REASON_VMFUNC:        HandleVmfunc(Ctx);       break;
    case VMX_EXIT_REASON_VMCALL:        HandleHypercall(Ctx);    break;
    // VMX instruction exits — guest attempted a VMX instruction while in VMX non-root.
    // For VMXON: set CF=1 in guest RFLAGS so Hyper-V/VBS interprets it as
    // "VMX not available" and falls back gracefully instead of crashing on #UD.
    // All other VMX instructions remain #UD (they should not appear before VMXON).
    case VMX_EXIT_REASON_VMXON_INSTR: {
        ULONG64 rflags = 0;
        __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
        rflags |= (1ULL << 0);   // CF=1: VMXON failed (SDM Vol 3C §30.3 error encoding)
        rflags &= ~(1ULL << 6);  // ZF=0: no current-VMCS error
        __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
        AdvanceGuestRip();
        HvLogDbg("[VMX-INSTR] VMXON from guest -> CF=1 (firmware-locked model)");
        break;
    }
    case VMX_EXIT_REASON_VMXOFF_INSTR:
    case VMX_EXIT_REASON_VMCLEAR:
    case VMX_EXIT_REASON_VMPTRLD:
    case VMX_EXIT_REASON_VMPTRST:
    case VMX_EXIT_REASON_VMLAUNCH_INSTR:
    case VMX_EXIT_REASON_VMRESUME_INSTR:
    case VMX_EXIT_REASON_VMREAD_INSTR:
    case VMX_EXIT_REASON_VMWRITE_INSTR:
        Ctx->Stats.Other++;
        HandleVmxInstruction(Ctx, reason);
        break;
    case VMX_EXIT_REASON_HLT:
        Ctx->Passed = TRUE;
        Ctx->TeardownPending = TRUE;
        break;
    default:
        Ctx->Stats.Other++;
        // Unknown exit reason.  Do NOT tear down — tearing down one core while
        // 31 others are live causes use-after-free on the freed ctx array.
        // Inject #UD so the guest sees a clean fault and the hypervisor keeps
        // running.  HvLogDbg (DbgPrint only) is safe above DISPATCH_LEVEL;
        // ZwWriteFile (used by HvLog) is not.
        {
            ULONG64 guestRip = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
            ULONG core = (ULONG)KeGetCurrentProcessorNumberEx(NULL);
            HvLogDbg("[UNHANDLED] core=%02u reason=%u (%s) RIP=0x%llX -> #UD",
                     core, reason, ExitReasonName(reason), guestRip);
            ULONG udInfo = 6 | (3UL << 8) | (1UL << 31);
            __vmx_vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, udInfo);
            __vmx_vmwrite(VMCS_VM_ENTRY_EXCEPTION_ERROR, 0);
            __vmx_vmwrite(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);
        }
        break;
    }

    // Reload guest DRs into hardware just before VMRESUME when the guest wrote
    // any DR this exit. Done here (VMX-root, after all handlers) so we never
    // clobber host-debugger breakpoints that were live during the exit window.
    // DR7 is written last: arming it before DR0-DR3 could immediately trigger
    // a hardware breakpoint on our own pre-VMRESUME instructions.
    if (Ctx->DrDirty && !Ctx->TeardownPending) {
        __writedr(0, Ctx->GuestDr[0]);
        __writedr(1, Ctx->GuestDr[1]);
        __writedr(2, Ctx->GuestDr[2]);
        __writedr(3, Ctx->GuestDr[3]);
        __writedr(6, Ctx->GuestDr[6]);
        __writedr(7, Ctx->GuestDr[7]);
        Ctx->DrDirty = FALSE;
    }

    // Cache warming: prefetch the hot fields the VMRESUME path will touch.
    // PREFETCHT0 is a hint only — never faults, safe at any IRQL.
    _mm_prefetch((const char*)Ctx,                   _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->GuestRegs,       _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->GuestRegs + 64,  _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->TeardownPending,  _MM_HINT_T0);

    // Accumulate handler cost into VMCS_TSC_OFFSET.
    // Jitter: bits [3:0] of exit TSC, biased by -7 → range [-7, +8] cycles.
    if (!Ctx->TeardownPending) {
        ULONG64 tscExit = __rdtsc();
        ULONG64 elapsed = tscExit - tscEntry;
        ULONG64 jitter  = (tscExit & 0xFULL) - 7ULL;
        ULONG64 current = 0;
        __vmx_vmread(VMCS_TSC_OFFSET, &current);
        __vmx_vmwrite(VMCS_TSC_OFFSET, current - elapsed + jitter);

        if (Ctx->AperMperfActive) {
            Ctx->MperfOffset += __readmsr(IA32_MPERF) - mperfEntry;
            Ctx->AperOffset  += __readmsr(IA32_APERF) - aperfEntry;
        }
    }
}

// Returns TRUE if the processor supports Architectural LBR (CPUID[0x1C].EAX != 0)
// AND the VMX exit/entry controls accept the LBR auto-swap bits. Raptor Lake
// documents Arch LBR in CPUID[0x1C] but VMX LBR virtualization (bits 29/21 in
// exit/entry controls) requires the bits to survive AdjustControls — if the
// firmware capability MSR clears them we fall back to software-only handling.
static BOOLEAN CheckArchLbrVmxSupport(void)
{
    int regs[4];
    __cpuidex(regs, 0x1C, 0);
    if (regs[0] == 0) return FALSE;   // Arch LBR not enumerated

    ULONG exitTest  = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE  | VM_EXIT_LOAD_IA32_LBR_CTL,
                                     IA32_VMX_EXIT_CTLS);
    ULONG entryTest = AdjustControls(VM_ENTRY_IA32E_MODE_GUEST | VM_ENTRY_LOAD_IA32_LBR_CTL,
                                     IA32_VMX_ENTRY_CTLS);

    return ((exitTest  & VM_EXIT_LOAD_IA32_LBR_CTL)  != 0) &&
           ((entryTest & VM_ENTRY_LOAD_IA32_LBR_CTL) != 0);
}

// Detect per-core topology properties: invariant TSC and hybrid core type.
// Must be called from within an IPI callback (already pinned to this core).
// Populates ctx->InvariantTsc and ctx->CoreType.
static void DetectCoreTopology(PCORE_VMX_CONTEXT ctx, ULONG procNum)
{
    int regs[4];

    // Invariant TSC: CPUID[0x80000007].EDX bit 8.
    __cpuid(regs, 0x80000007);
    ctx->InvariantTsc = (regs[3] & (1 << 8)) ? TRUE : FALSE;

    // Hybrid architecture: CPUID[7,0].EDX bit 15 signals hybrid topology.
    // If present, CPUID[0x1A,0].EAX bits [31:24] give the core type:
    //   0x40 = Atom (E-core), 0x20 = Core (P-core) — Intel Hybrid Architecture SDM.
    ctx->CoreType = 0;
    __cpuidex(regs, 7, 0);
    if (regs[3] & (1 << 15)) {
        __cpuidex(regs, 0x1A, 0);
        ULONG coreTypeId = (ULONG)((regs[0] >> 24) & 0xFF);
        if      (coreTypeId == 0x20) ctx->CoreType = 1;  // P-core
        else if (coreTypeId == 0x40) ctx->CoreType = 2;  // E-core
    }

    static const char* const coreNames[] = { "Unknown", "P-core", "E-core" };
    ULONG typeIdx = (ctx->CoreType <= 2) ? ctx->CoreType : 0;
    HvLogDbg("[CORE %02u] %s InvariantTSC=%u XSaveSize=%u",
             procNum, coreNames[typeIdx], ctx->InvariantTsc, ctx->XSaveSize);
}

// ---------------------------------------------------------------------------
// IsPCoreThread — returns TRUE only for non-HT P-core threads on the 14900K.
//
// Three-gate check executed from within the IPI callback (already pinned to
// this logical processor, so CPUID reflects the correct core):
//
//  Gate 1 — slot range: procNum must have a context slot (0..g_ProcCount-1).
//  Gate 2 — static mask: procNum must be set in HV_PCORE_AFFINITY_MASK.
//            Rejects E-core threads (16-31) immediately without touching CPUID.
//  Gate 3 — CPUID[0x1F] SMT topology: if the CPU reports SMT-level siblings,
//            only launch on SMT thread 0 of each P-core.  On the 14900K each
//            P-core exposes 2 HT threads; launching on both would duplicate
//            VMXON on the same physical core, causing resource contention on
//            the shared VMCS cache and contributing to the IPI barrier timeout.
//            E-cores are single-threaded (no SMT level in their topology), so
//            this gate is a no-op for them (already caught by gate 2).
//
// Returns FALSE for any thread that should be skipped; caller returns 0.
// ---------------------------------------------------------------------------
static BOOLEAN IsPCoreThread(ULONG procNum)
{
    // Gate 1
    if (procNum >= g_ProcCount) return FALSE;
    // Gate 2
    if (procNum >= 64 || !((HV_PCORE_AFFINITY_MASK >> procNum) & 1ULL)) return FALSE;

    // Core 0 bypasses the CPUID SMT check unconditionally — it is always the
    // primary thread of P-core 0 and the topology CPUID can return stale or
    // zero data when called during the pilot VMLAUNCH window.
    if (procNum == 0) return TRUE;

    // Gate 3 — CPUID[0x1F, subleaf 0] reports the SMT level.
    // EAX bits [4:0] = bits to shift APIC ID to get the next-level ID.
    // ECX bits [15:8] = level type: 1 = SMT, 2 = Core, 0 = invalid (done).
    // If subleaf 0 is an SMT level, ECX[15:8]==1 and EAX gives the shift.
    // The SMT-local thread ID is (x2APIC_ID & ((1 << shift) - 1)).
    // We skip all threads where that ID != 0 (i.e. only the primary HT thread
    // of each P-core participates in VMX launch).
    int regs[4];
    __cpuidex(regs, 0x1F, 0);
    ULONG levelType = ((ULONG)regs[2] >> 8) & 0xFF;
    if (levelType == 1) {   // subleaf 0 is an SMT level
        ULONG shift   = (ULONG)regs[0] & 0x1F;
        ULONG x2apic  = (ULONG)regs[3];   // EDX = x2APIC ID of this logical processor
        ULONG smtId   = x2apic & ((1UL << shift) - 1);
        if (smtId != 0) return FALSE;      // secondary HT thread — skip
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// VmxLaunchCore — KeIpiGenericCall worker, runs simultaneously on every core.
// ctxArrayPtr is a PCORE_VMX_CONTEXT array; each core indexes by its own number.
//
// IPI barrier contract: KeIpiGenericCall delivers this callback at IPI_LEVEL
// and waits at KiIpiWaitForRequestBarrier until every logical processor has
// returned.  Any work done between arrival and return holds the entire system
// at the barrier.  Doing hundreds of MSR reads, LAR/LSL calls, RtlCopyMemory,
// and AdjustControls inside that window is the cause of the 0xA deadlock.
//
// Split strategy:
//   Phase A — at current IRQL: everything that reads hardware state and
//              computes VMCS values.  The physical addresses of non-paged
//              allocations are stable; topology detection, control-field
//              adjustment, and the GDT copy all belong here.
//   Phase B — narrow IPI_LEVEL window: VMXON → VMPTRLD → VMWRITE batch →
//              AsmLaunchAndReturn → VMXOFF on failure → KeLowerIrql.
//              This is the only window where the core is invisible to the
//              Windows IPI manager.  It is kept as short as possible so the
//              barrier clears on all cores near-simultaneously.
// ---------------------------------------------------------------------------
ULONG_PTR VmxLaunchCore(ULONG_PTR ctxArrayPtr)
{
    // Global cache write-back + TLB/pipeline serialization before any VMX work.
    // __wbinvd flushes all D-cache lines and invalidates I-TLB entries on this
    // execution engine, eliminating stale prefetches of our payload pages under
    // the KDMapper freestanding footprint.  The subsequent CPUID(0) is a full
    // serializing instruction (SDM §8.3) that drains the OOO window so no
    // speculative fetch of Phase A code can race the cache flush.
    __wbinvd();
    {
        int _s[4];
        __cpuid(_s, 0);
    }

    PCORE_VMX_CONTEXT arr = (PCORE_VMX_CONTEXT)ctxArrayPtr;
    ULONG procNum = KeGetCurrentProcessorNumberEx(NULL);

    // -----------------------------------------------------------------------
    // Phase A: pre-flight work at current IRQL (IPI_LEVEL or lower).
    // Read all hardware state and compute every VMCS value we will need.
    // Nothing here touches VMX instructions — no barrier exposure yet.
    // -----------------------------------------------------------------------
    if (!IsPCoreThread(procNum)) {
        return 0;
    }

    if (g_VmxDiag) g_VmxDiag->StepIndicator = VMX_STEP_ENTRY;

    PCORE_VMX_CONTEXT ctx = &arr[procNum];

    g_CoreCtx[procNum] = ctx;
    DetectCoreTopology(ctx, procNum);
    // Ignore CPUID topology result — force all threads in the 0xFFFF mask to P-core.
    if (procNum < 64 && ((HV_PCORE_AFFINITY_MASK >> procNum) & 1ULL))
        ctx->CoreType = 1;

    ULONG revId = GetVmcsRevisionId();
    *(ULONG*)ctx->VmxonRegion = revId;
    *(ULONG*)ctx->VmcsRegion  = revId;

    ULONG64 gdtBase  = AsmGetGdtBase();
    USHORT  gdtLimit = AsmGetGdtLimit();
    RtlCopyMemory(ctx->ShadowGdt, (PVOID)gdtBase, min((ULONG)gdtLimit + 1, PAGE_SIZE));
    ULONG64 shadowGdtBase = (ULONG64)ctx->ShadowGdt;
    ULONG64 idtBase  = AsmGetIdtBase();
    USHORT  idtLimit = AsmGetIdtLimit();

    USHORT selCs = AsmGetCs();
    USHORT selDs = AsmGetDs();
    USHORT selEs = AsmGetEs();
    USHORT selSs = AsmGetSs();
    USHORT selFs = AsmGetFs();
    USHORT selGs = AsmGetGs();
    USHORT selTr = AsmGetTr();

    ULONG64 fsBase = __readmsr(IA32_FS_BASE);
    ULONG64 gsBase = __readmsr(IA32_GS_BASE);
    ULONG64 trBase = GetTssBase(gdtBase, selTr);

    ctx->GuestLstar = __readmsr(IA32_LSTAR);

    // VM-entry MSR-load area (BSOD #24 fix): initialize the 16-byte entry in MsrLoadPage.
    // The page-aligned physical address satisfies SDM §26.2.1.3 (4KB alignment required).
    if (ctx->MsrLoadPage) {
        ULONG  *msrIdx  = (ULONG  *)((ULONG_PTR)ctx->MsrLoadPage + 0);
        ULONG  *msrRsvd = (ULONG  *)((ULONG_PTR)ctx->MsrLoadPage + 4);
        ULONG64 *msrDat = (ULONG64*)((ULONG_PTR)ctx->MsrLoadPage + 8);
        *msrIdx  = IA32_KERNEL_GS_BASE;
        *msrRsvd = 0;
        *msrDat  = __readmsr(IA32_KERNEL_GS_BASE);
        ctx->MsrLoadPhysAddr = MmGetPhysicalAddress(ctx->MsrLoadPage).QuadPart;
    } else {
        ctx->MsrLoadPhysAddr = 0;
    }

    // Hardcoded: LAR is unreliable under KDMapper; Raptor Lake entry checker
    // rejects any AR value that doesn't match exactly what the CPU expects.
    // 0xA09B = Execute/Read, Accessed, Long Mode (CS); 0xC093 = Read/Write, Accessed, 32-bit (SS).
    ULONG arCs = 0xA09B;
    ULONG arDs = (AsmGetLar(selDs) >> 8) & 0xF0FF;
    ULONG arEs = (AsmGetLar(selEs) >> 8) & 0xF0FF;
    ULONG arSs = 0xC093;
    ULONG arFs = (AsmGetLar(selFs) >> 8) & 0xF0FF;
    ULONG arGs = (AsmGetLar(selGs) >> 8) & 0xF0FF;
    ULONG arTr = (AsmGetLar(selTr) >> 8) & 0xF0FF;

    ULONG limCs = 0xFFFFFFFF;   // SDM: 64-bit CS must have limit=0xFFFFFFFF; LSL unreliable under mapper
    ULONG limDs = AsmGetLsl(selDs);
    ULONG limEs = AsmGetLsl(selEs);
    ULONG limSs = 0xFFFFFFFF;   // SDM: SS limit must match CS in ring-0 VMX entry check
    ULONG limFs = AsmGetLsl(selFs);
    ULONG limGs = AsmGetLsl(selGs);
    ULONG limTr = AsmGetLsl(selTr);

    ULONG64 cr0 = AdjustCr0(__readcr0());
    ULONG64 cr3 = __readcr3();
    ULONG64 cr4 = AdjustCr4(__readcr4());

    ULONG64 hostRsp = ((ULONG64)ctx->HostStack + 0x8000 - 16) & ~0xFULL;

    // Alignment checks — ZwWriteFile is safe here (Phase A, before IRQL raise).
    if ((shadowGdtBase & 0xF) != 0)
        HvLog("!!! DayZHV: [WARN core=%02u] shadowGDT VA=0x%llX is NOT 16B-aligned (low nibble=0x%llX) — VMCS entry check may reject",
              procNum, shadowGdtBase, shadowGdtBase & 0xF);
    if ((idtBase & 0xF) != 0)
        HvLog("!!! DayZHV: [WARN core=%02u] IDT VA=0x%llX is NOT 16B-aligned (low nibble=0x%llX) — VMCS entry check may reject",
              procNum, idtBase, idtBase & 0xF);

    // Log pre-launch segment selector/AR/limit snapshot every time.
    // If VMLAUNCH later fails with error 7 (invalid guest state) this gives the
    // exact values that were written to the VMCS without needing a debugger.
    HvLog("!!! DayZHV: [DIAG core=%02u] SEL  CS=0x%04X DS=0x%04X ES=0x%04X SS=0x%04X FS=0x%04X GS=0x%04X TR=0x%04X",
          procNum, selCs, selDs, selEs, selSs, selFs, selGs, selTr);
    HvLog("!!! DayZHV: [DIAG core=%02u] AR   CS=0x%04X DS=0x%04X ES=0x%04X SS=0x%04X FS=0x%04X GS=0x%04X TR=0x%04X",
          procNum, arCs, arDs, arEs, arSs, arFs, arGs, arTr);
    HvLog("!!! DayZHV: [DIAG core=%02u] LIM  CS=0x%08X DS=0x%08X TR=0x%08X",
          procNum, limCs, limDs, limTr);
    HvLog("!!! DayZHV: [DIAG core=%02u] BASE GDT=0x%llX(shadow=0x%llX) IDT=0x%llX FS=0x%llX GS=0x%llX TR=0x%llX",
          procNum, gdtBase, shadowGdtBase, idtBase, fsBase, gsBase, trBase);
    HvLog("!!! DayZHV: [DIAG core=%02u] CR   CR0=0x%llX CR3=0x%llX CR4=0x%llX hostRsp=0x%llX",
          procNum, cr0, cr3, cr4, hostRsp);
    HvLog("!!! DayZHV: [DIAG core=%02u] MSR  EFER=0x%llX PAT=0x%llX RFLAGS=0x%llX LSTAR=0x%llX KGSBASE=0x%llX",
          procNum, ctx->PreLaunchEfer, ctx->PreLaunchPat, ctx->PreLaunchRflags,
          ctx->GuestLstar, ctx->HostKernelGsBase);

    ULONG pinCtls = AdjustControls(0, IA32_VMX_PINBASED_CTLS);
    ULONG cpuCtls = AdjustControls(CPU_BASED_HLT_EXITING |
                                   CPU_BASED_USE_TSC_OFFSETTING |
                                   CPU_BASED_MOV_DR_EXITING |
                                   CPU_BASED_USE_IO_BITMAPS |
                                   CPU_BASED_USE_MSR_BITMAPS |
                                   CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
                                   CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
                                   IA32_VMX_PROCBASED_CTLS);
    // Explicitly clear MTF regardless of what AdjustControls allowed.
    cpuCtls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    ULONG cpu2Want = SECONDARY_EXEC_ENABLE_EPT            |
                     SECONDARY_EXEC_ENABLE_EPT_AD         |
                     SECONDARY_EXEC_ENABLE_VPID           |
                     SECONDARY_EXEC_DESC_TABLE_EXITING    |
                     SECONDARY_EXEC_ENABLE_XSETBV         |
                     SECONDARY_EXEC_ENABLE_VMFUNC         |
                     SECONDARY_EXEC_VMCS_SHADOWING        |
                     SECONDARY_EXEC_MODE_BASED_EPT_EXEC   |
                     SECONDARY_EXEC_SPP;
    ULONG cpu2Ctls = AdjustControls(cpu2Want, IA32_VMX_PROCBASED_CTLS2);

    BOOLEAN vmfuncOk = (cpu2Ctls & SECONDARY_EXEC_ENABLE_VMFUNC)       != 0;
    BOOLEAN shadowOk = (cpu2Ctls & SECONDARY_EXEC_VMCS_SHADOWING)      != 0 &&
                       ctx->ShadowVmcsPage && ctx->VmreadBitmap && ctx->VmwriteBitmap;
    BOOLEAN sppOk    = (cpu2Ctls & SECONDARY_EXEC_SPP)                 != 0 &&
                       ctx->SppTablePage;
    BOOLEAN mbecOk   = (cpu2Ctls & SECONDARY_EXEC_MODE_BASED_EPT_EXEC) != 0;

    ctx->VmfuncEnabled     = vmfuncOk;
    ctx->VmcsShadowEnabled = shadowOk;
    ctx->SppEnabled        = sppOk;
    ctx->MbecEnabled       = mbecOk;

    BOOLEAN lbrOk = CheckArchLbrVmxSupport();
    ctx->LbrVirtEnabled = lbrOk;

    ULONG exitTest  = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE |
                                     VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL |
                                     (lbrOk ? VM_EXIT_LOAD_IA32_LBR_CTL : 0),
                                     IA32_VMX_EXIT_CTLS);
    ULONG entryTest = AdjustControls(VM_ENTRY_IA32E_MODE_GUEST |
                                     VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |
                                     (lbrOk ? VM_ENTRY_LOAD_IA32_LBR_CTL : 0),
                                     IA32_VMX_ENTRY_CTLS);
    BOOLEAN pmuOk = ((exitTest  & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) != 0) &&
                    ((entryTest & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) != 0);
    ULONG exitCtls  = exitTest;
    ULONG entryCtls = entryTest;

    // Log the final negotiated control values and which optional features survived.
    HvLog("!!! DayZHV: [DIAG core=%02u] CTL  pin=0x%08X cpu=0x%08X cpu2=0x%08X exit=0x%08X entry=0x%08X",
          procNum, pinCtls, cpuCtls, cpu2Ctls, exitCtls, entryCtls);
    HvLog("!!! DayZHV: [DIAG core=%02u] FEAT vmfunc=%u shadow=%u spp=%u mbec=%u lbr=%u pmu=%u",
          procNum, (ULONG)vmfuncOk, (ULONG)shadowOk, (ULONG)sppOk,
          (ULONG)mbecOk, (ULONG)lbrOk, (ULONG)pmuOk);

    PHYSICAL_ADDRESS vmxonPhys   = MmGetPhysicalAddress(ctx->VmxonRegion);
    PHYSICAL_ADDRESS vmcsPhys    = MmGetPhysicalAddress(ctx->VmcsRegion);
    PHYSICAL_ADDRESS msrBmpPhys  = MmGetPhysicalAddress(ctx->MsrBitmap);
    PHYSICAL_ADDRESS ioBmpAPhys  = MmGetPhysicalAddress(ctx->IoBitmapA);
    PHYSICAL_ADDRESS ioBmpBPhys  = MmGetPhysicalAddress(ctx->IoBitmapB);

    // Optional-feature physical addresses — computed before raise so the
    // narrow IPI window never calls MmGetPhysicalAddress.
    PHYSICAL_ADDRESS eptpListPhys = {0}, shadowPhys = {0};
    PHYSICAL_ADDRESS vmrdBmpPhys  = {0}, vmwrBmpPhys = {0}, sppPhys = {0};
    if (vmfuncOk && ctx->EptpListPage)
        eptpListPhys = MmGetPhysicalAddress(ctx->EptpListPage);
    if (shadowOk) {
        *(ULONG*)ctx->ShadowVmcsPage  = GetVmcsRevisionId();
        *(ULONG*)ctx->ShadowVmcsPage |= (1UL << 31);
        shadowPhys   = MmGetPhysicalAddress(ctx->ShadowVmcsPage);
        vmrdBmpPhys  = MmGetPhysicalAddress(ctx->VmreadBitmap);
        vmwrBmpPhys  = MmGetPhysicalAddress(ctx->VmwriteBitmap);
    }
    if (sppOk)
        sppPhys = MmGetPhysicalAddress(ctx->SppTablePage);

    // Snapshot pre-launch diagnostics while pageable reads are still safe.
    ctx->PreLaunchEfer   = __readmsr(0xC0000080);
    ctx->PreLaunchPat    = __readmsr(0x277);
    ctx->PreLaunchRflags = (ULONG64)__readeflags();

    // SYSENTER MSRs — read once here so the VMWRITE loop is MSR-free.
    ULONG64 sysenterCs  = __readmsr(0x174);
    ULONG64 sysenterEsp = __readmsr(0x175);
    ULONG64 sysenterEip = __readmsr(0x176);

    // Pre-compute CR4 with VMXE set so Phase B never calls __readcr4().
    ULONG64 cr4WithVmxe    = cr4 | (1ULL << 13);
    ULONG64 cr4WithoutVmxe = cr4 & ~(1ULL << 13);

    // Global TLB prep (Phase A, before IRQL raise):
    // KeFlushQueuedDpcs() drains all per-CPU deferred procedure call queues,
    // including CcAsyncLazywriteWorker, before we enter the interrupt-masked
    // window.  This is the primary mitigation for the 0xA collision with the
    // Cache Manager's lazy-write path seen in KeAccumulateTicks.
    KeFlushQueuedDpcs();
    if (g_VmxDiag) g_VmxDiag->StepIndicator = VMX_STEP_CACHE_FLUSH;

    // Dummy CR3 reload after DPC drain: Windows may have queued System PTE
    // flushes inside those DPCs; the CR3 write flushes any remaining stale
    // TLB entries for the manual-mapped VMXON/VMCS regions on this core.
    __writecr3(cr3);

    // Full store/load fence then pipeline serialization.
    // KeMemoryBarrier() emits MFENCE. The CPUID below is a full serializing
    // instruction (SDM Vol 3A §8.3) — it retires all prior instructions and
    // drains the store buffer, making every Phase A write architecturally visible
    // before we enter Phase B.  This replaces the CPUID that was previously inside
    // AsmLaunchAndReturn (inside the cli window); it now runs before the raise,
    // removing ~150 cycles from the interrupt-masked window.
    KeMemoryBarrier();
    int _cpuid_regs[4];
    __cpuid(_cpuid_regs, 0);

    // 14900K Big/Little yield: 500 PAUSE iterations give E-cores and P-cores
    // time to drain high-priority background work (lazy-write, prefetch) before
    // we enter the cli window.  Each PAUSE is ~5–10 ns on Raptor Lake; 500
    // iterations ≈ 2.5–5 µs — long enough for the hardware scheduler to service
    // any queued microops without adding measurable IPI latency.
    for (int _pi = 0; _pi < 500; _pi++)
        _mm_pause();

    // IPI checkin barrier: wait for all g_ProcCount P-cores to complete Phase A
    // before any core enters Phase B.  This prevents the fastest core from
    // VMLAUNCH-ing while slower cores are still in OS calls (MSR reads, LAR/LSL),
    // which would leave the IPI barrier half-populated and could cause the straggler
    // cores to observe a partially-virtualized system during their own Phase B.
    // g_PcoreCheckin was reset to 0 by the caller (VmxInitialize) before the IPI.
    InterlockedIncrement(&g_PcoreCheckin);
    while (InterlockedCompareExchange(&g_PcoreCheckin, 0, 0) < (LONG)g_ProcCount)
        _mm_pause();

    // -----------------------------------------------------------------------
    // Phase B: micro-burst window.
    // Sequence: cli → CR3-flush → CR4.VMXE → VMXON → VMPTRLD →
    //           pre-computed VMWRITE block → VMLAUNCH.
    // Between cli and vmlaunch: only VMX instructions and pre-computed stores.
    // No MSR reads, no OS calls, no logging, no branches on runtime data.
    // -----------------------------------------------------------------------

    // VBS / Hyper-V conflict check (Phase A, before raise — logging still safe).
    // If CR4.VMXE is already set, another hypervisor owns VMX root on this core.
    // Attempting VMXON while a peer is already in root mode causes a silent hang
    // on 14900K (the VMXON instruction faults but the CPU does not generate an
    // architectural #GP visible to us — it just stalls).  VMXOFF first, then
    // log a hard warning so the user knows VBS/Hyper-V must be disabled.
    {
        ULONG64 cr4Live = __readcr4();
        if (cr4Live & CR4_VMXE) {
            HvLog("!!! DayZHV: [VBS CONFLICT core=%02u] CR4.VMXE set — peer HV active, issuing VMXOFF to recover", procNum);
            __vmx_off();
        }
    }

    // CR0/CR4 fixed-mask audit — results written to the lockless diagnostic
    // buffer.  No ZwWriteFile here: the synchronous DriverEntry context makes
    // all file I/O unsafe (deadlock on the I/O serialization mutex).
    {
        unsigned __int64 live_cr0 = __readcr0();
        unsigned __int64 live_cr4 = __readcr4();
        ULONG64 cr0f0 = __readmsr(IA32_VMX_CR0_FIXED0);
        ULONG64 cr0f1 = __readmsr(IA32_VMX_CR0_FIXED1);
        if (g_VmxDiag) {
            g_VmxDiag->Cr0Value   = live_cr0;
            g_VmxDiag->Cr4Value   = live_cr4;
            g_VmxDiag->Fixed0Cr0  = cr0f0;
            g_VmxDiag->Fixed1Cr0  = cr0f1;
            g_VmxDiag->StepIndicator = VMX_STEP_CR_AUDIT;
        }
    }

    // Pre-Phase-B sentinel — written to the lockless buffer; if the machine
    // hangs during VMXON the buffer is readable from WinDbg via the Magic field.
    ctx->LaunchResult = 0xFB;
    if (g_VmxDiag) {
        g_VmxDiag->LaunchResult  = 0xFB;
        g_VmxDiag->StepIndicator = VMX_STEP_VMXON_ATTEMPT;
    }

    KIRQL oldIrql;
    KeRaiseIrql(IPI_LEVEL, &oldIrql);
    _disable();

    // Re-flush CR3 inside the cli window: ensures TLB coherency for the
    // manual-mapped VMXON/VMCS pages on this specific core after interrupts
    // are masked, before the CPU touches them in VMXON.
    __writecr3(cr3);

    // Forced CR4/CR0 consistency: explicit serialized VMXE enable.
    // __writecr4 alone is not a serializing instruction on all microcode
    // revisions of Raptor Lake.  Following it with a CPUID (leaf 0) drains
    // the out-of-order pipeline and ensures the updated CR4 is architecturally
    // visible to the subsequent VMXON before any speculative fetch can observe
    // the old CR4 value.  The CPUID result is discarded; the side-effect is
    // the serialization (SDM Vol 3A §8.3 "Serializing Instructions").
    __writecr4(cr4WithVmxe);
    {
        int _ser[4];
        __cpuid(_ser, 0);
    }

    // Second pipeline flush immediately before VMXON.  The first CPUID (above)
    // serialized the __writecr4.  This one serializes the __writecr3 and any
    // microcode-speculative prefetches that may have buffered the old CR4 state
    // across the cli boundary on Raptor Lake (observed hang pattern, 14900K).
    {
        int _ser2[4];
        __cpuid(_ser2, 0);
    }

    // Trace tag 0xFB: if machine hangs here, VMXON is the killer.
    // __vmx_on returns: 0=success, 1=CF set (VMfailInvalid), 2=ZF set (VMfailValid).
    // VMXON only ever sets CF — it has no current VMCS so ZF is architecturally
    // impossible.  Under KDMapper (no Load Config, /GS-) there is no security
    // cookie to corrupt, but vmxonRet is declared and tested here in the tightest
    // possible scope to prevent any compiler reordering across the VMX instruction.
    //
    // EFLAGS capture: raw CPU flags are sampled via __readeflags() immediately
    // before and after __vmx_on so the CF/ZF state is durably recorded even if
    // the core hangs inside the instruction on the next attempt.  The values are
    // written synchronously to disk via HvLog (FILE_WRITE_THROUGH) before any
    // branch so the diagnostic layout reaches the SSD regardless of what follows.
    {
        unsigned char vmxonRet  = 0xFF;   // explicit sentinel — not zero-init reliance
        // Capture live CR0/CR4 (with VMXE already set) immediately before VMXON.
        if (g_VmxDiag) {
            g_VmxDiag->Cr0Value = __readcr0();
            g_VmxDiag->Cr4Value = __readcr4();
        }
        ULONG64 eflagsBefore = (ULONG64)__readeflags();
        vmxonRet = __vmx_on((ULONGLONG*)&vmxonPhys.QuadPart);
        ULONG64 eflagsAfter  = (ULONG64)__readeflags();

        // Write EFLAGS and result directly into the lockless diagnostic buffer.
        // No ZwWriteFile here — we are inside the cli / IPI_LEVEL window.
        if (g_VmxDiag) {
            g_VmxDiag->EflagsBefore = eflagsBefore;
            g_VmxDiag->EflagsAfter  = eflagsAfter;
            g_VmxDiag->VmxonResult  = (ULONG)vmxonRet;
            g_VmxDiag->LaunchResult = (vmxonRet != 0) ? 0xFE : 0xFA;
        }

        if (vmxonRet != 0) {
            __writecr4(cr4WithoutVmxe);
            ctx->LaunchResult = 0xFE;
            _enable();
            KeLowerIrql(oldIrql);
            HvLog("!!! DayZHV: [VMXON FAIL core=%02u] __vmx_on returned %u  eflagsBefore=0x%llX eflagsAfter=0x%llX  vmxon_pa=0x%llX",
                  procNum, (ULONG)vmxonRet, eflagsBefore, eflagsAfter, vmxonPhys.QuadPart);
            return 0;
        }
    }
    // Survived VMXON — advance trace tag.
    ctx->LaunchResult = 0xFA;  // sentinel: VMXON OK, about to VMPTRLD

    // Trace tag 0xFA: if machine hangs here, VMPTRLD is the killer.
    {
        unsigned char vmptrldRet = __vmx_vmptrld((ULONGLONG*)&vmcsPhys.QuadPart);
        if (vmptrldRet != 0) {
            // Record VMPTRLD failure in the diagnostic buffer; no file I/O inside cli.
            if (g_VmxDiag) g_VmxDiag->LaunchResult = 0xFD;
            __vmx_off();
            __writecr4(cr4WithoutVmxe);
            ctx->LaunchResult = 0xFD;
            _enable();
            KeLowerIrql(oldIrql);
            HvLog("!!! DayZHV: [VMPTRLD FAIL core=%02u] __vmx_vmptrld returned %u  vmcs_pa=0x%llX",
                  procNum, (ULONG)vmptrldRet, vmcsPhys.QuadPart);
            return 0;
        }
    }
    // Survived VMPTRLD — advance trace tag.
    ctx->LaunchResult = 0xF9;  // sentinel: VMPTRLD OK, about to VMWRITE+VMLAUNCH

    // Straight-line VMWRITE block — no conditional branches inside the cli window.
    // Results OR'd into vmwStat; a single check after the block handles any failure.
    // VMWRITE can only fail on a bad field encoding or no-current-VMCS; both would
    // mean the hardware itself is broken, so aborting after the block is sufficient.
    unsigned char vmwStat = 0;
#define W(f,v)  vmwStat |= __vmx_vmwrite((f), (ULONG64)(v))

    W(VMCS_PIN_BASED_VM_EXEC_CONTROL,    pinCtls);
    W(VMCS_CPU_BASED_VM_EXEC_CONTROL,    cpuCtls);
    W(VMCS_SECONDARY_VM_EXEC_CONTROL,    cpu2Ctls);
    W(VMCS_VPID,                         procNum + 1);
    W(VMCS_EPT_POINTER,                  ctx->Eptp);
    W(VMCS_MSR_BITMAP,                   msrBmpPhys.QuadPart);
    W(VMCS_IO_BITMAP_A,                  ioBmpAPhys.QuadPart);
    W(VMCS_IO_BITMAP_B,                  ioBmpBPhys.QuadPart);
    W(VMCS_TSC_OFFSET,                   0);

    // Optional features: branching on compile-time-stable booleans set in Phase A.
    if (vmfuncOk && ctx->EptpListPage) {
        W(VMCS_VMFUNC_CONTROLS,   1ULL);
        W(VMCS_EPTP_LIST_ADDRESS, eptpListPhys.QuadPart);
    }
    if (shadowOk) {
        W(VMCS_VMREAD_BITMAP,  vmrdBmpPhys.QuadPart);
        W(VMCS_VMWRITE_BITMAP, vmwrBmpPhys.QuadPart);
    }
    if (sppOk)
        W(VMCS_SPP_TABLE_POINTER, sppPhys.QuadPart);
    if (pmuOk) {
        W(VMCS_GUEST_PERF_GLOBAL_CTRL, ctx->GuestPerfGlobalCtrl);
        W(VMCS_HOST_PERF_GLOBAL_CTRL,  0ULL);
    }

    W(VMCS_VM_EXIT_CONTROLS,          exitCtls);
    W(VMCS_VM_ENTRY_CONTROLS,         entryCtls);
    W(VMCS_EXCEPTION_BITMAP,          (1UL << 1));
    W(VMCS_CR3_TARGET_COUNT,          0);
    W(VMCS_VM_EXIT_MSR_STORE_COUNT,   0);
    W(VMCS_VM_EXIT_MSR_LOAD_COUNT,    0);
    W(VMCS_VM_ENTRY_MSR_LOAD_COUNT,   ctx->MsrLoadPhysAddr ? 1 : 0);
    if (ctx->MsrLoadPhysAddr) W(VMCS_VM_ENTRY_MSR_LOAD_ADDR, ctx->MsrLoadPhysAddr);
    W(VMCS_VM_ENTRY_INTR_INFO,        0);
    W(VMCS_CR0_GUEST_HOST_MASK,       0);
    W(VMCS_CR4_GUEST_HOST_MASK,       CR4_HV_OWNED_MASK);
    W(VMCS_CR0_READ_SHADOW,           cr0);
    W(VMCS_CR4_READ_SHADOW,           cr4 & ~CR4_VMXE);
    W(VMCS_VMCS_LINK_POINTER,         shadowOk ? shadowPhys.QuadPart : 0xFFFFFFFFFFFFFFFFULL);

    W(VMCS_HOST_CR0,          cr0);
    W(VMCS_HOST_CR3,          cr3);
    W(VMCS_HOST_CR4,          cr4);
    W(VMCS_HOST_CS_SELECTOR,  selCs & ~7U);
    W(VMCS_HOST_SS_SELECTOR,  selSs & ~7U);
    W(VMCS_HOST_DS_SELECTOR,  selDs & ~7U);
    W(VMCS_HOST_ES_SELECTOR,  selEs & ~7U);
    W(VMCS_HOST_FS_SELECTOR,  selFs & ~7U);
    W(VMCS_HOST_GS_SELECTOR,  selGs & ~7U);
    W(VMCS_HOST_TR_SELECTOR,  selTr & ~7U);
    W(VMCS_HOST_FS_BASE,      fsBase);
    W(VMCS_HOST_GS_BASE,      gsBase);
    W(VMCS_HOST_TR_BASE,      trBase);
    W(VMCS_HOST_GDTR_BASE,    shadowGdtBase);
    W(VMCS_HOST_IDTR_BASE,    idtBase);
    W(VMCS_HOST_RSP,          hostRsp);
    W(VMCS_HOST_RIP,          (ULONG64)AsmVmExitHandler);
    W(VMCS_HOST_SYSENTER_CS,  sysenterCs);
    W(VMCS_HOST_SYSENTER_ESP, sysenterEsp);
    W(VMCS_HOST_SYSENTER_EIP, sysenterEip);

    W(VMCS_GUEST_CR0,    cr0);
    W(VMCS_GUEST_CR3,    cr3);
    W(VMCS_GUEST_CR4,    cr4);
    W(VMCS_GUEST_DR7,    0x400);
    W(VMCS_GUEST_RFLAGS, 0x2);

    W(VMCS_GUEST_CS_SELECTOR,      selCs);
    W(VMCS_GUEST_CS_BASE,          0);
    W(VMCS_GUEST_CS_LIMIT,         limCs);
    W(VMCS_GUEST_CS_ACCESS_RIGHTS, arCs);
    W(VMCS_GUEST_DS_SELECTOR,      selDs);
    W(VMCS_GUEST_DS_BASE,          0);
    W(VMCS_GUEST_DS_LIMIT,         limDs);
    W(VMCS_GUEST_DS_ACCESS_RIGHTS, arDs);
    W(VMCS_GUEST_ES_SELECTOR,      selEs);
    W(VMCS_GUEST_ES_BASE,          0);
    W(VMCS_GUEST_ES_LIMIT,         limEs);
    W(VMCS_GUEST_ES_ACCESS_RIGHTS, arEs);
    W(VMCS_GUEST_SS_SELECTOR,      selSs);
    W(VMCS_GUEST_SS_BASE,          0);
    W(VMCS_GUEST_SS_LIMIT,         limSs);
    W(VMCS_GUEST_SS_ACCESS_RIGHTS, arSs);
    W(VMCS_GUEST_FS_SELECTOR,      selFs);
    W(VMCS_GUEST_FS_BASE,          fsBase);
    W(VMCS_GUEST_FS_LIMIT,         limFs);
    W(VMCS_GUEST_FS_ACCESS_RIGHTS, arFs);
    W(VMCS_GUEST_GS_SELECTOR,      selGs);
    W(VMCS_GUEST_GS_BASE,          gsBase);
    W(VMCS_GUEST_GS_LIMIT,         limGs);
    W(VMCS_GUEST_GS_ACCESS_RIGHTS, arGs);
    W(VMCS_GUEST_TR_SELECTOR,      selTr);
    W(VMCS_GUEST_TR_BASE,          trBase);
    W(VMCS_GUEST_TR_LIMIT,         limTr);
    W(VMCS_GUEST_TR_ACCESS_RIGHTS, arTr);
    W(VMCS_GUEST_LDTR_SELECTOR,      0);
    W(VMCS_GUEST_LDTR_BASE,          0);
    W(VMCS_GUEST_LDTR_LIMIT,         0xFFFF);
    W(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    W(VMCS_GUEST_GDTR_BASE,  shadowGdtBase);
    W(VMCS_GUEST_GDTR_LIMIT, gdtLimit);
    W(VMCS_GUEST_IDTR_BASE,  idtBase);
    W(VMCS_GUEST_IDTR_LIMIT, idtLimit);
    W(VMCS_GUEST_INTERRUPTIBILITY,        0);
    W(VMCS_GUEST_ACTIVITY_STATE,          0);
    W(VMCS_GUEST_PENDING_DBG_EXCEPTIONS,  0);
    W(VMCS_GUEST_DEBUGCTL,                0);
    W(VMCS_GUEST_SYSENTER_CS,      sysenterCs);
    W(VMCS_GUEST_SYSENTER_ESP,     sysenterEsp);
    W(VMCS_GUEST_SYSENTER_EIP,     sysenterEip);

#undef W

    // Single post-block check: if any VMWRITE failed, abort before VMLAUNCH.
    // VMWRITE failure sets ZF (VMfailValid) when there is a current VMCS, so
    // VM_INSTRUCTION_ERROR is readable here.  CF (VMfailInvalid, no current VMCS)
    // would mean VMPTRLD silently succeeded with a bad pointer — extremely unlikely,
    // but the error read is still safe: it returns 0 (no error recorded) in that case.
    if (vmwStat != 0) {
        LogVmxInstrError(procNum, "VMWRITE batch");
        __vmx_off();
        __writecr4(cr4WithoutVmxe);
        ctx->LaunchResult = 0xFC;
        _enable();
        KeLowerIrql(oldIrql);
        return 0;
    }

    ctx->LaunchResult = AsmLaunchAndReturn(hostRsp, ctx);

    // LaunchResult != 0: vmlaunch failed — tear down VMX on this core.
    // LaunchResult == 0: guest ran and called teardown; AsmVmExitHandler
    //   already executed VMXOFF and jumped to launch_resume.  Do NOT write
    //   CR4 here — VMXE is already clear and we are back in host mode.
    if (ctx->LaunchResult != 0) {
        // VMLAUNCH fell through — CPU rejected the VMCS (ZF=1, VMfailValid).
        // VM_INSTRUCTION_ERROR and VM_EXIT_REASON are both valid here.
        ULONG64 exitReason = 0xDEAD, vmInstrError = 0xDEAD;
        __vmx_vmread(VMCS_VM_EXIT_REASON,       &exitReason);
        __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR,  &vmInstrError);
        ctx->VmEntryError = vmInstrError;
        ctx->ExitReason   = (ULONG)exitReason;
        HvLog("!!! DayZHV: [VMLAUNCH FAIL core=%02u] VM_EXIT_REASON=0x%08llX  "
              "VM_INSTRUCTION_ERROR=%llu (%s)",
              procNum, exitReason, vmInstrError, VmxInstrErrorName(vmInstrError));
        __vmx_off();
        __writecr4(cr4WithoutVmxe);
    }

    // Re-enable interrupts, then lower IRQL so the deferred tick can fire
    // safely outside VMX root.
    _enable();
    KeLowerIrql(oldIrql);

    // --- DIAG: Decode instruction-trace sentinel and log results. ---
    // LaunchResult values and their meanings:
    //   0x00 = success (guest launched, tore down cleanly)
    //   0xFB = machine died inside VMXON (log stopped before 0xFA)
    //   0xFA = machine died inside VMPTRLD (log stopped before 0xF9)
    //   0xF9 = machine died inside VMWRITE block or VMLAUNCH itself
    //   0xFE = VMXON instruction returned non-zero (bad region/CR4)
    //   0xFD = VMPTRLD instruction returned non-zero (bad VMCS PA)
    //   0xFC = a VMWRITE in the batch failed (bad field / no current VMCS)
    //   any other non-zero = AsmLaunchAndReturn reported VMLAUNCH failure
    {
        const char *phase = "?";
        switch (ctx->LaunchResult) {
        case 0x00: phase = "SUCCESS";                                         break;
        case 0xFB: phase = "HUNG in VMXON  (log never advanced past 0xFB)";  break;
        case 0xFA: phase = "HUNG in VMPTRLD(log never advanced past 0xFA)";  break;
        case 0xF9: phase = "HUNG in VMWRITE/VMLAUNCH (log stopped at 0xF9)"; break;
        case 0xFE: phase = "VMXON returned failure";                          break;
        case 0xFD: phase = "VMPTRLD returned failure";                        break;
        case 0xFC: phase = "VMWRITE batch failure";                           break;
        default:   phase = "VMLAUNCH fell through (CPU rejected VMCS)";       break;
        }
        HvLog("!!! DayZHV: [VMINSTR DIAG core=%02u] LaunchResult=0x%02X  Phase: %s",
              procNum, ctx->LaunchResult, phase);
        if (ctx->LaunchResult != 0) {
            HvLog("!!! DayZHV: [VMINSTR DIAG core=%02u] VM_EXIT_REASON=0x%08X  VM_INSTRUCTION_ERROR=0x%llX",
                  procNum, ctx->ExitReason, ctx->VmEntryError);
            HvLog("!!! DayZHV: [VMINSTR DIAG core=%02u] MTF_FLAG_in_cpuCtls=CLEARED(explicit &= ~0x08000000)",
                  procNum);
            HvLog("!!! DayZHV: [VMINSTR DIAG core=%02u] shadowGDT=0x%llX(%s)  IDT=0x%llX(%s)",
                  procNum,
                  shadowGdtBase, (shadowGdtBase & 0xF) == 0 ? "16B-aligned" : "UNALIGNED",
                  idtBase,       (idtBase       & 0xF) == 0 ? "16B-aligned" : "UNALIGNED");
        }
    }

    // Post-launch diagnostics logged after returning to normal IRQL.
    if (vmfuncOk && ctx->EptpListPage)
        HvLog("!!! DayZHV: [DIAG core=%02u] VMFUNC enabled  eptp_list_pa=0x%llX", procNum, eptpListPhys.QuadPart);
    if (shadowOk)
        HvLog("!!! DayZHV: [DIAG core=%02u] VMCS shadowing enabled  shadow_pa=0x%llX", procNum, shadowPhys.QuadPart);
    if (sppOk)
        HvLog("!!! DayZHV: [DIAG core=%02u] SPP enabled  spp_table_pa=0x%llX", procNum, sppPhys.QuadPart);
    if (pmuOk)
        HvLog("!!! DayZHV: [DIAG core=%02u] PMU isolation enabled  guest_perf_ctrl=0x%llX", procNum, ctx->GuestPerfGlobalCtrl);

    return 0;
}

// ---------------------------------------------------------------------------
// VmxTeardown — signal all cores to vmxoff, then free driver allocations.
// Called from DriverUnload at PASSIVE_LEVEL.
// ---------------------------------------------------------------------------
static ULONG_PTR VmxTeardownCore(ULONG_PTR unused)
{
    UNREFERENCED_PARAMETER(unused);
    ULONG proc = KeGetCurrentProcessorNumberEx(NULL);
    HvLogDbg("[TEARDOWN] core %u pending", proc);
    if (g_CoreCtx[proc])
        g_CoreCtx[proc]->TeardownPending = TRUE;
    // Force a VM-exit on this core so VmExitDispatch sees TeardownPending.
    // CPUID always causes a VM-exit when in VMX non-root (Intel SDM Vol 3C 25.1.2).
    int r[4];
    __cpuid(r, 0);
    HvLogDbg("[TEARDOWN] core %u vmxoff done", proc);
    return 0;
}

void VmxTeardown(void)
{
    if (!g_CtxArray) return;

    KeIpiGenericCall(VmxTeardownCore, 0);
    // All cores have now vmxoff'd and jumped back to launch_resume.

    // Log aggregated exit telemetry before freeing contexts.
    EXIT_STATS total = {0};
    for (ULONG i = 0; i < g_ProcCount; i++) {
        total.TotalExits   += g_CtxArray[i].Stats.TotalExits;
        total.ExternalInt  += g_CtxArray[i].Stats.ExternalInt;
        total.Preemption   += g_CtxArray[i].Stats.Preemption;
        total.Cpuid        += g_CtxArray[i].Stats.Cpuid;
        total.Rdmsr        += g_CtxArray[i].Stats.Rdmsr;
        total.Wrmsr        += g_CtxArray[i].Stats.Wrmsr;
        total.EptViolation += g_CtxArray[i].Stats.EptViolation;
        total.Mtf          += g_CtxArray[i].Stats.Mtf;
        total.Exception    += g_CtxArray[i].Stats.Exception;
        total.Other        += g_CtxArray[i].Stats.Other;
    }
    HvLog("!!! DayZHV: [STATS] Total=%llu ExtInt=%llu Preempt=%llu CPUID=%llu "
          "RDMSR=%llu WRMSR=%llu EPT=%llu MTF=%llu Exc=%llu Other=%llu",
          total.TotalExits, total.ExternalInt, total.Preemption,
          total.Cpuid, total.Rdmsr, total.Wrmsr,
          total.EptViolation, total.Mtf, total.Exception, total.Other);

    FreeCoreCxtArray(g_CtxArray, g_ProcCount);
    ExFreePoolWithTag(g_CtxArray, 'HvCA');
    EptFree(&g_Ept);
    if (g_DecoyPage) {
        ExFreePoolWithTag(g_DecoyPage, 'HvDC');
        g_DecoyPage = NULL;
    }
    if (g_VmxDiag) {
        ExFreePoolWithTag(g_VmxDiag, 'HvDB');
        g_VmxDiag = NULL;
    }
    g_CtxArray    = NULL;
    g_ProcCount   = 0;
    g_LstarLocked = FALSE;  // reset so a reload starts with LSTAR writes permitted
    RtlZeroMemory(g_CoreCtx, sizeof(g_CoreCtx));
}

// ---------------------------------------------------------------------------
// VmxProbeCore — IPI worker: VMXON + VMPTRLD + write all VMCS fields +
// read them back to verify, then VMXOFF.  Never executes VMLAUNCH.
// Populates ctx->LaunchResult: 0 = VMCS valid, non-zero = bad field logged.
//
// Same Phase A / Phase B split as VmxLaunchCore: all reads and computes at
// current IRQL, VMX instructions only inside the narrow IPI_LEVEL window.
// ---------------------------------------------------------------------------
static ULONG_PTR VmxProbeCore(ULONG_PTR ctxArrayPtr)
{
    PCORE_VMX_CONTEXT arr = (PCORE_VMX_CONTEXT)ctxArrayPtr;
    ULONG procNum = KeGetCurrentProcessorNumberEx(NULL);
    if (procNum >= g_ProcCount) return 0;
    PCORE_VMX_CONTEXT ctx = &arr[procNum];

    // ------------------------------------------------------------------
    // Phase A: compute all VMCS values at current IRQL.
    // ------------------------------------------------------------------
    DetectCoreTopology(ctx, procNum);
    // Ignore CPUID topology result — force all threads in the 0xFFFF mask to P-core.
    if (procNum < 64 && ((HV_PCORE_AFFINITY_MASK >> procNum) & 1ULL))
        ctx->CoreType = 1;
    ctx->LaunchResult = 0xFF;

    // Log MSR 0x3A and Revision ID for each probed core — hardware lock state
    // and RevisionId mismatch are the two silent hang causes on 14900K.
    {
        ULONGLONG fc       = __readmsr(IA32_FEATURE_CONTROL);
        ULONGLONG vmxBasic = __readmsr(IA32_VMX_BASIC);
        ULONG     rid      = (ULONG)(vmxBasic & 0x7FFFFFFF);
        HvLog("!!! DayZHV: [PROBE core %u] IA32_FEATURE_CONTROL=0x%llX  Lock=%u  Bit2=%u  RevisionId=0x%08X  VMX_BASIC=0x%llX",
              procNum, fc, (ULONG)(fc & 1), (ULONG)((fc >> 2) & 1), rid, vmxBasic);
        if ((fc & 0x1) && !(fc & 0x4))
            HvLog("!!! DayZHV: [PROBE core %u] FATAL — BIOS locked MSR 0x3A without EnableVmxOutsideSmx. VMXON will #GP.", procNum);
    }

    ULONG revId = GetVmcsRevisionId();
    *(ULONG*)ctx->VmxonRegion = revId;
    *(ULONG*)ctx->VmcsRegion  = revId;

    ULONG64 gdtBase  = AsmGetGdtBase();
    USHORT  gdtLimit = AsmGetGdtLimit();
    RtlCopyMemory(ctx->ShadowGdt, (PVOID)gdtBase, min((ULONG)gdtLimit + 1, PAGE_SIZE));
    ULONG64 shadowGdtBase = (ULONG64)ctx->ShadowGdt;
    ULONG64 idtBase  = AsmGetIdtBase();
    USHORT  idtLimit = AsmGetIdtLimit();
    USHORT selCs = AsmGetCs(), selDs = AsmGetDs(), selEs = AsmGetEs();
    USHORT selSs = AsmGetSs(), selFs = AsmGetFs(), selGs = AsmGetGs();
    USHORT selTr = AsmGetTr();
    ULONG64 fsBase = __readmsr(IA32_FS_BASE);
    ULONG64 gsBase = __readmsr(IA32_GS_BASE);
    ULONG64 trBase = GetTssBase(gdtBase, selTr);
    ULONG arCs = 0xA09B;
    ULONG arDs = (AsmGetLar(selDs) >> 8) & 0xF0FF;
    ULONG arEs = (AsmGetLar(selEs) >> 8) & 0xF0FF;
    ULONG arSs = 0xC093;
    ULONG arFs = (AsmGetLar(selFs) >> 8) & 0xF0FF;
    ULONG arGs = (AsmGetLar(selGs) >> 8) & 0xF0FF;
    ULONG arTr = (AsmGetLar(selTr) >> 8) & 0xF0FF;
    ULONG limCs = 0xFFFFFFFF;   // SDM: 64-bit CS must have limit=0xFFFFFFFF; LSL unreliable under mapper
    ULONG limDs = AsmGetLsl(selDs);
    ULONG limEs = AsmGetLsl(selEs);
    ULONG limSs = 0xFFFFFFFF;   // SDM: SS limit must match CS in ring-0 VMX entry check
    ULONG limFs = AsmGetLsl(selFs), limGs = AsmGetLsl(selGs);
    ULONG limTr = AsmGetLsl(selTr);
    ULONG64 cr0 = AdjustCr0(__readcr0());
    ULONG64 cr3 = __readcr3();
    ULONG64 cr4 = AdjustCr4(__readcr4());
    ULONG64 hostRsp = ((ULONG64)ctx->HostStack + 0x8000 - 16) & ~0xFULL;
    ULONG pinCtls  = AdjustControls(0, IA32_VMX_PINBASED_CTLS);
    ULONG cpuCtls  = AdjustControls(CPU_BASED_HLT_EXITING |
                                    CPU_BASED_USE_TSC_OFFSETTING |
                                    CPU_BASED_MOV_DR_EXITING |
                                    CPU_BASED_USE_IO_BITMAPS |
                                    CPU_BASED_USE_MSR_BITMAPS |
                                    CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
                                    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
                                    IA32_VMX_PROCBASED_CTLS);
    ULONG cpu2Ctls = AdjustControls(SECONDARY_EXEC_ENABLE_EPT |
                                    SECONDARY_EXEC_ENABLE_EPT_AD |
                                    SECONDARY_EXEC_ENABLE_VPID |
                                    SECONDARY_EXEC_DESC_TABLE_EXITING |
                                    SECONDARY_EXEC_ENABLE_XSETBV,
                                    IA32_VMX_PROCBASED_CTLS2);
    ULONG exitCtls  = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE, IA32_VMX_EXIT_CTLS);
    ULONG entryCtls = AdjustControls(VM_ENTRY_IA32E_MODE_GUEST,    IA32_VMX_ENTRY_CTLS);

    PHYSICAL_ADDRESS vmxonPhys   = MmGetPhysicalAddress(ctx->VmxonRegion);
    PHYSICAL_ADDRESS vmcsPhys    = MmGetPhysicalAddress(ctx->VmcsRegion);
    PHYSICAL_ADDRESS msrBmpPhys  = MmGetPhysicalAddress(ctx->MsrBitmap);
    PHYSICAL_ADDRESS ioBmpAPhys  = MmGetPhysicalAddress(ctx->IoBitmapA);
    PHYSICAL_ADDRESS ioBmpBPhys  = MmGetPhysicalAddress(ctx->IoBitmapB);

    ULONG64 sysenterCs  = __readmsr(0x174);
    ULONG64 sysenterEsp = __readmsr(0x175);
    ULONG64 sysenterEip = __readmsr(0x176);

    // Initialize VM-entry MSR-load area (probe path — same structure as launch path).
    if (ctx->MsrLoadPage) {
        ULONG  *msrIdx  = (ULONG  *)((ULONG_PTR)ctx->MsrLoadPage + 0);
        ULONG  *msrRsvd = (ULONG  *)((ULONG_PTR)ctx->MsrLoadPage + 4);
        ULONG64 *msrDat = (ULONG64*)((ULONG_PTR)ctx->MsrLoadPage + 8);
        *msrIdx  = IA32_KERNEL_GS_BASE;
        *msrRsvd = 0;
        *msrDat  = __readmsr(IA32_KERNEL_GS_BASE);
        ctx->MsrLoadPhysAddr = MmGetPhysicalAddress(ctx->MsrLoadPage).QuadPart;
    } else {
        ctx->MsrLoadPhysAddr = 0;
    }

    KeFlushQueuedDpcs();
    __writecr3(__readcr3());
    KeMemoryBarrier();
    int _unused[4]; __cpuid(_unused, 0);

    // Pre-compute CR4 variants so Phase B never calls __readcr4().
    ULONG64 cr4WithVmxe    = cr4 | (1ULL << 13);
    ULONG64 cr4WithoutVmxe = cr4 & ~(1ULL << 13);

    for (int _pi = 0; _pi < 500; _pi++)
        _mm_pause();

    // ------------------------------------------------------------------
    // Phase B: narrow IPI_LEVEL window — VMX instructions only.
    // ------------------------------------------------------------------
    KIRQL oldIrql;
    KeRaiseIrql(IPI_LEVEL, &oldIrql);
    _disable();

    __writecr4(cr4WithVmxe);

    {
        unsigned char _vonRet = __vmx_on((ULONGLONG*)&vmxonPhys.QuadPart);
        if (_vonRet != 0) {
            __writecr4(cr4WithoutVmxe);
            ctx->LaunchResult = 0xFE;
            _enable();
            KeLowerIrql(oldIrql);
            HvLog("!!! DayZHV: [PROBE VMXON FAIL core=%02u] __vmx_on returned %u  vmxon_pa=0x%llX",
                  procNum, (ULONG)_vonRet, vmxonPhys.QuadPart);
            return 0;
        }
    }

    {
        unsigned char _pldRet = __vmx_vmptrld((ULONGLONG*)&vmcsPhys.QuadPart);
        if (_pldRet != 0) {
            __vmx_off();
            __writecr4(cr4WithoutVmxe);
            ctx->LaunchResult = 0xFD;
            _enable();
            KeLowerIrql(oldIrql);
            HvLog("!!! DayZHV: [PROBE VMPTRLD FAIL core=%02u] __vmx_vmptrld returned %u  vmcs_pa=0x%llX",
                  procNum, (ULONG)_pldRet, vmcsPhys.QuadPart);
            return 0;
        }
    }

#define PVMW(field, value) do { \
    if (__vmx_vmwrite((field), (ULONG64)(value)) != 0) { \
        __vmx_off(); __writecr4(cr4WithoutVmxe); \
        ctx->LaunchResult = 0xFC; ctx->FailedVmwriteField = (field); \
        _enable(); KeLowerIrql(oldIrql); return 0; \
    } \
} while(0)

#define PVMR(field, expected) do { \
    ULONG64 _rd = 0; __vmx_vmread((field), &_rd); \
    if (_rd != (ULONG64)(expected)) { \
        __vmx_off(); __writecr4(cr4WithoutVmxe); \
        ctx->LaunchResult = 0xFB; ctx->FailedVmwriteField = (field); \
        _enable(); KeLowerIrql(oldIrql); \
        HvLog("!!! DayZHV: [PROBE READBACK MISMATCH core=%02u] field=0x%04X wrote=0x%llX read=0x%llX", \
              procNum, (field), (ULONG64)(expected), _rd); \
        return 0; \
    } \
} while(0)

    PVMW(VMCS_PIN_BASED_VM_EXEC_CONTROL,   pinCtls);
    PVMW(VMCS_CPU_BASED_VM_EXEC_CONTROL,   cpuCtls);
    PVMW(VMCS_SECONDARY_VM_EXEC_CONTROL,   cpu2Ctls);
    PVMW(VMCS_VPID,                        procNum + 1);
    PVMW(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMW(VMCS_MSR_BITMAP,                  msrBmpPhys.QuadPart);
    PVMW(VMCS_IO_BITMAP_A,                 ioBmpAPhys.QuadPart);
    PVMW(VMCS_IO_BITMAP_B,                 ioBmpBPhys.QuadPart);
    PVMW(VMCS_TSC_OFFSET,                  0);
    PVMW(VMCS_VM_EXIT_CONTROLS,            exitCtls);
    PVMW(VMCS_VM_ENTRY_CONTROLS,           entryCtls);
    PVMW(VMCS_EXCEPTION_BITMAP,            0);
    PVMW(VMCS_CR3_TARGET_COUNT,            0);
    PVMW(VMCS_VM_EXIT_MSR_STORE_COUNT,     0);
    PVMW(VMCS_VM_EXIT_MSR_LOAD_COUNT,      0);
    PVMW(VMCS_VM_ENTRY_MSR_LOAD_COUNT,     ctx->MsrLoadPhysAddr ? 1 : 0);
    if (ctx->MsrLoadPhysAddr) PVMW(VMCS_VM_ENTRY_MSR_LOAD_ADDR, ctx->MsrLoadPhysAddr);
    PVMW(VMCS_VM_ENTRY_INTR_INFO,          0);
    PVMW(VMCS_CR0_GUEST_HOST_MASK,         0);
    PVMW(VMCS_CR4_GUEST_HOST_MASK,         CR4_HV_OWNED_MASK);
    PVMW(VMCS_CR0_READ_SHADOW,             cr0);
    PVMW(VMCS_CR4_READ_SHADOW,             cr4 & ~CR4_VMXE);
    PVMW(VMCS_VMCS_LINK_POINTER,           0xFFFFFFFFFFFFFFFFULL);
    PVMW(VMCS_HOST_CR0,                    cr0);
    PVMW(VMCS_HOST_CR3,                    cr3);
    PVMW(VMCS_HOST_CR4,                    cr4);
    PVMW(VMCS_HOST_CS_SELECTOR,            selCs & ~7U);
    PVMW(VMCS_HOST_SS_SELECTOR,            selSs & ~7U);
    PVMW(VMCS_HOST_DS_SELECTOR,            selDs & ~7U);
    PVMW(VMCS_HOST_ES_SELECTOR,            selEs & ~7U);
    PVMW(VMCS_HOST_FS_SELECTOR,            selFs & ~7U);
    PVMW(VMCS_HOST_GS_SELECTOR,            selGs & ~7U);
    PVMW(VMCS_HOST_TR_SELECTOR,            selTr & ~7U);
    PVMW(VMCS_HOST_FS_BASE,                fsBase);
    PVMW(VMCS_HOST_GS_BASE,                gsBase);
    PVMW(VMCS_HOST_TR_BASE,                trBase);
    PVMW(VMCS_HOST_GDTR_BASE,              shadowGdtBase);
    PVMW(VMCS_HOST_IDTR_BASE,              idtBase);
    PVMW(VMCS_HOST_RSP,                    hostRsp);
    PVMW(VMCS_HOST_RIP,                    (ULONG64)AsmVmExitHandler);
    PVMW(VMCS_HOST_SYSENTER_CS,            sysenterCs);
    PVMW(VMCS_HOST_SYSENTER_ESP,           sysenterEsp);
    PVMW(VMCS_HOST_SYSENTER_EIP,           sysenterEip);
    PVMW(VMCS_GUEST_CR0,                   cr0);
    PVMW(VMCS_GUEST_CR3,                   cr3);
    PVMW(VMCS_GUEST_CR4,                   cr4);
    PVMW(VMCS_GUEST_DR7,                   0x400);
    PVMW(VMCS_GUEST_RFLAGS,                0x2);
    PVMW(VMCS_GUEST_CS_SELECTOR,           selCs);
    PVMW(VMCS_GUEST_CS_BASE,               0);
    PVMW(VMCS_GUEST_CS_LIMIT,              limCs);
    PVMW(VMCS_GUEST_CS_ACCESS_RIGHTS,      arCs);
    PVMW(VMCS_GUEST_DS_SELECTOR,           selDs);
    PVMW(VMCS_GUEST_DS_BASE,               0);
    PVMW(VMCS_GUEST_DS_LIMIT,              limDs);
    PVMW(VMCS_GUEST_DS_ACCESS_RIGHTS,      arDs);
    PVMW(VMCS_GUEST_ES_SELECTOR,           selEs);
    PVMW(VMCS_GUEST_ES_BASE,               0);
    PVMW(VMCS_GUEST_ES_LIMIT,              limEs);
    PVMW(VMCS_GUEST_ES_ACCESS_RIGHTS,      arEs);
    PVMW(VMCS_GUEST_SS_SELECTOR,           selSs);
    PVMW(VMCS_GUEST_SS_BASE,               0);
    PVMW(VMCS_GUEST_SS_LIMIT,              limSs);
    PVMW(VMCS_GUEST_SS_ACCESS_RIGHTS,      arSs);
    PVMW(VMCS_GUEST_FS_SELECTOR,           selFs);
    PVMW(VMCS_GUEST_FS_BASE,               fsBase);
    PVMW(VMCS_GUEST_FS_LIMIT,              limFs);
    PVMW(VMCS_GUEST_FS_ACCESS_RIGHTS,      arFs);
    PVMW(VMCS_GUEST_GS_SELECTOR,           selGs);
    PVMW(VMCS_GUEST_GS_BASE,               gsBase);
    PVMW(VMCS_GUEST_GS_LIMIT,              limGs);
    PVMW(VMCS_GUEST_GS_ACCESS_RIGHTS,      arGs);
    PVMW(VMCS_GUEST_TR_SELECTOR,           selTr);
    PVMW(VMCS_GUEST_TR_BASE,               trBase);
    PVMW(VMCS_GUEST_TR_LIMIT,              limTr);
    PVMW(VMCS_GUEST_TR_ACCESS_RIGHTS,      arTr);
    PVMW(VMCS_GUEST_LDTR_SELECTOR,         0);
    PVMW(VMCS_GUEST_LDTR_BASE,             0);
    PVMW(VMCS_GUEST_LDTR_LIMIT,            0xFFFF);
    PVMW(VMCS_GUEST_LDTR_ACCESS_RIGHTS,    0x10000);
    PVMW(VMCS_GUEST_GDTR_BASE,             shadowGdtBase);
    PVMW(VMCS_GUEST_GDTR_LIMIT,            gdtLimit);
    PVMW(VMCS_GUEST_IDTR_BASE,             idtBase);
    PVMW(VMCS_GUEST_IDTR_LIMIT,            idtLimit);
    PVMW(VMCS_GUEST_INTERRUPTIBILITY,        0);
    PVMW(VMCS_GUEST_ACTIVITY_STATE,          0);
    PVMW(VMCS_GUEST_PENDING_DBG_EXCEPTIONS,  0);
    PVMW(VMCS_GUEST_DEBUGCTL,                0);
    PVMW(VMCS_GUEST_SYSENTER_CS,           sysenterCs);
    PVMW(VMCS_GUEST_SYSENTER_ESP,          sysenterEsp);
    PVMW(VMCS_GUEST_SYSENTER_EIP,          sysenterEip);

    PVMR(VMCS_PIN_BASED_VM_EXEC_CONTROL,   pinCtls);
    PVMR(VMCS_CPU_BASED_VM_EXEC_CONTROL,   cpuCtls);
    PVMR(VMCS_SECONDARY_VM_EXEC_CONTROL,   cpu2Ctls);
    PVMR(VMCS_VPID,                        procNum + 1);
    PVMR(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMR(VMCS_MSR_BITMAP,                  msrBmpPhys.QuadPart);
    PVMR(VMCS_IO_BITMAP_A,                 ioBmpAPhys.QuadPart);
    PVMR(VMCS_IO_BITMAP_B,                 ioBmpBPhys.QuadPart);
    PVMR(VMCS_TSC_OFFSET,                  0);
    PVMR(VMCS_VM_EXIT_CONTROLS,            exitCtls);
    PVMR(VMCS_VM_ENTRY_CONTROLS,           entryCtls);
    PVMR(VMCS_HOST_RIP,                    (ULONG64)AsmVmExitHandler);
    PVMR(VMCS_HOST_RSP,                    hostRsp);
    PVMR(VMCS_HOST_CR0,                    cr0);
    PVMR(VMCS_HOST_CR3,                    cr3);
    PVMR(VMCS_HOST_CR4,                    cr4);
    PVMR(VMCS_HOST_CS_SELECTOR,            selCs & ~7U);
    PVMR(VMCS_HOST_TR_SELECTOR,            selTr & ~7U);
    PVMR(VMCS_HOST_GDTR_BASE,              shadowGdtBase);
    PVMR(VMCS_GUEST_CR0,                   cr0);
    PVMR(VMCS_GUEST_CR3,                   cr3);
    PVMR(VMCS_GUEST_CR4,                   cr4);
    PVMR(VMCS_CR4_GUEST_HOST_MASK,         CR4_HV_OWNED_MASK);
    PVMR(VMCS_CR4_READ_SHADOW,             cr4 & ~CR4_VMXE);
    PVMR(VMCS_VMCS_LINK_POINTER,           0xFFFFFFFFFFFFFFFFULL);

#undef PVMW
#undef PVMR

    __vmx_off();
    __writecr4(cr4WithoutVmxe);
    ctx->LaunchResult = 0;
    _enable();
    KeLowerIrql(oldIrql);
    return 0;
}

// ---------------------------------------------------------------------------
// LogCoreResult — shared result printer used by probe and launch phases.
// ---------------------------------------------------------------------------
static void LogCoreResult(ULONG i, PCORE_VMX_CONTEXT ctx, const char *phase)
{
    BOOLEAN isProbe = (phase[0] == 'P' && phase[1] == 'R');  // "PROBE"
    if (ctx->LaunchResult == 0) {
        if (isProbe) {
            HvLog("!!! DayZHV: [%s CORE %02u] OK", phase, i);
        } else {
            HvLog("!!! DayZHV: [%s CORE %02u] OK  KgsBase=0x%llX (KPCR)",
                  phase, i, ctx->HostKernelGsBase);
        }
    } else if (ctx->LaunchResult == 0xFC || ctx->LaunchResult == 0xFB) {
        HvLog("!!! DayZHV: [%s CORE %02u] FAIL  result=0x%X vmwrite_field=0x%04X",
              phase, i, ctx->LaunchResult, ctx->FailedVmwriteField);
    } else {
        HvLog("!!! DayZHV: [%s CORE %02u] FAIL  result=0x%X exit=%u(%s) vmErr=%llu actState=%llu rflags=0x%llX",
              phase, i, ctx->LaunchResult, ctx->ExitReason,
              ExitReasonName(ctx->ExitReason),
              ctx->VmEntryError, ctx->GuestActivity, ctx->GuestRflags);
    }
}

// ---------------------------------------------------------------------------
// VmxIsolateInfrastructure — write-protect hypervisor control structures.
//
// Runs after EptBuildIdentityMap and self-hiding, before Phase 1 probe.
// Three passes:
//   1. VmcsRegion + VmxonRegion for each core   (EPT_READ | EPT_EXEC)
//   2. All EPT paging structures (PML4 + children walked live)
//   3. Driver image pages (base via RtlPcToFileHeader, size from PE header)
//
// Each protected GPA is also registered in g_WpTable (sorted ascending).
// g_InveptPending is set at the end so each core flushes on its first exit.
// Write faults on registered GPAs are handled in HandleEptViolation (#GP(0)).
// ---------------------------------------------------------------------------
static void WpRegister(ULONG64 Gpa)
{
    Gpa &= ~0xFFFULL;
    if (g_WpCount >= WP_TABLE_SIZE) return;
    // Skip if already registered (e.g. two cores share a page — unlikely but safe).
    for (ULONG i = 0; i < g_WpCount; i++)
        if (g_WpTable[i] == Gpa) return;
    g_WpTable[g_WpCount++] = Gpa;
}

static void WpProtectPage(PEPT_CONTEXT Ept, PVOID Va)
{
    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(Va);
    if (pa.QuadPart == 0) return;
    ULONG64 gpa = (ULONG64)pa.QuadPart & ~0xFFFULL;
    EptMapPage4KB(Ept, gpa, gpa, EPT_READ | EPT_EXEC | EPT_MEMTYPE_WB);
    WpRegister(gpa);
}

static int WpGpaCompare(const void *a, const void *b)
{
    ULONG64 ga = *(const ULONG64*)a;
    ULONG64 gb = *(const ULONG64*)b;
    if (ga < gb) return -1;
    if (ga > gb) return  1;
    return 0;
}

static void VmxIsolateInfrastructure(ULONG ProcCount)
{
    // Pass 1 — VMCS and VMXON regions.
    for (ULONG i = 0; i < ProcCount; i++) {
        if (g_CtxArray[i].VmcsRegion)
            WpProtectPage(&g_Ept, g_CtxArray[i].VmcsRegion);
        if (g_CtxArray[i].VmxonRegion)
            WpProtectPage(&g_Ept, g_CtxArray[i].VmxonRegion);
    }
    HvLog("!!! DayZHV: [ISOLATE] Pass 1: %u VMCS/VMXON pages protected.", g_WpCount);

    // Pass 2 — EPT paging structures: walk PML4 → PDPT → PD, collect table VAs.
    // PT pages are created on demand (lazy-map); only pre-built identity-map
    // tables (PML4 + all PDPT/PD pages) are present now.
    ULONG eptPagesBefore = g_WpCount;
    {
        WpProtectPage(&g_Ept, g_Ept.Pml4);

        ULONG64 *pml4 = (ULONG64*)g_Ept.Pml4;
        for (ULONG pi = 0; pi < 512; pi++) {
            if (!(pml4[pi] & EPT_READ)) continue;
            ULONG64 pdpt_phys = pml4[pi] & ~0xFFFULL;
            ULONG64 *pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
            if (!pdpt_va) continue;
            WpProtectPage(&g_Ept, pdpt_va);

            for (ULONG qi = 0; qi < 512; qi++) {
                if (!(pdpt_va[qi] & EPT_READ)) continue;
                // Skip PDPTE large-page leaves (1GB) — no child PD.
                if (pdpt_va[qi] & EPT_LARGE_PAGE) continue;
                ULONG64 pd_phys = pdpt_va[qi] & ~0xFFFULL;
                ULONG64 *pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
                if (!pd_va) continue;
                WpProtectPage(&g_Ept, pd_va);
                // PT pages (4KB split leaves) are not walked here; they are
                // created lazily and protected individually if EptMapPage4KB
                // is called on a protected range later.
            }
        }
    }
    HvLog("!!! DayZHV: [ISOLATE] Pass 2: %u EPT paging-structure pages protected.",
          g_WpCount - eptPagesBefore);

    // Pass 3 — Driver image.
    ULONG imgPagesBefore = g_WpCount;
    {
        PVOID imageBase = NULL;
        PVOID result    = RtlPcToFileHeader((PVOID)(ULONG_PTR)VmxInitialize, &imageBase);
        if (result && imageBase) {
            // PE optional header SizeOfImage is at a fixed offset from the image base.
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
                    (ULONG_PTR)imageBase + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
                    ULONG64 base = (ULONG64)imageBase;
                    ULONG64 end  = base + imageSize;
                    for (ULONG64 va = base; va < end; va += PAGE_SIZE)
                        WpProtectPage(&g_Ept, (PVOID)va);
                }
            }
        }
    }
    HvLog("!!! DayZHV: [ISOLATE] Pass 3: %u driver image pages protected.",
          g_WpCount - imgPagesBefore);

    // Sort g_WpTable ascending for O(log n) binary search in WpTableContains.
    if (g_WpCount > 1) {
        // Insertion sort — 256 elements max, paid once at init, no external deps.
        for (ULONG i = 1; i < g_WpCount; i++) {
            ULONG64 key = g_WpTable[i];
            LONG    j   = (LONG)i - 1;
            while (j >= 0 && g_WpTable[j] > key) {
                g_WpTable[j + 1] = g_WpTable[j];
                j--;
            }
            g_WpTable[j + 1] = key;
        }
    }

    // Do NOT call EptInvalidate here — VMXON has not run yet at this point.
    // g_InveptPending will cause each core to flush on its first VM-exit.
    InterlockedExchange(&g_InveptPending, 1);

    HvLog("!!! DayZHV: [ISOLATE] Done. %u pages write-protected. INVEPT deferred.",
          g_WpCount);
}

// ---------------------------------------------------------------------------
// CalibrateCpuidCache — called at PASSIVE_LEVEL before any VMXON.
// Captures bare-metal CPUID responses for:
//   1. All leaves in the hypervisor range 0x40000000..0x4000000F
//   2. The 8 leaves immediately above the maximum standard leaf
//   3. CPUID exit latency: timed as (RDTSC-before − RDTSC-after) with the
//      pipeline serialised via CPUID itself, averaged over 64 iterations.
// Results stored in g_CpuidCache — the exit handler returns these values
// verbatim so the guest cannot distinguish from a bare-metal CPUID response.
// ---------------------------------------------------------------------------
static void CalibrateCpuidCache(void)
{
    int regs[4];

    // Max standard leaf.
    __cpuid(regs, 0);
    g_CpuidCache.MaxStdLeaf = (ULONG)regs[0];

    // Hypervisor range: sample each leaf in order.
    // On bare metal every leaf in this range returns EAX=EBX=ECX=EDX=0.
    for (ULONG i = 0; i < CPUID_CACHE_HV_LEAVES; i++) {
        ULONG leaf = 0x40000000 + i;
        __cpuidex(regs, (int)leaf, 0);
        g_CpuidCache.HvRange[i].Leaf = leaf;
        g_CpuidCache.HvRange[i].Eax  = (ULONG)regs[0];
        g_CpuidCache.HvRange[i].Ebx  = (ULONG)regs[1];
        g_CpuidCache.HvRange[i].Ecx  = (ULONG)regs[2];
        g_CpuidCache.HvRange[i].Edx  = (ULONG)regs[3];
    }

    // Beyond-max leaves: CPU returns max_std_leaf's EAX in EAX (or 0),
    // and in practice all-zeros — capture the actual hardware values.
    for (ULONG i = 0; i < CPUID_CACHE_BEYOND_MAX; i++) {
        ULONG leaf = g_CpuidCache.MaxStdLeaf + 1 + i;
        __cpuidex(regs, (int)leaf, 0);
        g_CpuidCache.BeyondMax[i].Leaf = leaf;
        g_CpuidCache.BeyondMax[i].Eax  = (ULONG)regs[0];
        g_CpuidCache.BeyondMax[i].Ebx  = (ULONG)regs[1];
        g_CpuidCache.BeyondMax[i].Ecx  = (ULONG)regs[2];
        g_CpuidCache.BeyondMax[i].Edx  = (ULONG)regs[3];
    }

    // TSC cost calibration: measure the TSC ticks consumed by a single CPUID
    // instruction on the host. The guest will receive this value back when it
    // executes RDTSC immediately after CPUID, making the sequence timing-clean.
    // CPUID serialises the pipeline; the first sample is a warm-up and discarded.
    // Inner loop: 64 iterations, store the minimum (not average) to avoid OS jitter.
    __cpuid(regs, 0);   // warm-up + pipeline drain
    ULONG64 minCost = (ULONG64)-1;
    for (ULONG i = 0; i < 64; i++) {
        ULONG64 t0 = __rdtsc();
        __cpuid(regs, 0);   // the instruction being timed
        ULONG64 t1 = __rdtsc();
        ULONG64 sample = t1 - t0;
        if (sample < minCost) minCost = sample;
    }
    g_CpuidCache.CpuidExitCost = minCost;

    HvLog("!!! DayZHV: [CALIB] MaxStdLeaf=0x%X  HvRange[0]=%08X/%08X/%08X/%08X  "
          "CpuidExitCost=%llu ticks",
          g_CpuidCache.MaxStdLeaf,
          g_CpuidCache.HvRange[0].Eax, g_CpuidCache.HvRange[0].Ebx,
          g_CpuidCache.HvRange[0].Ecx, g_CpuidCache.HvRange[0].Edx,
          g_CpuidCache.CpuidExitCost);
}

// ---------------------------------------------------------------------------
// VmxInitialize — probe all cores (no VMLAUNCH), then single-core pilot,
// then full resident launch via KeIpiGenericCall.
// ---------------------------------------------------------------------------
NTSTATUS VmxInitialize(void)
{
    HvLogOpen();
    HvLog("!!! DayZHV: ===== RESIDENT HYPERVISOR LAUNCH BEGIN =====");

    if (!IsVmxSupported() || !IsVmxEnabledInBios()) {
        HvLog("!!! DayZHV: [FAIL] VMX not supported or disabled in BIOS.");
        HvLogClose();
        return STATUS_NOT_SUPPORTED;
    }

    // Capture bare-metal CPUID responses and TSC cost before any VMXON.
    CalibrateCpuidCache();

    ULONG procCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    HvLog("!!! DayZHV: [INFO] Logical processor count: %u", procCount);

    // Force P-core count from the hardcoded affinity mask — avoids KeQueryGroupAffinity
    // returning 0 on some mapper launch paths, which previously zeroed pCoreCount and
    // aborted before reaching VMLAUNCH.
    ULONG pCoreCount = (ULONG)__popcnt64((ULONG64)HV_PCORE_AFFINITY_MASK);
    HvLog("!!! DayZHV: [INFO] P-core thread count (forced mask 0x%04X): %u  (total logical: %u)",
          (ULONG)HV_PCORE_AFFINITY_MASK, pCoreCount, procCount);
    procCount = pCoreCount;   // launch only on P-core threads

    if (procCount > MAX_LOGICAL_PROCESSORS) {
        HvLog("!!! DayZHV: [FAIL] procCount %u exceeds MAX_LOGICAL_PROCESSORS %u",
              procCount, MAX_LOGICAL_PROCESSORS);
        HvLogClose();
        return STATUS_NOT_SUPPORTED;
    }

    g_CtxArray = (PCORE_VMX_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(CORE_VMX_CONTEXT) * procCount, 'HvCA');
    if (!g_CtxArray) {
        HvLog("!!! DayZHV: [FAIL] Failed to allocate context array.");
        HvLogClose();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_CtxArray, sizeof(CORE_VMX_CONTEXT) * procCount);
    g_ProcCount = procCount;

    // Diagnostic buffer: allocated once per VmxInitialize call.  If a prior
    // call left a live pointer (re-entrant from power resume), reuse it.
    if (!g_VmxDiag) {
        g_VmxDiag = (PVMX_DIAG_BUFFER)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(VMX_DIAG_BUFFER), 'HvDB');
        if (g_VmxDiag) {
            RtlZeroMemory(g_VmxDiag, sizeof(VMX_DIAG_BUFFER));
            g_VmxDiag->Magic = VMX_DIAG_MAGIC;
        } else {
            HvLog("!!! DayZHV: [WARN] Diagnostic buffer allocation failed — diag writes skipped.");
        }
    } else {
        // Re-arm for the new launch attempt.
        RtlZeroMemory(g_VmxDiag, sizeof(VMX_DIAG_BUFFER));
        g_VmxDiag->Magic = VMX_DIAG_MAGIC;
    }

    NTSTATUS status = AllocCoreCtxArray(g_CtxArray, procCount);
    if (!NT_SUCCESS(status)) {
        HvLog("!!! DayZHV: [FAIL] Region allocation failed.");
        ExFreePoolWithTag(g_CtxArray, 'HvCA');
        g_CtxArray = NULL;
        HvLogClose();
        return status;
    }

    // Probe MBEC on the BSP before building the EPT — the identity map leaf
    // entries must have EPT_EXEC_USER set if MBEC will be active, and the map
    // is built once and shared across all cores. MBEC capability is uniform
    // across logical processors on the same physical CPU.
    {
        // Read IA32_VMX_PROCBASED_CTLS2 directly — we're not in VMX-root yet.
        ULONG64 cap2 = __readmsr(IA32_VMX_PROCBASED_CTLS2);
        // Allowed-1 bits are in the high 32; bit 22 = MBEC.
        g_MbecEnabled = ((cap2 >> 32) & SECONDARY_EXEC_MODE_BASED_EPT_EXEC) != 0;
        HvLog("!!! DayZHV: [MBEC] Mode-Based Execute Control: %s",
              g_MbecEnabled ? "supported — EPT_EXEC_USER will be set on all leaf entries"
                            : "not supported — single execute bit per EPT entry");
    }

    status = EptBuildIdentityMap(&g_Ept);
    if (!NT_SUCCESS(status)) {
        HvLog("!!! DayZHV: [FAIL] EPT build failed: 0x%X", status);
        FreeCoreCxtArray(g_CtxArray, procCount);
        ExFreePoolWithTag(g_CtxArray, 'HvCA');
        g_CtxArray = NULL;
        HvLogClose();
        return status;
    }
    HvLog("!!! DayZHV: [INFO] EPT identity map built. EPTP=0x%llX  MBEC=%u",
          g_Ept.Eptp, (ULONG)g_MbecEnabled);

    // Punch a hole in the identity map at HV_IPC_GPA so any guest access to
    // this page causes an EPT violation.  HandleEptViolation dispatches write
    // accesses through the hypercall ABI as the EPT-violation IPC channel.
    // The identity map may have covered this GPA with a 2MB large page; split
    // it and mark the 4KB leaf non-present (flags=0, no read/write/execute).
    EptMapPage4KB(&g_Ept, HV_IPC_GPA & HV_IPC_GPA_MASK,
                  HV_IPC_GPA & HV_IPC_GPA_MASK, 0 /* non-present */);
    HvLog("!!! DayZHV: [IPC] EPT-violation IPC channel armed at GPA=0x%llX",
          HV_IPC_GPA & HV_IPC_GPA_MASK);

    for (ULONG i = 0; i < procCount; i++) {
        g_CtxArray[i].Eptp = g_Ept.Eptp;
        // VMFUNC EPTP list: slot 0 = identity view (the only view we expose).
        // A guest executing VMFUNC(EAX=0, ECX=0) switches to this entry —
        // which is the same EPTP already active, so the swap is a safe no-op
        // from the guest's perspective. Additional views (e.g. restricted) can
        // be added by writing additional EPTP values into slots 1-511.
        if (g_CtxArray[i].EptpListPage)
            ((ULONG64*)g_CtxArray[i].EptpListPage)[0] = g_Ept.Eptp;
    }

    // -----------------------------------------------------------------------
    // Scoped EPT self-hiding: make hypervisor control pages invisible to the
    // guest. A single zeroed decoy page is returned for any R/W fault on a
    // hidden GPA; X faults redirect to the real HPA (harmless — these pages
    // contain data, not code). Driver image pages are left visible to avoid
    // PatchGuard/loader interference.
    // Hidden: CORE_VMX_CONTEXT array, and per-core MsrBitmap, IoBitmapA/B.
    // NOT hidden: VmxonRegion, VmcsRegion, HostStack (CPU-hardware accessible).
    // -----------------------------------------------------------------------
    PVOID decoyPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvDC');
    if (decoyPage) {
        RtlZeroMemory(decoyPage, PAGE_SIZE);

        EptHideRange(&g_Ept, g_CtxArray,
                     sizeof(CORE_VMX_CONTEXT) * procCount, decoyPage);

        for (ULONG i = 0; i < procCount; i++) {
            if (g_CtxArray[i].MsrBitmap)
                EptHideRange(&g_Ept, g_CtxArray[i].MsrBitmap, PAGE_SIZE, decoyPage);
            if (g_CtxArray[i].IoBitmapA)
                EptHideRange(&g_Ept, g_CtxArray[i].IoBitmapA, PAGE_SIZE, decoyPage);
            if (g_CtxArray[i].IoBitmapB)
                EptHideRange(&g_Ept, g_CtxArray[i].IoBitmapB, PAGE_SIZE, decoyPage);
        }

        // Do NOT call EptInvalidate here — VMXON has not run yet.
        // g_InveptPending will flush on each core's first VM-exit.
        InterlockedExchange(&g_InveptPending, 1);
        HvLog("!!! DayZHV: [INFO] EPT self-hiding applied (%u cores, decoy=0x%p). INVEPT deferred.",
              procCount, decoyPage);

        g_DecoyPage = decoyPage;   // freed in VmxTeardown after EptFree
    } else {
        HvLog("!!! DayZHV: [WARN] Decoy page alloc failed — self-hiding skipped.");
    }

    // -----------------------------------------------------------------------
    // Architectural Isolation: write-protect VMCS, VMXON, EPT paging structures,
    // and driver image pages. Any guest write to these GPAs triggers #GP(0).
    // Runs after self-hiding so both policies are layered on the same EPT.
    // -----------------------------------------------------------------------
    VmxIsolateInfrastructure(procCount);

    // -----------------------------------------------------------------------
    // Phase 1: VMCS probe — VMXON + write + readback + VMXOFF per P-core.
    // Runs each probe sequentially, pinned to one core at a time, so no IPI
    // broadcast holds every E-core thread at the barrier during the VMX window.
    // -----------------------------------------------------------------------
    HvLog("!!! DayZHV: [PHASE 1] VMCS probe (no VMLAUNCH) on %u P-core(s)...", procCount);
    {
        GROUP_AFFINITY probeAffinity = {0}, probeOldAffinity = {0};
        for (ULONG i = 0; i < procCount; i++) {
            probeAffinity.Group = 0;
            probeAffinity.Mask  = 1ULL << i;
            KeSetSystemGroupAffinityThread(&probeAffinity, &probeOldAffinity);
            VmxProbeCore((ULONG_PTR)g_CtxArray);
            KeRevertToUserGroupAffinityThread(&probeOldAffinity);
        }
    }

    ULONG probeFailed = 0;
    for (ULONG i = 0; i < procCount; i++) {
        LogCoreResult(i, &g_CtxArray[i], "PROBE");
        if (g_CtxArray[i].LaunchResult != 0) probeFailed++;
        g_CtxArray[i].LaunchResult = 0xFF;   // reset for launch phase
    }

    if (probeFailed > 0) {
        HvLog("!!! DayZHV: [PHASE 1] FAIL — %u core(s) failed VMCS probe. Aborting.", probeFailed);
        FreeCoreCxtArray(g_CtxArray, procCount);
        ExFreePoolWithTag(g_CtxArray, 'HvCA');
        g_CtxArray = NULL;
        EptFree(&g_Ept);
        HvLogClose();
        return STATUS_UNSUCCESSFUL;
    }
    HvLog("!!! DayZHV: [PHASE 1] PASS — all %u cores probed OK.", procCount);

    // Log hybrid topology and extended-state summary.
    ULONG pCores = 0, eCores = 0, unknownCores = 0;
    BOOLEAN allInvariant = TRUE;
    for (ULONG i = 0; i < procCount; i++) {
        if      (g_CtxArray[i].CoreType == 1) pCores++;
        else if (g_CtxArray[i].CoreType == 2) eCores++;
        else                                  unknownCores++;
        if (!g_CtxArray[i].InvariantTsc) allInvariant = FALSE;
    }
    HvLog("!!! DayZHV: [TOPOLOGY] P-cores=%u E-cores=%u Unknown=%u InvariantTSC=%s XSaveSize=%u",
          pCores, eCores, unknownCores,
          allInvariant ? "YES" : "NO",
          g_CtxArray[0].XSaveSize);
    if (!allInvariant)
        HvLog("!!! DayZHV: [WARN] Non-invariant TSC detected — TSC offset masking may drift across P/E cores.");

    // HLAT audit: probe capability and log result. Expected: FALSE on Raptor Lake.
    ProbeHlat();

    // -----------------------------------------------------------------------
    // Phase 2: Single-core pilot launch on core 0.
    // If this freezes or BSODs, only one core is affected and the log will
    // contain the phase 1 results — giving us the last known good state.
    //
    // Pre-populate all g_CoreCtx slots before launching.  AsmVmExitHandler
    // indexes g_CoreCtx by the system-wide processor number (KPRCB.Number,
    // gs:[1A4h]).  If any core receives an IPI or external interrupt during
    // the pilot window and takes a VM-exit on a VMCS that still has
    // HOST_RIP=AsmVmExitHandler, a NULL g_CoreCtx slot causes a NULL-deref
    // write at the top of AsmVmExitHandler — corrupting the KPRCB.
    //
    // KeSetSystemAffinityThreadEx takes a group-relative KAFFINITY bitmask.
    // On multi-group systems (32 cores = 2 groups of 16 on Raptor Lake),
    // bit 0 of KAFFINITY pins to processor 0 within the CURRENT group —
    // which may be system-wide processor 16, not 0.  AsmVmExitHandler reads
    // the system-wide number from gs:[1A4h]; if that differs from the slot
    // we pre-populated (index 0), it loads a NULL ctx pointer and crashes.
    // Fix: use KeSetSystemGroupAffinityThread with an explicit GROUP_AFFINITY
    // that names group 0 / processor 0 unambiguously.
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Pre-pilot diagnostics: log MSR 0x3A and VMCS Revision ID.
    // These are the two most common silent hang causes on 14900K:
    //   - BIOS locks IA32_FEATURE_CONTROL without bit 2 → VMXON #GP at ring 0
    //   - VMCS header RevisionId mismatch → VMLAUNCH hangs or fails with invalid state
    // -----------------------------------------------------------------------
    {
        ULONGLONG fc      = __readmsr(IA32_FEATURE_CONTROL);
        ULONG     revId   = (ULONG)(__readmsr(IA32_VMX_BASIC) & 0x7FFFFFFF);
        ULONGLONG vmxBasic = __readmsr(IA32_VMX_BASIC);
        HvLog("!!! DayZHV: [PRE-PILOT] IA32_FEATURE_CONTROL (MSR 0x3A) = 0x%llX  Lock=%u  EnableVmxOutsideSmx=%u",
              fc, (ULONG)(fc & 1), (ULONG)((fc >> 2) & 1));
        HvLog("!!! DayZHV: [PRE-PILOT] IA32_VMX_BASIC (MSR 0x480) = 0x%llX  RevisionId=0x%08X  MemType=%u  TrueCtls=%u",
              vmxBasic, revId,
              (ULONG)((vmxBasic >> 50) & 0xF),
              (ULONG)((vmxBasic >> 55) & 1));
        HvLog("!!! DayZHV: [PRE-PILOT] VMCS header RevisionId applied to VmxonRegion and VmcsRegion on core 0 = 0x%08X",
              *(ULONG*)g_CtxArray[0].VmxonRegion);
        if (*(ULONG*)g_CtxArray[0].VmxonRegion != revId)
            HvLog("!!! DayZHV: [PRE-PILOT] WARNING: RevisionId MISMATCH — region header=0x%08X vs MSR=0x%08X",
                  *(ULONG*)g_CtxArray[0].VmxonRegion, revId);
        if (!(fc & 0x1))
            HvLog("!!! DayZHV: [PRE-PILOT] WARNING: IA32_FEATURE_CONTROL is NOT locked — BIOS did not initialize VMX.");
        if ((fc & 0x1) && !(fc & 0x4))
            HvLog("!!! DayZHV: [PRE-PILOT] FATAL: Locked but bit 2 clear — VMXON will #GP.  BIOS blocks VMX.");
    }

    HvLog("!!! DayZHV: [PHASE 2] Pilot VMLAUNCH on core 0...");

    // Pre-populate all slots so no VM-exit on any core reads a NULL ctx.
    for (ULONG i = 0; i < procCount; i++)
        g_CoreCtx[i] = &g_CtxArray[i];

    // Phase 2 is a single-core direct call — NOT an IPI broadcast.
    // VmxLaunchCore's Phase A barrier waits until g_PcoreCheckin reaches
    // g_ProcCount before entering Phase B.  In Phase 3 the IPI delivers all
    // g_ProcCount cores simultaneously and each increments the counter.
    // In Phase 2 only core 0 runs, so its single increment would leave the
    // counter at 1 and spin forever waiting for 15 more cores that never arrive.
    // Pre-seeding to (procCount - 1) means core 0's own InterlockedIncrement
    // brings the total to procCount, satisfying the condition immediately.
    InterlockedExchange(&g_PcoreCheckin, (LONG)procCount - 1);

    GROUP_AFFINITY newAffinity = {0}, oldGroupAffinity = {0};
    newAffinity.Group = 0;
    newAffinity.Mask  = 1;   // processor 0 within group 0 = system-wide processor 0
    KeSetSystemGroupAffinityThread(&newAffinity, &oldGroupAffinity);
    VmxLaunchCore((ULONG_PTR)g_CtxArray);
    KeRevertToUserGroupAffinityThread(&oldGroupAffinity);

    HvLog("!!! DayZHV: [PILOT CORE 00] HostKernelGsBase=0x%llX (KPCR addr, expect 0xFFFF...)",
          g_CtxArray[0].HostKernelGsBase);
    LogCoreResult(0, &g_CtxArray[0], "PILOT");
    if (g_CtxArray[0].LaunchResult != 0) {
        HvLog("!!! DayZHV: [PHASE 2] FAIL — pilot launch failed. Aborting.");
        FreeCoreCxtArray(g_CtxArray, procCount);
        ExFreePoolWithTag(g_CtxArray, 'HvCA');
        g_CtxArray = NULL;
        EptFree(&g_Ept);
        HvLogClose();
        return STATUS_UNSUCCESSFUL;
    }
    HvLog("!!! DayZHV: [PHASE 2] PASS — core 0 pilot OK.");

    // -----------------------------------------------------------------------
    // Phase 3: Full resident launch on all cores via IPI.
    // We reach here only after probe + pilot both passed.
    // -----------------------------------------------------------------------
    HvLog("!!! DayZHV: [PHASE 3] Firing IPI to go resident on all %u cores...", procCount);

    // Reset all contexts for the real launch (core 0 already tore down above).
    for (ULONG i = 0; i < procCount; i++) {
        RtlZeroMemory(g_CtxArray[i].VmxonRegion, PAGE_SIZE);
        RtlZeroMemory(g_CtxArray[i].VmcsRegion,  PAGE_SIZE);
        g_CtxArray[i].LaunchResult   = 0xFF;
        g_CtxArray[i].ExitReason     = 0xFFFFFFFF;
        g_CtxArray[i].TeardownPending = FALSE;
        g_CoreCtx[i] = NULL;
    }

    // Phase 3: fire VMLAUNCH on all P-core threads simultaneously via IPI.
    // KeIpiGenericCall broadcasts to every logical processor; VmxLaunchCore
    // skips non-P-core threads by checking whether the processor number falls
    // within the P-core range (0..procCount-1).  This is safe because procCount
    // was already clamped to the P-core popcount above, and g_CoreCtx is only
    // populated for slots 0..procCount-1.
    //
    // Reset the checkin counter so each P-core can signal readiness in Phase A
    // and the first core to reach Phase B waits for all peers before proceeding.
    InterlockedExchange(&g_PcoreCheckin, 0);
    KeIpiGenericCall(VmxLaunchCore, (ULONG_PTR)g_CtxArray);

    HvLog("!!! DayZHV: [PHASE 3] IPI complete. Results:");
    ULONG passed = 0, failed = 0;
    for (ULONG i = 0; i < procCount; i++) {
        LogCoreResult(i, &g_CtxArray[i], "LAUNCH");
        if (g_CtxArray[i].LaunchResult == 0) {
            passed++;
        } else {
            failed++;
            // Only dump EFER/PAT/RFLAGS for failing cores — success is noise-free.
            HvLog("!!! DayZHV: [CORE %02u] pre-launch diag: EFER=0x%llX PAT=0x%llX RFLAGS=0x%llX KgsBase=0x%llX",
                  i, g_CtxArray[i].PreLaunchEfer, g_CtxArray[i].PreLaunchPat,
                  g_CtxArray[i].PreLaunchRflags, g_CtxArray[i].HostKernelGsBase);
        }
    }

    HvLog("!!! DayZHV: [SUMMARY] %u/%u cores launched.", passed, procCount);

    if (failed > 0) {
        HvLog("!!! DayZHV: [FAIL] Partial launch — tearing down.");
        VmxTeardown();
        HvLog("!!! DayZHV: ===== RESIDENT LAUNCH FAILED =====");
        HvLogClose();
        return STATUS_UNSUCCESSFUL;
    }

    HvLog("!!! DayZHV: ===== RESIDENT HYPERVISOR ACTIVE =====");

    // -----------------------------------------------------------------------
    // Sentinel write-trap on nt!NtAddAtom.
    //
    // PatchGuard 0x109 Arg4:1 fires when a kernel function page is modified
    // after PatchGuard has stored its reference hash.  NtAddAtom is a frequent
    // target because its prologue is short and easy to patch.
    //
    // Now that the hypervisor is fully resident and EPT is live, register the
    // physical page backing NtAddAtom as write-protected.  Any subsequent guest
    // write to that GPA will exit with an EPT violation; HandleEptViolation
    // injects #GP(0) and logs "[WP] GPA=... RIP=..." — the RIP identifies the
    // caller that would have triggered the 0x109.
    //
    // This is a diagnostic trap, not a permanent policy.  Once the offending
    // caller is identified, either remove the write or EPT-shadow the page so
    // the hypervisor can service it invisibly to PatchGuard.
    // -----------------------------------------------------------------------
    {
        UNICODE_STRING ntAddAtomName = RTL_CONSTANT_STRING(L"NtAddAtom");
        PVOID ntAddAtomVa = MmGetSystemRoutineAddress(&ntAddAtomName);
        if (ntAddAtomVa) {
            WpProtectPage(&g_Ept, ntAddAtomVa);
            InterlockedExchange(&g_InveptPending, 1);
            HvLog("!!! DayZHV: [WP TRAP] nt!NtAddAtom VA=%p write-trapped — any write will log [WP] RIP",
                  ntAddAtomVa);
        } else {
            HvLog("!!! DayZHV: [WARN] MmGetSystemRoutineAddress(NtAddAtom) returned NULL — trap skipped");
        }
    }

    return STATUS_SUCCESS;
}
