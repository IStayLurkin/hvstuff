#include <ntddk.h>
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include "Vmx.h"

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

    // Ensure newline
    SIZE_T len = strlen(buf);
    if (len < sizeof(buf) - 1 && buf[len-1] != '\n') {
        buf[len]   = '\n';
        buf[len+1] = '\0';
        len++;
    }

    IO_STATUS_BLOCK iosb;
    ZwWriteFile(g_LogHandle, NULL, NULL, NULL, &iosb, buf, (ULONG)len, NULL, NULL);

    // Mirror to DebugView as well
    DbgPrint("%s", buf);
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
    // Bit 0 = lock, bit 2 = VMXON outside SMX enabled
    if (!(fc & 0x1))  return FALSE;   // not locked — BIOS hasn't set it up
    if (!(fc & 0x4))  return FALSE;   // VMXON outside SMX not enabled
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
        arr[i].GuestXss      = __readmsr(IA32_XSS);
        arr[i].GuestRtitCtl  = 0;   // PT disabled at hypervisor launch
        arr[i].LbrVirtEnabled = FALSE;  // set per-core in VmxLaunchCore/VmxProbeCore

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

        if (!arr[i].VmxonRegion || !arr[i].VmcsRegion ||
            !arr[i].HostStack   || !arr[i].GuestStack  ||
            !arr[i].ShadowGdt   || !arr[i].MsrBitmap   ||
            !arr[i].IoBitmapA   || !arr[i].IoBitmapB) {
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
        DbgPrint("DayZHV: IN  port=0x%04X size=%u val=0x%X\n", port, sizeMinus1 + 1, val);
    } else {
        ULONG val = (ULONG)(Ctx->GuestRegs.Rax);
        switch (sizeMinus1) {
        case 0: __outbyte(port,  (UCHAR)val);  break;
        case 1: __outword(port,  (USHORT)val); break;
        case 3: __outdword(port, val);         break;
        }
        DbgPrint("DayZHV: OUT port=0x%04X size=%u val=0x%X\n", port, sizeMinus1 + 1, val);
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
    DbgPrint("DayZHV: injecting vector=0x%02X info=0x%08X ec=0x%X\n",
             entryInfo & 0xFF, entryInfo, errorCode);
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
        DbgPrint("DayZHV: deferred injection vector=0x%02X (interruptibility=0x%llX)\n",
                 entryInfo & 0xFF, interruptibility);
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
    ULONG64 rip = 0, len = 0;
    __vmx_vmread(VMCS_GUEST_RIP,              &rip);
    __vmx_vmread(VMCS_VM_EXIT_INSTRUCTION_LEN, &len);
    __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
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
    __cpuidex(regs, (int)leaf, (int)Ctx->GuestRegs.Rcx);

    if (leaf == 1)
        regs[2] &= ~(1 << 31);     // clear hypervisor present bit

    if (leaf == 0x40000000)
        regs[0] = regs[1] = regs[2] = regs[3] = 0;

    if (leaf == 0x80000002 || leaf == 0x80000003 || leaf == 0x80000004) {
        // Index into the 48-byte string: leaf 0x80000002 → offset 0, ..3 → 16, ..4 → 32
        const ULONG *p = (const ULONG *)(g_BrandString + (leaf - 0x80000002) * 16);
        regs[0] = p[0]; regs[1] = p[1]; regs[2] = p[2]; regs[3] = p[3];
    }

    Ctx->GuestRegs.Rax = (ULONG64)(ULONG)regs[0];
    Ctx->GuestRegs.Rbx = (ULONG64)(ULONG)regs[1];
    Ctx->GuestRegs.Rcx = (ULONG64)(ULONG)regs[2];
    Ctx->GuestRegs.Rdx = (ULONG64)(ULONG)regs[3];
    AdvanceGuestRip();
}

static void HandleRdmsr(PCORE_VMX_CONTEXT Ctx)
{
    ULONG msr = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val = 0;

    if (msr == IA32_FEATURE_CONTROL) {
        // Spoof: report locked + VMXON-outside-SMX enabled regardless of hardware.
        // DbgPrint is safe at any IRQL; HvLog (ZwWriteFile) is not.
        val = 0x5;
        DbgPrint("DayZHV: RDMSR IA32_FEATURE_CONTROL intercepted — returning spoofed 0x%llX\n", val);
    } else if (msr == IA32_APIC_BASE) {
        val = __readmsr(IA32_APIC_BASE);
        DbgPrint("DayZHV: RDMSR IA32_APIC_BASE intercepted — val=0x%llX\n", val);
    } else if (msr == IA32_ENERGY_PERF_BIAS) {
        val = 0x6;   // balanced — nominal Windows default, hides exit-driven power oscillation
        DbgPrint("DayZHV: RDMSR IA32_ENERGY_PERF_BIAS spoofed 0x%llX\n", val);
    } else if (msr == IA32_PACKAGE_THERM_STATUS) {
        val = 0x0;   // all status/log bits clear — no thermal events reported
        DbgPrint("DayZHV: RDMSR IA32_PACKAGE_THERM_STATUS spoofed 0x%llX\n", val);
    } else if (msr == IA32_LSTAR) {
        val = __readmsr(IA32_LSTAR);
        DbgPrint("DayZHV: RDMSR IA32_LSTAR intercepted — val=0x%llX\n", val);
    } else if (msr == IA32_DEBUGCTL) {
        val = __readmsr(IA32_DEBUGCTL);
        DbgPrint("DayZHV: RDMSR IA32_DEBUGCTL intercepted — val=0x%llX\n", val);
    } else if (msr == IA32_RTIT_CTL) {
        // Return the guest's shadow value; the hardware register has TraceEn=0
        // while in VMX-root so the host's own execution is never traced.
        val = Ctx->GuestRtitCtl;
        DbgPrint("DayZHV: RDMSR IA32_RTIT_CTL -> shadow=0x%llX\n", val);
    } else if (msr == IA32_XSS) {
        val = Ctx->GuestXss;
        DbgPrint("DayZHV: RDMSR IA32_XSS -> shadow=0x%llX\n", val);
    } else if (msr == IA32_LBR_CTL) {
        // If hardware Arch-LBR auto-swap is active the guest state is in the
        // hardware register (CPU restores it on VM-entry); read it directly.
        val = Ctx->LbrVirtEnabled ? __readmsr(IA32_LBR_CTL) : 0;
        DbgPrint("DayZHV: RDMSR IA32_LBR_CTL -> 0x%llX\n", val);
    } else if (msr == IA32_VMX_BASIC || (msr >= 0x481 && msr <= 0x48B)) {
        val = 0;
    } else if (msr >= 0x40000000 && msr <= 0x400000FF) {
        // Hypervisor-synthetic MSR range: return all zeros.
        // Prevents guests from detecting Hyper-V enlightenment protocols.
        val = 0;
    } else {
        val = __readmsr(msr);
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

    if (msr == IA32_FEATURE_CONTROL) {
        DbgPrint("DayZHV: WRMSR IA32_FEATURE_CONTROL intercepted — swallowed value=0x%llX\n", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_APIC_BASE) {
        DbgPrint("DayZHV: WRMSR IA32_APIC_BASE swallowed — guest attempted remap to 0x%llX\n", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_ENERGY_PERF_BIAS || msr == IA32_PACKAGE_THERM_STATUS) {
        DbgPrint("DayZHV: WRMSR thermal/power MSR 0x%X swallowed val=0x%llX\n", msr, val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_LSTAR) {
        DbgPrint("DayZHV: WRMSR IA32_LSTAR intercepted — new KernelEntry=0x%llX\n", val);
        // Pass through — kernel legitimately sets LSTAR during boot/resume.
        __writemsr(IA32_LSTAR, val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_DEBUGCTL) {
        DbgPrint("DayZHV: WRMSR IA32_DEBUGCTL intercepted — val=0x%llX\n", val);
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
        DbgPrint("DayZHV: WRMSR IA32_RTIT_CTL shadow=0x%llX hw=0x%llX\n", val, val & ~1ULL);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_XSS) {
        // Shadow the guest's XSS. Pass through to hardware so the CPU's own
        // XSAVES/XRSTORS (e.g. from our XSAVEC path) see the correct state mask.
        Ctx->GuestXss = val;
        __writemsr(IA32_XSS, val);
        DbgPrint("DayZHV: WRMSR IA32_XSS shadow+hw=0x%llX\n", val);
        AdvanceGuestRip();
        return;
    }
    if (msr == IA32_LBR_CTL) {
        // If Arch-LBR auto-swap is active, write directly — the CPU saves/restores
        // the full LBR stack automatically on VM-exit/entry so there is no host
        // pollution. If not active, swallow (guest LBR not fully virtualized).
        if (Ctx->LbrVirtEnabled)
            __writemsr(IA32_LBR_CTL, val);
        DbgPrint("DayZHV: WRMSR IA32_LBR_CTL val=0x%llX active=%u\n", val, Ctx->LbrVirtEnabled);
        AdvanceGuestRip();
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
        DbgPrint("DayZHV: WRMSR synthetic MSR 0x%X -> #GP injected\n", msr);
        return;
    }
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
            break;
        case 3:
            __vmx_vmwrite(VMCS_GUEST_CR3, *gpr);
            break;
        case 4:
            __vmx_vmwrite(VMCS_GUEST_CR4,       *gpr);
            __vmx_vmwrite(VMCS_CR4_READ_SHADOW,  *gpr);
            break;
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
        Ctx->GuestDr[dr] = *gpr;
        WriteDr(dr, *gpr);
        DbgPrint("DayZHV: MOV DR%u <- GPR val=0x%llX\n", dr, *gpr);
    } else {
        // MOV GPR, DR — guest reading a debug register.
        *gpr = Ctx->GuestDr[dr];
        DbgPrint("DayZHV: MOV GPR <- DR%u val=0x%llX\n", dr, *gpr);
    }

    AdvanceGuestRip();
}

static void HandleXsetbv(PCORE_VMX_CONTEXT Ctx)
{
    ULONG   xcr   = (ULONG)Ctx->GuestRegs.Rcx;
    ULONG64 val   = ((Ctx->GuestRegs.Rdx & 0xFFFFFFFF) << 32) |
                     (Ctx->GuestRegs.Rax & 0xFFFFFFFF);
    DbgPrint("DayZHV: XSETBV XCR%u=0x%llX\n", xcr, val);
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

    DbgPrint("DayZHV: descriptor-table exit reason=%u instr=%s qual=0x%llX\n",
             reason, name, qual);

    AdvanceGuestRip();
}

static void HandleEptViolation(PCORE_VMX_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    ULONG64 gpa  = 0;
    ULONG64 qual = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION,     &qual);

    // Protected page — shadow table handles the PTE swap + INVEPT + DbgPrint.
    if (EptHandleViolation(&g_Ept, gpa, qual)) return;

    // Unprotected GPA (e.g. MMIO hole): lazy-map identity 4KB UC and retry.
    EptMapPage4KB(&g_Ept, gpa & ~0xFFFULL, gpa & ~0xFFFULL, EPT_RWX | EPT_MEMTYPE_UC);
    // Attempt to re-merge the 2MB region; UC pages won't satisfy the uniform-flags
    // check (flags differ from WB neighbours), so this is a no-op for true MMIO holes.
    // For regions where all 512 4KB PTEs were mapped UC+RWX, this restores the large page.
    EptTryMerge2MB(&g_Ept, gpa);
    EptInvalidate(g_Ept.Eptp);
    // No AdvanceGuestRip — faulting access re-executes after EPT is fixed.
}

void VmExitDispatch(PCORE_VMX_CONTEXT Ctx)
{
    // TSC offset masking: subtract handler wall-time from the guest-visible TSC
    // so EPT violation overhead doesn't appear in guest RDTSC measurements.
    ULONG64 tscEntry = __rdtsc();

    ULONG reason = Ctx->ExitReason & 0xFFFF;

    switch (reason) {
    case VMX_EXIT_REASON_CPUID:         HandleCpuid(Ctx);        break;
    case VMX_EXIT_REASON_RDMSR:         HandleRdmsr(Ctx);        break;
    case VMX_EXIT_REASON_WRMSR:         HandleWrmsr(Ctx);        break;
    case VMX_EXIT_REASON_DR_ACCESS:     HandleDrAccess(Ctx);     break;
    case VMX_EXIT_REASON_CR_ACCESS:     HandleCrAccess(Ctx);     break;
    case VMX_EXIT_REASON_EPT_VIOLATION: HandleEptViolation(Ctx); break;
    case VMX_EXIT_REASON_EXTERNAL_INT:  /* hardware re-injects */ break;
    case VMX_EXIT_REASON_PREEMPTION:    /* timer — just resume */ break;
    case VMX_EXIT_REASON_IO_ACCESS:     HandleIoAccess(Ctx);     break;
    case VMX_EXIT_REASON_GDTR_IDTR:
    case VMX_EXIT_REASON_LDTR_TR:       HandleDescriptorTable(Ctx, reason); break;
    case VMX_EXIT_REASON_XSETBV:        HandleXsetbv(Ctx);       break;
    case VMX_EXIT_REASON_INTERRUPT_WINDOW: HandleInterruptWindow(Ctx); break;
    case VMX_EXIT_REASON_VMCALL:
    case VMX_EXIT_REASON_HLT:
        Ctx->Passed = TRUE;
        Ctx->TeardownPending = TRUE;
        break;
    default:
        // Attempt to re-inject as a hardware exception before giving up.
        // Covers #GP, #PF, #UD and other faults that fell through unhandled.
        if (!InjectPendingException(Ctx))
            Ctx->TeardownPending = TRUE;
        break;
    }

    // Cache warming: prefetch the hot fields the VMRESUME path will touch.
    // This reduces the measurable L1D miss spike that occurs when the guest
    // resumes and its working set has been partially evicted by handler code.
    // PREFETCHT0 is a hint only — never faults, safe at any IRQL.
    // We prefetch: GuestRegs block, TeardownPending byte, and the ctx base.
    _mm_prefetch((const char*)Ctx,                               _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->GuestRegs,                   _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->GuestRegs + 64,              _MM_HINT_T0);
    _mm_prefetch((const char*)&Ctx->TeardownPending,             _MM_HINT_T0);

    // Accumulate handler cost into VMCS_TSC_OFFSET (signed: subtract elapsed ticks).
    // Add low-bit jitter from the exit TSC to simulate pipeline/cache variance:
    //   bits [3:0] of the exit TSC give a value 0-15; subtract 7 to centre on zero.
    //   Net jitter range: -7 to +8 cycles — indistinguishable from hardware noise.
    // Skip on teardown — we're about to vmxoff anyway.
    if (!Ctx->TeardownPending) {
        ULONG64 tscExit = __rdtsc();
        ULONG64 elapsed = tscExit - tscEntry;
        ULONG64 jitter  = (tscExit & 0xFULL) - 7ULL; // signed via 2s-complement wrap
        ULONG64 current = 0;
        __vmx_vmread(VMCS_TSC_OFFSET, &current);
        __vmx_vmwrite(VMCS_TSC_OFFSET, current - elapsed + jitter);
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
    DbgPrint("DayZHV: [CORE %02u] %s  InvariantTSC=%u  XSaveSize=%u\n",
             procNum, coreNames[typeIdx], ctx->InvariantTsc, ctx->XSaveSize);
}

// ---------------------------------------------------------------------------
// VmxLaunchCore — KeIpiGenericCall worker, runs simultaneously on every core.
// ctxArrayPtr is a PCORE_VMX_CONTEXT array; each core indexes by its own number.
// ---------------------------------------------------------------------------
ULONG_PTR VmxLaunchCore(ULONG_PTR ctxArrayPtr)
{
    PCORE_VMX_CONTEXT arr = (PCORE_VMX_CONTEXT)ctxArrayPtr;
    ULONG procNum = KeGetCurrentProcessorNumberEx(NULL);
    PCORE_VMX_CONTEXT ctx = &arr[procNum];

    g_CoreCtx[procNum] = ctx;
    DetectCoreTopology(ctx, procNum);

    ULONG revId = GetVmcsRevisionId();
    *(ULONG*)ctx->VmxonRegion = revId;
    *(ULONG*)ctx->VmcsRegion  = revId;

    __writecr4(__readcr4() | (1ULL << 13));

    PHYSICAL_ADDRESS vmxonPhys = MmGetPhysicalAddress(ctx->VmxonRegion);
    if (__vmx_on((ULONGLONG*)&vmxonPhys.QuadPart) != 0) {
        __writecr4(__readcr4() & ~(1ULL << 13));
        ctx->LaunchResult = 0xFE;
        return 0;
    }

    PHYSICAL_ADDRESS vmcsPhys = MmGetPhysicalAddress(ctx->VmcsRegion);
    if (__vmx_vmptrld((ULONGLONG*)&vmcsPhys.QuadPart) != 0) {
        __vmx_off();
        __writecr4(__readcr4() & ~(1ULL << 13));
        ctx->LaunchResult = 0xFD;
        return 0;
    }

    ULONG64 gdtBase  = AsmGetGdtBase();
    USHORT  gdtLimit = AsmGetGdtLimit();

    // Copy the live GDT into the per-core shadow page.  The guest GDTR will
    // point at this copy so the CPU's TR busy-bit write on VM-exit lands here
    // instead of in the real kernel GDT (prevents PatchGuard 0x109).
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

    ULONG arCs = (AsmGetLar(selCs) >> 8) & 0xF0FF;
    ULONG arDs = (AsmGetLar(selDs) >> 8) & 0xF0FF;
    ULONG arEs = (AsmGetLar(selEs) >> 8) & 0xF0FF;
    ULONG arSs = (AsmGetLar(selSs) >> 8) & 0xF0FF;
    ULONG arFs = (AsmGetLar(selFs) >> 8) & 0xF0FF;
    ULONG arGs = (AsmGetLar(selGs) >> 8) & 0xF0FF;
    ULONG arTr = (AsmGetLar(selTr) >> 8) & 0xF0FF;

    ULONG limCs = AsmGetLsl(selCs);
    ULONG limDs = AsmGetLsl(selDs);
    ULONG limEs = AsmGetLsl(selEs);
    ULONG limSs = AsmGetLsl(selSs);
    ULONG limFs = AsmGetLsl(selFs);
    ULONG limGs = AsmGetLsl(selGs);
    ULONG limTr = AsmGetLsl(selTr);

    ULONG64 cr0 = AdjustCr0(__readcr0());
    ULONG64 cr3 = __readcr3();
    ULONG64 cr4 = AdjustCr4(__readcr4());

    ULONG64 hostRsp = ((ULONG64)ctx->HostStack + 0x8000 - 16) & ~0xFULL;

    ULONG pinCtls  = AdjustControls(0,                        IA32_VMX_PINBASED_CTLS);
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
    BOOLEAN lbrOk  = CheckArchLbrVmxSupport();
    ctx->LbrVirtEnabled = lbrOk;
    ULONG exitCtls = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE |
                                    (lbrOk ? VM_EXIT_LOAD_IA32_LBR_CTL : 0),
                                    IA32_VMX_EXIT_CTLS);
    ULONG entryCtls= AdjustControls(VM_ENTRY_IA32E_MODE_GUEST |
                                    (lbrOk ? VM_ENTRY_LOAD_IA32_LBR_CTL : 0),
                                    IA32_VMX_ENTRY_CTLS);

    PHYSICAL_ADDRESS msrBitmapPhys = MmGetPhysicalAddress(ctx->MsrBitmap);
    PHYSICAL_ADDRESS ioBitmapAPhys = MmGetPhysicalAddress(ctx->IoBitmapA);
    PHYSICAL_ADDRESS ioBitmapBPhys = MmGetPhysicalAddress(ctx->IoBitmapB);

#define LVMW(field, value) do { \
    if (__vmx_vmwrite((field), (ULONG64)(value)) != 0) { \
        __vmx_off(); \
        __writecr4(__readcr4() & ~(1ULL << 13)); \
        ctx->LaunchResult = 0xFC; \
        ctx->FailedVmwriteField = (field); \
        return 0; \
    } \
} while(0)

    LVMW(VMCS_PIN_BASED_VM_EXEC_CONTROL,    pinCtls);
    LVMW(VMCS_CPU_BASED_VM_EXEC_CONTROL,    cpuCtls);
    LVMW(VMCS_SECONDARY_VM_EXEC_CONTROL,    cpu2Ctls);
    LVMW(VMCS_VPID,                         procNum + 1);
    LVMW(VMCS_EPT_POINTER,                  ctx->Eptp);
    LVMW(VMCS_MSR_BITMAP,                   msrBitmapPhys.QuadPart);
    LVMW(VMCS_IO_BITMAP_A,                  ioBitmapAPhys.QuadPart);
    LVMW(VMCS_IO_BITMAP_B,                  ioBitmapBPhys.QuadPart);
    LVMW(VMCS_TSC_OFFSET,                   0);
    LVMW(VMCS_VM_EXIT_CONTROLS,             exitCtls);
    LVMW(VMCS_VM_ENTRY_CONTROLS,         entryCtls);
    LVMW(VMCS_EXCEPTION_BITMAP,          0);
    LVMW(VMCS_CR3_TARGET_COUNT,          0);
    LVMW(VMCS_VM_EXIT_MSR_STORE_COUNT,   0);
    LVMW(VMCS_VM_EXIT_MSR_LOAD_COUNT,    0);
    LVMW(VMCS_VM_ENTRY_MSR_LOAD_COUNT,   0);
    LVMW(VMCS_VM_ENTRY_INTR_INFO,        0);
    LVMW(VMCS_CR0_GUEST_HOST_MASK,       0);
    LVMW(VMCS_CR4_GUEST_HOST_MASK,       (1ULL << 13));   // own VMXE — guest reads shadow
    LVMW(VMCS_CR0_READ_SHADOW,           cr0);
    LVMW(VMCS_CR4_READ_SHADOW,           cr4 & ~(1ULL << 13));  // VMXE=0 in guest view
    LVMW(VMCS_VMCS_LINK_POINTER,         0xFFFFFFFFFFFFFFFFULL);

    LVMW(VMCS_HOST_CR0,          cr0);
    LVMW(VMCS_HOST_CR3,          cr3);
    LVMW(VMCS_HOST_CR4,          cr4);
    LVMW(VMCS_HOST_CS_SELECTOR,  selCs & ~7U);
    LVMW(VMCS_HOST_SS_SELECTOR,  selSs & ~7U);
    LVMW(VMCS_HOST_DS_SELECTOR,  selDs & ~7U);
    LVMW(VMCS_HOST_ES_SELECTOR,  selEs & ~7U);
    LVMW(VMCS_HOST_FS_SELECTOR,  selFs & ~7U);
    LVMW(VMCS_HOST_GS_SELECTOR,  selGs & ~7U);
    LVMW(VMCS_HOST_TR_SELECTOR,  selTr & ~7U);
    LVMW(VMCS_HOST_FS_BASE,      fsBase);
    LVMW(VMCS_HOST_GS_BASE,      gsBase);
    LVMW(VMCS_HOST_TR_BASE,      trBase);
    LVMW(VMCS_HOST_GDTR_BASE,    shadowGdtBase);
    LVMW(VMCS_HOST_IDTR_BASE,    idtBase);
    LVMW(VMCS_HOST_RSP,          hostRsp);
    LVMW(VMCS_HOST_RIP,          (ULONG64)AsmVmExitHandler);
    LVMW(VMCS_HOST_SYSENTER_CS,  __readmsr(0x174));
    LVMW(VMCS_HOST_SYSENTER_ESP, __readmsr(0x175));
    LVMW(VMCS_HOST_SYSENTER_EIP, __readmsr(0x176));

    LVMW(VMCS_GUEST_CR0,    cr0);
    LVMW(VMCS_GUEST_CR3,    cr3);
    LVMW(VMCS_GUEST_CR4,    cr4);
    LVMW(VMCS_GUEST_DR7,    0x400);
    LVMW(VMCS_GUEST_RFLAGS, 0x2);
    // GUEST_RSP and GUEST_RIP are written inside AsmLaunchAndReturn immediately
    // before vmlaunch, capturing the real kernel stack and continuation RIP.

    LVMW(VMCS_GUEST_CS_SELECTOR,      selCs);
    LVMW(VMCS_GUEST_CS_BASE,          0);
    LVMW(VMCS_GUEST_CS_LIMIT,         limCs);
    LVMW(VMCS_GUEST_CS_ACCESS_RIGHTS, arCs);
    LVMW(VMCS_GUEST_DS_SELECTOR,      selDs);
    LVMW(VMCS_GUEST_DS_BASE,          0);
    LVMW(VMCS_GUEST_DS_LIMIT,         limDs);
    LVMW(VMCS_GUEST_DS_ACCESS_RIGHTS, arDs);
    LVMW(VMCS_GUEST_ES_SELECTOR,      selEs);
    LVMW(VMCS_GUEST_ES_BASE,          0);
    LVMW(VMCS_GUEST_ES_LIMIT,         limEs);
    LVMW(VMCS_GUEST_ES_ACCESS_RIGHTS, arEs);
    LVMW(VMCS_GUEST_SS_SELECTOR,      selSs);
    LVMW(VMCS_GUEST_SS_BASE,          0);
    LVMW(VMCS_GUEST_SS_LIMIT,         limSs);
    LVMW(VMCS_GUEST_SS_ACCESS_RIGHTS, arSs);
    LVMW(VMCS_GUEST_FS_SELECTOR,      selFs);
    LVMW(VMCS_GUEST_FS_BASE,          fsBase);
    LVMW(VMCS_GUEST_FS_LIMIT,         limFs);
    LVMW(VMCS_GUEST_FS_ACCESS_RIGHTS, arFs);
    LVMW(VMCS_GUEST_GS_SELECTOR,      selGs);
    LVMW(VMCS_GUEST_GS_BASE,          gsBase);
    LVMW(VMCS_GUEST_GS_LIMIT,         limGs);
    LVMW(VMCS_GUEST_GS_ACCESS_RIGHTS, arGs);
    LVMW(VMCS_GUEST_TR_SELECTOR,      selTr);
    LVMW(VMCS_GUEST_TR_BASE,          trBase);
    LVMW(VMCS_GUEST_TR_LIMIT,         limTr);
    LVMW(VMCS_GUEST_TR_ACCESS_RIGHTS, arTr);

    LVMW(VMCS_GUEST_LDTR_SELECTOR,      0);
    LVMW(VMCS_GUEST_LDTR_BASE,          0);
    LVMW(VMCS_GUEST_LDTR_LIMIT,         0xFFFF);
    LVMW(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x10000);

    LVMW(VMCS_GUEST_GDTR_BASE,  shadowGdtBase);
    LVMW(VMCS_GUEST_GDTR_LIMIT, gdtLimit);
    LVMW(VMCS_GUEST_IDTR_BASE,  idtBase);
    LVMW(VMCS_GUEST_IDTR_LIMIT, idtLimit);

    LVMW(VMCS_GUEST_INTERRUPTIBILITY, 0);
    LVMW(VMCS_GUEST_ACTIVITY_STATE,   0);
    LVMW(VMCS_GUEST_DEBUGCTL,         0);
    LVMW(VMCS_GUEST_SYSENTER_CS,      __readmsr(0x174));
    LVMW(VMCS_GUEST_SYSENTER_ESP,     __readmsr(0x175));
    LVMW(VMCS_GUEST_SYSENTER_EIP,     __readmsr(0x176));

#undef LVMW

    ctx->PreLaunchEfer   = __readmsr(0xC0000080);
    ctx->PreLaunchPat    = __readmsr(0x277);
    ctx->PreLaunchRflags = (ULONG64)__readeflags();

    ctx->LaunchResult = AsmLaunchAndReturn(hostRsp, ctx);

    // Two return paths:
    //   LaunchResult != 0  — vmlaunch failed; we never entered VMX non-root.
    //                        vmxoff + clear VMXE to leave VMX operation cleanly.
    //   LaunchResult == 0  — vmlaunch succeeded (guest ran and tore down via
    //                        TeardownPending); AsmVmExitHandler already called
    //                        vmxoff before jumping to launch_resume.  Do NOT
    //                        touch CR4 here — we are back in host mode and VMXE
    //                        is already clear.  Writing CR4 from inside VMX
    //                        non-root (which is where we would be on a bogus
    //                        early return) causes #GP -> triple fault -> freeze.
    if (ctx->LaunchResult != 0) {
        __vmx_off();
        __writecr4(__readcr4() & ~(1ULL << 13));
    }

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
    if (g_CoreCtx[proc])
        g_CoreCtx[proc]->TeardownPending = TRUE;
    // Force a VM-exit on this core so VmExitDispatch sees TeardownPending.
    // CPUID always causes a VM-exit when in VMX non-root (Intel SDM Vol 3C 25.1.2).
    int r[4];
    __cpuid(r, 0);
    return 0;
}

void VmxTeardown(void)
{
    if (!g_CtxArray) return;

    KeIpiGenericCall(VmxTeardownCore, 0);
    // All cores have now vmxoff'd and jumped back to launch_resume → returned from
    // AsmLaunchAndReturn → returned from VmxLaunchCore → IPI callback returned.

    FreeCoreCxtArray(g_CtxArray, g_ProcCount);
    ExFreePoolWithTag(g_CtxArray, 'HvCA');
    EptFree(&g_Ept);
    if (g_DecoyPage) {
        ExFreePoolWithTag(g_DecoyPage, 'HvDC');
        g_DecoyPage = NULL;
    }
    g_CtxArray  = NULL;
    g_ProcCount = 0;
    RtlZeroMemory(g_CoreCtx, sizeof(g_CoreCtx));
}

// ---------------------------------------------------------------------------
// VmxProbeCore — IPI worker: VMXON + VMPTRLD + write all VMCS fields +
// read them back to verify, then VMXOFF.  Never executes VMLAUNCH.
// Populates ctx->LaunchResult: 0 = VMCS valid, non-zero = bad field logged.
// ---------------------------------------------------------------------------
static ULONG_PTR VmxProbeCore(ULONG_PTR ctxArrayPtr)
{
    PCORE_VMX_CONTEXT arr = (PCORE_VMX_CONTEXT)ctxArrayPtr;
    ULONG procNum = KeGetCurrentProcessorNumberEx(NULL);
    PCORE_VMX_CONTEXT ctx = &arr[procNum];

    DetectCoreTopology(ctx, procNum);
    ctx->LaunchResult = 0xFF;   // assume failure until proven ok

    ULONG revId = GetVmcsRevisionId();
    *(ULONG*)ctx->VmxonRegion = revId;
    *(ULONG*)ctx->VmcsRegion  = revId;

    __writecr4(__readcr4() | (1ULL << 13));

    PHYSICAL_ADDRESS vmxonPhys = MmGetPhysicalAddress(ctx->VmxonRegion);
    if (__vmx_on((ULONGLONG*)&vmxonPhys.QuadPart) != 0) {
        __writecr4(__readcr4() & ~(1ULL << 13));
        ctx->LaunchResult = 0xFE;
        return 0;
    }

    PHYSICAL_ADDRESS vmcsPhys = MmGetPhysicalAddress(ctx->VmcsRegion);
    if (__vmx_vmptrld((ULONGLONG*)&vmcsPhys.QuadPart) != 0) {
        __vmx_off();
        __writecr4(__readcr4() & ~(1ULL << 13));
        ctx->LaunchResult = 0xFD;
        return 0;
    }

    // Build the same VMCS state VmxLaunchCore would write, then verify readback.
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
    ULONG arCs = (AsmGetLar(selCs) >> 8) & 0xF0FF;
    ULONG arDs = (AsmGetLar(selDs) >> 8) & 0xF0FF;
    ULONG arEs = (AsmGetLar(selEs) >> 8) & 0xF0FF;
    ULONG arSs = (AsmGetLar(selSs) >> 8) & 0xF0FF;
    ULONG arFs = (AsmGetLar(selFs) >> 8) & 0xF0FF;
    ULONG arGs = (AsmGetLar(selGs) >> 8) & 0xF0FF;
    ULONG arTr = (AsmGetLar(selTr) >> 8) & 0xF0FF;
    ULONG limCs = AsmGetLsl(selCs), limDs = AsmGetLsl(selDs);
    ULONG limEs = AsmGetLsl(selEs), limSs = AsmGetLsl(selSs);
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
    ULONG exitCtls = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE, IA32_VMX_EXIT_CTLS);
    ULONG entryCtls= AdjustControls(VM_ENTRY_IA32E_MODE_GUEST,    IA32_VMX_ENTRY_CTLS);

    PHYSICAL_ADDRESS msrBitmapPhys = MmGetPhysicalAddress(ctx->MsrBitmap);
    PHYSICAL_ADDRESS ioBitmapAPhys = MmGetPhysicalAddress(ctx->IoBitmapA);
    PHYSICAL_ADDRESS ioBitmapBPhys = MmGetPhysicalAddress(ctx->IoBitmapB);

#define PVMW(field, value) do { \
    if (__vmx_vmwrite((field), (ULONG64)(value)) != 0) { \
        __vmx_off(); __writecr4(__readcr4() & ~(1ULL << 13)); \
        ctx->LaunchResult = 0xFC; ctx->FailedVmwriteField = (field); return 0; \
    } \
} while(0)

#define PVMR(field, expected) do { \
    ULONG64 _rd = 0; __vmx_vmread((field), &_rd); \
    if (_rd != (ULONG64)(expected)) { \
        HvLog("!!! DayZHV: [PROBE CORE %02u] READBACK MISMATCH field=0x%04X wrote=0x%llX read=0x%llX", \
              procNum, (field), (ULONG64)(expected), _rd); \
        __vmx_off(); __writecr4(__readcr4() & ~(1ULL << 13)); \
        ctx->LaunchResult = 0xFB; ctx->FailedVmwriteField = (field); return 0; \
    } \
} while(0)

    PVMW(VMCS_PIN_BASED_VM_EXEC_CONTROL,   pinCtls);
    PVMW(VMCS_CPU_BASED_VM_EXEC_CONTROL,   cpuCtls);
    PVMW(VMCS_SECONDARY_VM_EXEC_CONTROL,   cpu2Ctls);
    PVMW(VMCS_VPID,                        procNum + 1);
    PVMW(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMW(VMCS_MSR_BITMAP,                  msrBitmapPhys.QuadPart);
    PVMW(VMCS_IO_BITMAP_A,                 ioBitmapAPhys.QuadPart);
    PVMW(VMCS_IO_BITMAP_B,                 ioBitmapBPhys.QuadPart);
    PVMW(VMCS_TSC_OFFSET,                  0);
    PVMW(VMCS_VM_EXIT_CONTROLS,            exitCtls);
    PVMW(VMCS_VM_ENTRY_CONTROLS,           entryCtls);
    PVMW(VMCS_EXCEPTION_BITMAP,            0);
    PVMW(VMCS_CR3_TARGET_COUNT,            0);
    PVMW(VMCS_VM_EXIT_MSR_STORE_COUNT,     0);
    PVMW(VMCS_VM_EXIT_MSR_LOAD_COUNT,      0);
    PVMW(VMCS_VM_ENTRY_MSR_LOAD_COUNT,     0);
    PVMW(VMCS_VM_ENTRY_INTR_INFO,          0);
    PVMW(VMCS_CR0_GUEST_HOST_MASK,         0);
    PVMW(VMCS_CR4_GUEST_HOST_MASK,         (1ULL << 13));
    PVMW(VMCS_CR0_READ_SHADOW,             cr0);
    PVMW(VMCS_CR4_READ_SHADOW,             cr4 & ~(1ULL << 13));
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
    PVMW(VMCS_HOST_GS_BASE,               gsBase);
    PVMW(VMCS_HOST_TR_BASE,                trBase);
    PVMW(VMCS_HOST_GDTR_BASE,              shadowGdtBase);
    PVMW(VMCS_HOST_IDTR_BASE,              idtBase);
    PVMW(VMCS_HOST_RSP,                    hostRsp);
    PVMW(VMCS_HOST_RIP,                    (ULONG64)AsmVmExitHandler);
    PVMW(VMCS_HOST_SYSENTER_CS,            __readmsr(0x174));
    PVMW(VMCS_HOST_SYSENTER_ESP,           __readmsr(0x175));
    PVMW(VMCS_HOST_SYSENTER_EIP,           __readmsr(0x176));
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
    PVMW(VMCS_GUEST_INTERRUPTIBILITY,      0);
    PVMW(VMCS_GUEST_ACTIVITY_STATE,        0);
    PVMW(VMCS_GUEST_DEBUGCTL,              0);
    PVMW(VMCS_GUEST_SYSENTER_CS,           __readmsr(0x174));
    PVMW(VMCS_GUEST_SYSENTER_ESP,          __readmsr(0x175));
    PVMW(VMCS_GUEST_SYSENTER_EIP,          __readmsr(0x176));

    // Read back a representative sample of critical fields to catch silent failures.
    PVMR(VMCS_PIN_BASED_VM_EXEC_CONTROL,   pinCtls);
    PVMR(VMCS_CPU_BASED_VM_EXEC_CONTROL,   cpuCtls);
    PVMR(VMCS_SECONDARY_VM_EXEC_CONTROL,   cpu2Ctls);
    PVMR(VMCS_VPID,                        procNum + 1);
    PVMR(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMR(VMCS_MSR_BITMAP,                  msrBitmapPhys.QuadPart);
    PVMR(VMCS_IO_BITMAP_A,                 ioBitmapAPhys.QuadPart);
    PVMR(VMCS_IO_BITMAP_B,                 ioBitmapBPhys.QuadPart);
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
    PVMR(VMCS_CR4_GUEST_HOST_MASK,         (1ULL << 13));
    PVMR(VMCS_CR4_READ_SHADOW,             cr4 & ~(1ULL << 13));
    PVMR(VMCS_VMCS_LINK_POINTER,           0xFFFFFFFFFFFFFFFFULL);

#undef PVMW
#undef PVMR

    __vmx_off();
    __writecr4(__readcr4() & ~(1ULL << 13));
    ctx->LaunchResult = 0;   // all fields written and verified
    return 0;
}

// ---------------------------------------------------------------------------
// LogCoreResult — shared result printer used by probe and launch phases.
// ---------------------------------------------------------------------------
static void LogCoreResult(ULONG i, PCORE_VMX_CONTEXT ctx, const char *phase)
{
    if (ctx->LaunchResult == 0) {
        HvLog("!!! DayZHV: [%s CORE %02u] OK", phase, i);
    } else if (ctx->LaunchResult == 0xFC || ctx->LaunchResult == 0xFB) {
        HvLog("!!! DayZHV: [%s CORE %02u] FAIL  result=0x%X bad_field=0x%04X",
              phase, i, ctx->LaunchResult, ctx->FailedVmwriteField);
    } else {
        HvLog("!!! DayZHV: [%s CORE %02u] FAIL  result=0x%X exit=0x%X vmErr=%llu actState=%llu rflags=0x%llX",
              phase, i, ctx->LaunchResult, ctx->ExitReason,
              ctx->VmEntryError, ctx->GuestActivity, ctx->GuestRflags);
    }
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

    ULONG procCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    HvLog("!!! DayZHV: [INFO] Logical processor count: %u", procCount);

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

    NTSTATUS status = AllocCoreCtxArray(g_CtxArray, procCount);
    if (!NT_SUCCESS(status)) {
        HvLog("!!! DayZHV: [FAIL] Region allocation failed.");
        ExFreePoolWithTag(g_CtxArray, 'HvCA');
        g_CtxArray = NULL;
        HvLogClose();
        return status;
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
    HvLog("!!! DayZHV: [INFO] EPT identity map built. EPTP=0x%llX", g_Ept.Eptp);

    for (ULONG i = 0; i < procCount; i++)
        g_CtxArray[i].Eptp = g_Ept.Eptp;

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

        EptInvalidate(g_Ept.Eptp);
        HvLog("!!! DayZHV: [INFO] EPT self-hiding applied (%u cores, decoy=0x%p).",
              procCount, decoyPage);

        g_DecoyPage = decoyPage;   // freed in VmxTeardown after EptFree
    } else {
        HvLog("!!! DayZHV: [WARN] Decoy page alloc failed — self-hiding skipped.");
    }

    // -----------------------------------------------------------------------
    // Phase 1: VMCS probe — VMXON + write + readback + VMXOFF on every core.
    // No VMLAUNCH. Safe to run even if VMCS state is wrong.
    // -----------------------------------------------------------------------
    HvLog("!!! DayZHV: [PHASE 1] VMCS probe (no VMLAUNCH) on all %u cores...", procCount);
    KeIpiGenericCall(VmxProbeCore, (ULONG_PTR)g_CtxArray);

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

    // -----------------------------------------------------------------------
    // Phase 2: Single-core pilot launch on core 0.
    // If this freezes or BSODs, only one core is affected and the log will
    // contain the phase 1 results — giving us the last known good state.
    // -----------------------------------------------------------------------
    HvLog("!!! DayZHV: [PHASE 2] Pilot VMLAUNCH on core 0...");
    g_CoreCtx[0] = &g_CtxArray[0];

    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)1);
    VmxLaunchCore((ULONG_PTR)g_CtxArray);
    KeRevertToUserAffinityThreadEx(oldAffinity);

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

    KeIpiGenericCall(VmxLaunchCore, (ULONG_PTR)g_CtxArray);

    HvLog("!!! DayZHV: [PHASE 3] IPI complete. Results:");
    ULONG passed = 0, failed = 0;
    for (ULONG i = 0; i < procCount; i++) {
        HvLog("!!! DayZHV: [CORE %02u] pre-launch: EFER=0x%llX PAT=0x%llX RFLAGS=0x%llX",
              i, g_CtxArray[i].PreLaunchEfer, g_CtxArray[i].PreLaunchPat, g_CtxArray[i].PreLaunchRflags);
        LogCoreResult(i, &g_CtxArray[i], "LAUNCH");
        if (g_CtxArray[i].LaunchResult == 0) passed++; else failed++;
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
    return STATUS_SUCCESS;
}
