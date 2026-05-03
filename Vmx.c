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
    }
}

static NTSTATUS AllocCoreCtxArray(PCORE_VMX_CONTEXT arr, ULONG count)
{
    for (ULONG i = 0; i < count; i++) {
        arr[i].VmxonRegion  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVO');
        arr[i].VmcsRegion   = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvVC');
        arr[i].HostStack    = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000,   'HvHS');
        arr[i].GuestStack   = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000,    'HvGS');
        arr[i].ShadowGdt    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvGD');
        arr[i].MsrBitmap    = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvMB');
        arr[i].ExitReason   = 0xFFFFFFFF;
        arr[i].LaunchResult = 0xFF;
        arr[i].Passed       = FALSE;

        if (!arr[i].VmxonRegion || !arr[i].VmcsRegion ||
            !arr[i].HostStack   || !arr[i].GuestStack  ||
            !arr[i].ShadowGdt   || !arr[i].MsrBitmap) {
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
    }
    return STATUS_SUCCESS;
}


// ---------------------------------------------------------------------------
// VM-exit dispatch
// ---------------------------------------------------------------------------

static void AdvanceGuestRip(void)
{
    ULONG64 rip = 0, len = 0;
    __vmx_vmread(VMCS_GUEST_RIP,              &rip);
    __vmx_vmread(VMCS_VM_EXIT_INSTRUCTION_LEN, &len);
    __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
}

static void HandleCpuid(PCORE_VMX_CONTEXT Ctx)
{
    int regs[4] = {0};
    __cpuidex(regs, (int)Ctx->GuestRegs.Rax, (int)Ctx->GuestRegs.Rcx);

    if ((ULONG)Ctx->GuestRegs.Rax == 1)
        regs[2] &= ~(1 << 31);     // clear hypervisor present bit

    if ((ULONG)Ctx->GuestRegs.Rax == 0x40000000)
        regs[0] = regs[1] = regs[2] = regs[3] = 0;

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
    } else if (msr == IA32_VMX_BASIC || (msr >= 0x481 && msr <= 0x48B)) {
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
    if (msr == IA32_VMX_BASIC || (msr >= 0x481 && msr <= 0x48B)) {
        AdvanceGuestRip();
        return;
    }
    __writemsr(msr, val);
    AdvanceGuestRip();
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

static void HandleEptViolation(PCORE_VMX_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    ULONG64 gpa = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
    EptMapPage4KB(&g_Ept, gpa & ~0xFFFULL, gpa & ~0xFFFULL,
                  EPT_RWX | EPT_MEMTYPE_UC);
    EptInvalidate(g_Ept.Eptp);
    // No AdvanceGuestRip — the faulting access re-executes after EPT is fixed.
}

void VmExitDispatch(PCORE_VMX_CONTEXT Ctx)
{
    ULONG reason = Ctx->ExitReason & 0xFFFF;

    switch (reason) {
    case VMX_EXIT_REASON_CPUID:         HandleCpuid(Ctx);        break;
    case VMX_EXIT_REASON_RDMSR:         HandleRdmsr(Ctx);        break;
    case VMX_EXIT_REASON_WRMSR:         HandleWrmsr(Ctx);        break;
    case VMX_EXIT_REASON_CR_ACCESS:     HandleCrAccess(Ctx);     break;
    case VMX_EXIT_REASON_EPT_VIOLATION: HandleEptViolation(Ctx); break;
    case VMX_EXIT_REASON_EXTERNAL_INT:  /* hardware re-injects */ break;
    case VMX_EXIT_REASON_PREEMPTION:    /* timer — just resume */ break;
    case VMX_EXIT_REASON_VMCALL:
    case VMX_EXIT_REASON_HLT:
        Ctx->Passed = TRUE;
        Ctx->TeardownPending = TRUE;
        break;
    default:
        Ctx->TeardownPending = TRUE;
        break;
    }
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
                                    CPU_BASED_USE_MSR_BITMAPS |
                                    CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
                                    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
                                    IA32_VMX_PROCBASED_CTLS);
    ULONG cpu2Ctls = AdjustControls(SECONDARY_EXEC_ENABLE_EPT, IA32_VMX_PROCBASED_CTLS2);
    ULONG exitCtls = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE, IA32_VMX_EXIT_CTLS);
    ULONG entryCtls= AdjustControls(VM_ENTRY_IA32E_MODE_GUEST, IA32_VMX_ENTRY_CTLS);

    PHYSICAL_ADDRESS msrBitmapPhys = MmGetPhysicalAddress(ctx->MsrBitmap);

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
    LVMW(VMCS_EPT_POINTER,                  ctx->Eptp);
    LVMW(VMCS_MSR_BITMAP,                   msrBitmapPhys.QuadPart);
    LVMW(VMCS_VM_EXIT_CONTROLS,             exitCtls);
    LVMW(VMCS_VM_ENTRY_CONTROLS,         entryCtls);
    LVMW(VMCS_EXCEPTION_BITMAP,          0);
    LVMW(VMCS_CR3_TARGET_COUNT,          0);
    LVMW(VMCS_VM_EXIT_MSR_STORE_COUNT,   0);
    LVMW(VMCS_VM_EXIT_MSR_LOAD_COUNT,    0);
    LVMW(VMCS_VM_ENTRY_MSR_LOAD_COUNT,   0);
    LVMW(VMCS_VM_ENTRY_INTR_INFO,        0);
    LVMW(VMCS_CR0_GUEST_HOST_MASK,       0);
    LVMW(VMCS_CR4_GUEST_HOST_MASK,       0);
    LVMW(VMCS_CR0_READ_SHADOW,           cr0);
    LVMW(VMCS_CR4_READ_SHADOW,           cr4);
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
                                    CPU_BASED_USE_MSR_BITMAPS |
                                    CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
                                    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
                                    IA32_VMX_PROCBASED_CTLS);
    ULONG cpu2Ctls = AdjustControls(SECONDARY_EXEC_ENABLE_EPT, IA32_VMX_PROCBASED_CTLS2);
    ULONG exitCtls = AdjustControls(VM_EXIT_HOST_ADDR_SPACE_SIZE, IA32_VMX_EXIT_CTLS);
    ULONG entryCtls= AdjustControls(VM_ENTRY_IA32E_MODE_GUEST,    IA32_VMX_ENTRY_CTLS);

    PHYSICAL_ADDRESS msrBitmapPhys = MmGetPhysicalAddress(ctx->MsrBitmap);

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
    PVMW(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMW(VMCS_MSR_BITMAP,                  msrBitmapPhys.QuadPart);
    PVMW(VMCS_VM_EXIT_CONTROLS,            exitCtls);
    PVMW(VMCS_VM_ENTRY_CONTROLS,           entryCtls);
    PVMW(VMCS_EXCEPTION_BITMAP,            0);
    PVMW(VMCS_CR3_TARGET_COUNT,            0);
    PVMW(VMCS_VM_EXIT_MSR_STORE_COUNT,     0);
    PVMW(VMCS_VM_EXIT_MSR_LOAD_COUNT,      0);
    PVMW(VMCS_VM_ENTRY_MSR_LOAD_COUNT,     0);
    PVMW(VMCS_VM_ENTRY_INTR_INFO,          0);
    PVMW(VMCS_CR0_GUEST_HOST_MASK,         0);
    PVMW(VMCS_CR4_GUEST_HOST_MASK,         0);
    PVMW(VMCS_CR0_READ_SHADOW,             cr0);
    PVMW(VMCS_CR4_READ_SHADOW,             cr4);
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
    PVMR(VMCS_EPT_POINTER,                 ctx->Eptp);
    PVMR(VMCS_MSR_BITMAP,                  msrBitmapPhys.QuadPart);
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
