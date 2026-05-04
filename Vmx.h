#pragma once
#include <ntddk.h>
#include <intrin.h>

// ---------------------------------------------------------------------------
// IOCTL
// ---------------------------------------------------------------------------
#define IOCTL_DISK_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KERNEL_READ_REQUEST {
    ULONG     ProcessId;
    ULONGLONG Address;
    ULONGLONG Size;
    PVOID     Buffer;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// ---------------------------------------------------------------------------
// MSR indices
// ---------------------------------------------------------------------------
#define IA32_FEATURE_CONTROL        0x3A
#define IA32_DEBUGCTL               0x1D9
#define IA32_RTIT_CTL               0x570   // Intel PT control
#define IA32_XSS                    0xDA0   // supervisor/user XSAVE state mask
#define IA32_LBR_CTL                0x14CE  // Architectural LBR control (Alder Lake+)
#define IA32_APIC_BASE              0x1B
#define IA32_ENERGY_PERF_BIAS       0x1B0
#define IA32_PACKAGE_THERM_STATUS   0x1B1
#define IA32_VMX_BASIC              0x480
#define IA32_VMX_PINBASED_CTLS      0x481
#define IA32_VMX_PROCBASED_CTLS     0x482
#define IA32_VMX_EXIT_CTLS          0x483
#define IA32_VMX_ENTRY_CTLS         0x484
#define IA32_VMX_CR0_FIXED0         0x486
#define IA32_VMX_CR0_FIXED1         0x487
#define IA32_VMX_CR4_FIXED0         0x488
#define IA32_VMX_CR4_FIXED1         0x489
#define IA32_LSTAR                  0xC0000082
#define IA32_FS_BASE                0xC0000100
#define IA32_GS_BASE                0xC0000101

// ---------------------------------------------------------------------------
// VMCS field encodings (Intel SDM Vol 3D, Appendix B)
// ---------------------------------------------------------------------------

// 16-bit guest fields
#define VMCS_GUEST_ES_SELECTOR          0x0800
#define VMCS_GUEST_CS_SELECTOR          0x0802
#define VMCS_GUEST_SS_SELECTOR          0x0804
#define VMCS_GUEST_DS_SELECTOR          0x0806
#define VMCS_GUEST_FS_SELECTOR          0x0808
#define VMCS_GUEST_GS_SELECTOR          0x080A
#define VMCS_GUEST_LDTR_SELECTOR        0x080C
#define VMCS_GUEST_TR_SELECTOR          0x080E

// 16-bit host fields
#define VMCS_HOST_ES_SELECTOR           0x0C00
#define VMCS_HOST_CS_SELECTOR           0x0C02
#define VMCS_HOST_SS_SELECTOR           0x0C04
#define VMCS_HOST_DS_SELECTOR           0x0C06
#define VMCS_HOST_FS_SELECTOR           0x0C08
#define VMCS_HOST_GS_SELECTOR           0x0C0A
#define VMCS_HOST_TR_SELECTOR           0x0C0C

// 16-bit control fields
#define VMCS_VPID                       0x0000

// 64-bit control fields
#define VMCS_IO_BITMAP_A                0x2000
#define VMCS_IO_BITMAP_B                0x2002
#define VMCS_MSR_BITMAP                 0x2004
#define VMCS_TSC_OFFSET                 0x2010
#define VMCS_VMCS_LINK_POINTER          0x2800

// 64-bit guest fields
#define VMCS_GUEST_DEBUGCTL             0x2802

// 32-bit control fields
#define VMCS_PIN_BASED_VM_EXEC_CONTROL  0x4000
#define VMCS_CPU_BASED_VM_EXEC_CONTROL  0x4002
#define VMCS_EXCEPTION_BITMAP           0x4004
#define VMCS_VM_EXIT_CONTROLS           0x400C
#define VMCS_VM_EXIT_MSR_STORE_COUNT    0x400E
#define VMCS_VM_EXIT_MSR_LOAD_COUNT     0x4010
#define VMCS_VM_ENTRY_CONTROLS          0x4012
#define VMCS_VM_ENTRY_MSR_LOAD_COUNT    0x4014
#define VMCS_VM_ENTRY_INTR_INFO         0x4016
#define VMCS_CR3_TARGET_COUNT           0x400A

// 32-bit guest fields
#define VMCS_GUEST_ES_LIMIT             0x4800
#define VMCS_GUEST_CS_LIMIT             0x4802
#define VMCS_GUEST_SS_LIMIT             0x4804
#define VMCS_GUEST_DS_LIMIT             0x4806
#define VMCS_GUEST_FS_LIMIT             0x4808
#define VMCS_GUEST_GS_LIMIT             0x480A
#define VMCS_GUEST_LDTR_LIMIT           0x480C
#define VMCS_GUEST_TR_LIMIT             0x480E
#define VMCS_GUEST_GDTR_LIMIT           0x4810
#define VMCS_GUEST_IDTR_LIMIT           0x4812
#define VMCS_GUEST_ES_ACCESS_RIGHTS     0x4814
#define VMCS_GUEST_CS_ACCESS_RIGHTS     0x4816
#define VMCS_GUEST_SS_ACCESS_RIGHTS     0x4818
#define VMCS_GUEST_DS_ACCESS_RIGHTS     0x481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS     0x481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS     0x481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS   0x4820
#define VMCS_GUEST_TR_ACCESS_RIGHTS     0x4822
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824
#define VMCS_GUEST_ACTIVITY_STATE       0x4826
#define VMCS_GUEST_SYSENTER_CS          0x482A

// 32-bit host fields
#define VMCS_HOST_SYSENTER_CS           0x4C00

// 32-bit read-only
#define VMCS_VM_EXIT_REASON             0x4402
#define VMCS_VM_INSTRUCTION_ERROR       0x4400
#define VMCS_VM_EXIT_INSTRUCTION_LEN    0x440C
#define VMCS_VM_EXIT_INTR_INFO          0x4404
#define VMCS_VM_EXIT_INTR_ERROR_CODE    0x4406

// 32-bit control (VM-entry event injection)
#define VMCS_VM_ENTRY_INTR_INFO_FIELD   0x4016   // same encoding as VMCS_VM_ENTRY_INTR_INFO
#define VMCS_VM_ENTRY_EXCEPTION_ERROR   0x4018
#define VMCS_VM_ENTRY_INSTRUCTION_LEN   0x401A

// Natural-width read-only
#define VMCS_EXIT_QUALIFICATION         0x6400
#define VMCS_GUEST_PHYSICAL_ADDRESS     0x2400

// Natural-width control fields
#define VMCS_CR0_GUEST_HOST_MASK        0x6000
#define VMCS_CR4_GUEST_HOST_MASK        0x6002
#define VMCS_CR0_READ_SHADOW            0x6004
#define VMCS_CR4_READ_SHADOW            0x6006
#define VMCS_CR3_TARGET_VALUE0          0x6008

// Natural-width guest fields
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680A
#define VMCS_GUEST_DS_BASE              0x680C
#define VMCS_GUEST_FS_BASE              0x680E
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681A
#define VMCS_GUEST_RSP                  0x681C
#define VMCS_GUEST_RIP                  0x681E
#define VMCS_GUEST_RFLAGS               0x6820
#define VMCS_GUEST_SYSENTER_ESP         0x6824
#define VMCS_GUEST_SYSENTER_EIP         0x6826

// Natural-width host fields
#define VMCS_HOST_CR0                   0x6C00
#define VMCS_HOST_CR3                   0x6C02
#define VMCS_HOST_CR4                   0x6C04
#define VMCS_HOST_FS_BASE               0x6C06
#define VMCS_HOST_GS_BASE               0x6C08
#define VMCS_HOST_TR_BASE               0x6C0A
#define VMCS_HOST_GDTR_BASE             0x6C0C
#define VMCS_HOST_IDTR_BASE             0x6C0E
#define VMCS_HOST_SYSENTER_ESP          0x6C10
#define VMCS_HOST_SYSENTER_EIP          0x6C12
#define VMCS_HOST_RSP                   0x6C14
#define VMCS_HOST_RIP                   0x6C16

// ---------------------------------------------------------------------------
// VM exit reasons
// ---------------------------------------------------------------------------
#define VMX_EXIT_REASON_EXTERNAL_INT    1
#define VMX_EXIT_REASON_HLT             12
#define VMX_EXIT_REASON_CPUID           10
#define VMX_EXIT_REASON_DR_ACCESS       29
#define VMX_EXIT_REASON_CR_ACCESS       28
#define VMX_EXIT_REASON_RDMSR           31
#define VMX_EXIT_REASON_WRMSR           32
#define VMX_EXIT_REASON_IO_ACCESS       30
#define VMX_EXIT_REASON_VMCALL          18
#define VMX_EXIT_REASON_INTERRUPT_WINDOW 7
#define VMX_EXIT_REASON_GDTR_IDTR       46
#define VMX_EXIT_REASON_LDTR_TR         47
#define VMX_EXIT_REASON_EPT_VIOLATION   48
#define VMX_EXIT_REASON_PREEMPTION      52
#define VMX_EXIT_REASON_XSETBV          55

// ---------------------------------------------------------------------------
// Control bit flags
// ---------------------------------------------------------------------------
#define VM_EXIT_HOST_ADDR_SPACE_SIZE    (1UL << 9)
#define VM_EXIT_LOAD_IA32_LBR_CTL      (1UL << 29)  // auto-clear LBR on exit (SDM §27.2.3)
#define VM_ENTRY_IA32E_MODE_GUEST       (1UL << 9)
#define VM_ENTRY_LOAD_IA32_LBR_CTL     (1UL << 21)  // auto-restore LBR on entry (SDM §26.3.1)
#define IA32_VMX_EXIT_CTLS2             0x493        // tertiary exit controls capability MSR
#define IA32_VMX_ENTRY_CTLS2            0x494        // tertiary entry controls capability MSR
#define CPU_BASED_INTERRUPT_WINDOW_EXITING    (1UL << 2)
#define CPU_BASED_USE_TSC_OFFSETTING          (1UL << 3)
#define CPU_BASED_MOV_DR_EXITING              (1UL << 23)
#define CPU_BASED_USE_IO_BITMAPS              (1UL << 25)
#define CPU_BASED_HLT_EXITING                 (1UL << 7)
#define CPU_BASED_USE_MSR_BITMAPS             (1UL << 28)
#define CPU_BASED_CR3_LOAD_EXITING            (1UL << 15)
#define CPU_BASED_CR3_STORE_EXITING           (1UL << 16)
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS (1UL << 31)
#define SECONDARY_EXEC_ENABLE_EPT             (1UL << 1)
#define SECONDARY_EXEC_DESC_TABLE_EXITING     (1UL << 2)
#define SECONDARY_EXEC_ENABLE_VPID            (1UL << 7)
#define SECONDARY_EXEC_ENABLE_XSETBV          (1UL << 13)
#define SECONDARY_EXEC_ENABLE_EPT_AD          (1UL << 21)

// EPTP bit 6: enable EPT accessed/dirty flags (SDM Vol 3C §28.2.6)
#define EPT_AD_ENABLE                         (1ULL << 6)

#define IA32_VMX_PROCBASED_CTLS2    0x48B

#define VMCS_SECONDARY_VM_EXEC_CONTROL  0x401E
#define VMCS_EPT_POINTER                0x201A

// ---------------------------------------------------------------------------
// 64-bit TSS descriptor (16 bytes in long mode)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR_64 {
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMiddle;
    UCHAR   AccessRights;
    UCHAR   LimitHighFlags;
    UCHAR   BaseHigh;
    ULONG   BaseUpper;
    ULONG   Reserved;
} SEGMENT_DESCRIPTOR_64, *PSEGMENT_DESCRIPTOR_64;
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Guest GPR save area — filled on every VM-exit, restored before VMRESUME.
// ---------------------------------------------------------------------------
typedef struct _GUEST_REGS {
    ULONG64 Rax;    // +00h
    ULONG64 Rcx;    // +08h
    ULONG64 Rdx;    // +10h
    ULONG64 Rbx;    // +18h
    ULONG64 Rsp;    // +20h  (from VMCS GUEST_RSP, not real stack)
    ULONG64 Rbp;    // +28h
    ULONG64 Rsi;    // +30h
    ULONG64 Rdi;    // +38h
    ULONG64 R8;     // +40h
    ULONG64 R9;     // +48h
    ULONG64 R10;    // +50h
    ULONG64 R11;    // +58h
    ULONG64 R12;    // +60h
    ULONG64 R13;    // +68h
    ULONG64 R14;    // +70h
    ULONG64 R15;    // +78h
} GUEST_REGS, *PGUEST_REGS;

// ---------------------------------------------------------------------------
// Per-core VMX context — one slot per logical processor.
// ---------------------------------------------------------------------------
typedef struct _CORE_VMX_CONTEXT {
    PVOID   VmxonRegion;        // +00h
    PVOID   VmcsRegion;         // +08h
    PVOID   HostStack;          // +10h
    PVOID   GuestStack;         // +18h
    ULONG64 HostResumeRip;      // +20h
    ULONG64 HostResumeRsp;      // +28h
    ULONG   ExitReason;         // +30h
    ULONG   LaunchResult;       // +34h
    BOOLEAN Passed;             // +38h
    // 7 bytes padding
    ULONG64 Eptp;               // +40h
    PVOID   ShadowGdt;          // +48h
    ULONG64 VmEntryError;       // +50h
    ULONG64 GuestRflags;        // +58h
    ULONG64 GuestActivity;      // +60h
    ULONG64 PreLaunchEfer;      // +68h
    ULONG64 PreLaunchPat;       // +70h
    ULONG64 PreLaunchRflags;    // +78h
    ULONG   FailedVmwriteField; // +80h
    // 4 bytes padding
    GUEST_REGS GuestRegs;       // +88h  (16 * 8 = 80h bytes)
    BOOLEAN    TeardownPending; // +108h
    // 7 bytes padding
    PVOID      MsrBitmap;       // +110h  4KB non-paged; intercept bits for IA32_FEATURE_CONTROL
    PVOID      IoBitmapA;       // +118h  4KB non-paged; ports 0x0000-0x7FFF
    PVOID      IoBitmapB;       // +120h  4KB non-paged; ports 0x8000-0xFFFF
    BOOLEAN    PendingInjection;    // +128h  deferred event waiting for interrupt window
    // 3 bytes padding
    ULONG      PendingIntrInfo;     // +12Ch  VM_ENTRY_INTR_INFO_FIELD value to inject
    ULONG      PendingErrorCode;    // +130h  error code if PendingIntrInfo bit 11 set
    // 4 bytes padding (to next 8-byte boundary)
    ULONG64    GuestDr[8];          // +138h  guest DR0-DR7 shadow (8 * 8 = 40h bytes)
    PVOID      XSaveArea;           // +178h  64-byte-aligned XSAVEC/XRSTOR buffer
    ULONG      XSaveSize;           // +180h  byte size of the save area
    // 4 bytes padding
    ULONG64    XSaveMask;           // +188h  EDX:EAX mask passed to XSAVEC/XRSTOR
    BOOLEAN    InvariantTsc;        // +190h  CPUID[0x80000007].EDX bit 8 confirmed
    UCHAR      CoreType;            // +191h  0=unknown, 1=P-core, 2=E-core (CPUID[0x1F])
    // 6 bytes padding to next 8-byte boundary
    ULONG64    GuestXss;            // +198h  shadow of IA32_XSS (0xDA0) seen by guest
    ULONG64    GuestRtitCtl;        // +1A0h  shadow of IA32_RTIT_CTL (0x570) seen by guest
    BOOLEAN    LbrVirtEnabled;      // +1A8h  TRUE if hardware Arch-LBR auto-swap in use
} CORE_VMX_CONTEXT, *PCORE_VMX_CONTEXT;

// Indexed by KeGetCurrentProcessorNumberEx(NULL). Written before IPI, read by exit handler.
#define MAX_LOGICAL_PROCESSORS 64
extern PCORE_VMX_CONTEXT g_CoreCtx[MAX_LOGICAL_PROCESSORS];

// ---------------------------------------------------------------------------
// EPT entry flags
// ---------------------------------------------------------------------------
#define EPT_READ        (1ULL << 0)
#define EPT_WRITE       (1ULL << 1)
#define EPT_EXEC        (1ULL << 2)
#define EPT_MEMTYPE_UC  (0ULL << 3)   // uncacheable — for MMIO pages
#define EPT_MEMTYPE_WB  (6ULL << 3)   // write-back  — for RAM pages
#define EPT_LARGE_PAGE  (1ULL << 7)
#define EPT_RWX         (EPT_READ | EPT_WRITE | EPT_EXEC)

// EPT walk length: 4-level = value 3 in EPTP bits [5:3]
#define EPT_PAGE_WALK_4 (3ULL << 3)
// Memory type for EPT structures in EPTP bits [2:0]: WB = 6
#define EPT_MEMTYPE_WB_EPTP (6ULL)

typedef struct _EPT_CONTEXT {
    PVOID   Pml4;           // 4KB, physically contiguous
    ULONG64 Eptp;           // value to write to VMCS_EPT_POINTER
} EPT_CONTEXT, *PEPT_CONTEXT;

// Exit qualification access bits (SDM Vol 3C §27.2.1 Table 27-7)
#define EPT_QUAL_READ    (1ULL << 0)
#define EPT_QUAL_WRITE   (1ULL << 1)
#define EPT_QUAL_EXECUTE (1ULL << 2)

// One entry in the shadow protection table.
// RealHpa  — original host-physical page the guest normally executes.
// ShadowHpa — decoy host-physical page shown on R/W access.
// AccessMask — EPT_READ/WRITE/EXEC bits that are *allowed* without faulting.
//              Bits absent from the mask trigger the shadow swap.
#define EPT_SHADOW_TABLE_SIZE 64
typedef struct _EPT_SHADOW_ENTRY {
    ULONG64          Gpa;        // 4KB-aligned guest-physical address
    PHYSICAL_ADDRESS RealHpa;    // original HPA (used for X faults)
    PHYSICAL_ADDRESS ShadowHpa;  // decoy HPA   (used for R/W faults)
    ULONG64          AccessMask; // EPT_READ | EPT_WRITE | EPT_EXEC allowed
    BOOLEAN          Active;
} EPT_SHADOW_ENTRY, *PEPT_SHADOW_ENTRY;

NTSTATUS EptBuildIdentityMap(PEPT_CONTEXT Ept);
void     EptFree(PEPT_CONTEXT Ept);
void     EptMapPage4KB(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 Hpa, ULONG64 Flags);
void     EptInvalidate(ULONG64 Eptp);
NTSTATUS EptSetPermissions(PEPT_CONTEXT Ept, ULONG64 Gpa, PVOID ShadowVa, ULONG64 AccessMask);
BOOLEAN  EptHandleViolation(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 ExitQual);
void     EptHideRange(PEPT_CONTEXT Ept, PVOID Va, SIZE_T Bytes, PVOID DecoyVa);
BOOLEAN  EptTryMerge2MB(PEPT_CONTEXT Ept, ULONG64 Gpa);

// Shadow table — defined in Ept.c, read by HandleEptViolation in Vmx.c.
extern EPT_SHADOW_ENTRY g_EptShadowTable[EPT_SHADOW_TABLE_SIZE];
extern ULONG            g_EptShadowCount;

// Driver-lifetime EPT context — defined in Vmx.c, used by EPT violation handler.
extern EPT_CONTEXT g_Ept;

// ---------------------------------------------------------------------------
// Assembly prototypes (Arch.asm)
// ---------------------------------------------------------------------------
ULONG64  AsmGetGdtBase(void);
USHORT   AsmGetGdtLimit(void);
ULONG64  AsmGetIdtBase(void);
USHORT   AsmGetIdtLimit(void);
USHORT   AsmGetCs(void);
USHORT   AsmGetDs(void);
USHORT   AsmGetEs(void);
USHORT   AsmGetSs(void);
USHORT   AsmGetFs(void);
USHORT   AsmGetGs(void);
USHORT   AsmGetTr(void);
ULONG    AsmGetLar(USHORT Selector);
ULONG    AsmGetLsl(USHORT Selector);
void     AsmGuestStub(void);
void     AsmVmExitHandler(void);
UCHAR    AsmLaunchAndReturn(ULONG64 HostRsp, PCORE_VMX_CONTEXT Ctx);
void     AsmInveptSingleContext(ULONG64 Eptp);

// ---------------------------------------------------------------------------
// Static layout assertions — build fails if ASM EQU offsets diverge from C.
// Every CTX_* constant in Arch.asm must match the corresponding field offset.
// ---------------------------------------------------------------------------
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmxonRegion)   == 0x00);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmcsRegion)    == 0x08);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, HostStack)     == 0x10);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestStack)    == 0x18);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, HostResumeRip) == 0x20);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, HostResumeRsp) == 0x28);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, ExitReason)    == 0x30);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, LaunchResult)  == 0x34);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, Passed)        == 0x38);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, Eptp)          == 0x40);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, ShadowGdt)     == 0x48);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmEntryError)  == 0x50);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestRflags)   == 0x58);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestActivity) == 0x60);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestRegs)     == 0x88);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, TeardownPending) == 0x108);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, MsrBitmap)      == 0x110);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, IoBitmapA)         == 0x118);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, IoBitmapB)         == 0x120);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, PendingInjection)  == 0x128);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, PendingIntrInfo)   == 0x12C);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, PendingErrorCode)  == 0x130);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestDr)           == 0x138);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, XSaveArea)         == 0x178);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, XSaveSize)         == 0x180);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, XSaveMask)         == 0x188);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, InvariantTsc)      == 0x190);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, CoreType)          == 0x191);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestXss)          == 0x198);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestRtitCtl)      == 0x1A0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, LbrVirtEnabled)    == 0x1A8);
C_ASSERT(sizeof(GUEST_REGS) == 0x80);

// ---------------------------------------------------------------------------
// C prototypes
// ---------------------------------------------------------------------------
BOOLEAN  IsVmxSupported(void);
BOOLEAN  IsVmxEnabledInBios(void);
NTSTATUS VmxInitialize(void);
void     VmxTeardown(void);
ULONG_PTR VmxLaunchCore(ULONG_PTR ctxArrayPtr);
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void     VmExitDispatch(PCORE_VMX_CONTEXT Ctx);

// ---------------------------------------------------------------------------
// File logging
// ---------------------------------------------------------------------------
void     HvLogOpen(void);
void     HvLog(const char *fmt, ...);
void     HvLogClose(void);

