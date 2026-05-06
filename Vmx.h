#pragma once
#include <ntddk.h>
#include <intrin.h>

// RtlPcToFileHeader is exported by ntoskrnl but not declared in all WDK km headers.
NTSYSAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

// ---------------------------------------------------------------------------
// IOCTL
// ---------------------------------------------------------------------------
#define IOCTL_DISK_READ_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_SCAN_PATTERN   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_READ_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_LOAD_MODULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Input:  null-terminated wchar_t path (e.g. L"\\??\\C:\\payload.sys")
// Output: none
// Status: STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_FOUND,
//         STATUS_ENTRYPOINT_NOT_FOUND, STATUS_INVALID_IMAGE_FORMAT
#define HV_LOAD_PATH_MAX        520  // 260 wchars * 2 bytes

// Input layout for IOCTL_HV_READ_MEMORY (12 bytes, METHOD_BUFFERED).
// Output: raw bytes copied from Kva (max HV_READ_MAX_LENGTH bytes).
// STATUS_INVALID_PARAMETER if Length == 0 || Length > HV_READ_MAX_LENGTH.
// Unmapped / guard-page faults are caught via __try and returned as-is.
#define HV_READ_MAX_LENGTH      65536

typedef struct _HV_READ_REQUEST {
    ULONG64 Kva;        // kernel virtual address to read from
    ULONG   Length;     // byte count (1..HV_READ_MAX_LENGTH)
} HV_READ_REQUEST, *PHV_READ_REQUEST;

#define MAX_PATTERN_LEN 256     // max byte-pattern string length including null terminator

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
#define IA32_MPERF                  0xE7    // Maximum Performance Frequency Clock Counter
#define IA32_APERF                  0xE8    // Actual Performance Frequency Clock Counter
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
#define VMCS_GUEST_LINEAR_ADDRESS       0x640A  // linear address reported on #PF / EPT exits

// Natural-width control fields
#define VMCS_CR0_GUEST_HOST_MASK        0x6000
#define VMCS_CR4_GUEST_HOST_MASK        0x6002
#define VMCS_CR0_READ_SHADOW            0x6004
#define VMCS_CR4_READ_SHADOW            0x6006

// CR4 bits enforced by the hypervisor — guest writes to these bits exit to us.
// Bit 13 = VMXE  (we own it: guest must not enable VMX directly)
// Bit 20 = SMEP  (Supervisor Mode Execution Prevention — minimum security baseline)
// Bit 21 = SMAP  (Supervisor Mode Access Prevention — minimum security baseline)
#define CR4_VMXE    (1ULL << 13)
#define CR4_SMEP    (1ULL << 20)
#define CR4_SMAP    (1ULL << 21)
#define CR4_HV_OWNED_MASK   (CR4_VMXE | CR4_SMEP | CR4_SMAP)
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
// Phase 12 additions
// ---------------------------------------------------------------------------

// Secondary exec control bits
#define SECONDARY_EXEC_ENABLE_VMFUNC          (1UL << 13)
#define SECONDARY_EXEC_VMCS_SHADOWING         (1UL << 14)
#define SECONDARY_EXEC_MODE_BASED_EPT_EXEC    (1UL << 22)  // MBEC: separate user/supervisor execute bits in EPT
#define SECONDARY_EXEC_SPP                    (1UL << 23)

// Primary exec control bits (Phase 13)
#define CPU_BASED_MONITOR_TRAP_FLAG           (1UL << 27)
#define CPU_BASED_RDTSC_EXITING               (1UL << 12)

// VM-exit control bits (Phase 12)
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL    (1UL << 12)
#define VM_EXIT_SAVE_IA32_PERF_GLOBAL_CTRL    (1UL << 30)

// VM-entry control bits (Phase 12)
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL   (1UL << 13)

// VMCS 64-bit control fields (Phase 12 / 13)
#define VMCS_VMFUNC_CONTROLS                  0x2018  // SDM Vol 3D App B
#define VMCS_EPTP_LIST_ADDRESS                0x2024  // physical address of 512-entry EPTP list
#define VMCS_VMREAD_BITMAP                    0x2026  // 4KB; bit set = VMREAD exits
#define VMCS_VMWRITE_BITMAP                   0x2028  // 4KB; bit set = VMWRITE exits
#define VMCS_SPP_TABLE_POINTER                0x2030  // Sub-Page Permission Table base (4KB)
#define VMCS_VMCS_LINK_POINTER_SHADOW         0x2800  // same encoding — link ptr is the shadow VMCS PA

// VMCS 64-bit guest fields (Phase 12)
#define VMCS_GUEST_PERF_GLOBAL_CTRL           0x2808

// VMCS 64-bit host fields (Phase 12)
#define VMCS_HOST_PERF_GLOBAL_CTRL            0x2C04

// MSR indices (Phase 12)
#define IA32_PERF_GLOBAL_CTRL                 0x38F
#define IA32_PERF_GLOBAL_STATUS               0x38E
#define IA32_PERF_GLOBAL_OVF_CTRL             0x390
#define IA32_FIXED_CTR_CTRL                   0x38D
#define IA32_FIXED_CTR0                       0x309  // inst_retired.any
#define IA32_FIXED_CTR1                       0x30A  // cpu_clk_unhalted.thread
#define IA32_FIXED_CTR2                       0x30B  // cpu_clk_unhalted.ref_tsc
#define IA32_PMC0                             0xC1
#define IA32_PERFEVTSEL0                      0x186

// VM-exit reasons (Phase 13/14)
#define VMX_EXIT_REASON_MTF                   37   // Monitor Trap Flag single-step
#define VMX_EXIT_REASON_EXCEPTION_NMI         0    // exception or NMI (exception bitmap hit)

// ---------------------------------------------------------------------------
// HLAT — Hardware-enforced Linear Address Translation (Phase 14 audit)
// HLAT is enumerated by CPUID[0x20,0].EBX bit 0. It requires:
//   - IA32_VMX_TERTIARY_PROCBASED_CTLS (MSR 0x492), bit 1 = HLAT enable
//   - VMCS_HLAT_PREFIX_SIZE (64-bit control, encoding TBD per SDM addendum)
//   - HLATP (HLAT Prefix Table) — one 4KB page per CR3 to be protected
// AVAILABILITY: Sapphire Rapids Xeon (2023) and later. NOT present on
// Raptor Lake desktop (i9-14900K). ProbeHlat() will return FALSE on this CPU.
// Raptor Lake does support EPT A/D bits (Phase 2) and MBEC (implemented,
// see SECONDARY_EXEC_MODE_BASED_EPT_EXEC) for per-page access control.
// ---------------------------------------------------------------------------
#define IA32_VMX_TERTIARY_PROCBASED_CTLS      0x492
#define TERTIARY_EXEC_HLAT_ENABLE             (1ULL << 1)
#define CPUID_HLAT_LEAF                       0x20

// VM-exit reason for RDTSC (SDM Vol 3D Appendix C, reason 16)
#define VMX_EXIT_REASON_RDTSC                 16

// VM-exit reasons for VMX instructions (SDM Vol 3D Appendix C-1, exact values)
// These fire when the guest executes a VMX instruction while in VMX non-root.
#define VMX_EXIT_REASON_VMCLEAR               19
#define VMX_EXIT_REASON_VMLAUNCH_INSTR        20
#define VMX_EXIT_REASON_VMPTRLD               21
#define VMX_EXIT_REASON_VMPTRST               22
#define VMX_EXIT_REASON_VMREAD_INSTR          23
#define VMX_EXIT_REASON_VMRESUME_INSTR        24
#define VMX_EXIT_REASON_VMWRITE_INSTR         25
#define VMX_EXIT_REASON_VMXOFF_INSTR          26
#define VMX_EXIT_REASON_VMXON_INSTR           27
#define VMX_EXIT_REASON_VMFUNC                59

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
// Pre-VMXON CPUID calibration cache.
// Populated once in VmxInitialize before any VMXON.  Covers:
//   - All leaves in the hypervisor range [0x40000000, 0x4FFFFFFF]
//   - Any leaf > max_std_leaf as returned by CPUID[0].EAX
// The exit handler returns these cached values verbatim so the guest sees
// exactly what bare-metal returned before the hypervisor was installed.
// ---------------------------------------------------------------------------
#define CPUID_CACHE_HV_LEAVES       16    // 0x40000000..0x4000000F sampled
#define CPUID_CACHE_BEYOND_MAX      8     // max_std_leaf+1 .. max_std_leaf+8

typedef struct _CPUID_CACHE_ENTRY {
    ULONG Leaf;
    ULONG Eax, Ebx, Ecx, Edx;
} CPUID_CACHE_ENTRY, *PCPUID_CACHE_ENTRY;

typedef struct _CPUID_CACHE {
    ULONG              MaxStdLeaf;    // CPUID[0].EAX — largest valid standard leaf
    CPUID_CACHE_ENTRY  HvRange[CPUID_CACHE_HV_LEAVES];   // hypervisor-range leaves
    CPUID_CACHE_ENTRY  BeyondMax[CPUID_CACHE_BEYOND_MAX]; // beyond-max-leaf leaves
    ULONG64            CpuidExitCost; // TSC ticks consumed by a bare-metal CPUID exit
} CPUID_CACHE, *PCPUID_CACHE;

extern CPUID_CACHE g_CpuidCache;   // defined in Vmx.c, populated before VMXON

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
// Exit telemetry — per-core exit counters, updated in VmExitDispatch.
// ---------------------------------------------------------------------------
typedef struct _EXIT_STATS {
    ULONG64 TotalExits;
    ULONG64 ExternalInt;
    ULONG64 Preemption;
    ULONG64 Cpuid;
    ULONG64 Rdmsr;
    ULONG64 Wrmsr;
    ULONG64 EptViolation;
    ULONG64 Mtf;
    ULONG64 Exception;
    ULONG64 Other;
} EXIT_STATS, *PEXIT_STATS;

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
    // 7 bytes padding to next 8-byte boundary
    ULONG64    AperOffset;          // +1B0h  accumulated APERF ticks consumed by exits
    ULONG64    MperfOffset;         // +1B8h  accumulated MPERF ticks consumed by exits
    BOOLEAN    AperMperfActive;     // +1C0h  set on first guest RDMSR of APERF/MPERF
    // 7 bytes padding
    ULONG64    GuestPerfGlobalCtrl; // +1C8h  shadow of IA32_PERF_GLOBAL_CTRL for guest
    PVOID      EptpListPage;        // +1D0h  4KB non-paged; 512-slot EPTP list for VMFUNC
    BOOLEAN    VmfuncEnabled;       // +1D8h  TRUE if VMFUNC leaf 0 was successfully armed
    // 7 bytes padding
    PVOID      ShadowVmcsPage;      // +1E0h  4KB; shadow VMCS for nested guest acceleration
    PVOID      VmreadBitmap;        // +1E8h  4KB; controls which VMREAD fields shadow vs exit
    PVOID      VmwriteBitmap;       // +1F0h  4KB; controls which VMWRITE fields shadow vs exit
    PVOID      SppTablePage;        // +1F8h  4KB; Sub-Page Permission Table (SPP) if supported
    BOOLEAN    VmcsShadowEnabled;   // +200h  TRUE if VMCS shadowing active on this core
    BOOLEAN    SppEnabled;          // +201h  TRUE if SPP active on this core
    BOOLEAN    MtfArmed;            // +202h  TRUE if MTF single-step is currently enabled
    BOOLEAN    PfExitEnabled;       // +203h  TRUE if #PF (bit 14) is in the exception bitmap
    BOOLEAN    DrDirty;             // +204h  guest wrote a DR; reload hardware before VMRESUME
    BOOLEAN    MbecEnabled;         // +205h  TRUE if MBEC (Mode-Based Execute Control) is active
    BOOLEAN    RdtscPending;        // +206h  TRUE: RDTSC_EXITING armed after a CPUID exit
    // 1 byte padding
    EXIT_STATS Stats;               // +208h  per-core VM-exit telemetry counters
} CORE_VMX_CONTEXT, *PCORE_VMX_CONTEXT;

// Indexed by KeGetCurrentProcessorNumberEx(NULL). Written before IPI, read by exit handler.
#define MAX_LOGICAL_PROCESSORS 64
extern PCORE_VMX_CONTEXT g_CoreCtx[MAX_LOGICAL_PROCESSORS];

// ---------------------------------------------------------------------------
// EPT entry flags
// ---------------------------------------------------------------------------
#define EPT_READ        (1ULL << 0)
#define EPT_WRITE       (1ULL << 1)
#define EPT_EXEC        (1ULL << 2)   // supervisor-mode execute (also plain execute when MBEC off)
#define EPT_MEMTYPE_UC  (0ULL << 3)   // uncacheable — for MMIO pages
#define EPT_MEMTYPE_WB  (6ULL << 3)   // write-back  — for RAM pages
#define EPT_LARGE_PAGE  (1ULL << 7)
#define EPT_EXEC_USER   (1ULL << 10)  // user-mode execute (MBEC only; ignored when MBEC off)
#define EPT_RWX         (EPT_READ | EPT_WRITE | EPT_EXEC)
// Full RWX with both supervisor and user execute — use when MBEC is active so
// user-mode code in identity-mapped pages remains executable.
#define EPT_RWX_MBEC    (EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER)

// EPT walk length: 4-level = value 3 in EPTP bits [5:3]
#define EPT_PAGE_WALK_4 (3ULL << 3)
// Memory type for EPT structures in EPTP bits [2:0]: WB = 6
#define EPT_MEMTYPE_WB_EPTP (6ULL)

typedef struct _EPT_CONTEXT {
    PVOID   Pml4;           // 4KB, physically contiguous
    ULONG64 Eptp;           // value to write to VMCS_EPT_POINTER
} EPT_CONTEXT, *PEPT_CONTEXT;

// Exit qualification access bits (SDM Vol 3C §27.2.1 Table 27-7)
#define EPT_QUAL_READ         (1ULL << 0)
#define EPT_QUAL_WRITE        (1ULL << 1)
#define EPT_QUAL_EXECUTE      (1ULL << 2)
// MBEC instruction-fetch qualification bits (SDM Vol 3C §28.3.3.3, MBEC-enabled exits only)
#define EPT_QUAL_EXEC_SUPER   (1ULL << 10)  // supervisor-mode (CPL < 3) instruction fetch
#define EPT_QUAL_EXEC_USER    (1ULL << 11)  // user-mode      (CPL = 3) instruction fetch

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

// Set to TRUE before calling EptBuildIdentityMap when MBEC is available.
// Ept.c reads this to decide whether to set EPT_EXEC_USER on leaf entries.
extern BOOLEAN g_MbecEnabled;

// Return codes for EptHandleViolation.
#define EPT_VIOLATION_NONE     0   // GPA not in shadow table — fall through to lazy-map
#define EPT_VIOLATION_HANDLED  1   // R/W on hidden page — decoy served, INVEPT done
#define EPT_VIOLATION_EXEC     2   // X on hidden page — caller must inject #PF(0)

NTSTATUS EptBuildIdentityMap(PEPT_CONTEXT Ept);
void     EptFree(PEPT_CONTEXT Ept);
void     EptMapPage4KB(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 Hpa, ULONG64 Flags);
ULONG64  EptGetPteFlags(PEPT_CONTEXT Ept, ULONG64 Gpa);  // returns leaf PTE flags; 0 if large/missing
void     EptInvalidate(ULONG64 Eptp);
NTSTATUS EptSetPermissions(PEPT_CONTEXT Ept, ULONG64 Gpa, PVOID ShadowVa, ULONG64 AccessMask);
ULONG    EptHandleViolation(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 ExitQual);
void     EptHideRange(PEPT_CONTEXT Ept, PVOID Va, SIZE_T Bytes, PVOID DecoyVa);
BOOLEAN  EptTryMerge2MB(PEPT_CONTEXT Ept, ULONG64 Gpa);

// Shadow table — defined in Ept.c, read by HandleEptViolation in Vmx.c.
extern EPT_SHADOW_ENTRY g_EptShadowTable[EPT_SHADOW_TABLE_SIZE];
extern ULONG            g_EptShadowCount;

// Driver-lifetime EPT context — defined in Vmx.c, used by EPT violation handler.
extern EPT_CONTEXT g_Ept;

// Lazy INVEPT flag — set by any path that modifies EPT PTEs before VMXON or
// on one core; cleared by VmExitDispatch on each core after issuing INVEPT.
extern volatile LONG g_InveptPending;

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
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, AperOffset)          == 0x1B0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, MperfOffset)         == 0x1B8);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, AperMperfActive)     == 0x1C0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, GuestPerfGlobalCtrl) == 0x1C8);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, EptpListPage)        == 0x1D0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmfuncEnabled)       == 0x1D8);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, ShadowVmcsPage)      == 0x1E0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmreadBitmap)        == 0x1E8);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmwriteBitmap)       == 0x1F0);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, SppTablePage)        == 0x1F8);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, VmcsShadowEnabled)   == 0x200);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, SppEnabled)          == 0x201);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, MtfArmed)            == 0x202);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, PfExitEnabled)       == 0x203);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, DrDirty)             == 0x204);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, MbecEnabled)         == 0x205);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, RdtscPending)        == 0x206);
C_ASSERT(FIELD_OFFSET(CORE_VMX_CONTEXT, Stats)               == 0x208);
C_ASSERT(sizeof(GUEST_REGS) == 0x80);

// ---------------------------------------------------------------------------
// C prototypes
// ---------------------------------------------------------------------------
BOOLEAN  IsVmxSupported(void);
BOOLEAN  IsVmxEnabledInBios(void);
NTSTATUS VmxInitialize(void);
UINT64   KernelScanPattern(const char *Pattern);
void     VmxTeardown(void);
ULONG_PTR VmxLaunchCore(ULONG_PTR ctxArrayPtr);
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void     VmExitDispatch(PCORE_VMX_CONTEXT Ctx);

// DPC latency harness — started after VmxInitialize succeeds, cancelled by VmxTeardown.
void     DpcLatencyStart(void);
void     DpcLatencyStop(void);

// HLAT capability probe — returns FALSE on Raptor Lake desktop (feature absent).
BOOLEAN  ProbeHlat(void);

// MTF single-step API — arm/disarm Monitor Trap Flag on the current core's live VMCS.
// Must be called from within VMX non-root (e.g. from a VMCALL handler) so the current
// VMCS is already loaded. Disarm is called automatically by HandleMtf each time.
void     MtfArm(PCORE_VMX_CONTEXT Ctx);
void     MtfDisarm(PCORE_VMX_CONTEXT Ctx);

// ---------------------------------------------------------------------------
// Hypercall ABI (VMCALL interface)
// RAX = hypercall ID, RBX/RCX/RDX = arguments, RAX on return = result.
// ---------------------------------------------------------------------------
#define HV_CALL_MTF_TOGGLE          0x01ULL  // arg0(RBX): 1=arm, 0=disarm
#define HV_CALL_EPT_SWITCH_VIEW     0x02ULL  // arg0(RBX): EPTP list index (0-511)
#define HV_CALL_GET_PERF_COUNTERS   0x03ULL  // ret RAX=MperfOffset, RBX=AperOffset
#define HV_CALL_SET_EPT_POLICY      0x05ULL  // arg0(RBX): GPA (4KB-aligned), arg1(RCX): policy bits
#define HV_CALL_LOCK_LSTAR          0x06ULL  // lock LSTAR; subsequent WRMSR IA32_LSTAR are rejected
#define HV_CALL_WP_REGISTER         0x07ULL  // arg0(RBX): GPA — add to g_WpTable + set EPT_READ|EPT_EXEC
#define HV_CALL_TEARDOWN            0xFFULL  // clean teardown (replaces old VMCALL path)

// Return codes written to guest RAX after hypercall dispatch.
#define HV_STATUS_SUCCESS           0x00ULL
#define HV_STATUS_INVALID_CALL      0x01ULL
#define HV_STATUS_NOT_SUPPORTED     0x02ULL
#define HV_STATUS_BAD_ALIGNMENT     0x03ULL  // GPA not 4KB-aligned

// Valid policy bits for HV_CALL_SET_EPT_POLICY.
// Caller may combine: EPT_READ, EPT_WRITE, EPT_EXEC (supervisor-X), EPT_EXEC_USER (user-X).
// EPT_EXEC_USER is only honoured when MBEC is active; rejected otherwise.
#define HV_EPT_POLICY_MASK          (EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER)

// ---------------------------------------------------------------------------
// File logging
// ---------------------------------------------------------------------------
void     HvLogOpen(void);
void     HvLog(const char *fmt, ...);
void     HvLogClose(void);

