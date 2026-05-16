#include <ntddk.h>
#include <intrin.h>
#include "Vmx.h"

#ifdef HV_VERBOSE
#define HV_VERBOSE_LOG(fmt, ...) DbgPrint("DayZHV: " fmt "\n", ##__VA_ARGS__)
#else
#define HV_VERBOSE_LOG(fmt, ...) ((void)0)
#endif

#define EPT_TABLE_ENTRIES 512

// Shadow/protect table — fixed array, non-paged by virtue of being a BSS global.
EPT_SHADOW_ENTRY g_EptShadowTable[EPT_SHADOW_TABLE_SIZE] = {0};
ULONG            g_EptShadowCount = 0;

// Set by VmxInitialize after probing SECONDARY_EXEC_MODE_BASED_EPT_EXEC.
// When TRUE, EptBuildIdentityMap sets EPT_EXEC_USER on all leaf entries so
// user-mode code in identity-mapped pages remains executable under MBEC.
BOOLEAN g_MbecEnabled = FALSE;

static PVOID AllocEptTable(void)
{
    // Must use contiguous allocator — EptBuildIdentityMap and EptMapPage4KB
    // walk the EPT by calling MmGetVirtualForPhysical on parent entry values.
    // That reverse-mapping only works for memory registered in the PFN database
    // with a known VA, which MmAllocateContiguousMemory guarantees.
    // ExAllocatePool2 pages are not reliably reverse-mappable this way.
    //
    // hi must be the full physical address range (no upper bound).  A bound of
    // 0x7FFF... was the prior value; it allowed allocations at physical addresses
    // whose MmGetVirtualForPhysical result falls in user-mode VA space, causing
    // the EPT hardware to dereference a user-mode pointer at kernel privilege.
    PHYSICAL_ADDRESS lo = {0}, hi = {0}, align = {0};
    hi.QuadPart    = (LONGLONG)0xFFFFFFFFFFFFFFFF;
    align.QuadPart = PAGE_SIZE;
    PVOID p = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lo, hi, align, MmCached);
    if (p) RtlZeroMemory(p, PAGE_SIZE);
    return p;
}

// Map a single 4KB page into the EPT during EptBuildIdentityMap (before VMXON).
// Identical walk to EptMapPage4KB but without the split path (no large pages yet
// exist in the region being populated) and uses EPT_MEMTYPE_WB leaf flags.
static NTSTATUS EptMap4KBLeaf(ULONG64* Pml4, ULONG64 Pa, ULONG64 LeafFlags)
{
    ULONG pml4i = (ULONG)((Pa >> 39) & 0x1FF);
    ULONG pdpti = (ULONG)((Pa >> 30) & 0x1FF);
    ULONG pdi   = (ULONG)((Pa >> 21) & 0x1FF);
    ULONG pti   = (ULONG)((Pa >> 12) & 0x1FF);

    if (!(Pml4[pml4i] & EPT_READ)) {
        PVOID t = AllocEptTable();
        if (!t) return STATUS_INSUFFICIENT_RESOURCES;
        Pml4[pml4i] = MmGetPhysicalAddress(t).QuadPart | EPT_RWX;
    }
    ULONG64 pdpt_phys = Pml4[pml4i] & ~0xFFFULL;
    ULONG64* pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
    if (!pdpt_va) {
        HvLog("!!! DayZHV: [EPT4K] MmGetVirtualForPhysical(PDPT) returned NULL  pa=0x%llX pdpt_phys=0x%llX", Pa, pdpt_phys);
        return STATUS_UNSUCCESSFUL;
    }

    if (!(pdpt_va[pdpti] & EPT_READ)) {
        PVOID t = AllocEptTable();
        if (!t) return STATUS_INSUFFICIENT_RESOURCES;
        pdpt_va[pdpti] = MmGetPhysicalAddress(t).QuadPart | EPT_RWX;
    }
    ULONG64 pd_phys = pdpt_va[pdpti] & ~0xFFFULL;
    ULONG64* pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
    if (!pd_va) {
        HvLog("!!! DayZHV: [EPT4K] MmGetVirtualForPhysical(PD) returned NULL  pa=0x%llX pd_phys=0x%llX", Pa, pd_phys);
        return STATUS_UNSUCCESSFUL;
    }

    if (!(pd_va[pdi] & EPT_READ)) {
        PVOID t = AllocEptTable();
        if (!t) return STATUS_INSUFFICIENT_RESOURCES;
        pd_va[pdi] = MmGetPhysicalAddress(t).QuadPart | EPT_RWX;
    }
    ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
    ULONG64* pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
    if (!pt_va) {
        HvLog("!!! DayZHV: [EPT4K] MmGetVirtualForPhysical(PT) returned NULL  pa=0x%llX pt_phys=0x%llX", Pa, pt_phys);
        return STATUS_UNSUCCESSFUL;
    }

    pt_va[pti] = (Pa & ~0xFFFULL) | LeafFlags;
    return STATUS_SUCCESS;
}

NTSTATUS EptBuildIdentityMap(PEPT_CONTEXT Ept)
{
    Ept->Pml4 = AllocEptTable();
    if (!Ept->Pml4) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG64* pml4 = (ULONG64*)Ept->Pml4;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_UNSUCCESSFUL;

    ULONG64 leafRwx = g_MbecEnabled ? EPT_RWX_MBEC : EPT_RWX;

    ULONG rangeCount = 0;
    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) {
        ULONG64 base = ranges[i].BaseAddress.QuadPart;
        ULONG64 end  = base + ranges[i].NumberOfBytes.QuadPart;
        rangeCount++;

        HvLog("!!! DayZHV: [EPT] RAM range[%u] base=0x%llX end=0x%llX (%llu MB)",
              i, base, end, ranges[i].NumberOfBytes.QuadPart >> 20);

        if (base >= 0x000FFFFFFFFFFFFFULL && base != 0) {
            HvLog("!!! DayZHV: [EPT] FATAL range[%u] base=0x%llX exceeds 52-bit PA limit — aborting identity map", i, base);
            ExFreePool(ranges);
            return STATUS_INVALID_PARAMETER;
        }

        // Map every page in this physical range at 4KB granularity.
        // No 2MB large pages are used anywhere in the identity map.
        // Rationale: EptMapPage4KB is called from VMX root (HIGH_LEVEL) during
        // EPT violation handling.  Splitting a large-page PDE from VMX root
        // requires calling AllocEptTable (MmAllocateContiguousMemorySpecifyCache),
        // which is unsafe at HIGH_LEVEL and can return a physical page that is
        // simultaneously live in the guest's PFN database.  The EPT identity map
        // then aliases that page — the hypervisor writes EPT entries into it while
        // the guest reads it as a KTHREAD/EPROCESS, corrupting pool objects
        // (KTHREAD.ApcState.Process → user-space address → BSOD 0xA in
        // KeAccumulateTicks).  Building at 4KB from the start means EptMapPage4KB
        // only ever writes a leaf PTE — no allocation, no split, no aliasing risk.
        for (ULONG64 pa = base & ~0xFFFULL; pa < end; pa += PAGE_SIZE) {
            NTSTATUS s = EptMap4KBLeaf(pml4, pa, leafRwx | EPT_MEMTYPE_WB);
            if (!NT_SUCCESS(s)) {
                HvLog("!!! DayZHV: [EPT] FATAL EptMap4KBLeaf failed  pa=0x%llX range[%u](base=0x%llX end=0x%llX) status=0x%08X",
                      pa, i, base, end, (ULONG)s);
                ExFreePool(ranges);
                return s;
            }
        }
    }
    HvLog("!!! DayZHV: [EPT] identity map built: %u RAM ranges  eptp_will_be_computed_after_mmio", rangeCount);

    // Map firmware-reserved MMIO regions as UC, read-only, no-execute so that
    // guest PTE walks into these regions produce a valid (non-garbage) EPT translation
    // rather than an EPT violation.  MmGetVirtualForPhysical on these HPAs returns
    // NULL (correct), so callers that guard against NULL will handle them cleanly.
    // Regions covered: local APIC (1 page), IOAPIC (1 page), PCIe config (256MB ECAM).
    static const struct { ULONG64 Base; ULONG64 Size; } kMmio[] = {
        { 0xFEE00000ULL,         PAGE_SIZE        },   // local APIC
        { 0xFEC00000ULL,         PAGE_SIZE        },   // IOAPIC
        { 0xE0000000ULL,         0x10000000ULL    },   // PCIe ECAM (256MB, typical Z790)
    };
    for (ULONG m = 0; m < ARRAYSIZE(kMmio); m++) {
        ULONG64 mbase = kMmio[m].Base;
        ULONG64 mend  = mbase + kMmio[m].Size;
        for (ULONG64 pa = mbase; pa < mend; pa += PAGE_SIZE) {
            // Only map if not already covered by a RAM range above.
            // All RAM is now 4KB, so the walk is always to the PT level.
            ULONG pml4i = (ULONG)((pa >> 39) & 0x1FF);
            ULONG pdpti = (ULONG)((pa >> 30) & 0x1FF);
            ULONG pdi   = (ULONG)((pa >> 21) & 0x1FF);
            ULONG pti   = (ULONG)((pa >> 12) & 0x1FF);
            if (pml4[pml4i] & EPT_READ) {
                ULONG64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
                ULONG64* pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
                if (pdpt_va && (pdpt_va[pdpti] & EPT_READ)) {
                    ULONG64 pd_phys = pdpt_va[pdpti] & ~0xFFFULL;
                    ULONG64* pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
                    if (pd_va && (pd_va[pdi] & EPT_READ)) {
                        ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
                        ULONG64* pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
                        if (pt_va && (pt_va[pti] & EPT_READ)) continue;
                    }
                }
            }
            NTSTATUS s = EptMap4KBLeaf(pml4, pa, EPT_READ | EPT_WRITE | EPT_MEMTYPE_UC);
            if (!NT_SUCCESS(s)) {
                HvLog("!!! DayZHV: [EPT] FATAL EptMap4KBLeaf failed for MMIO region[%u] pa=0x%llX status=0x%08X",
                      m, pa, (ULONG)s);
                ExFreePool(ranges);
                return s;
            }
        }
    }

    ExFreePool(ranges);

    PHYSICAL_ADDRESS pml4Phys = MmGetPhysicalAddress(Ept->Pml4);
    Ept->Eptp = pml4Phys.QuadPart | EPT_PAGE_WALK_4 | EPT_MEMTYPE_WB_EPTP | EPT_AD_ENABLE;
    HvLog("!!! DayZHV: [EPT] EPTP=0x%llX  pml4_pa=0x%llX  mbec=%u", Ept->Eptp, pml4Phys.QuadPart, (ULONG)g_MbecEnabled);
    return STATUS_SUCCESS;
}

// Map a single 4KB guest-physical page (Gpa) to host-physical page (Hpa) with Flags.
// The identity map is built entirely at 4KB granularity by EptBuildIdentityMap, so
// the PT for every valid GPA already exists — this function only writes the leaf PTE.
// No allocation, no split, no lock: safe to call from VMX root at any IRQL.
void EptMapPage4KB(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 Hpa, ULONG64 Flags)
{
    if (!Ept->Pml4) return;

    if ((Gpa & 0xFFF) || (Hpa & 0xFFF)) return;
    if (Gpa >= 0x000FFFFFFFFFFFFFULL || Hpa >= 0x000FFFFFFFFFFFFFULL) return;

    ULONG pml4i = (ULONG)((Gpa >> 39) & 0x1FF);
    ULONG pdpti = (ULONG)((Gpa >> 30) & 0x1FF);
    ULONG pdi   = (ULONG)((Gpa >> 21) & 0x1FF);
    ULONG pti   = (ULONG)((Gpa >> 12) & 0x1FF);

    ULONG64 *pml4 = (ULONG64*)Ept->Pml4;
    if (!(pml4[pml4i] & EPT_READ)) return;

    ULONG64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
    ULONG64 *pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
    if (!pdpt_va || !(pdpt_va[pdpti] & EPT_READ)) return;

    ULONG64 pd_phys = pdpt_va[pdpti] & ~0xFFFULL;
    ULONG64 *pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
    if (!pd_va || !(pd_va[pdi] & EPT_READ)) return;

    ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
    ULONG64 *pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
    if (!pt_va) return;

    // Naturally-atomic 64-bit aligned store — idempotent across concurrent writers.
    pt_va[pti] = (Hpa & ~0xFFFULL) | Flags;
}

void EptInvalidate(ULONG64 Eptp)
{
    AsmInveptSingleContext(Eptp);
}

// Walk the live EPT and return a pointer to the 4KB PTE for Gpa.
// Returns NULL if the walk hits a missing entry.
static ULONG64* EptGetPte(PEPT_CONTEXT Ept, ULONG64 Gpa)
{
    if (!Ept->Pml4) return NULL;

    ULONG pml4i = (ULONG)((Gpa >> 39) & 0x1FF);
    ULONG pdpti = (ULONG)((Gpa >> 30) & 0x1FF);
    ULONG pdi   = (ULONG)((Gpa >> 21) & 0x1FF);
    ULONG pti   = (ULONG)((Gpa >> 12) & 0x1FF);

    ULONG64 *pml4 = (ULONG64*)Ept->Pml4;
    if (!(pml4[pml4i] & EPT_READ)) return NULL;

    ULONG64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
    ULONG64 *pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
    if (!pdpt_va || !(pdpt_va[pdpti] & EPT_READ)) return NULL;

    ULONG64 pd_phys = pdpt_va[pdpti] & ~0xFFFULL;
    ULONG64 *pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
    if (!pd_va || !(pd_va[pdi] & EPT_READ)) return NULL;

    ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
    ULONG64 *pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
    if (!pt_va) return NULL;

    return &pt_va[pti];
}

// Return the permission flag bits of the leaf PTE for Gpa.
// Returns 0 if the walk hits a large-page leaf or a missing entry — caller
// must treat 0 as "unknown / not yet split" and not as "no permissions".
ULONG64 EptGetPteFlags(PEPT_CONTEXT Ept, ULONG64 Gpa)
{
    ULONG64 *pte = EptGetPte(Ept, Gpa);
    if (!pte) return 0;
    return *pte & 0xFFFULL;
}

// Protect a single 4KB GPA: split any covering 2MB page, set AccessMask on the PTE,
// and record the real/shadow HPA pair for violation-handler swapping.
// ShadowVa must be a caller-allocated non-paged buffer (PAGE_SIZE) that stays alive
// as long as the hypervisor is running.
NTSTATUS EptSetPermissions(PEPT_CONTEXT Ept, ULONG64 Gpa, PVOID ShadowVa, ULONG64 AccessMask)
{
    Gpa &= ~0xFFFULL;

    if (g_EptShadowCount >= EPT_SHADOW_TABLE_SIZE) return STATUS_INSUFFICIENT_RESOURCES;

    // Derive real HPA from the live EPT before splitting.
    // If the page hasn't been touched yet it may still be a 2MB leaf — read its base.
    ULONG64 realHpa = Gpa;  // identity map: GPA == HPA at baseline
    PHYSICAL_ADDRESS shadowPhys = MmGetPhysicalAddress(ShadowVa);

    // Write the 4KB leaf PTE with the requested permissions.
    // The identity map is pre-built at 4KB granularity so no split is needed.
    EptMapPage4KB(Ept, Gpa, realHpa, AccessMask | EPT_MEMTYPE_WB);
    // Set the lazy-flush flag rather than calling EptInvalidate directly.
    // This function may be called before VMXON (e.g. EptHideRange in VmxInitialize);
    // INVEPT outside VMX root operation raises #UD. VmExitDispatch drains the flag
    // on each core's first exit, which is sufficient — the TLB is cold at that point.
    InterlockedExchange(&g_InveptPending, 1);

    // Record the shadow entry.
    PEPT_SHADOW_ENTRY e   = &g_EptShadowTable[g_EptShadowCount++];
    e->Gpa                = Gpa;
    e->RealHpa.QuadPart   = (LONGLONG)realHpa;
    e->ShadowHpa          = shadowPhys;
    e->AccessMask         = AccessMask;
    e->Active             = TRUE;

    HV_VERBOSE_LOG("EPT shadow set GPA=0x%llX real=0x%llX decoy=0x%llX mask=0x%llX",
                   Gpa, realHpa, shadowPhys.QuadPart, AccessMask);

    return STATUS_SUCCESS;
}

// Called from HandleEptViolation. Identifies the faulting GPA in the shadow table
// and serves the decoy (shadow) HPA for R/W faults.
//
// Execute faults on hidden pages are NOT redirected to the real HPA. Hidden pages
// are hypervisor data pages — nothing legitimate executes them. Serving the real
// HPA on an X fault would be detectable: an attacker who triggers an X fault and
// observes that execution continues (rather than faulting) knows a swap occurred.
// Instead we return EPT_VIOLATION_EXEC to the caller, which injects #PF(0) into
// the guest — architecturally identical to executing a non-present page.
//
// Return values:
//   EPT_VIOLATION_HANDLED  — R/W fault served; PTE swapped to decoy, INVEPT done.
//   EPT_VIOLATION_EXEC     — X fault on a hidden page; caller must inject #PF.
//   EPT_VIOLATION_NONE     — GPA not in the shadow table; fall through to lazy-map.
#define EPT_VIOLATION_NONE     0
#define EPT_VIOLATION_HANDLED  1
#define EPT_VIOLATION_EXEC     2

ULONG EptHandleViolation(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 ExitQual)
{
    Gpa &= ~0xFFFULL;

    for (ULONG i = 0; i < g_EptShadowCount; i++) {
        PEPT_SHADOW_ENTRY e = &g_EptShadowTable[i];
        if (!e->Active || e->Gpa != Gpa) continue;

        // Execute fault on a hidden data page — do not redirect.
        // Caller injects #PF(0); the guest sees a non-present page fault,
        // indistinguishable from a normal page-not-present condition.
        if (ExitQual & (EPT_QUAL_EXECUTE | EPT_QUAL_EXEC_USER)) {
            HV_VERBOSE_LOG("EPT exec-hidden GPA=0x%llX qual=0x%llX -> #PF", Gpa, ExitQual);
            return EPT_VIOLATION_EXEC;
        }

        // R/W fault — serve the decoy (zeroed) page.
        ULONG64 *pte = EptGetPte(Ept, Gpa);
        if (!pte) return EPT_VIOLATION_NONE;

        ULONG64 decoyHpa = (ULONG64)e->ShadowHpa.QuadPart;
        // R/W on decoy; execute remains denied (EPT_EXEC=0) so a follow-up
        // execute fault re-enters this handler and gets the #PF path above.
        *pte = (decoyHpa & ~0xFFFULL) | (EPT_READ | EPT_WRITE) | EPT_MEMTYPE_WB;

        EptInvalidate(Ept->Eptp);

        HV_VERBOSE_LOG("EPT rw-hidden GPA=0x%llX -> decoy=0x%llX", Gpa, decoyHpa);
        return EPT_VIOLATION_HANDLED;
    }

    return EPT_VIOLATION_NONE;
}

// Hide a VA range from the guest by setting all covering PTEs to AccessMask=0.
// Every GPA in the range redirects R/W faults to DecoyVa (caller-provided zeroed page)
// and X faults to the real HPA. Walk is page-by-page; pages not in the EPT are skipped.
void EptHideRange(PEPT_CONTEXT Ept, PVOID Va, SIZE_T Bytes, PVOID DecoyVa)
{
    ULONG64 base = (ULONG64)Va & ~0xFFFULL;
    ULONG64 end  = ((ULONG64)Va + Bytes + PAGE_SIZE - 1) & ~0xFFFULL;

    for (ULONG64 va = base; va < end; va += PAGE_SIZE) {
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)va);
        if (pa.QuadPart == 0) continue;
        // AccessMask=0: all accesses fault → EptHandleViolation serves DecoyVa for R/W,
        // real HPA for X. EptSetPermissions splits any 2MB covering leaf automatically.
        EptSetPermissions(Ept, (ULONG64)pa.QuadPart, DecoyVa, 0);
    }
}

void EptFree(PEPT_CONTEXT Ept)
{
    if (!Ept->Pml4) return;
    ULONG64* pml4 = (ULONG64*)Ept->Pml4;

    for (ULONG i = 0; i < EPT_TABLE_ENTRIES; i++) {
        if (!(pml4[i] & EPT_READ)) continue;
        ULONG64 pdpt_phys = pml4[i] & ~0xFFFULL;
        ULONG64* pdpt = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
        if (!pdpt) continue;

        for (ULONG j = 0; j < EPT_TABLE_ENTRIES; j++) {
            if (!(pdpt[j] & EPT_READ)) continue;
            ULONG64 pd_phys = pdpt[j] & ~0xFFFULL;
            ULONG64* pd_va = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
            if (!pd_va) continue;

            for (ULONG k = 0; k < EPT_TABLE_ENTRIES; k++) {
                if (!(pd_va[k] & EPT_READ)) continue;
                ULONG64 pt_phys = pd_va[k] & ~0xFFFULL;
                PVOID pt_va = MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
                if (pt_va) MmFreeContiguousMemory(pt_va);
            }
            MmFreeContiguousMemory(pd_va);
        }
        MmFreeContiguousMemory(pdpt);
    }
    MmFreeContiguousMemory(Ept->Pml4);
    Ept->Pml4 = NULL;
    Ept->Eptp = 0;
}
