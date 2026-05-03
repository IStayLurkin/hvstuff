#include <ntddk.h>
#include <intrin.h>
#include "Vmx.h"

#define EPT_TABLE_ENTRIES 512

// Shadow/protect table — fixed array, non-paged by virtue of being a BSS global.
EPT_SHADOW_ENTRY g_EptShadowTable[EPT_SHADOW_TABLE_SIZE] = {0};
ULONG            g_EptShadowCount = 0;

static PVOID AllocEptTable(void)
{
    // Must use contiguous allocator — EptBuildIdentityMap and EptMapPage4KB
    // walk the EPT by calling MmGetVirtualForPhysical on parent entry values.
    // That reverse-mapping only works for memory registered in the PFN database
    // with a known VA, which MmAllocateContiguousMemory guarantees.
    // ExAllocatePool2 pages are not reliably reverse-mappable this way.
    PHYSICAL_ADDRESS lo = {0}, hi = {0}, align = {0};
    hi.QuadPart    = 0x7FFFFFFFFFFFF000LL;
    align.QuadPart = PAGE_SIZE;
    PVOID p = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lo, hi, align, MmCached);
    if (p) RtlZeroMemory(p, PAGE_SIZE);
    return p;
}

NTSTATUS EptBuildIdentityMap(PEPT_CONTEXT Ept)
{
    Ept->Pml4 = AllocEptTable();
    if (!Ept->Pml4) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG64* pml4 = (ULONG64*)Ept->Pml4;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_UNSUCCESSFUL;

    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) {
        ULONG64 base = ranges[i].BaseAddress.QuadPart;
        ULONG64 size = ranges[i].NumberOfBytes.QuadPart;
        ULONG64 end  = base + size;

        base &= ~((ULONG64)0x1FFFFF);
        end   = (end + 0x1FFFFF) & ~((ULONG64)0x1FFFFF);

        for (ULONG64 pa = base; pa < end; pa += 0x200000) {
            ULONG pml4i = (ULONG)((pa >> 39) & 0x1FF);
            ULONG pdpti = (ULONG)((pa >> 30) & 0x1FF);
            ULONG pdi   = (ULONG)((pa >> 21) & 0x1FF);

            // PML4E
            if (!(pml4[pml4i] & EPT_READ)) {
                PVOID pdpt = AllocEptTable();
                if (!pdpt) { ExFreePool(ranges); return STATUS_INSUFFICIENT_RESOURCES; }
                pml4[pml4i] = MmGetPhysicalAddress(pdpt).QuadPart | EPT_RWX;
            }

            // PDPTE
            ULONG64 pdpte_phys = pml4[pml4i] & ~0xFFFULL;
            ULONG64* pdpt_va   = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpte_phys);
            if (!pdpt_va) { ExFreePool(ranges); return STATUS_UNSUCCESSFUL; }

            if (!(pdpt_va[pdpti] & EPT_READ)) {
                PVOID pd = AllocEptTable();
                if (!pd) { ExFreePool(ranges); return STATUS_INSUFFICIENT_RESOURCES; }
                pdpt_va[pdpti] = MmGetPhysicalAddress(pd).QuadPart | EPT_RWX;
            }

            // PDE — 2MB large page leaf
            ULONG64 pde_phys = pdpt_va[pdpti] & ~0xFFFULL;
            ULONG64* pd_va   = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pde_phys);
            if (!pd_va) { ExFreePool(ranges); return STATUS_UNSUCCESSFUL; }

            pd_va[pdi] = pa | EPT_RWX | EPT_MEMTYPE_WB | EPT_LARGE_PAGE;
        }
    }

    ExFreePool(ranges);

    PHYSICAL_ADDRESS pml4Phys = MmGetPhysicalAddress(Ept->Pml4);
    Ept->Eptp = pml4Phys.QuadPart | EPT_PAGE_WALK_4 | EPT_MEMTYPE_WB_EPTP | EPT_AD_ENABLE;
    return STATUS_SUCCESS;
}

// Map a single 4KB guest-physical page (Gpa) to host-physical page (Hpa) with Flags.
// If a 2MB large-page PDE already covers this range it is split into 512 x 4KB PTEs first.
// Safe to call from DISPATCH_LEVEL (all allocations are non-paged, no pageable APIs).
void EptMapPage4KB(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 Hpa, ULONG64 Flags)
{
    if (!Ept->Pml4) return;

    ULONG pml4i = (ULONG)((Gpa >> 39) & 0x1FF);
    ULONG pdpti = (ULONG)((Gpa >> 30) & 0x1FF);
    ULONG pdi   = (ULONG)((Gpa >> 21) & 0x1FF);
    ULONG pti   = (ULONG)((Gpa >> 12) & 0x1FF);

    ULONG64 *pml4 = (ULONG64*)Ept->Pml4;

    // PML4E
    if (!(pml4[pml4i] & EPT_READ)) {
        PVOID pdpt = AllocEptTable();
        if (!pdpt) return;
        pml4[pml4i] = MmGetPhysicalAddress(pdpt).QuadPart | EPT_RWX;
    }

    // PDPTE
    ULONG64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
    ULONG64 *pdpt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pdpt_phys);
    if (!pdpt_va) return;

    if (!(pdpt_va[pdpti] & EPT_READ)) {
        PVOID pd = AllocEptTable();
        if (!pd) return;
        pdpt_va[pdpti] = MmGetPhysicalAddress(pd).QuadPart | EPT_RWX;
    }

    // PDE
    ULONG64 pd_phys = pdpt_va[pdpti] & ~0xFFFULL;
    ULONG64 *pd_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
    if (!pd_va) return;

    // If this PDE is a 2MB large-page leaf, split it into 512 x 4KB PTEs.
    if (pd_va[pdi] & EPT_LARGE_PAGE) {
        ULONG64 large_base  = pd_va[pdi] & ~0x1FFFFFULL; // 2MB-aligned base HPA
        ULONG64 large_flags = pd_va[pdi] & 0xFFFULL & ~EPT_LARGE_PAGE; // preserve RWX+memtype

        PVOID pt_new = AllocEptTable();
        if (!pt_new) return;

        ULONG64 *pt_va = (ULONG64*)pt_new;
        for (ULONG k = 0; k < 512; k++)
            pt_va[k] = (large_base + (ULONG64)k * PAGE_SIZE) | large_flags;

        pd_va[pdi] = MmGetPhysicalAddress(pt_new).QuadPart | EPT_RWX;
    }

    // PT — either pre-existing or just created by split above
    if (!(pd_va[pdi] & EPT_READ)) {
        PVOID pt = AllocEptTable();
        if (!pt) return;
        pd_va[pdi] = MmGetPhysicalAddress(pt).QuadPart | EPT_RWX;
    }

    ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
    ULONG64 *pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
    if (!pt_va) return;

    pt_va[pti] = (Hpa & ~0xFFFULL) | Flags;
}

void EptInvalidate(ULONG64 Eptp)
{
    AsmInveptSingleContext(Eptp);
}

// Walk the live EPT and return a pointer to the 4KB PTE for Gpa.
// Returns NULL if the walk bottoms out at a large-page leaf or a missing entry.
// Caller must ensure the page was already split to 4KB via EptMapPage4KB.
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
    if (!pd_va) return NULL;

    // Still a large-page leaf — caller forgot to split first.
    if (pd_va[pdi] & EPT_LARGE_PAGE) return NULL;
    if (!(pd_va[pdi] & EPT_READ))    return NULL;

    ULONG64 pt_phys = pd_va[pdi] & ~0xFFFULL;
    ULONG64 *pt_va  = (ULONG64*)MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pt_phys);
    if (!pt_va) return NULL;

    return &pt_va[pti];
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

    // Force a 4KB PTE with the requested permissions.
    // EptMapPage4KB splits any covering 2MB PDE automatically.
    EptMapPage4KB(Ept, Gpa, realHpa, AccessMask | EPT_MEMTYPE_WB);
    EptInvalidate(Ept->Eptp);

    // Record the shadow entry.
    PEPT_SHADOW_ENTRY e   = &g_EptShadowTable[g_EptShadowCount++];
    e->Gpa                = Gpa;
    e->RealHpa.QuadPart   = (LONGLONG)realHpa;
    e->ShadowHpa          = shadowPhys;
    e->AccessMask         = AccessMask;
    e->Active             = TRUE;

    DbgPrint("DayZHV: EptSetPermissions GPA=0x%llX RealHPA=0x%llX ShadowHPA=0x%llX mask=0x%llX\n",
             Gpa, realHpa, shadowPhys.QuadPart, AccessMask);

    return STATUS_SUCCESS;
}

// Called from HandleEptViolation. Identifies the faulting GPA in the shadow table,
// swaps the PTE to shadow (R/W fault) or real (X fault), and invalidates the TLB.
// Returns TRUE if the GPA was a protected page (violation handled); FALSE to fall
// through to the lazy-map path for unmapped GPAs.
BOOLEAN EptHandleViolation(PEPT_CONTEXT Ept, ULONG64 Gpa, ULONG64 ExitQual)
{
    Gpa &= ~0xFFFULL;

    for (ULONG i = 0; i < g_EptShadowCount; i++) {
        PEPT_SHADOW_ENTRY e = &g_EptShadowTable[i];
        if (!e->Active || e->Gpa != Gpa) continue;

        ULONG64 *pte = EptGetPte(Ept, Gpa);
        if (!pte) return FALSE;

        ULONG64 accessType = ExitQual & (EPT_QUAL_READ | EPT_QUAL_WRITE | EPT_QUAL_EXECUTE);
        ULONG64 newHpa;

        if (accessType & (EPT_QUAL_READ | EPT_QUAL_WRITE)) {
            // R/W fault — redirect to shadow (decoy) page.
            newHpa = (ULONG64)e->ShadowHpa.QuadPart;
            // Allow R/W on the shadow, remove execute so X faults still redirect to real.
            *pte = (newHpa & ~0xFFFULL) | (EPT_READ | EPT_WRITE) | EPT_MEMTYPE_WB;
            DbgPrint("DayZHV: EPT R/W intercept GPA=0x%llX qual=0x%llX -> shadow HPA=0x%llX\n",
                     Gpa, ExitQual, newHpa);
        } else {
            // X fault — redirect to real page.
            newHpa = (ULONG64)e->RealHpa.QuadPart;
            // Allow execute on the real page, remove R/W so reads still go to shadow.
            *pte = (newHpa & ~0xFFFULL) | EPT_EXEC | EPT_MEMTYPE_WB;
            DbgPrint("DayZHV: EPT X intercept GPA=0x%llX qual=0x%llX -> real HPA=0x%llX\n",
                     Gpa, ExitQual, newHpa);
        }

        EptInvalidate(Ept->Eptp);
        return TRUE;
    }

    return FALSE;  // not a protected page
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
            PVOID pd_va = MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&pd_phys);
            if (pd_va) MmFreeContiguousMemory(pd_va);
        }
        MmFreeContiguousMemory(pdpt);
    }
    MmFreeContiguousMemory(Ept->Pml4);
    Ept->Pml4 = NULL;
    Ept->Eptp = 0;
}
