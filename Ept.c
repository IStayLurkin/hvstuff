#include <ntddk.h>
#include <intrin.h>
#include "Vmx.h"

#define EPT_TABLE_ENTRIES 512

static PVOID AllocEptTable(void)
{
    PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'HvET');
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
    Ept->Eptp = pml4Phys.QuadPart | EPT_PAGE_WALK_4 | EPT_MEMTYPE_WB_EPTP;
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
            if (pd_va) ExFreePoolWithTag(pd_va, 'HvET');
        }
        ExFreePoolWithTag(pdpt, 'HvET');
    }
    ExFreePoolWithTag(Ept->Pml4, 'HvET');
    Ept->Pml4 = NULL;
    Ept->Eptp = 0;
}
