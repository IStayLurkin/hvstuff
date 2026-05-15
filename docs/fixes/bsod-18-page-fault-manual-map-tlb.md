# BSOD #18 — PAGE_FAULT_IN_NONPAGED_AREA (0x50) on manual-map Phase 3 launch

**Stop code**: `PAGE_FAULT_IN_NONPAGED_AREA` (0x50)  
**Failing context**: Phase 3 IPI broadcast (`KeIpiGenericCall` → `VmxLaunchCore`)  
**Host**: i9-14900K (32 logical processors, 16 P-cores threads 0-15)  
**Date fixed**: 2026-05-14  

---

## Root Cause

When the driver is loaded via manual-map (KDMapper/RTCore) rather than `sc create`,
the System PTE mappings for the driver image are written by the loader on one logical
processor. `KeIpiGenericCall` then broadcasts to all cores simultaneously. On a 14900K
with 32 logical processors, the IPI can arrive on a P-core before that core's TLB has
been invalidated for the new PTE entries, causing a page fault on the first instruction
fetch from a freshly mapped driver page.

E-cores (threads 16-31) are a secondary vector: they handle non-paged pool and System
PTE regions differently during C-state wake-up, and a stale `g_ProcCount` (from a prior
failed launch attempt) could allow an E-core to bypass the affinity guard and dereference
a `g_CtxArray` slot that was never initialized for it.

---

## Fixes Applied

### 1. Per-core TLB flush before VMLAUNCH — `Vmx.c` (`VmxLaunchCore`)

```c
__writecr3(__readcr3());
```

Added immediately before `AsmLaunchAndReturn`. Writing CR3 back to itself flushes all
non-global TLB entries on the executing logical processor without changing the address
space. This is the architecturally defined invalidation mechanism (Intel SDM Vol 3A §4.10.4).

### 2. Memory barrier + serializing CPUID — `Vmx.c` (`VmxLaunchCore`)

```c
KeMemoryBarrier();           // MFENCE — orders all prior loads and stores
int r[4];
__cpuid(r, 0);               // serializing instruction — retires all prior ops
```

`KeMemoryBarrier` emits MFENCE to order memory operations. `CPUID` is a serializing
instruction (Intel SDM Vol 3A §8.3): the CPU waits for all prior instructions to retire
before fetching the next, ensuring the TLB flush has fully taken effect on this core
before the VMX entry sequence begins.

### 3. CPUID serialization at the ASM level — `Arch.asm` (`AsmLaunchAndReturn`)

```asm
push rdx
xor  eax, eax
cpuid           ; serializing fence immediately before vmlaunch
pop  rdx
```

A second serialization fence placed directly in the assembly trampoline, just before
`vmlaunch`. RDX (the `ctx` pointer) is preserved across CPUID which clobbers all four
GPRs. This guarantees the C-level flush and barrier are visible before the CPU begins
VMX entry regardless of any intervening compiler reordering.

### 4. Hardened E-core guard — `Vmx.c` (`VmxLaunchCore`)

```c
if (procNum >= g_ProcCount) return 0;
if (procNum >= 64 || !((HV_PCORE_AFFINITY_MASK >> procNum) & 1ULL)) return 0;
```

Added a second, independent guard that checks the bit directly in `HV_PCORE_AFFINITY_MASK`
(0x0000FFFF = threads 0-15). This catches any E-core (threads 16-31) that receives the
IPI broadcast even if `g_ProcCount` is stale from a prior failed launch attempt. Both
conditions must pass; either failure returns without touching `g_CtxArray`.

---

## vcxproj fixes (same session)

- `Ept.c` and `Loader.c` were missing from `<ClCompile>` in `dayzdriv.vcxproj`, causing
  10 linker `LNK2019` errors (`EptBuildIdentityMap`, `ManualLoad`, `g_MbecEnabled`, etc.).
- WDK `TestSign` step failed with *"No file digest algorithm specified"* — fixed by adding
  `<DriverSign><FileDigestAlgorithm>SHA256</FileDigestAlgorithm></DriverSign>` to the
  `ItemDefinitionGroup`. The WDK targets pass this as `/fd "SHA256"` to signtool.
