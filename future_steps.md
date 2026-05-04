# Future Steps — dayzdriv

Last updated: 2026-05-04

---

## DONE

- [x] Resident hypervisor — 32/32 cores, 3-phase safety pipeline
- [x] EPT identity map + lazy 4KB split
- [x] MSR bitmap (only IA32_FEATURE_CONTROL intercepted)
- [x] Self-hiding (EptHideRange on g_CtxArray, MsrBitmap, IoBitmaps)
- [x] MBEC (Mode-Based Execute Control) in EPT
- [x] HV_CALL_SET_EPT_POLICY (0x05) — runtime EPT permission control
- [x] HV_CALL_LOCK_LSTAR (0x06) — LSTAR write enforcement
- [x] VmxIsolateInfrastructure — write-protect VMCS/VMXON/EPT/driver image pages
- [x] HV_CALL_WP_REGISTER (0x07) — runtime GPA write-protection from usermode
- [x] MBEC user-execute guardrail in HandleEptViolation ([MBEC] events)
- [x] HvBridge.dll — user-mode hypercall bridge (IssueHypercall + IssueHypercallRaw)
- [x] spectre/hv_client.py — Python HvClient + Sentinel commissioning entrypoint
- [x] resolver/Resolver.c — one-shot kernel driver writes sentinel_gpas.txt

---

## 1. IPI-driven INVEPT broadcast (coherency gap)

`EptInvalidate` currently runs on the calling core only. After `wp_register`
or `set_ept_policy`, other cores retain stale EPT TLB entries until their
next VM-exit.

Fix: after each `g_WpTable` insertion or EPT PTE change in the hypercall
handler, issue `KeIpiGenericCall` with a stub that calls
`EptInvalidate(g_Ept.Eptp)` on every core. The infrastructure
(`KeIpiGenericCall`) is already used in `VmxInitialize`.

---

## 2. IOCTL interface for usermode memory reads

`IOCTL_DISK_READ_MEMORY` and `KERNEL_READ_REQUEST` are defined in `Vmx.h` but
`IoControl` is not wired up in `Driver.c`. Implement:
- Register `IRP_MJ_DEVICE_CONTROL` in `DriverEntry`
- `IoControl` handler: validate request, read guest physical memory, copy to user buffer

---

## 3. Stealth memory reads via EPT remapping

Swap a target physical page's EPT entry to point at a shadow copy.
Guest (Windows + anti-cheat) sees the original; hypervisor reads the shadow.
- Add `EptRemapPage` / `EptRestorePage` helpers in `Ept.c`
- Wire into IOCTL handler: remap → read → restore → INVEPT

---

## 4. Sentinel target expansion

Add DayZ-specific GPAs to `g_Symbols[]` in `resolver/Resolver.c` once the
game process mapping is known:
- Target memory region base (overlay read target)
- Anti-cheat module pages (write-protect to detect tampering)

Requires the IOCTL interface (step 2) to map game VA → GPA.

---

## 5. Usermode ESP client

Small `.exe` that opens `\\.\DayZLink`, sends `KERNEL_READ_REQUEST` structs,
and parses DayZ game memory:
- Entity list walk
- Player coordinates / health
- Loot / vehicle positions

Depends on steps 2 and 3.

---

## Priority order

1 (IPI broadcast) is a standalone kernel fix — no dependencies.
2 must pass before 3, 3 before 5.
4 can be done in parallel with 2/3 once the IOCTL is stubbed.
