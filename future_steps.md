# Future Steps — dayzdriv

Last updated: 2026-05-02

---

## 1. Verify resident hypervisor (blocker for everything else)

Run `build_dayz.bat → 1`. Confirm log ends with:
```
===== RESIDENT HYPERVISOR ACTIVE =====
```
If it fails, the 3-phase pipeline will log exactly which phase and field broke.

---

## 2. IOCTL interface for usermode memory reads

`IOCTL_DISK_READ_MEMORY` and `KERNEL_READ_REQUEST` are defined in `Vmx.h` but
`IoControl` is prototyped and never wired up in `Driver.c`. Implement:
- Register `IRP_MJ_DEVICE_CONTROL` in `DriverEntry`
- `IoControl` handler: validate request, read guest physical memory, copy to user buffer

---

## 3. Stealth memory reads via EPT remapping

Swap a target physical page's EPT entry to point at a shadow copy.
Guest (Windows + anti-cheat) sees the original; hypervisor reads the shadow.
- Add `EptRemapPage` / `EptRestorePage` helpers in `Ept.c`
- Wire into IOCTL handler: remap → read → restore → INVEPT

---

## 4. Usermode client

Small `.exe` that opens `\\.\DayZLink`, sends `KERNEL_READ_REQUEST` structs,
and parses DayZ game memory:
- Entity list walk
- Player coordinates / health
- Loot / vehicle positions

---

## Priority order

1 must pass before 2, 2 before 3, 3 before 4.
