# dayzdriv — BSOD Fix Reference

Quick-reference for every BSOD resolved during development.  
Full write-ups are in `docs/fixes/`.

---

| # | Stop Code | Short Description | Files Changed | Commit | Doc |
|---|-----------|-------------------|---------------|--------|-----|
| 13 | 0x1E KMODE_EXCEPTION | Pre-VMXON INVEPT raises #UD — INVEPT is only valid inside VMX operation | `Vmx.c` | `917d276` | [doc](docs/fixes/bsod-13-pre-vmxon-invept.md) |
| 14 | 0xD1 DRIVER_IRQL | Stale non-volatile regs on teardown — kernel stack reused by IPI while HV resident | `Arch.asm`, `Vmx.c`, `Vmx.h` | `4d7aa42` | [doc](docs/fixes/bsod-14-stale-nonvolatile-regs-teardown.md) |
| 15 | 0xA IRQL_NOT_LESS | Phase 2 pilot on wrong processor → NULL ctx → KPRCB corruption | `Vmx.c` | `1bdc30d` | [doc](docs/fixes/bsod-15-pilot-wrong-processor-null-ctx.md) |
| 16 | 0xA IRQL_NOT_LESS | IA32_KERNEL_GS_BASE not restored on VM-exit → NMI SWAPGS swaps to user-space GS | `Arch.asm`, `Vmx.c` | `c08b21b` | [doc](docs/fixes/bsod-17-kernel-gs-base-zero-system-threads.md) |
| 17 | 0xA IRQL_NOT_LESS | KERNEL_GS_BASE=0 on system threads — wrong MSR read at launch (saved user TEB, not KPCR) | `Arch.asm` | `c08b21b` | [doc](docs/fixes/bsod-17-kernel-gs-base-zero-system-threads.md) |
| 18 | 0x50 PAGE_FAULT | Manual-map launch: System PTEs not flushed to all P-core TLBs before Phase 3 IPI | `Vmx.c`, `Arch.asm` | `d2b8917` | [doc](docs/fixes/bsod-18-page-fault-manual-map-tlb.md) |
| 19 | 0x50 PAGE_FAULT | `IoCreateDevice` with mapper-supplied `DriverObject` faults in `ObfReferenceObjectWithTag` — borrow `\Driver\Null`; VMX-first ordering | `Driver.c`, `Vmx.h` | pending | [doc](docs/fixes/bsod-19-iocreatdevice-invalid-driverobject.md) |

---

## Build quick-reference

```
MSBuild dayzdriv.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `bin\dayzdriv.sys` (test-signed, SHA256)

### vcxproj fixes applied (2026-05-14)
- Added `Ept.c` and `Loader.c` to `<ClCompile>` (were missing → 10 LNK2019 errors)
- Added `<DriverSign><FileDigestAlgorithm>SHA256</FileDigestAlgorithm></DriverSign>` (WDK signtool /fd fix)

---

## Current known issues / next steps

### Build
- `build_dayz.bat` uses `G:\VS2022BT` (MSVC 14.38) for compile/link.
  The bat still works for the driver menu (start/stop/log/analyze) but its
  compile/link steps require that path to exist.
- `__pycache__` directories are gitignored but not purged. Run `git clean -fd`
  to remove them locally.
- `auto.cpp` (85 KB usermode overlay) lives at repo root and is gitignored.
  Remove manually when no longer needed.

### Likely next BSOD candidates (post-#19 fix)

- **IRP dispatch fallthrough** — we patched `\Driver\Null`'s global MajorFunction
  table for the four slots we handle.  Any IRP type we didn't patch falls through
  to Null's original (or zeroed) handler.  If the I/O manager sends an unexpected
  IRP type to `\Device\DayZHV`, it will likely bugcheck or silently pend.
- **Power IRP path** — `DispatchPower` calls `PoStartNextPowerIrp`.  A
  manually-mapped device is not in a PnP stack; power IRPs may never arrive,
  but if they do the completion path could fault.
- **DriverUnload never called by kdmapper** — teardown must be triggered via
  `IOCTL_HV_IPC_CALL` with `HV_IPC_TEARDOWN` before unloading.  SCM unload
  will not fire `DriverUnload` for a manually-mapped driver.
- **`\Driver\Null` dispatch side-effects** — we overwrote Null's global dispatch
  table entries.  Any other device currently attached to `\Driver\Null` will
  route those IRP types to our handlers.  Unlikely to matter on a stock system
  but could produce unexpected behaviour if `\Device\Null` is opened concurrently.
