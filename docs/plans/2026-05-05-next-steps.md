# Next Steps

## Status snapshot (2026-05-05)

| Layer | State |
|---|---|
| VMX hypervisor (resident, 32-core) | Stable — 32/32 PASS, all known BSODs fixed |
| Python bridge (SpectreMemory / MemoryWorker) | Complete — 17/17 tests pass, wired into ESP loop |
| Manual PE loader (IOCTL_HV_LOAD_MODULE) | Built, signed — awaiting first hardware smoke test |
| Test signing mode | **OFF** — driver fails to start (error 577) |

---

## Step 1 — Enable test signing and smoke-test the loader

**Blocker:** `bcdedit /set testsigning on` + reboot required before `sc start dayz` will work.

After reboot (elevated):
```
sc create dayz binPath= "F:\vsprojs\dayzdriv\bin\dayzdriv.sys" type= kernel
sc start dayz
```

Then run the Python loader smoke test:
```
python F:\vsprojs\dayzdriv\tests\test_loader.py
```

Expected:
- `DeviceIoControl: ok=1  GetLastError=0x00000000`
- Kernel log (`logs\dayzdriv.log`) contains: `!!! Payload: DriverEntry called -- manual load succeeded`

If the loader smoke test fails, check the kernel log for the NTSTATUS from `ManualLoad` and trace from there.

---

## Step 2 — Wire payload into the hypervisor

Once `ManualLoad` is confirmed working, the payload can be loaded *after* `VmxInitialize` returns so it runs inside the VMX guest context. The flow:

1. `DriverEntry` calls `VmxInitialize` (launches guest on all cores)
2. `DriverEntry` calls `ManualLoad(payloadPath, &g_Payload)` — payload `DriverEntry` runs at PASSIVE_LEVEL in the now-virtualized kernel
3. `DriverUnload` calls `ManualUnload(&g_Payload)` before `VmxTeardown`

The payload communicates back via shared non-paged globals or a dedicated IOCTL.

---

## Step 3 — Payload capabilities

With a loaded payload running under the hypervisor, near-term options:

- **EPT hide** — payload marks its own pages UC/no-execute in the EPT so they're invisible to the guest OS page walker
- **VMCALL interface** — payload issues VMCALL to request services from the hypervisor (e.g. read physical memory, intercept MSR)
- **CR3 intercept** — hypervisor already has CR3-load exiting; payload can register a callback to observe process switches

Pick one to drive Step 3 scope.

---

## Step 4 — Harden the exit handler for unknown exit reasons

Currently `VmExitDispatch` default case sets `TeardownPending` — any unhandled exit reason tears down all cores. This is safe for smoke tests but fragile for a resident payload. Replace with a "re-inject and count" policy:

1. Read `VM_EXIT_INTR_INFO` — if it's a hardware exception, re-inject via `VM_ENTRY_INTR_INFO`
2. Increment a per-reason counter in a non-paged array
3. Only tear down if the same unhandled reason fires >N times in a row (indicates a loop)

---

## Pending cleanup

- `RtlPcToFileHeader` forward decl added to `Vmx.h` — verify it doesn't conflict if a future WDK update adds it to `ntddk.h` (just delete the line)
- `GuestStack` allocation in `CORE_VMX_CONTEXT` is retained but unused — safe to remove once resident hypervisor is confirmed stable across reboots
