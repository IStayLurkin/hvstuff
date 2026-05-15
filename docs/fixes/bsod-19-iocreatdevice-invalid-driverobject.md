# BSOD #19 — 0x50 PAGE_FAULT in `nt!ObfReferenceObjectWithTag` (IoCreateDevice)

## Summary

`IoCreateDevice` was called with the mapper-supplied `DriverObject` before
`VmxInitialize`.  The Object Manager's reference-count path
(`ObfReferenceObjectWithTag`) validated the object header of that pointer, which
is not a real kernel object under kdmapper, and faulted.

---

## Crash details

| Field | Value |
|-------|-------|
| Stop code | `0x50 PAGE_FAULT_IN_NONPAGED_AREA` |
| Faulting module | `nt!ObfReferenceObjectWithTag` |
| Called from | `nt!IoCreateDevice` |
| Root cause | Mapper-supplied `DriverObject` passed to `IoCreateDevice` before VMX init |

### Call stack (reconstructed)

```
nt!ObfReferenceObjectWithTag
nt!IoCreateDevice
dayzdriv!DriverEntry
```

---

## Root cause

Under kdmapper (and RTCore-style manual mappers) `DriverEntry` receives a
`DriverObject` pointer that is **not** a real Windows kernel object.  It has no
`OBJECT_HEADER` prepended by `ObCreateObject`, so the Object Manager's
reference-count machinery (`ObfReferenceObjectWithTag`) faults when it tries to
walk the header.

The old `DriverEntry` called `IoCreateDevice(DriverObject, ...)` as its **first**
action — before `VmxInitialize` and before any safe fallback could absorb the
crash.

Two compounding problems:

1. **Order**: Object Manager API called before the hypervisor was resident.
2. **Invalid object**: Mapper pointer used as a `DRIVER_OBJECT` argument.

---

## Fix

**File:** `Driver.c` — `DriverEntry` rewritten.  
**File:** `Vmx.h` — two ntoskrnl exports declared.

### Step 1 — VMX first

`VmxInitialize()` is now the unconditional first call in `DriverEntry`.  The
hypervisor is resident on all cores before any Object Manager API is touched.
If VMX init fails, `DriverEntry` returns immediately with no I/O setup attempted.

### Step 2 — Borrow `\Driver\Null`

`IoCreateDevice` requires a `DRIVER_OBJECT` whose `OBJECT_HEADER` the Object
Manager can reference-count.  A raw pool block fails this check for the same
reason the mapper pointer does — it lacks an `ObCreateObject`-managed header.

Solution: call `ObReferenceObjectByName(L"\\Driver\\Null")` to obtain a genuine
kernel object.  `\Driver\Null` is always present, has no usermode-accessible
devices of its own, and the Object Manager accepts it unconditionally.

```c
UNICODE_STRING nullDrvName = RTL_CONSTANT_STRING(L"\\Driver\\Null");
PDRIVER_OBJECT borrowedDrv = NULL;
ObReferenceObjectByName(&nullDrvName, OBJ_CASE_INSENSITIVE, NULL, 0,
                        *IoDriverObjectType, KernelMode, NULL,
                        (PVOID *)&borrowedDrv);

IoCreateDevice(borrowedDrv, 0, &devName,
               FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);

ObDereferenceObject(borrowedDrv);  // device holds its own reference
```

### Step 3 — Patch MajorFunction after creation

After `IoCreateDevice` links the new device to `\Driver\Null`, the four dispatch
slots (`IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`, `IRP_MJ_POWER`)
are overwritten with our handlers.  `\Driver\Null` never handles these IRPs from
`\Device\DayZHV`, so there is no dispatch conflict.

### Step 4 — Global device pointer

The device object is tracked in `g_DeviceObject` (module global) instead of via
`DriverObject->DeviceObject`.  `DriverUnload` uses the global — it is fully
decoupled from whichever driver object the device ended up linked to.

### New declarations in `Vmx.h`

Both exports are present in `ntoskrnl.exe` but intentionally withheld from public
WDK headers:

```c
extern POBJECT_TYPE *IoDriverObjectType;

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes,
    PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID ParseContext, PVOID *Object);
```

---

## Expected next crashes

The IOCTL bridge and device object are now up.  Likely next failure points:

- **IRP dispatch on `\Driver\Null` slots** — if any IRP type we didn't patch
  falls through to Null's default handler, it will pend or complete incorrectly.
- **Power IRP path** — `DispatchPower` calls `PoStartNextPowerIrp` which may
  require the device to be in a PnP stack; a manually-mapped device is not.
- **DriverUnload never called** — kdmapper has no unload mechanism; teardown must
  be triggered via `IOCTL_HV_IPC_CALL` with `HV_IPC_TEARDOWN`, not via SCM.
- **`\Driver\Null` MajorFunction side-effects** — we patched Null's global
  dispatch table; if any other device attached to `\Driver\Null` expects the
  original handlers they will get ours instead.  Unlikely on a stock system but
  worth watching.

---

## Files changed

| File | Change |
|------|--------|
| `Driver.c` | `DriverEntry` rewritten: VMX-first ordering, `\Driver\Null` borrow, `g_DeviceObject` global, `DO_DEVICE_INITIALIZING` cleared explicitly |
| `Driver.c` | `DriverUnload` uses `g_DeviceObject` instead of `DriverObject->DeviceObject` |
| `Vmx.h` | `extern POBJECT_TYPE *IoDriverObjectType` + `ObReferenceObjectByName` prototype |
