# Logging Refactor — 2026-05-07

**Goal**: eliminate DebugView flooding, keep durable file log clean, and make failure
diagnostics immediately actionable without needing to dig through thousands of per-exit
lines.

---

## Problem Before

- `HvLog` (the durable file logger) also called `DbgPrint` on every write, so every lifecycle
  event appeared in both the log file and DebugView.
- ~70 raw `DbgPrint` calls fired on **every VM-exit** (RDMSR, WRMSR, CR access, EPT map,
  etc.) — thousands per second on a running guest.  DebugView was unusable.
- Unhandled VM-exits logged only a bare integer (`reason=48`) with no human-readable name
  and no core number.
- `LogCoreResult` for the probe phase printed `KgsBase=0x0` (expected since `AsmLaunchAndReturn`
  is never called in probe) — misleading noise.
- Pre-launch diagnostics (EFER, PAT, RFLAGS) were printed for every core even when all 32
  passed, adding ~96 lines of noise per successful run.

---

## Three-Tier Architecture

### Tier 1 — `HvLog` (durable file, no DebugView)

```c
void HvLog(const char *fmt, ...);
```

- Writes a timestamped line to `dayzdriv.log` via `ZwWriteFile`.
- **No** `DbgPrint` mirror.  File is the record of truth.
- Used for: driver load/unload, phase transitions, per-core pass/fail summary, teardown.
- Safe at PASSIVE_LEVEL (called from IRP dispatch and worker context only).

### Tier 2 — `HvLogDbg` (DebugView only, IRQL-safe)

```c
static void HvLogDbg(const char *fmt, ...);
```

- Calls `DbgPrint("DayZHV: %s\n", buf)` — visible in DebugView / WinDbg, never touches a
  file.
- Safe at any IRQL (no locks, no allocations, no I/O).
- Used for: unhandled VM-exit warnings, injection events, CR4 SMEP/SMAP modifications,
  hypercall dispatch, teardown per-core completion.  Infrequent events only.

### Tier 3 — `HV_VERBOSE_LOG` (compile-gated, per-exit spam)

```c
// #define HV_VERBOSE          ← uncomment to enable
#ifdef HV_VERBOSE
#define HV_VERBOSE_LOG(fmt, ...) DbgPrint("DayZHV: " fmt "\n", ##__VA_ARGS__)
#else
#define HV_VERBOSE_LOG(fmt, ...) ((void)0)
#endif
```

- Zero cost when `HV_VERBOSE` is not defined.
- Used for: RDMSR/WRMSR handler details, CR0/CR3/CR4 per-access, DR shadow, IO port, XSETBV,
  descriptor-table exits, EPT lazy-map, MTF step, #DB/#PF details, PMU, VMFUNC, per-core
  feature flags during init.
- Enable during active development or when tracing a specific exit type; leave off for
  production loads.

---

## Additional Improvements

### `ExitReasonName(ULONG reason)`

New helper function, ~70-entry switch table mapping Intel VM-exit reason codes to strings:

```c
static const char *ExitReasonName(ULONG reason);
// ExitReasonName(48) → "EPT_VIOLATION"
// ExitReasonName(10) → "CPUID"
// ExitReasonName(999) → "REASON_999"
```

Used in:
- Unhandled VM-exit log: `[UNHANDLED] core=02 reason=48 (EPT_VIOLATION) RIP=0xFFFFF...`
- `LogCoreResult` FAIL path: shows reason name alongside the integer.

### `LogCoreResult` split — probe vs launch

- **Probe phase** (`PROBE`): on pass, logs plain `OK` with no `KgsBase` field (it is always
  zero in probe since `AsmLaunchAndReturn` is never called — printing it was misleading).
- **Launch phase** (`PILOT` / `ALL`): on pass, logs `OK  KgsBase=0x<addr> (KPCR)`.  If the
  address is zero or in user-space range, that is an immediate diagnostic flag for the
  KERNEL_GS_BASE-class of bugs.

### Per-core pre-launch diagnostics on failure only

EFER, PAT, RFLAGS, KgsBase are only logged for cores that **fail** to launch.  Previously
printed for every core regardless of outcome, adding ~96 lines of noise per successful start.

---

## Files Changed

| File | Change |
|------|--------|
| `Vmx.c` | Added `HvLogDbg`, `HV_VERBOSE` / `HV_VERBOSE_LOG`; removed DbgPrint mirror from `HvLog`; added `ExitReasonName`; converted all ~70 raw DbgPrint calls to appropriate tier; updated `LogCoreResult` and pre-launch diag logic |
| `Ept.c` | Added `HV_VERBOSE` block at top; converted 4 DbgPrint calls to `HV_VERBOSE_LOG` |
