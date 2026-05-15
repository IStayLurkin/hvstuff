# i9-14900K / MSI MAG Z790 — VMX Compatibility Notes

Platform: Intel Core i9-14900K (Raptor Lake), MSI MAG Z790, Windows 11 26100.

---

## Shadow GDT / IDT alignment — CONFIRMED OK (2026-05-15)

The diagnostic added in `VmxLaunchCore` logs the alignment of both the shadow
GDT base and the live IDT base before the IRQL raise.  On this platform:

- **Shadow GDT base**: 16-byte aligned (`OK(16B)`) — confirmed by `(shadowGdtBase & 0xF) == 0`
- **IDT base**: 16-byte aligned (`OK(16B)`) — confirmed by `(idtBase & 0xF) == 0`

Alignment is **not** the cause of the observed VMXON hang.  Both descriptors
meet the 16-byte boundary requirement that 14th-gen microcode appears to enforce
more strictly than earlier generations.

---

## Silent VMXON hang — root cause analysis

**Symptom:** Core hangs between the `[VMINSTR DIAG] >>> VMXON pending` sentinel
and the next log entry.  `LaunchResult` stays at `0xFB` (the pre-VMXON sentinel
value written in Phase A).  No BSOD, no `__vmx_on` return value recorded.

### Root cause 1: VBS / Hyper-V conflict (CR4.VMXE already set)

If Windows boots with `hypervisorlaunchtype` set to `auto` (the default on
systems with Secure Boot + TPM), the Windows Hypervisor Platform (VBS) owns VMX
root on every logical core.  `CR4.VMXE` is already 1 at the time our driver
issues VMXON.

The Intel SDM (Vol 3C §24.11.5) specifies that VMXON fails with VMfailInvalid
if the CPU is already in VMX root operation, but on Raptor Lake the failure is
**silent** — no `#GP`, no architectural indication.  The VMXON instruction
simply does not return.

**Mitigation added** (`VmxLaunchCore`, before Phase B):
```c
ULONG64 cr4Live = __readcr4();
if (cr4Live & CR4_VMXE) {
    HvLog("[VBS CONFLICT] CR4.VMXE already set ...");
    __vmx_off();
}
```
The `__vmx_off()` attempt may itself fail silently (we are not in VMX root), but
it ensures the architectural state machine is not stuck in a half-entered state
before we retry VMXON.

**Required system configuration to use this driver:**
```
bcdedit /set hypervisorlaunchtype off
```
Reboot required.  Verify with `systeminfo | findstr Hyper-V`.

### Root cause 2: CR4 write not serialized before VMXON

`MOV CR4, reg` is not listed as a serializing instruction in SDM Vol 3A §8.3.
On Raptor Lake with certain microcode revisions, the out-of-order engine may
fetch the VMXON opcode before the updated CR4 (with VMXE=1) is visible to the
instruction decoder.  VMXON with VMXE=0 produces a `#GP(0)` which, inside a
`cli` + `IPI_LEVEL` window, is lethal.

**Fix added** (`VmxLaunchCore`, Phase B, immediately after `__writecr4`):
```c
__writecr4(cr4WithVmxe);
int _ser[4];
__cpuid(_ser, 0);   // full pipeline serialization (SDM Vol 3A §8.3)
```
`CPUID` is a serializing instruction: it completes execution of all prior
instructions before executing and drains the store buffer.  This guarantees
that the VMXON microop sees `CR4.VMXE = 1`.

---

## MSR 0x480 (IA32_VMX_BASIC) — verified baseline (14900K)

```
IA32_VMX_BASIC (MSR 0x480) = 0x3DA050000000013
```

Field decode:

| Bits | Value | Meaning |
|------|-------|---------|
| [30:0] | `0x13` | VMCS revision identifier written to VMXON/VMCS regions |
| [44:32] | `0x1000` (4096) | VMCS size in bytes |
| [48] | `0` | VMCS/VMXON regions must be in 32-bit physical address space: NO |
| [49] | `1` | Dual-monitor treatment of SMI supported |
| [53:50] | `0x6` | Memory type for VMCS accesses: WB (write-back) |
| [54] | `1` | VM-exit info reports all INS/OUTS qualifying info |
| [55] | `1` | "TRUE" VMX controls supported (use TRUE MSRs 0x48E–0x491) |

This value must appear in `IA32_FEATURE_CONTROL` logging in `dayzdriv.log` when the driver loads successfully. If the VMCS revision ID written to the VMXON region does not match bits [30:0] = `0x13`, VMPTRLD will fail with CF set (VMfailInvalid).

---

## Platform-specific VMXON checklist

Before loading the driver on 14900K / Z790:

- [ ] Hyper-V disabled: `bcdedit /set hypervisorlaunchtype off` + reboot
- [ ] VBS disabled: `msinfo32` → "Virtualization-based security: Not enabled"
- [ ] WSL2 using WSL1 or `--no-virt` if needed (WSL2 requires Hyper-V)
- [ ] Credential Guard off (requires group policy or registry — see MSDN)
- [ ] Intel VT-x enabled in UEFI (Z790 MAG: Advanced → CPU Configuration → Intel VMX)
- [ ] **VT-d DISABLED** in UEFI (Z790 MAG: Advanced → CPU Configuration → Intel VT-d → Disabled). VT-d activates the IOMMU hypervisor layer; on Z790 Tomahawk firmware it occupies VMX root before our driver and causes a silent VMXON hang identical to the VBS conflict.
- [ ] Shadow GDT 16B aligned (logged as `OK(16B)` in dayzdriv.log)
- [ ] IDT base 16B aligned (logged as `OK(16B)` in dayzdriv.log)
