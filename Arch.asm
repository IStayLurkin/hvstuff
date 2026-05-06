; ---------------------------------------------------------------------------
; Per-core context pointer array — defined in Vmx.c
; ---------------------------------------------------------------------------
EXTERNDEF g_CoreCtx:QWORD       ; PCORE_VMX_CONTEXT g_CoreCtx[64]
EXTERNDEF VmExitDispatch:PROC   ; void VmExitDispatch(PCORE_VMX_CONTEXT)

; CORE_VMX_CONTEXT field offsets — must match struct layout in Vmx.h
CTX_VMXON        EQU 00h    ; PVOID VmxonRegion
CTX_VMCS         EQU 08h    ; PVOID VmcsRegion
CTX_HOSTSTACK    EQU 10h    ; PVOID HostStack
CTX_GUESTSTACK   EQU 18h    ; PVOID GuestStack
CTX_RESUMERIP    EQU 20h    ; ULONG64 HostResumeRip
CTX_RESUMERSP    EQU 28h    ; ULONG64 HostResumeRsp
CTX_EXITREASON   EQU 30h    ; ULONG ExitReason
CTX_LAUNCHRESULT EQU 34h    ; ULONG LaunchResult
CTX_PASSED       EQU 38h    ; BOOLEAN Passed
CTX_EPTP         EQU 40h    ; ULONG64 Eptp
; CTX_SHADOWGDT   EQU 48h   ; PVOID ShadowGdt (not used in asm)
CTX_VMENTRYERROR EQU 50h    ; ULONG64 VmEntryError
CTX_GUESTRFLAGS  EQU 58h    ; ULONG64 GuestRflags
CTX_GUESTACTIVITY EQU 60h   ; ULONG64 GuestActivity
; New fields for resident hypervisor:
CTX_GUESTREGS    EQU 88h    ; GUEST_REGS (16 * 8 = 80h bytes)
CTX_TEARDOWN     EQU 108h   ; BOOLEAN TeardownPending
CTX_XSAVEAREA    EQU 178h   ; PVOID XSaveArea (64-byte-aligned buffer)
CTX_XSAVEMASK    EQU 188h   ; ULONG64 XSaveMask (EDX:EAX for XSAVEC/XRSTOR)
; Debug register shadow: GuestDr[0..7] at +138h (8 qwords).
; We save/restore DR0-DR3 and DR6 on every exit to isolate host breakpoints.
; DR7 lives in the VMCS GUEST_DR7 field and is loaded automatically by the CPU;
; we only touch it here when GuestDr[7] was updated by HandleDrAccess.
CTX_GUESTDR0     EQU 138h   ; GuestDr[0]
CTX_GUESTDR1     EQU 140h   ; GuestDr[1]
CTX_GUESTDR2     EQU 148h   ; GuestDr[2]
CTX_GUESTDR3     EQU 150h   ; GuestDr[3]
CTX_GUESTDR6     EQU 168h   ; GuestDr[6]
CTX_DRDIRTY      EQU 204h   ; BOOLEAN DrDirty

.code

; -----------------------------------------------------------------------
; AsmGetGdtBase / AsmGetGdtLimit
; -----------------------------------------------------------------------
AsmGetGdtBase proc
    sub  rsp, 16
    sgdt [rsp]          ; [rsp+0] = limit (2 bytes), [rsp+2] = base (8 bytes)
    mov  rax, [rsp+2]
    add  rsp, 16
    ret
AsmGetGdtBase endp

AsmGetGdtLimit proc
    sub  rsp, 16
    sgdt [rsp]
    movzx rax, word ptr [rsp]
    add  rsp, 16
    ret
AsmGetGdtLimit endp

; -----------------------------------------------------------------------
; AsmGetIdtBase / AsmGetIdtLimit
; -----------------------------------------------------------------------
AsmGetIdtBase proc
    sub  rsp, 16
    sidt [rsp]
    mov  rax, [rsp+2]
    add  rsp, 16
    ret
AsmGetIdtBase endp

AsmGetIdtLimit proc
    sub  rsp, 16
    sidt [rsp]
    movzx rax, word ptr [rsp]
    add  rsp, 16
    ret
AsmGetIdtLimit endp

; -----------------------------------------------------------------------
; Segment selector getters
; -----------------------------------------------------------------------
AsmGetCs proc
    mov ax, cs
    ret
AsmGetCs endp

AsmGetDs proc
    mov ax, ds
    ret
AsmGetDs endp

AsmGetEs proc
    mov ax, es
    ret
AsmGetEs endp

AsmGetSs proc
    mov ax, ss
    ret
AsmGetSs endp

AsmGetFs proc
    mov ax, fs
    ret
AsmGetFs endp

AsmGetGs proc
    mov ax, gs
    ret
AsmGetGs endp

AsmGetTr proc
    str ax
    ret
AsmGetTr endp

; -----------------------------------------------------------------------
; AsmGetLar(USHORT selector) -> ULONG
;   LAR loads the access rights from the GDT/LDT descriptor into the
;   destination register. Returns 0 in ZF=0 case (invalid selector).
;   Caller masks: (result >> 8) & 0xF0FF for VMCS access-rights format.
; -----------------------------------------------------------------------
AsmGetLar proc
    ; rcx = selector (first argument, Windows x64 ABI)
    lar  eax, ecx
    jz   lar_ok
    xor  eax, eax       ; invalid selector — return 0
lar_ok:
    ret
AsmGetLar endp

; -----------------------------------------------------------------------
; AsmGetLsl(USHORT selector) -> ULONG
;   LSL loads the segment limit. Returns 0 on invalid selector.
; -----------------------------------------------------------------------
AsmGetLsl proc
    ; rcx = selector
    lsl  eax, ecx
    jz   lsl_ok
    xor  eax, eax
lsl_ok:
    ret
AsmGetLsl endp

; -----------------------------------------------------------------------
; AsmGuestStub — guest entry point
;   Executes VMCALL to trigger a VM-exit, then halts as a safety net.
;   RIP is set to this label in GUEST_RIP.
; -----------------------------------------------------------------------
AsmGuestStub proc
    vmcall
    hlt                 ; should never reach here
AsmGuestStub endp

; -----------------------------------------------------------------------
; AsmLaunchAndReturn(ULONG64 HostRsp) — save continuation then VMLAUNCH.
;
;   RCX = HOST_RSP value (only used to satisfy the existing C signature;
;         the value is already written into VMCS_HOST_RSP by the C caller).
;
;   Resume RIP and RSP are stored in the non-paged C globals g_HostResumeRip
;   and g_HostResumeRsp (both in Vmx.c .data section, always non-paged).
;   AsmVmExitHandler reads them on VM-exit — no stack-slot addressing needed.
;
;   On success (VMLAUNCH transfers to guest), execution eventually resumes
;   at launch_resume after AsmVmExitHandler restores RSP and jumps there.
;   Returns 0 in RAX on the success path; CF|ZF (non-zero) on failure.
; -----------------------------------------------------------------------
; AsmLaunchAndReturn(ULONG64 HostRsp, PCORE_VMX_CONTEXT Ctx)
;   RCX = HostRsp (already written to VMCS by caller, not used here)
;   RDX = Ctx     (PCORE_VMX_CONTEXT — resume state written here before vmlaunch)
AsmLaunchAndReturn proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    sub  rsp, 20h                       ; shadow space

    ; Write host resume state into the per-core context struct.
    lea  rax, launch_resume
    mov  [rdx + CTX_RESUMERIP], rax     ; ctx->HostResumeRip = &launch_resume
    mov  [rdx + CTX_RESUMERSP], rsp     ; ctx->HostResumeRsp = current RSP

    ; Write GUEST_RSP and GUEST_RIP into VMCS immediately before vmlaunch so
    ; the captured values reflect the real kernel stack and continuation point.
    ; The guest resumes at vmlaunch_guest_rip with the live kernel RSP intact.
    mov  rax, 681Ch                     ; VMCS_GUEST_RSP field encoding
    vmwrite rax, rsp
    lea  rax, vmlaunch_guest_rip
    mov  rcx, 681Eh                     ; VMCS_GUEST_RIP field encoding
    vmwrite rcx, rax

    vmlaunch
    ; vmlaunch failed (CF=1 or ZF=1) — encode result in RAX (non-zero) and return.
    ; On success the CPU transitions to VMX non-root and the guest begins executing
    ; at vmlaunch_guest_rip below; this failure path is never reached on success.
    setc al
    movzx eax, al
    setz  cl
    or    al, cl
    jmp  vmlaunch_return

vmlaunch_guest_rip:
    ; Guest entry point after successful vmlaunch.
    ; RSP and all registers are exactly as they were before vmlaunch.
    ; Execution continues here inside VMX non-root as if vmlaunch was a no-op.
    ; Return 0 to VmxLaunchCore — signals successful launch, not a failure code.
    xor  eax, eax

vmlaunch_return:
    add  rsp, 20h
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret

launch_resume:
    ; AsmVmExitHandler restored RSP from ctx->HostResumeRsp (pointing here,
    ; after sub rsp,20h). Skip past shadow space before popping saved regs.
    add  rsp, 20h
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    xor  eax, eax                       ; return 0 = success path
    ret
AsmLaunchAndReturn endp

; -----------------------------------------------------------------------
; AsmVmExitHandler — host RIP after any VM-exit.
;   CPU loads HOST_RSP into RSP on every exit.  NO return address on stack.
;
;   Saves all guest GPRs into ctx->GuestRegs, reads exit reason, calls
;   VmExitDispatch(ctx), then either VMRESUMEs or VMXOFFs+jumps to
;   launch_resume depending on ctx->TeardownPending.
; -----------------------------------------------------------------------
AsmVmExitHandler proc
    ; RAX and RCX are used to get the ctx pointer — save them on the host
    ; stack first so we can restore them into GuestRegs after.
    push rax
    push rcx

    ; Get processor index from KPCR.Prcb.Number = gs:[1A4h].
    mov  eax, dword ptr gs:[1A4h]
    lea  rcx, g_CoreCtx
    mov  rcx, [rcx + rax*8]             ; rcx = PCORE_VMX_CONTEXT

    ; Save the pushed guest rax/rcx from stack into GuestRegs.
    pop  qword ptr [rcx + CTX_GUESTREGS + 8]   ; GuestRegs.Rcx
    pop  qword ptr [rcx + CTX_GUESTREGS + 0]   ; GuestRegs.Rax

    ; Save remaining GPRs.
    mov  [rcx + CTX_GUESTREGS + 10h], rdx
    mov  [rcx + CTX_GUESTREGS + 18h], rbx
    mov  [rcx + CTX_GUESTREGS + 28h], rbp
    mov  [rcx + CTX_GUESTREGS + 30h], rsi
    mov  [rcx + CTX_GUESTREGS + 38h], rdi
    mov  [rcx + CTX_GUESTREGS + 40h], r8
    mov  [rcx + CTX_GUESTREGS + 48h], r9
    mov  [rcx + CTX_GUESTREGS + 50h], r10
    mov  [rcx + CTX_GUESTREGS + 58h], r11
    mov  [rcx + CTX_GUESTREGS + 60h], r12
    mov  [rcx + CTX_GUESTREGS + 68h], r13
    mov  [rcx + CTX_GUESTREGS + 70h], r14
    mov  [rcx + CTX_GUESTREGS + 78h], r15

    ; GuestRegs.Rsp — read GUEST_RSP from VMCS (field 0x681C).
    mov  rdx, 681Ch
    vmread rax, rdx
    mov  [rcx + CTX_GUESTREGS + 20h], rax

    ; Read exit reason into ctx->ExitReason.
    mov  rdx, 4402h
    vmread rax, rdx
    mov  [rcx + CTX_EXITREASON], eax

    ; --- DR isolation: save host DRs on stack, load guest shadow into hardware --
    ; Keeps host-debugger breakpoints out of the VMX-root window and gives C
    ; code a clean DR6 status register (no stale #DB conditions from the host).
    ; DR7 is controlled by VMCS GUEST_DR7 — CPU loads/saves it automatically.
    ; Strategy:
    ;   1. Push host DR0-DR3 and DR6 onto the host stack.
    ;   2. Load guest shadow values from ctx->GuestDr[] into hardware.
    ;   3. After VmExitDispatch returns, read hardware DR0-DR3/DR6 back into
    ;      ctx->GuestDr[] (captures any writes the C handler made via WriteDr).
    ;   4. Pop host DRs back to hardware before VMRESUME.
    sub  rsp, 48h               ; 5 saved DRs (40h) + 8 bytes padding = 48h (keeps 16-byte alignment)
    mov  rax, dr0
    mov  [rsp + 00h], rax
    mov  rax, dr1
    mov  [rsp + 08h], rax
    mov  rax, dr2
    mov  [rsp + 10h], rax
    mov  rax, dr3
    mov  [rsp + 18h], rax
    mov  rax, dr6
    mov  [rsp + 20h], rax

    ; Load guest shadow DR0-DR3/DR6 into hardware.
    mov  rax, [rcx + CTX_GUESTDR0]
    mov  dr0, rax
    mov  rax, [rcx + CTX_GUESTDR1]
    mov  dr1, rax
    mov  rax, [rcx + CTX_GUESTDR2]
    mov  dr2, rax
    mov  rax, [rcx + CTX_GUESTDR3]
    mov  dr3, rax
    mov  rax, [rcx + CTX_GUESTDR6]
    mov  dr6, rax

    ; Save ctx in RBX (non-volatile) across the call so we can reload after.
    mov  rbx, rcx

    ; XSAVEC64 — save all guest user-extended state (XMM/YMM/ZMM/opmask/PKRU)
    ; before VmExitDispatch runs any C code that the compiler may vectorize.
    ; Skip if XSaveArea is NULL (XSAVE unavailable or not yet set up).
    mov  rdi, [rcx + CTX_XSAVEAREA]
    test rdi, rdi
    jz   dispatch_call

    ; Load EDX:EAX mask from ctx->XSaveMask (64-bit value, low=EAX, high=EDX).
    mov  rax, [rcx + CTX_XSAVEMASK]
    mov  rdx, rax
    shr  rdx, 32
    ; XSAVEC64 [rdi] — compacted save to 64-byte-aligned buffer.
    xsavec64 [rdi]

dispatch_call:
    sub  rsp, 20h
    call VmExitDispatch
    add  rsp, 20h
    mov  rcx, rbx                           ; reload ctx — RCX is volatile

    ; XRSTOR64 — restore guest extended state before VMRESUME.
    mov  rdi, [rcx + CTX_XSAVEAREA]
    test rdi, rdi
    jz   xrstor_skip

    mov  rax, [rcx + CTX_XSAVEMASK]
    mov  rdx, rax
    shr  rdx, 32
    xrstor64 [rdi]

xrstor_skip:

    ; --- DR isolation: flush hardware DR0-DR3/DR6 back to guest shadow ------
    ; If VmExitDispatch handled a DR-access exit it called WriteDr() which
    ; updated ctx->GuestDr[] directly — hardware was already loaded from shadow
    ; on entry, so reading back now is consistent regardless of exit reason.
    mov  rax, dr0
    mov  [rcx + CTX_GUESTDR0], rax
    mov  rax, dr1
    mov  [rcx + CTX_GUESTDR1], rax
    mov  rax, dr2
    mov  [rcx + CTX_GUESTDR2], rax
    mov  rax, dr3
    mov  [rcx + CTX_GUESTDR3], rax
    mov  rax, dr6
    mov  [rcx + CTX_GUESTDR6], rax

    ; Restore host DRs from the stack slot saved on entry.
    mov  rax, [rsp + 20h]
    mov  dr6, rax
    mov  rax, [rsp + 18h]
    mov  dr3, rax
    mov  rax, [rsp + 10h]
    mov  dr2, rax
    mov  rax, [rsp + 08h]
    mov  dr1, rax
    mov  rax, [rsp + 00h]
    mov  dr0, rax
    add  rsp, 48h               ; release the DR save area (matches sub rsp,48h on entry)

    ; Check TeardownPending.
    movzx eax, byte ptr [rcx + CTX_TEARDOWN]
    test  eax, eax
    jnz   do_teardown

    ; Restore guest GPRs and VMRESUME.
    mov  rax, [rcx + CTX_GUESTREGS + 0]
    mov  rdx, [rcx + CTX_GUESTREGS + 10h]
    mov  rbx, [rcx + CTX_GUESTREGS + 18h]
    mov  rbp, [rcx + CTX_GUESTREGS + 28h]
    mov  rsi, [rcx + CTX_GUESTREGS + 30h]
    mov  rdi, [rcx + CTX_GUESTREGS + 38h]
    mov  r8,  [rcx + CTX_GUESTREGS + 40h]
    mov  r9,  [rcx + CTX_GUESTREGS + 48h]
    mov  r10, [rcx + CTX_GUESTREGS + 50h]
    mov  r11, [rcx + CTX_GUESTREGS + 58h]
    mov  r12, [rcx + CTX_GUESTREGS + 60h]
    mov  r13, [rcx + CTX_GUESTREGS + 68h]
    mov  r14, [rcx + CTX_GUESTREGS + 70h]
    mov  r15, [rcx + CTX_GUESTREGS + 78h]
    mov  rcx, [rcx + CTX_GUESTREGS + 8]   ; restore rcx last (clobbers ctx ptr)
    vmresume
    ; vmresume failed — reload ctx and fall through to teardown.
    mov  eax, dword ptr gs:[1A4h]
    lea  rcx, g_CoreCtx
    mov  rcx, [rcx + rax*8]

do_teardown:
    ; RSP at this point is either:
    ;   (a) host pool stack + 48h DR frame live  (normal teardown CPUID exit)
    ;   (b) host pool stack + DR frame already released (vmresume failure fallthrough)
    ; In both cases CTX_RESUMERSP completely replaces RSP, so the host stack
    ; state is irrelevant — no kernel stack residue is possible.
    ;
    ; Guest RFLAGS lives in VMCS GUEST_RFLAGS and is never written to any stack;
    ; it evaporates when the VMCS is unloaded by vmxoff.  The kernel thread stack
    ; that launch_resume returns through is bit-for-bit identical to the state
    ; captured at vmlaunch time: 8 non-volatile pushes + shadow space = no residue.
    vmxoff
    ; Restore all non-volatile GPRs to the exact pre-vmlaunch values before
    ; returning to VmxLaunchCore.  RSP is set to the saved frame bottom;
    ; launch_resume will add rsp,20h (skip shadow), pop the 8 non-volatiles, ret.
    mov  rsp, qword ptr [rcx + CTX_RESUMERSP]
    jmp  qword ptr [rcx + CTX_RESUMERIP]
AsmVmExitHandler endp

; -----------------------------------------------------------------------
; AsmInveptSingleContext(ULONG64 Eptp)
;   Invalidates all EPT-derived TLB entries for the given EPTP.
;   Descriptor: { Eptp (8 bytes), Reserved=0 (8 bytes) } on stack.
;   INVEPT type 1 = single-context invalidation (Intel SDM Vol 3C 28.3.3).
; -----------------------------------------------------------------------
AsmInveptSingleContext proc
    ; RCX = Eptp
    push 0          ; Reserved (high qword)
    push rcx        ; Eptp    (low qword)
    mov  rcx, 1     ; type = 1 (single-context)
    invept rcx, oword ptr [rsp]
    add  rsp, 16
    ret
AsmInveptSingleContext endp

end
