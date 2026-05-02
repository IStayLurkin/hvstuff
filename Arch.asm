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

    ; Call VmExitDispatch(ctx).  RCX already = ctx.
    ; Save ctx in RBX (non-volatile) across the call so we can reload after.
    mov  rbx, rcx
    sub  rsp, 20h
    call VmExitDispatch
    add  rsp, 20h
    mov  rcx, rbx                           ; reload ctx — RCX is volatile

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
    vmxoff
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
