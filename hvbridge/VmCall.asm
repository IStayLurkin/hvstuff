; VmCall.asm — MASM x64 stubs for issuing VMCALLs to the dayzdriv hypervisor.
;
; Hypercall ABI (Vmx.h):
;   RAX = hypercall ID
;   RBX = arg0
;   RCX = arg1
;   RAX on return = HV_STATUS_* code
;
; RBX is callee-saved per the Windows x64 ABI — preserved across both stubs.

.CODE

; AsmVmCall(Gpa, Policy) — hardcoded to HV_CALL_SET_EPT_POLICY (0x05).
; Windows x64 ABI: RCX = Gpa, RDX = Policy
AsmVmCall PROC
    push    rbx
    mov     rbx, rcx               ; arg0 (GPA)    -> RBX
    mov     rcx, rdx               ; arg1 (Policy) -> RCX
    mov     rax, 05h               ; HV_CALL_SET_EPT_POLICY
    db      0Fh, 01h, 0C1h         ; VMCALL
    pop     rbx
    ret
AsmVmCall ENDP

; AsmVmCallRaw(Id, Arg0, Arg1) — caller supplies the hypercall ID.
; Windows x64 ABI: RCX = Id, RDX = Arg0, R8 = Arg1
AsmVmCallRaw PROC
    push    rbx
    mov     rax, rcx               ; hypercall ID  -> RAX
    mov     rbx, rdx               ; arg0          -> RBX
    mov     rcx, r8                ; arg1          -> RCX
    db      0Fh, 01h, 0C1h         ; VMCALL
    pop     rbx
    ret
AsmVmCallRaw ENDP

END
