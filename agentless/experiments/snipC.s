# Snippet C: runs freely in guest ring 0. Reads, clears and rewrites DR0-3/DR6/DR7, then spins.
.code64
mov %dr7,%rax      # guest-visible DR7 before
mov %dr0,%rbx      # guest-visible DR0 before
xor %ecx,%ecx
mov %rcx,%dr7      # clear DR7
mov %rcx,%dr0      # clear DR0-3, DR6
mov %rcx,%dr1
mov %rcx,%dr2
mov %rcx,%dr3
mov %rcx,%dr6
mov %dr7,%rdx      # read back DR7
mov %dr0,%rsi      # read back DR0
mov $0x401,%rcx    # guest enables its own L0 (DR0=0)
mov %rcx,%dr7
mov %dr7,%rdi      # read back
xor %ecx,%ecx
mov %rcx,%dr7      # leave guest DR7 = 0 (no guest breakpoint left armed)
end: jmp end       # spin; a second hbreak sits here
