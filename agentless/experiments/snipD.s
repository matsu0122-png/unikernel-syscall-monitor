# Snippet D: ring-0 guest code. Reads the trap byte at the accept4 jmp, then writes the original opcode back.
.code64
movzbl 0x14100b,%eax   # guest view of trap byte
mov %cr0,%rcx
mov %rcx,%rdx
btr $16,%rcx           # clear CR0.WP so .text is writable from ring 0
mov %rcx,%cr0
movb $0xe9,0x14100b    # write the original opcode (jmp rel32) back
mov %rdx,%cr0          # restore CR0
movzbl 0x14100b,%ebx   # read back
end: jmp end
