set pagination off
set confirm off
set architecture i386:x86-64
set breakpoint always-inserted on
target remote localhost:1240
restore agentless/experiments/snipD.bin binary 0x140d70
break *0x14100b
hbreak *0x140d99
hbreak *0x141791
define next_stop
  continue
  printf "STOP pc=0x%lx  (0x14100b=accept4 int3, 0x141791=recvfrom hbreak sentinel)\n", $pc
  if $pc == 0x14100b
    set $pc = 0x1364a0
  end
end
printf "== guest byte at 0x14100b with int3 inserted:\n"
monitor xp /1bx 0x14100b
printf "== PHASE 1: int3 on accept4 jmp, resume by emulating the jmp (no single-step)\n"
next_stop
next_stop
next_stop
next_stop
set $s_rax=$rax
set $s_rbx=$rbx
set $s_rcx=$rcx
set $s_rdx=$rdx
set $s_efl=$eflags
set $s_pc=$pc
set $pc=0x140d70
printf "== PHASE 2: guest snippet reads the trap byte and writes 0xe9 back (CR0.WP cleared)\n"
continue
printf "   snippet end pc=0x%lx\n", $pc
printf "   guest read trap byte  = 0x%x\n", $eax
printf "   guest read after write= 0x%x\n", $ebx
monitor xp /1bx 0x14100b
set $rax=$s_rax
set $rbx=$s_rbx
set $rcx=$s_rcx
set $rdx=$s_rdx
set $eflags=$s_efl
set $pc=$s_pc
printf "== PHASE 3: after guest removal; expect only recvfrom sentinel stops\n"
next_stop
next_stop
next_stop
next_stop
delete
monitor xp /1bx 0x14100b
detach
