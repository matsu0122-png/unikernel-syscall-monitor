set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1240
restore agentless/experiments/snipC.bin binary 0x140d70
hbreak *0x14100b
hbreak *0x140da2
printf "== PHASE 0: 2 hbreaks set (accept4 jmp, snippet end); waiting for accept4 (curl)\n"
continue
printf "== HIT1 pc=0x%lx (baseline)\n", $pc
set $s_rax=$rax
set $s_rbx=$rbx
set $s_rcx=$rcx
set $s_rdx=$rdx
set $s_rsi=$rsi
set $s_rdi=$rdi
set $s_efl=$eflags
set $pc=0x140d70
printf "== PHASE 1: guest runs snippet C freely (clears DR0-3/6/7)\n"
continue
printf "== HIT2 pc=0x%lx (expect 0x140da2: hbreak at snippet end fired after guest cleared DRs)\n", $pc
printf "   guest DR7 before        = 0x%lx\n", $rax
printf "   guest DR0 before        = 0x%lx\n", $rbx
printf "   guest DR7 after clear   = 0x%lx\n", $rdx
printf "   guest DR0 after clear   = 0x%lx\n", $rsi
printf "   guest DR7 after 0x401   = 0x%lx\n", $rdi
set $rax=$s_rax
set $rbx=$s_rbx
set $rcx=$s_rcx
set $rdx=$s_rdx
set $rsi=$s_rsi
set $rdi=$s_rdi
set $eflags=$s_efl
set $pc=0x14100b
delete 2
printf "== PHASE 2: resumed original accept4; waiting for further accept4 hits\n"
continue
printf "== HIT3 pc=0x%lx\n", $pc
continue
printf "== HIT4 pc=0x%lx\n", $pc
continue
printf "== HIT5 pc=0x%lx\n", $pc
delete
detach
printf "== detached\n"
