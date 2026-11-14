set pagination off
set confirm off
set architecture i386:x86-64
target remote localhost:1240
hbreak *0x14100b
hbreak *0x140da2
continue
printf "== at accept4 pc=0x%lx\n", $pc
set $s_rax=$rax
set $s_rbx=$rbx
set $s_rcx=$rcx
set $s_rdx=$rdx
set $s_rsi=$rsi
set $s_rdi=$rdi
set $s_efl=$eflags
set $pc=0x140d70
delete 1
stepi
printf "step 1 -> pc=0x%lx\n", $pc
stepi
printf "step 2 -> pc=0x%lx\n", $pc
stepi
printf "step 3 -> pc=0x%lx\n", $pc
stepi
printf "step 4 -> pc=0x%lx\n", $pc
stepi
printf "step 5 -> pc=0x%lx\n", $pc
stepi
printf "step 6 -> pc=0x%lx\n", $pc
stepi
printf "step 7 -> pc=0x%lx\n", $pc
stepi
printf "step 8 -> pc=0x%lx\n", $pc
stepi
printf "step 9 -> pc=0x%lx\n", $pc
stepi
printf "step 10 -> pc=0x%lx\n", $pc
stepi
printf "step 11 -> pc=0x%lx\n", $pc
stepi
printf "step 12 -> pc=0x%lx\n", $pc
stepi
printf "step 13 -> pc=0x%lx\n", $pc
stepi
printf "step 14 -> pc=0x%lx\n", $pc
stepi
printf "step 15 -> pc=0x%lx\n", $pc
stepi
printf "step 16 -> pc=0x%lx\n", $pc
stepi
printf "step 17 -> pc=0x%lx\n", $pc
stepi
printf "step 18 -> pc=0x%lx\n", $pc
set $rax=$s_rax
set $rbx=$s_rbx
set $rcx=$s_rcx
set $rdx=$s_rdx
set $rsi=$s_rsi
set $rdi=$s_rdi
set $eflags=$s_efl
set $pc=0x14100b
delete
detach
