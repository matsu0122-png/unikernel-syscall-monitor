\
# Phase 1 manual proof-of-hook script (see plan: moonlit-kindling-dragon.md)
# Usage: gdb -q -nx -x phase1_manual_test.gdb
#
# Loads symbols from the .dbg build (NOT pushed to the remote target --
# `target remote` supplies the actual memory contents; `file` only tells
# gdb what the addresses mean). Confirmed this session that .text is
# identical address/size between the stripped and .dbg builds (no PIE),
# so this is safe.
file /home/matsu/catalog/library/nginx/1.25/.unikraft/build/nginx_qemu-x86_64.dbg
target remote localhost:1234

# Software breakpoint (int3 patch via gdbstub), NOT hbreak -- KVM's
# hardware breakpoint plumbing (KVM_SET_GUEST_DEBUG) has known upstream
# reliability bugs. Do not "optimize" this into hbreak.
break *_ukplat_syscall

commands
  printf "SYSCALL HIT: rax=%d rdi=0x%lx rsi=0x%lx rdx=0x%lx r10=0x%lx r8=0x%lx r9=0x%lx\n", $rax, $rdi, $rsi, $rdx, $r10, $r8, $r9
end

# Deliberately do NOT auto-continue in this manual test -- we want to stop
# and inspect register state by hand on the very first hit.
continue
