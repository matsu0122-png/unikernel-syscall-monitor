# Phase 6 (investigation only): move syscall capture inside QEMU, remove GDB/RSP

Status: **investigation complete, no code changed yet**. This document is the
basis for review before implementation starts on the `dev` branch.

## 0. What was actually checked (evidence basis)

The running hypervisor is `/usr/bin/qemu-system-x86_64` (`QEMU emulator
version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.31)`). To cite real function/file
names instead of guessing, the *exact matching* source package was pulled
with `apt-get source qemu-system-x86` (deb-src was already configured) and
extracted to `qemu-6.2+dfsg/`. All file:line references below are against
that tree unless noted. `_ukplat_syscall`'s address was independently
re-confirmed (not assumed) via:

```
$ nm backup_verified_build/nginx_qemu-x86_64.dbg | grep ukplat_syscall
0000000000101000 T _ukplat_syscall
0000000000141a00 T ukplat_syscall_handler

$ readelf -sW backup_verified_build/nginx_qemu-x86_64.dbg | grep ukplat_syscall
3031: 0000000000101000  0 NOTYPE GLOBAL DEFAULT 1 _ukplat_syscall
```

`NOTYPE` confirms README's note that this is an assembly-only label with no
DWARF `debug_info` (hence `gdb.lookup_global_symbol()` fails and
`gdb.decode_line("*_ukplat_syscall")` is needed — Phase 2's bug fix).
`readelf -h`/`-l` on `nginx_qemu-x86_64` show `Elf file type: EXEC` (not
`DYN`/PIE), so this ELF virtual address *is* the runtime guest virtual
address — no relocation to account for. `0x101000` is confirmed, not
assumed, for this exact build.

Also checked and ruled out as a source: `/home/matsu/kvm-vmi/qemu` (a much
older QEMU 2.11.93 fork with its own `accel/kvm/vm-introspection.c`) —
read for context only, per the project's standing rule not to touch
`/home/matsu/kvm-vmi`. Not used as a citation source below; all citations
are from the version-matched `qemu-6.2+dfsg` tree.

## 1. Current path, traced through real QEMU source

Contrary to treating "QEMU gdbstub" as one black box, the actual call chain
splits into a generic KVM-accelerator layer (arch-independent) and a thin
RSP-protocol layer (`gdbstub.c`) that merely *calls* the former. This
matters a lot for the redesign (see §7).

```
kvm_vcpu_thread_fn()                          accel/kvm/kvm-accel-ops.c:27
  └─ kvm_cpu_exec(cpu)                        accel/kvm/kvm-all.c
       └─ ioctl(KVM_RUN)                      accel/kvm/kvm-all.c:2853
       └─ run->exit_reason == KVM_EXIT_DEBUG
            └─ kvm_arch_handle_exit()         target/i386/kvm/kvm.c:4755
                 case KVM_EXIT_DEBUG:          target/i386/kvm/kvm.c:4798
                 └─ kvm_handle_debug()         target/i386/kvm/kvm.c:4636
                      └─ kvm_find_sw_breakpoint(cs, arch_info->pc)
                                               accel/kvm/kvm-all.c:3156
                      └─ return EXCP_DEBUG
  └─ if (r == EXCP_DEBUG)
       └─ cpu_handle_guest_debug(cpu)         softmmu/cpus.c:294
            └─ gdb_set_stop_cpu(cpu)
            └─ qemu_system_debug_request()    softmmu/runstate.c:658
                 (STOPS THE WHOLE VM, waits for an external controller)
```

**Key finding**: `cpu_handle_guest_debug()` does not just pause the
faulting vCPU — it calls `qemu_system_debug_request()`, which requests a
full machine stop (`RUN_STATE_DEBUG`) and is designed around "an external
debugger will inspect state and issue commands next." This is *itself*
part of the overhead: it's not merely "GDB is slow," the stock in-tree
debug-exit handling is architecturally built to hand control to an
external RSP client, not to resume autonomously.

From there, `gdbstub.c` (a separate `GDBState` state machine driven by RSP
packets over the socket `attach_gdbstub.py` opened) does the rest, and
critically, **for the KVM accelerator it does not implement breakpoint
patching itself** — it delegates directly to the same generic API a
custom implementation would call:

```c
// gdbstub.c:1028
static int gdb_breakpoint_insert(int type, target_ulong addr, target_ulong len)
{
    ...
    if (kvm_enabled()) {
        return kvm_insert_breakpoint(gdbserver_state.c_cpu, addr, len, type);
    }
    ...
}
// gdbstub.c:1065 gdb_breakpoint_remove() mirrors this with kvm_remove_breakpoint()
```

The "restore original byte → single-step → reinsert → continue" sequence
that `monitor.py` currently *appears* to do as one atomic Python callback
is, in stock QEMU, actually **driven by the remote gdb client issuing four
separate RSP commands** (`z0` remove, `s` step, `Z0` reinsert, `c`
continue) — i.e. up to 4 additional socket round trips beyond the initial
stop notification and the register read (`g`). This is concrete evidence
for *why* the measured per-hit cost (~2–2.5ms, see README Phase 3) is
~1000x a bare VM-exit: it's not one round trip, it's a whole RSP session
per syscall.

## 2. Answers to the 9 investigation questions

### Q1. Where does QEMU receive `KVM_EXIT_DEBUG`?

`kvm_arch_handle_exit()`, `target/i386/kvm/kvm.c:4755`, `case
KVM_EXIT_DEBUG:` at line 4798, dispatching to `kvm_handle_debug()` (line
4636). This is called from the generic `kvm_cpu_exec()` exit-reason switch
in `accel/kvm/kvm-all.c`, itself called from the per-vCPU thread loop in
`accel/kvm/kvm-accel-ops.c:kvm_vcpu_thread_fn()` (line 27).

`kvm_handle_debug()` distinguishes our software breakpoint from hardware
watchpoints/single-step via `kvm_find_sw_breakpoint(cs, arch_info->pc)`
(`accel/kvm/kvm-all.c:3156`, a linked-list lookup over
`cpu->kvm_state->kvm_sw_breakpoints`) — this is the arch-independent
registry the same list `kvm_insert_breakpoint()`/`kvm_remove_breakpoint()`
maintain.

### Q2. How to read rax/rdi/rsi/rdx/r10/r8/r9/rip from QEMU

Registers are **not** automatically synced into QEMU's `CPUX86State` on
every KVM exit (see the gotcha in §4). Must explicitly call:

```
cpu_synchronize_state(cs)              softmmu/cpus.c:170
  → cpus_accel->synchronize_state(cpu) (accel ops vtable, KVM's is kvm_cpu_synchronize_state)
  → kvm_arch_get_registers(cs)         target/i386/kvm/kvm.c:4250
  → kvm_getput_regs(cpu, 0)            target/i386/kvm/kvm.c:2506
  → ioctl(KVM_GET_REGS)                fills cpu->env.regs[] / env->eip
```

After that, plain field reads on `X86CPU *cpu = X86_CPU(cs); CPUX86State
*env = &cpu->env;`:

| syscall ABI reg | QEMU field | evidence |
|---|---|---|
| rax | `env->regs[R_EAX]` | `R_EAX = 0` (target/i386/cpu.h:47) |
| rdi | `env->regs[R_EDI]` | `R_EDI = 7` (cpu.h:54) |
| rsi | `env->regs[R_ESI]` | `R_ESI = 6` (cpu.h:53) |
| rdx | `env->regs[R_EDX]` | `R_EDX = 2` (cpu.h:49) |
| r10 | `env->regs[10]` | `kvm_getput_regs` line "`kvm_getput_reg(&regs.r10, &env->regs[10], set)`" (kvm.c:2528) — no `R_R10`-style enum past R10 is used consistently in this file, raw index is what the code itself uses |
| r8  | `env->regs[8]`  | kvm.c:2526 |
| r9  | `env->regs[9]`  | kvm.c:2527 |
| rip | `env->eip` | cpu.h:1447, filled by `kvm_getput_reg(&regs.rip, &env->eip, set)` (kvm.c:2532) |

This is exactly the register set `monitor.py` already reads via gdb's `g`
packet — same values, just read in-process instead of over RSP.

### Q3. How to read/write guest memory at a guest virtual address

`cpu_memory_rw_debug(CPUState *cpu, target_ulong addr, void *ptr,
target_ulong len, bool is_write)` — defined in `softmmu/physmem.c:3459`
(the `CONFIG_USER_ONLY` variant in `cpu.c:393` is unused here since this
is full-system emulation). It resolves guest-virtual → guest-physical (via
the vCPU's own page tables) → host pointer into the mmap'd guest RAM
region, and does a debug-style read/write that works regardless of page
protection bits. This is *the same function the existing gdbstub-driven
breakpoint patch already uses* — see Q4.

### Q4. Saving the original byte and writing `0xCC`

Already implemented, arch-specific, and directly reusable as-is:

```c
// target/i386/kvm/kvm.c:4525
int kvm_arch_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    static const uint8_t int3 = 0xcc;
    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn, 1, 0) ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&int3, 1, 1)) {
        return -EINVAL;
    }
    return 0;
}
```

`struct kvm_sw_breakpoint { target_ulong pc; target_ulong saved_insn; int
use_count; QTAILQ_ENTRY(...) entry; }` (`include/sysemu/kvm.h:395`). The
removal counterpart (`kvm_arch_remove_sw_breakpoint`, kvm.c:4536)
re-reads the byte, checks it's still `0xcc` (defends against a second
breakpoint or guest self-modifying code races), and restores
`bp->saved_insn`.

The generic wrapper layer (`kvm_insert_breakpoint`/`kvm_remove_breakpoint`,
`accel/kvm/kvm-all.c:3204`/`3243`) additionally handles `use_count`
ref-counting (so double-insertion at the same address is safe) and
maintains the `cpu->kvm_state->kvm_sw_breakpoints` list that
`kvm_find_sw_breakpoint` (Q1) searches. **These generic functions are not
gdbstub-specific** — they can be called directly by new code with no
dependency on `gdbstub.c` at all.

### Q5. Step-over without GDB (restore → single-step → reinsert → resume)

All three primitives already exist as plain internal C functions, with no
RSP/GDBState involvement:

- Remove: `kvm_remove_breakpoint(cpu, addr, 1, GDB_BREAKPOINT_SW)` (kvm-all.c:3243)
- Single-step exactly one instruction: `cpu_single_step(cpu, 1)` (`cpu.c:344`) —
  this just does `cpu->singlestep_enabled = 1; kvm_update_guest_debug(cpu, 0);`
  which issues `ioctl(KVM_SET_GUEST_DEBUG)` with
  `KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP` added to `dbg.control`
  (`kvm_update_guest_debug`, kvm-all.c, reading `cpu->singlestep_enabled`).
  The vCPU then needs one more `kvm_cpu_exec()` iteration to actually
  execute the single step and re-trap.
- Reinsert: `kvm_insert_breakpoint(cpu, addr, 1, GDB_BREAKPOINT_SW)` (kvm-all.c:3204)
- Resume: just don't stop — fall through to the next loop iteration of
  `kvm_vcpu_thread_fn`'s `kvm_cpu_exec()` call.

**Important gotcha (not obvious from a surface read, worth flagging
explicitly):** `kvm_handle_debug()` returns the *same* `EXCP_DEBUG` value
for both "hit our `int3`" and "single-step-completion trap" — the
distinguishing bit (`arch_info->dr6 & DR6_BS`) is consumed *inside*
`kvm_handle_debug()` itself and not passed up to the caller. A custom
handler replacing/wrapping `cpu_handle_guest_debug()` needs its own small
piece of state (e.g. a per-CPU enum: `WAIT_FOR_BP_HIT` /
`WAIT_FOR_STEP_DONE`) to know which phase of the sequence it's in when the
next `EXCP_DEBUG` arrives, since the generic return value alone doesn't
say. This is a real implementation detail, not a formality.

**Locking note — corrected 2026-08-23 (see §6 addendum below for the
full re-check):** the original draft of this note claimed the BQL is
already held by the time `kvm_vcpu_thread_fn` sees `EXCP_DEBUG`. That is
true only *after* `kvm_cpu_exec()` returns (it does
`qemu_mutex_unlock_iothread()` right before entering its do-while loop,
and only reacquires the lock — `cpu_exec_end(cpu);
qemu_mutex_lock_iothread();` — after the loop exits). **Inside** the loop,
where `kvm_arch_handle_exit()`/`kvm_handle_debug()` actually run, the BQL
is generally *not* held — except that the `KVM_EXIT_DEBUG` case
specifically is one of the few exit-reason branches in
`kvm_arch_handle_exit()` that wraps itself with its own
`qemu_mutex_lock_iothread(); ... qemu_mutex_unlock_iothread();` pair
around the call to `kvm_handle_debug()`. So the lock *is* held for that
specific call — just via a different, narrower mechanism than originally
stated. See §6 for why this changes the recommended insertion point.
A replacement handler placed inside (or called synchronously from)
`kvm_handle_debug()` can safely call `cpu_memory_rw_debug`,
`cpu_synchronize_state`, and do log file I/O right there without extra
locking.

### Q6. `KVM_SET_GUEST_DEBUG` — routing `#BP` to QEMU instead of the guest

```c
// target/i386/kvm/kvm.c: kvm_arch_update_guest_debug()
if (kvm_sw_breakpoints_active(cpu)) {
    dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
}
```
applied via `kvm_update_guest_debug()` → `kvm_invoke_set_guest_debug()` →
`kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG, &dbg)` (`accel/kvm/kvm-all.c`).
`KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP` is exactly what makes KVM
report `#BP` as `KVM_EXIT_DEBUG` to userspace (QEMU) instead of injecting
it into the guest's IDT as a normal exception — confirmed by
`kvm_handle_debug()`'s own `else` branch: `/* pass to guest */
kvm_queue_exception(...)` only runs when `ret == 0`, i.e. when the trap
did *not* match a known breakpoint. This is already exactly what happens
today (the existing tool already relies on this, via gdbstub's call into
the same `kvm_update_guest_debug` path) — nothing new needs enabling here,
it's inherited automatically the moment any breakpoint is inserted through
`kvm_insert_breakpoint()`.

### Q7. Can gdbstub's existing implementation be reused?

Yes, directly, and cheaply — because gdbstub.c essentially isn't a
breakpoint implementation. As shown in §1, `gdb_breakpoint_insert/remove`
in `gdbstub.c` are ~10-line wrappers that call straight into
`kvm_insert_breakpoint`/`kvm_remove_breakpoint`. **The real logic to reuse
lives in `accel/kvm/kvm-all.c` and `target/i386/kvm/kvm.c`, not in
`gdbstub.c`.** The plan is to call those functions directly from new code
and never link the new path through `gdbstub.c`, `GDBState`, or any RSP
parsing at all — not "reimplement gdbstub's logic," but "stop going
through gdbstub to reach logic that was already independent of it."

### Q8. Direct QEMU patch vs. QEMU plugin

Checked concretely: QEMU's plugin instrumentation hooks
(`qemu_plugin_vcpu_insn_trans_cb` etc.) are wired only into
`accel/tcg/translator.c` and `accel/tcg/plugin-gen.c` — a
`grep -rn qemu_plugin accel/kvm/` returns nothing. QEMU's own docs title
the feature "TCG Plugins" and state "Any QEMU binary with TCG support has
plugins enabled by default," with no KVM equivalent. **This means the
plugin API is a dead end for this project**: it only fires when the guest
is running under QEMU's own TCG software emulator, not when
`accel=kvm` is in effect (which is what makes the baseline ~12,000 req/s
possible in the first place — falling back to TCG to get plugin hooks
would defeat the entire premise of measuring KVM-path overhead). So this
has to be a direct QEMU source patch; there is no lower-invasiveness
plugin alternative for the KVM accelerator.

### Q9. What overhead is removed vs. what remains

**Removed:**
- The `QEMU ↔ gdb` TCP/loopback socket entirely (no RSP text protocol,
  no second OS process, no scheduler round trip between two processes).
- The 4-round-trip RSP command sequence per hit (`g` register read, `z0`
  remove, `s` step, `Z0` reinsert, `c` continue) collapses into direct
  in-process C function calls within the same vCPU thread iteration.
- `qemu_system_debug_request()`'s full-VM-stop semantics
  (`cpu_handle_guest_debug`'s current behavior) — a custom handler resumes
  autonomously instead of parking the whole machine waiting for an
  external controller.
- Python interpreter overhead for the per-hit callback (`monitor.py`'s
  `stop()`), replaced by a plain C function.

**Stays (inherent to this mechanism, not this project's implementation):**
- The `int3` trap itself: `#BP` → VM-exit → `KVM_EXIT_DEBUG` → re-entry.
  This is the microsecond-scale hardware cost noted in the original
  overhead analysis and is unavoidable for *any* software-breakpoint-based
  approach, in-QEMU or not.
- The mandatory single-step-over-breakpoint sequence itself (remove →
  step → reinsert) still costs **two full `KVM_RUN` round trips per
  syscall hit** (one for the original trap, one for the single-step
  completion trap) — this is a property of software breakpoints on x86,
  not of using gdb. Removing gdb removes the *RSP session* around this,
  not the two VM-exits themselves.
- `cpu_memory_rw_debug()`'s cost (two calls per insert, two per remove) —
  cheap (direct host memory writes, see the earlier VMI-mechanics
  discussion) but not zero, and now called 4x more often per hit than
  before if step-over is implemented naively per-hit rather than batched.

**Expected outcome**: the ~95–99% throughput drop measured in Phase 3
should shrink substantially (the dominant cost — cross-process RSP round
trips, per README's own Phase 3 analysis — goes away), but a real,
non-zero cost tied to "one syscall = two VM-exits" remains. This should be
re-measured with `bench_overhead.py`'s existing methodology once
implemented, not assumed.

## 3. Before / after

```
現在 (今回調査した実際のコード上の経路)
Unikraft nginx
  → syscall → _ukplat_syscall → int3(0xCC)
  → #BP → VM-Exit → KVM_EXIT_DEBUG
  → kvm_arch_handle_exit/kvm_handle_debug (target/i386/kvm/kvm.c)
  → EXCP_DEBUG → cpu_handle_guest_debug (softmmu/cpus.c)
  → qemu_system_debug_request(): 仮想マシン全体を停止
  → gdbstub.c: RSPで外部gdbへ通知 (別プロセス, TCPソケット)
  → gdb: g(レジスタ読取) → monitor.py stop()コールバック → JSONLへ記録
  → gdb: z0(除去)→s(1命令step)→Z0(再設置)→c(再開)  ※4往復
  → QEMU → Guest再開

変更後 (本ドキュメントの設計)
Unikraft nginx
  → syscall → _ukplat_syscall → int3(0xCC)
  → #BP → VM-Exit → KVM_EXIT_DEBUG
  → kvm_arch_handle_exit/kvm_handle_debug (無変更で再利用)
  → EXCP_DEBUG → 【新設】自作ハンドラ (kvm_vcpu_thread_fn から呼び出し、
     cpu_handle_guest_debug の代わりに使う分岐)
       → cpu_synchronize_state() でレジスタ同期
       → env->regs[R_EAX/R_EDI/R_ESI/R_EDX/8/9/10], env->eip を直接読取
       → ログへ記録 (QEMUプロセス内、ソケットなし)
       → kvm_remove_breakpoint() → cpu_single_step(1) → 1命令実行待ち
       → cpu_single_step(0) → kvm_insert_breakpoint() で0xCC再設置
  → QEMU → Guest再開 (VM全体は一度も停止しない)
```

## 4. Concrete file/function change plan

| 項目 | ファイル | 関数 | 内容 |
|---|---|---|---|
| 分岐点 | `accel/kvm/kvm-accel-ops.c` | `kvm_vcpu_thread_fn()` | `r == EXCP_DEBUG` の分岐で、これが自作監視用ブレークポイントか判定し、該当すれば `cpu_handle_guest_debug()` を呼ばずに新設ハンドラへ渡す |
| **新設** | 新規ファイル、例: `accel/kvm/syscall-monitor.c` | `syscall_monitor_handle_debug(CPUState *cpu)` | レジスタ同期→記録→step-over一式を1関数にまとめる。`kvm_vcpu_thread_fn`から直接呼ぶ |
| int3設置処理 | 新設ハンドラ内 or 起動時1回 | `kvm_insert_breakpoint(cpu, addr, 1, GDB_BREAKPOINT_SW)` | 既存関数をそのまま呼ぶだけ(`accel/kvm/kvm-all.c:3204`)。新規コード不要 |
| KVM_EXIT_DEBUG処理 | `target/i386/kvm/kvm.c` | `kvm_handle_debug()` | **無変更**。`EXCP_DEBUG`の返却はそのまま利用 |
| レジスタ取得処理 | 新設ハンドラ内 | `cpu_synchronize_state(cs)` 呼び出し後 `env->regs[...]`/`env->eip` を直接参照 | 新規コードは数行(構造体フィールド読み取りのみ) |
| breakpoint step-over処理 | 新設ハンドラ内 | `kvm_remove_breakpoint()` → `cpu_single_step(cpu,1)` → (次のEXCP_DEBUGで) `cpu_single_step(cpu,0)` → `kvm_insert_breakpoint()` | **要:状態管理**(§2 Q5のgotcha) — 「ブレークポイントヒット待ち」と「step完了待ち」を区別する per-CPU フラグが新規に必要 |
| ログ出力処理 | 新設ハンドラ内 | JSONL相当を直接`fprintf`/`qemu_fopen`等でファイルへ | 既存`monitor.py`のJSON構築ロジックをCへ移植(構造は単純: ts, num, syscall名, args) |
| syscall番号→名前解決 | 新設 (小さな静的テーブル) | 該当なし | `syscall_table.py`のC版(185エントリの`static const`配列) |
| 起動時のアドレス指定 | `vl.c` または新規`-object`/コマンドライン引数 | 新規パース処理 | `_ukplat_syscall`のアドレス(`nm`/`readelf`で事前確認した値、本ドキュメント§0参照)を実行時に受け取る。QEMU内でDWARFレスELFシンボルを解決する仕組みは新規に作らず、既存ツールと同じ「外部で事前確認した値を渡す」方式を踏襲 |

## 5. Open risks / things to settle before implementing

1. **EXCP_DEBUG disambiguation state** (§2 Q5) — needs a small explicit
   state machine; not optional, the return value alone is insufficient.
2. Whether the "step-over" pair of `KVM_RUN` calls should happen
   **synchronously inside the same handler invocation** (call
   `kvm_cpu_exec()` again ourselves, recursively, before returning to
   `kvm_vcpu_thread_fn`) or by **falling through the normal loop** with
   the state flag persisting across iterations. The recursive approach is
   simpler to reason about but needs checking for reentrancy assumptions
   elsewhere in `kvm_cpu_exec` (e.g. `cpu_exec_start`/`cpu_exec_end`
   pairing) before committing to it.
3. This is a genuine QEMU source patch — no plugin path exists for KVM
   (Q8). Means: a rebuilt, non-stock `qemu-system-x86_64` becomes a build
   dependency for this tool. Worth deciding whether kraftkit can be
   pointed at a custom-built QEMU binary before investing in the patch
   (not yet checked — separate from this investigation's scope).
4. Re-measure with `bench_overhead.py` once implemented — §2 Q9's
   "expected outcome" is reasoned from the code, not measured yet.

No code has been changed for this investigation. All quoted paths/lines
are against `qemu-6.2+dfsg` (matching the installed
`1:6.2+dfsg-2ubuntu6.31` package), extracted via `apt-get source
qemu-system-x86`.

---

## 6. Addendum (2026-08-23): 6 follow-up questions, and the minimal-change design

This section answers six specific follow-ups asked before implementation,
and revises §4's plan to something substantially smaller. Still
investigation only — no code changed.

### 6.1 Exact call path: `kvm_handle_debug()` → `cpu_handle_guest_debug()` → `qemu_system_debug_request()`

Traced precisely, with the important nuance that the "VM stop" is
**asynchronous and decoupled from the vCPU thread**:

```
kvm_arch_handle_exit()                         target/i386/kvm/kvm.c:4798
  case KVM_EXIT_DEBUG:
    qemu_mutex_lock_iothread()
    ret = kvm_handle_debug(cpu, &run->debug.arch)   kvm.c:4636
      → kvm_find_sw_breakpoint() matches → ret = EXCP_DEBUG
    qemu_mutex_unlock_iothread()
  return ret   // EXCP_DEBUG, still inside kvm_cpu_exec's do-while

kvm_cpu_exec()'s do-while loop: ret != 0 → loop exits             kvm-all.c
  cpu_exec_end(cpu); qemu_mutex_lock_iothread();
  return EXCP_DEBUG   // back to kvm_vcpu_thread_fn, BQL now held

kvm_vcpu_thread_fn()                          accel/kvm/kvm-accel-ops.c:27
  r = kvm_cpu_exec(cpu);       // == EXCP_DEBUG
  if (r == EXCP_DEBUG) cpu_handle_guest_debug(cpu);     softmmu/cpus.c:294
      → gdb_set_stop_cpu(cpu)
      → qemu_system_debug_request()                 softmmu/runstate.c:658
           debug_requested = 1;
           qemu_notify_event();     // just sets a flag + wakes the main loop
      → cpu->stopped = true;
```

`qemu_system_debug_request()` itself does **not** call `vm_stop()`. It
only sets `debug_requested = 1` and pings the event loop. The actual stop
happens later, **in the main thread**, when it next polls
`main_loop_should_exit()` (`softmmu/runstate.c`):

```c
static bool main_loop_should_exit(void)
{
    if (qemu_debug_requested()) {
        vm_stop(RUN_STATE_DEBUG);   // → do_vm_stop() → pause_all_vcpus(), bdrv_flush_all(), ...
    }
    ...
}
```

**This is the key fact that answers §6.2**: nothing *else* independently
triggers this stop. It only happens if `cpu_handle_guest_debug()` (or
something that itself calls `qemu_system_debug_request()`/`vm_stop()`) is
actually invoked. If our code intercepts the exit *before* that call and
never makes it, `debug_requested` is never set, the main loop's next
`main_loop_should_exit()` check is a no-op, and the VM never stops.

### 6.2 Can KVM_EXIT_DEBUG be consumed without ever reaching `cpu_handle_guest_debug()`, without stopping the VM?

**Yes — and the natural place to do it is earlier than previously
proposed.** §4 of the original design (this document, above) proposed
intercepting at the `kvm_vcpu_thread_fn()` level (i.e., check `r ==
EXCP_DEBUG` there, and branch around `cpu_handle_guest_debug()`). Re-examining
the code makes a smaller, arch-local interception point clear:

`kvm_handle_debug()` (`target/i386/kvm/kvm.c:4636`) already has the
information needed — it just did `kvm_find_sw_breakpoint(cs,
arch_info->pc)` and knows the exact matched breakpoint. Instead of
returning `EXCP_DEBUG` unconditionally for *any* recognized software
breakpoint, add one check: if the matched breakpoint's address is our
syscall-monitor address, **do the register-read + log + step-over-begin
work right there, and return `0` instead of `EXCP_DEBUG`.**

Why `0` is safe and correct (not "pass to guest," despite `kvm_handle_debug`'s
existing `if (ret == 0) { ... kvm_queue_exception(...) }` branch which
reinjects the exception into the guest when nothing matched): that
reinjection branch is **only reached when nothing matched the trap at
all** (an unrecognized `#DB`/`#BP` — a real guest bug or unrelated
condition). For *our* breakpoint we return 0 from a dedicated branch that
does not fall into that `if (ret == 0)` block — it returns early, before
that check. `kvm_arch_handle_exit()`'s caller, `kvm_cpu_exec()`'s
`} while (ret == 0);`, treats a `0` return exactly like every other
"handled in place, keep looping" exit reason already in that same switch
(`KVM_EXIT_IO`, `KVM_EXIT_MMIO`, etc. all return `ret = 0` and loop) — so
this is not a special case we're inventing, it's using the loop's already
-intended mechanism. **`kvm_vcpu_thread_fn()` and `cpu_handle_guest_debug()`
are never reached for our breakpoint at all** — no VM stop, no gdbstub
involvement, no new code in `kvm-accel-ops.c` or `cpus.c` needed. This
shrinks the change from "new file + hook in the generic vCPU thread loop"
down to "one new branch inside one existing x86-specific function."

### 6.3 State to distinguish int3-hit vs. single-step-completion

Recommendation: a tiny **per-vCPU** (not global — must be per-`CPUState`,
since `kvm_find_sw_breakpoint`/the debug info are already per-CPU) two-
state enum, exactly as sketched in the question:

```c
enum { VMI_NORMAL = 0, VMI_STEPPING } vmi_state;   // one field, e.g. added
                                                    // to X86CPU or looked up
                                                    // by cpu->cpu_index in a
                                                    // small static array
```

Why this specific shape is the safe minimum, grounded in what
`kvm_handle_debug()` actually reports:

- `arch_info->exception == EXCP01_DB` + `arch_info->dr6 & DR6_BS` is how
  KVM already reports "this trap was a single-step completion, not a
  breakpoint" (`kvm.c:4636`, the `if (arch_info->exception == EXCP01_DB)`
  branch, separate from the `else if (kvm_find_sw_breakpoint(...))`
  branch used for `int3`). **This bit already exists in the exit info** —
  it doesn't need to be invented. But it only tells you "this was a
  single-step trap," not "this was *our* single-step" (if the guest, or
  something else, ever single-steps for an unrelated reason — not
  expected in this setup, but the state flag is what makes the code
  correct rather than coincidentally-correct).
- So the state machine reads as: on entry to the debug handler, if
  `vmi_state == VMI_NORMAL` and the trap matches our breakpoint address →
  do the read/log, remove the breakpoint, call `cpu_single_step(cpu, 1)`,
  set `vmi_state = VMI_STEPPING`, return 0. On the *next* debug exit, if
  `vmi_state == VMI_STEPPING` (confirmed by `dr6 & DR6_BS` as a sanity
  check, not the sole source of truth) → call `cpu_single_step(cpu, 0)`,
  reinsert the breakpoint, set `vmi_state = VMI_NORMAL`, return 0.
- Per-vCPU (not a bare global) because this design should not silently
  break if the target ever runs with >1 vCPU (this project's builds are
  single-worker/single-vCPU today per README, but the state should still
  be modeled correctly rather than relying on that).

### 6.4 Avoiding a recursive `KVM_RUN` for the single-step — confirmed to work via the existing loop

Checked concretely whether calling `cpu_single_step(cpu, 1)` **from
inside the vCPU's own thread** (which is exactly where our handler runs —
same thread as `kvm_cpu_exec`'s do-while loop) actually takes effect in
time for that loop's *next* iteration, without needing to call
`kvm_cpu_exec()` again ourselves:

```c
// cpu.c:344
void cpu_single_step(CPUState *cpu, int enabled) {
    if (cpu->singlestep_enabled != enabled) {
        cpu->singlestep_enabled = enabled;
        if (kvm_enabled()) kvm_update_guest_debug(cpu, 0);
        ...
    }
}
// kvm_update_guest_debug() → run_on_cpu(cpu, kvm_invoke_set_guest_debug, ...)
// softmmu/cpus.c:385      → do_run_on_cpu(cpu, func, data, &qemu_global_mutex)
// cpus-common.c:134
void do_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data, ...) {
    if (qemu_cpu_is_self(cpu)) {
        func(cpu, data);   // <-- called directly, synchronously, no queueing
        return;
    }
    ... /* queue_work_on_cpu + kick + wait, only for the cross-thread case */
}
```

Since our handler executes on the target vCPU's own thread,
`qemu_cpu_is_self(cpu)` is true, so `do_run_on_cpu` calls
`kvm_invoke_set_guest_debug` **directly and synchronously** —
`kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG, &dbg)` has already completed by
the time `cpu_single_step()` returns. No queueing, no cross-thread kick,
no deadlock risk. This confirms: it is safe and correct to call
`cpu_single_step(cpu, 1)` inside the handler and then simply `return 0`
— `kvm_cpu_exec()`'s existing do-while loop will call `KVM_RUN` again on
its own next iteration, that call will execute exactly one guest
instruction (the debug control is already armed), and it will re-trap
into the same handler. **No recursive `kvm_cpu_exec()`/`KVM_RUN` call is
needed anywhere in this design** — requirement #4 is satisfiable exactly
as asked, and this is now verified rather than assumed.

One thing worth flagging for the risk list rather than treated as solved:
`kvm_arch_pre_run(cpu, run)` runs once per loop iteration before every
`KVM_RUN` (handles NMI/SMI/INIT injection) — read in full, it does not
touch guest-debug state, so it doesn't interfere with the armed
single-step. No conflict found, but noted as checked rather than assumed.

### 6.5 Safe timing for the first `kvm_insert_breakpoint()` call

Phase 5's dead end (README, and `run_capture_from_boot.py`) was arming
during kraftkit's own `-S` (paused-at-reset) window: `x/8xb 0x101000`
showed the `0xCC` byte never actually got written, reproducibly, even
though the same write mechanism works fine once the guest is running.
The likely reason, now clearer from reading `cpu_memory_rw_debug`'s
reliance on the vCPU's *current* address-translation mode: at the literal
reset vector the CPU is in 16-bit real mode (`cs:ip`-based addressing, no
flat linear address space), so "guest virtual address 0x101000" is not
yet a meaningful concept in the same sense it is once the kernel has
reached its final (identity-mapped, per this build's non-PIE `EXEC` ELF
with matching `VirtAddr == PhysAddr` LOAD segments, confirmed in §0) address
space. Writing "virtual 0x101000" through `cpu_memory_rw_debug` while
still in that early real-mode context is exactly the kind of translation
mismatch that would silently fail to land where expected.

For Phase 6 (attach-after-boot model, same scope as today's
`run_capture.py` — **not** re-attempting Phase 5's from-boot capture),
the safe and idiomatic hook is `qemu_add_vm_change_state_handler()`
(`softmmu/runstate.c:309`), which fires via `vm_state_notify(1,
RUN_STATE_RUNNING)` (`softmmu/cpus.c:691`) exactly when the machine
transitions to the running state — an existing, widely used pattern
(`hw/display/qxl.c`, `hw/net/e1000e_core.c`, `hw/nvram/spapr_nvram.c`,
`hw/ppc/spapr.c` all register callbacks this way for "do this once the
VM is actually running"). Concretely: register a change-state callback at
machine-init time; when it fires with `running == 1`, call
`kvm_insert_breakpoint(first_cpu, ADDR, 1, GDB_BREAKPOINT_SW)` directly.

This is also strictly safer than the current external-gdb workflow in one
respect worth naming: it removes the race entirely, rather than winning
it. The current tool (and Phase 5's attempt) races an *external* process
against kraftkit's own resume over its own QMP connection. A change-state
handler is *internal* to this same QEMU process — it fires deterministically
on this process's own runstate transition, with no cross-process timing
window at all. (This still targets the same "attach shortly after boot,
not from the very first instruction" model as today's tool — reaching
back for Phase 5's true from-boot goal would still hit the real-mode
translation issue this section describes, unless the breakpoint byte is
patched into the ELF image before the loader copies it into guest RAM,
which is a materially different mechanism, out of scope here.)

### 6.6 Which QEMU binary does `kraft run` actually use, and is it replaceable?

Confirmed by two independent means:

- `ps aux` cross-referenced with `which qemu-system-x86_64` and the
  version string (`QEMU emulator version 6.2.0 (Debian
  1:6.2+dfsg-2ubuntu6.31)`) matching exactly the source package pulled in
  §0: the binary is `/usr/bin/qemu-system-x86_64`, resolved via `$PATH`
  since nothing overrides it today (`~/.config/kraftkit/config.yaml` has
  no `qemu:` key).
- `strings /usr/bin/kraft` contains the literal Go struct tag:
  `` Qemu`yaml:"qemu,omitempty" env:"KRAFTKIT_QEMU" long:"qemu" usage:"Path to QEMU executable" default:""` ``,
  and `kraft run --help` confirms the flag is live:
  `--qemu string   Path to QEMU executable`. Related strings
  (`could not prepare QEMU process`, `could not generate QEMU config`,
  `could not find any accelerators in QEMU binary`, `malformed return
  value cannot parse QEMU version`) confirm kraftkit execs whatever binary
  this points to and probes its `--version`/accelerator support at
  runtime — i.e. it doesn't hardcode `/usr/bin/qemu-system-x86_64`, it
  discovers/accepts a path.

**Yes, replaceable, no kraftkit source changes needed.** Three equivalent
ways to point `kraft run` at a custom-built QEMU binary, in order of
convenience for iterating on Phase 6:
1. Per-invocation: `kraft run --qemu /path/to/custom/qemu-system-x86_64 ...`
   (also usable from `run_capture.py` by adding `"--qemu",
   CUSTOM_QEMU_PATH` to its `kraft run` argv).
2. Per-shell: `KRAFTKIT_QEMU=/path/to/custom/qemu-system-x86_64 kraft run ...`
3. Persistent: add `qemu: /path/to/custom/qemu-system-x86_64` to
   `~/.config/kraftkit/config.yaml`.

The custom binary must still answer `--version` in a form kraftkit's
parser accepts (`"malformed return value cannot parse QEMU version"` is
the failure string if not) — trivial to satisfy since Phase 6's build
is the same `qemu-6.2+dfsg` source with a small patch, not a version bump.

## 7. Revised minimal design (supersedes §4's file/function table)

Given §6.2 and §6.5, the change is smaller than §4 originally proposed.
No new file, no change to `accel/kvm/kvm-accel-ops.c`, no change to
`softmmu/cpus.c`.

| 項目 | ファイル | 変更内容 |
|---|---|---|
| 起動時パラメータ受け取り | `softmmu/vl.c` (or a small new `.c` file, contributor's choice) | 新しいコマンドラインオプション(例 `-syscall-monitor addr=0x101000,log=/path`)を`QemuOptsList`で追加。既存の同種オプションと同じパターンを踏襲。2つの値を static 変数に保持するだけ |
| 起動完了フック | 同上、または起動処理を行う既存の小さな `.c` | `qemu_add_vm_change_state_handler()`登録。`running==1`で一度だけ`kvm_insert_breakpoint(first_cpu, addr, 1, GDB_BREAKPOINT_SW)`を呼ぶ |
| **唯一のホットパス変更** | `target/i386/kvm/kvm.c` | `kvm_handle_debug()`内、`else if (kvm_find_sw_breakpoint(cs, arch_info->pc))`分岐に、アドレス一致時の処理を追加: ①`cpu_synchronize_state(cs)` ②`env->regs[...]`/`env->eip`読み取り→ログ出力 ③`vmi_state`に応じて`kvm_remove_breakpoint`+`cpu_single_step(cs,1)`(NORMAL→STEPPING)、または`cpu_single_step(cs,0)`+`kvm_insert_breakpoint`(STEPPING→NORMAL) ④`return 0`(`EXCP_DEBUG`を返さない) |
| per-vCPU状態 | `target/i386/kvm/kvm.c` 内 static、または `CPUX86State`に1フィールド追加 | `vmi_state`(NORMAL/STEPPING) 2値の保持のみ |
| ログ出力 | 同上の新ブランチ内 | `syscall_table.py`相当の静的テーブル(C配列)+単純な`fprintf` |
| gdbstub / RSP / kvm-accel-ops.c / cpus.c | — | **無変更**。既存のgdbデバッグは今まで通り動作し続ける(共存可能) |

この設計の利点:
- 変更ファイルは実質2つ(`kvm.c`が本体、起動オプション用に`vl.c`か新規小ファイル)。
- ホットパスの変更は`kvm_handle_debug()`内の1分岐のみ — `kvm_cpu_exec`のdo-whileループの「`ret==0`なら継続」という既存の仕組みをそのまま使うため、ループ制御自体は無変更。
- gdbによる既存のデバッグ機能(および現行のgdb方式ツール)と共存可能 — `kvm_find_sw_breakpoint`のリストは共有だが、アドレスで分岐するため干渉しない。
- Phase 5の「起動直後からの捕捉」問題には触れない(§6.5で述べた通りreal-modeの翻訳問題は残るため、スコープ外のまま)。

## 8. Remaining risks specific to this revised design

1. `kvm_handle_debug()`は`X86CPU`ではなく`CPUState`ベースの汎用ヘルパー
   (`kvm_find_sw_breakpoint`等)を呼んでいるが、実際のレジスタ読み取り
   コードは`X86CPU`にキャストする必要がある(`kvm.c`内の他関数と同じ
   パターン`X86CPU *cpu = X86_CPU(cs);` — 変更が同一ファイル内なので
   大きな障害にはならない)。
2. `vmi_state`を保持する場所(`CPUX86State`に生フィールドを足すか、
   `kvm.c`内のstatic配列で`cpu->cpu_index`引きにするか)は実装時に
   決める — 後者の方が`cpu.h`のABI変更を避けられ、パッチとしてより
   局所的。
3. ログ書き込みが同期I/O(`fprintf`+`fflush`相当)である場合、
   BQL保持中に呼ばれる(§1で訂正した通りこの分岐はロック保持下)ため、
   ディスクI/Oが遅いとBQLを長く握ることになる — 現行の`monitor.py`も
   同様の同期書き込みをしているため後退ではないが、行のバッファリング
   方針(line-bufferedか、非同期キューに逃がすか)は実装時に決める。
4. §5にある通り、Q9の「削減効果」はまだ実測していない —
   実装後に`bench_overhead.py`で再計測する。
