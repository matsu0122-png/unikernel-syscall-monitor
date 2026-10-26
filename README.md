# VMI syscall monitor for the Unikraft nginx unikernel

Research tool: agentless (VMI) syscall monitoring of the Unikraft-based
nginx unikernel in `../` (this repo's `qemu/x86_64` build), via QEMU's
GDB stub attached live over the kraftkit-managed HMP monitor socket.

Design and rationale: see `/home/matsu/.claude/plans/moonlit-kindling-dragon.md`.

## Status

- **Phase 1 (manual proof of hook): done.** See below.
- **Phase 2 (automated JSONL capture loop): done.** See below.
- **Phase 3 (overhead benchmark): done.** See below.
- **Phase 4 (ground-truth cross-check vs in-guest strace): done.** See below.
- **Phase 5 (capture from boot, not just after-the-fact attach): investigated, blocked.** See below. `legacy/run_capture.py` still only captures from whenever it attaches (a few seconds into an already-running guest); `legacy/run_capture_from_boot.py` documents why racing kraftkit's own boot sequence doesn't currently work.
- **Phase 6 (move capture inside QEMU, remove gdb/RSP): done.** See below. A patched QEMU (`legacy/qemu_patch/`) captures syscalls via a `KVM_EXIT_DEBUG` branch inside `kvm_handle_debug()` itself -- no external gdb process, no RSP protocol, no VM-wide debug-stop. ~90% throughput drop vs baseline (down from ~99% with the gdb/RSP mechanism) and, as a side effect, reliably captures from very early boot (Phase 5's original goal), because arming no longer depends on racing an external process against kraftkit's own resume.
- **Phase 7 (deterministic capture from the very first syscall): done.** See below. Roots-caused *why* Phase 6's boot-time capture was probabilistic (a one-shot QEMU-internal memory write, not an external race) and hooked that exact event (`fw_cfg_dma_transfer()` in `hw/nvram/fw_cfg.c`) instead of polling for it. 10/10 fresh boots captured an identical, deterministic 289-event sequence starting with the guest's actual first syscall, confirmed via an offset-0 exact match against Unikraft's own in-guest strace ground truth (134/134 comparable events identical). No measurable overhead change vs Phase 6.
- **Phase 8 (syscall return values): done.** See below. A second inline breakpoint at the `jmp *%rcx` that ends `_ukplat_syscall` reads `rax` on the way out, so each JSONL line now carries `ret` (plus `err`, e.g. `ENOENT`, for -errno results) and `dur_us`, in the same strace-style "after it returns" form as Unikraft's in-guest tracer. Throughput with entry + return capture is 6.4% of the unmonitored baseline (929 vs 14,501 req/s, mean of 5 alternating fresh-instance trials each); `--no-ret` restores Phase 6/7 entry-only behavior.
- **Phase 9 (overhead breakdown): done.** See below. Switches in the patched QEMU (`VMI_MONITOR_NO_REGS`/`NO_LOG`/`NO_DEBUGLOG`) remove one stage at a time. Of the ~104 us the monitor adds per syscall, ~90 us (~87%) is the trap mechanism alone (2 int3 + 2 single-step exits, remove/reinsert); register sync ~2 us, JSONL ~6.5 us, per-hit debug log ~5.4 us.
- **Phase 10-0 (investigation for an unmodified-QEMU design): done, no code yet.** See below and `docs/phase10_0_investigation.md`. Unikraft's own `uk_syscall_entertab_prio`/`uk_syscall_exittab_prio` hooks plus a distro-QEMU `memory-backend-file,share=on` give a host-readable view of guest RAM in which symbol address = file offset. Open design questions are listed before implementation starts.
- **Phase 10-1 (guest library `guest/lib-vmitrace`): done, smoke-tested.** See below and `docs/phase10_1_guest_library.md`. Records selected binary syscalls from syscall_shim's enter/exit hooks into a guest-RAM ring (no VM exit, overwrite when full), built from pinned local copies of Unikraft/lwip/libelf/elfloader with `tools/guest_build.py`. On the distro QEMU the ALL build's records start at `brk` and the per-request sequence and return values match Phase 8; the NET build records only the 16 NET syscalls.

## Phase 1 result

Hook point: `_ukplat_syscall` (`.unikraft/unikraft/plat/common/x86/syscall.S`),
the literal target of the guest's `syscall` instruction. At this address,
registers hold the raw Linux x86_64 syscall ABI: `rax`=number,
`rdi,rsi,rdx,r10,r8,r9`=args 1-6.

Steps that worked end to end:

```
kraft run -d -p 8080:80 --name vmitest .
python3 legacy/attach_gdbstub.py vmitest        # -> prints PORT=1234
gdb -q -nx -x legacy/phase1_manual_test.gdb     # attaches, sets breakpoint, waits
curl localhost:8080/                      # triggers a real syscall hit
```

First captured hit (single `curl`):

```
Breakpoint 1, _ukplat_syscall () at .../syscall.S:47
SYSCALL HIT: rax=96 rdi=0x1000182860 rsi=0x0 rdx=0x1 r10=0xffffffff r8=0x7 r9=0x401237260
```

`rax=96` is `__NR_gettimeofday` (confirmed against
`/usr/include/x86_64-linux-gnu/asm/unistd_64.h` and present as
`gettimeofday-2` in `.unikraft/build/libsyscall_shim/provided_syscalls.in`,
i.e. a 2-arg syscall). `rdi` is a pointer (the `struct timeval*`), `rsi=0`
(NULL `struct timezone*`) — exactly matches `gettimeofday(&tv, NULL)`.
Capture is correct.

## Phase 2 result

`syscall_table.py` (185/185 syscalls in `provided_syscalls.in` mapped to
their Linux x86_64 numbers via `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`
-- regenerate with the one-off script if the Kraftfile ever changes what's
provided), `legacy/monitor.py` (gdb-Python auto-continuing capture), and
`legacy/run_capture.py` (orchestrator: start/attach -> capture for a duration ->
detach -> stop+remove -> report) all work end to end:

```
python3 legacy/run_capture.py --name vmicapture --duration 15 --log logs/capture.jsonl
```

While that ran, 3 `curl localhost:8080/` requests produced 53 JSONL events
with exactly the syscall shape expected of nginx serving 3 static-file
requests: `accept4`x3, `epoll_ctl`x3, `recvfrom`x6, `openat`x1 +
`newfstatat`x1 + `pread64`x3 (open/stat/read the file), `writev`x3
(response), `close`x3, plus periodic `gettimeofday`/`clock_gettime`/
`epoll_wait` from the event loop. The instance was cleanly stopped and
removed afterward (`kraft ps -a` empty).

Two bugs found and fixed during this phase:
- `kraft ps -o json` (and `-l -o json`) prints literal `null`, not `[]`,
  when no instance is running -- `json.loads(...) or []` guards this in
  both `legacy/attach_gdbstub.py` and `legacy/run_capture.py`.
- `gdb.lookup_global_symbol()` cannot find `_ukplat_syscall` because it's
  an assembly-only label with no DWARF debug_info (searches DWARF only).
  Fixed by using `gdb.decode_line("*_ukplat_syscall")` to validate/resolve
  the same way the CLI's `break` command does (which works on plain ELF
  symbols too) instead of the Python symbol-lookup API.

## Phase 3 result

`legacy/bench_overhead.py` runs `ab` A/B (baseline: no gdbstub; monitored: VMI
breakpoint active on every syscall) against the *same* running instance,
switching conditions by attaching/detaching the gdbstub mid-run rather than
rebooting between conditions:

```
python3 legacy/bench_overhead.py --name vmibench --reps 5 --requests 500 --concurrency 5
```

Reproducible result across independent runs (~-98.8%, -98.9%, -95.5% on
three separate runs at different scales):

| condition            | requests/sec        | mean latency | p50    | p99      |
|----------------------|---------------------:|-------------:|-------:|---------:|
| baseline (no gdbstub)| ~11,900-12,800       | ~0.4 ms      | ~0 ms  | ~0.6-1 ms|
| monitored (VMI active)| ~120-134            | ~37-42 ms    | ~28 ms | ~33-1048 ms (see caveat below) |

**Throughput drops ~95-99% under this VMI mechanism.** This is the
concrete "real-time" cost of software-breakpoint-based syscall
interception (int3 -> KVM exit -> QEMU gdbstub round trip -> Python
callback -> continue) on *every single syscall* -- expected given nginx's
event loop issues several syscalls per request (see Phase 2's per-request
breakdown), each one now paying a full VM-exit-and-back round trip. This
is the key quantitative answer to the "how real-time can this be"
question motivating the project: workable for research capture/analysis,
not workable as an always-on production instrumentation approach without
a fundamentally lower-overhead mechanism (filtering to fewer syscalls of
interest via `VMI_INCLUDE_NRS`, or a future non-breakpoint approach).

**Unrelated but important discovery made while tuning benchmark scale:**
this Unikraft nginx build (64M memory, single worker) crashes outright
under sustained load -- observed twice, both times in the *unmonitored*
baseline condition (so unrelated to VMI overhead), consistently after
roughly **~1500-1700 cumulative HTTP requests** regardless of how they're
batched (one `ab -n 2000 -c 10` run died at 1614 requests; a `5x500`
sequence died on rep 4). Guest crash dump showed `orig_rax: 2` (`open`)
in progress, with large heap-like addresses in several registers --
consistent with a resource leak (likely fd- or ramfs/vfscore-related,
since nginx does `open`/`pread64`/`close` per static-file request) that
eventually exhausts something. `legacy/bench_overhead.py` now tolerates a failed
rep instead of losing all data, and defaults to a scale (500 req total
per condition) confirmed to stay under this threshold. Root-causing the
leak itself is out of scope here but is a real finding worth a separate
investigation -- possibly discoverable *with this same VMI tool* by
watching for `open` calls without matching `close`.

**p99 latency caveat**: one monitored run showed a 1048ms p99 outlier
(others were ~30-33ms) -- likely `ab`/scheduler jitter on a shared host
rather than a property of the mechanism itself; worth a larger-N rerun
before treating that specific number as characteristic.

**Process-management lesson learned this phase**: launching a background
command with both a trailing shell `&` *and* the tool's own
background-execution flag double-backgrounds it -- the tool's
"completed" notification fires for the outer shell's immediate return,
not the actual work, which keeps running detached and unsupervised. Don't
combine the two; use one or the other.

## Phase 4 result

`validate_strace.py` diffs the VMI-captured syscall *name* sequence
against Unikraft's own in-guest `CONFIG_LIBSYSCALL_SHIM_STRACE` output for
the same workload (one `curl localhost:8080/`), ignoring timestamps/arg
formatting:

```
python3 validate_strace.py --vmi logs/capture.jsonl --strace logs/strace_ground_truth.log
```

Method: temporarily uncommented `CONFIG_LIBSYSCALL_SHIM_STRACE` in the
Kraftfile, rebuilt, ran one `curl` and saved the in-guest console log as
ground truth (`logs/strace_ground_truth.log`), then **restored the
original verified binary from a pre-made backup** (`backup_verified_build/`,
md5-confirmed identical, not just Kraftfile-reverted-and-rebuilt) and ran
`legacy/run_capture.py` with the same single-`curl` workload for the VMI side.

Result: the strace ground truth has 307 syscalls (because it captures the
guest's *entire boot* -- ELF loading, dynamic linking of libc/libpcre/etc.,
nginx init, socket/bind/listen -- all of which happens before VMI attaches
a few seconds into the run) vs. 19 for the VMI capture. But the **last 18
of the 307 ground-truth syscalls are an exact, contiguous, in-order match**
for 18 of the 19 VMI-captured syscalls:

```
gettimeofday -> clock_gettime -> accept4 -> epoll_ctl -> epoll_wait ->
gettimeofday -> clock_gettime -> recvfrom -> openat -> newfstatat ->
pread64 -> writev -> setsockopt -> epoll_wait -> gettimeofday ->
clock_gettime -> recvfrom -> close
```

This is the actual apples-to-apples comparison (one HTTP request's worth
of syscalls) and it's a **perfect match** -- every syscall name, in the
correct order, with no gaps or extras, for the entire window where both
tools were observing. The "only in strace" ~289-syscall prefix is fully
explained by VMI attaching after boot, not a coverage gap in the tool
(the 1 VMI event *not* in that match is a trailing `epoll_wait` that
occurred after the ground-truth log capture window had already been
saved). **This confirms the VMI capture mechanism from Phases 1-2 is
correct**, not just plausible-looking.

## Phase 5 result (investigated, blocked)

Goal: capture syscalls from the guest's actual first instruction of boot,
not just from whenever `legacy/run_capture.py` happens to attach (which Phase 4
showed is several seconds and ~289 syscalls late).

Discovered that kraftkit launches QEMU with `-S` (paused at reset) and
only resumes it itself, over its own QMP connection, a short but
consistent **~90-100ms** after the monitor socket appears (measured
directly). `legacy/run_capture_from_boot.py` races that window: pre-load gdb's
debug symbols and pre-arm the syscall breakpoint as a *pending*
breakpoint (before any target is attached -- confirmed this works fine
in isolation, resolving purely off the symbol table) while `kraft run`'s
Docker/rootfs build is still in progress, then the instant `mon.sock`
appears, issue `gdbserver` over HMP and hand the port to the pre-loaded
gdb for `target remote` + `continue`. This reliably attaches while the
guest is still sitting at the literal CPU reset vector (gdb reports PC
`0xfff0`), before kraftkit's own resume ever fires.

Two problems found, one fixed:

- **Fixed:** publishing a host port (`-p 8080:80`) while resuming the
  guest via our own external gdb, during kraftkit's own management
  window, makes the whole `kraft run` command fail with a spurious
  `port 0.0.0.0:8080 is already in use by <name>` error and kill the
  instance it just spawned -- reproduced with a bisection down to a
  minimal case (plain `target remote` + `continue`, no breakpoint, no
  legacy/monitor.py at all). Confirmed by omission: the identical race without
  `-p` (no host port published) never fails. Root cause not identified
  beyond that scope (kraftkit's binary is stripped, no local source) --
  worked around by not publishing a port during this race.

- **Not fixed:** with the port issue out of the way, the guest boots
  successfully every time (confirmed reaching `ukplat_lcpu_halt_irq`,
  its idle loop) but **the syscall breakpoint never actually fires -- 0
  events, always**. Directly confirmed via `x/8xb 0x101000` (raw memory
  read at the breakpoint address) before and after a full boot: the
  original instruction bytes are there both times, never replaced with
  the `0xCC` trap byte, and `info breakpoints` shows no hit count.
  Reproduces identically with a plain CLI `break` command (not just
  legacy/monitor.py's Python `gdb.Breakpoint` subclass) and regardless of
  whether the breakpoint is set before or after `target remote` -- so
  it's not specific to this project's code. Giving the guest a head
  start before arming (tried 20ms and 150ms) didn't help either: RIP was
  identical (`0x52c`) in both cases, meaning wall-clock delay alone
  doesn't reach whatever state makes `0x101000` writable. Meanwhile
  attaching *after* kraftkit's own auto-resume (conceding the race)
  reliably lands on a guest that has *already* run past all boot
  syscalls -- this build's boot is fast enough to complete before any
  external process can react to the "running" state transition. Net
  effect: **there is currently no window where the breakpoint is both
  writable and still ahead of boot's syscalls**, using this external
  gdb-over-HMP mechanism.

For a full, reliable boot-to-request syscall trace *today*, use
Unikraft's own in-guest tracer instead of this tool's VMI mechanism:
uncomment `CONFIG_LIBSYSCALL_SHIM_STRACE` in the Kraftfile, rebuild, and
read the trace off the guest's console log -- this is how Phase 4's
ground-truth log was produced, and it isn't subject to any of the above.

## Phase 6 result

Investigation: `docs/phase6_inline_qemu_design.md` (traces the exact stock
QEMU 6.2.0 call path -- `kvm_arch_handle_exit()` ->
`kvm_handle_debug()` -> `cpu_handle_guest_debug()` ->
`qemu_system_debug_request()` -- and shows `gdbstub.c`'s breakpoint
handling is itself a thin wrapper over `kvm_insert_breakpoint()`/
`kvm_remove_breakpoint()`, i.e. logic already independent of gdb that new
code can call directly). Implementation: `legacy/qemu_patch/` (source-level
diff against the exact Debian-packaged QEMU 6.2.0 source, `apt-get
source qemu-system-x86` -- same version as the system binary this
project otherwise uses).

**Mechanism**: one new branch inside `kvm_handle_debug()`
(`target/i386/kvm/kvm.c`, x86-specific, ~40 lines) intercepts `int3` hits
at `_ukplat_syscall` before they ever reach `cpu_handle_guest_debug()` /
`qemu_system_debug_request()` (which is what makes stock QEMU stop the
*entire* VM and wait for an external debugger) -- returning `0` instead
of `EXCP_DEBUG` for this specific address makes `kvm_cpu_exec()`'s own
`while (ret == 0)` loop treat it exactly like any other in-place-handled
exit reason (`KVM_EXIT_IO`, `KVM_EXIT_MMIO`, ...) and re-enter `KVM_RUN`
immediately, with no VM stop and no external process involved at any
point. A per-vCPU state machine (`NORMAL` / `STEPPING`, keyed by
`CPUState*` in a `GHashTable`) drives the mandatory remove-original-byte
-> single-step -> reinsert-0xcc sequence across two `KVM_EXIT_DEBUG`
exits (confirmed: `cpu_single_step()` called from the vCPU's own thread
applies its `KVM_SET_GUEST_DEBUG` ioctl synchronously --
`do_run_on_cpu()`'s `qemu_cpu_is_self()` fast path -- so the *next*
iteration of `kvm_cpu_exec()`'s existing loop performs the actual step;
no recursive `kvm_cpu_exec()`/`KVM_RUN` call anywhere in this code).

**Breakpoint-arm verification (the direct Phase-5 lesson applied here)**:
`kvm_insert_breakpoint()` reporting success is not trusted alone --
every arm reads the byte back via `cpu_memory_rw_debug()` and requires
`0xcc`. This caught a real, new failure mode during development: arming
once at the first `RUN_STATE_RUNNING` transition (via
`qemu_add_vm_change_state_handler()`) read back as genuine `0xcc`
immediately, then was found reverted to the original byte (`0xfa`) a few
seconds later -- confirmed independently via a plain HMP `xp` physical-
memory read with no monitor code involved -- because this build's guest
boots through SeaBIOS -> iPXE -> chainload rather than jumping straight
to the kernel entry point, and something in that chain overwrites the
pre-staged kernel image bytes partway through boot. Fix: the arm/verify
step now keeps re-arming (idempotently: explicit `kvm_remove_breakpoint()`
before every `kvm_insert_breakpoint()`, since re-inserting at an address
KVM still considers registered is a silent no-op that skips the memory
write) every 200ms until a **real int3 hit** is observed, not just until
one readback succeeds -- proof of liveness, not a snapshot of it.

**Accuracy (checked before any performance measurement, per plan)**: a
single `curl` against the patched QEMU produced the exact same 19-event
syscall sequence, in the same order, with matching argument values, as a
live gdb/RSP capture run in the same session and as the sequence
documented in Phase 4 (`gettimeofday -> clock_gettime -> accept4 ->
epoll_ctl -> epoll_wait -> ... -> recvfrom -> close -> epoll_wait`).
Repeated hits, guest continuation after step-over, and HTTP completion
were all confirmed working before moving to benchmarking. As a side
effect (not the goal of this phase), the same run captured 289 syscalls
*before* the first `curl` was even sent -- because the breakpoint no
longer needs to win a race against kraftkit's own resume (it's armed
from inside this same QEMU process's own runstate callback, not an
external process attaching after the fact), this incidentally achieves
Phase 5's original goal too.

**Overhead** (`legacy/bench_overhead_inline.py`, 3 reps x 200 req, concurrency
5, three separate fresh instances -- ab-measured window excludes boot):

| condition | requests/sec | vs. baseline |
|---|---:|---:|
| A. baseline (custom QEMU, monitor disabled) | 15,267 | -- |
| B. inline monitor (this phase, no gdb) | 1,507 | -90.1% |
| C. gdb/RSP monitor (Phase 1-4 tool) | 132 | -99.1% |

Removing gdb/RSP/Python/the VM-wide debug-stop cuts the overhead from a
~99% throughput drop to a ~90% drop -- roughly **11x more throughput**
than the gdb-based mechanism under active monitoring. The remaining ~90%
is the cost inherent to software breakpoints on x86 regardless of who
handles the trap: every syscall still costs two full `KVM_RUN` round
trips (the `int3` trap itself, then the single-step-completion trap), and
that VM-exit/entry pair is not eliminated by moving the handler in-process
-- only the *externalization* of it (RSP round trips, a second OS
process, VM-wide pause) is.

**Design notes not obvious from a first read of the code, discovered
during implementation** (see `legacy/qemu_patch/README.md` for full build
instructions):
- The BQL is already held for the specific `KVM_EXIT_DEBUG` branch of
  `kvm_arch_handle_exit()` (it wraps that one case in its own
  `qemu_mutex_lock_iothread()`/`unlock` pair), even though it is *not*
  generally held elsewhere inside `kvm_cpu_exec()`'s exit loop -- so the
  new code's file I/O and memory patch calls need no extra locking, but
  this is a narrower guarantee than "the whole loop holds the BQL".
- `kraft run -d` daemonizes QEMU (`-daemonize` is in kraftkit's own qemu
  argv), which redirects the process's stdout/stderr to `/dev/null` once
  it forks into the background -- `error_report()`/`info_report()` alone
  are invisible for a detached instance. Diagnostics go to a second file
  (`<VMI_MONITOR_LOG>.debug.log`) opened before that happens instead.
- Building this project's QEMU from source (rather than using the distro
  package) needed `libslirp-dev` (for `-netdev user`, i.e. `-p` host-port
  publishing) and `--firmwarepath` pointed at this host's existing
  `seabios`/`ipxe-qemu` data files -- neither ships with a bare
  `./configure && ninja` build. `libslirp-dev` specifically wasn't
  installable without root in this environment; worked around by
  building `libslirp` from its own source into a local prefix and
  pointing `PKG_CONFIG_PATH` at it (fully documented in
  `legacy/qemu_patch/README.md`).
- `kraft run --qemu <path>` / `KRAFTKIT_QEMU` env var / `qemu:` in
  `~/.config/kraftkit/config.yaml` all point kraftkit at a custom-built
  QEMU binary -- no kraftkit source changes needed.

**Live terminal view (added after the initial Phase 6 implementation)**:
`legacy/run_capture_inline.py` now tails its own JSONL output file (a plain
Python re-implementation of `tail -f`, polling every 50ms) and prints
each event to the terminal as `[HH:MM:SS.mmm] name(args...)`, in
addition to writing the JSONL as before -- the two are not exclusive.
No change to the QEMU-side hot path (`vmi_monitor_breakpoint_hit()` in
`legacy/qemu_patch/target/i386/kvm/vmi-syscall-monitor.c`) was needed or made;
QEMU has no idea whether anything is reading the file it appends to.
Running with no `--duration` now waits for Ctrl-C instead of exiting
after a fixed time (`--duration N` still works exactly as before);
`--quiet` disables the terminal view (JSONL still written) for scripting
or for an apples-to-apples A/B against the live view; `--show-after-ready`
suppresses terminal output (not JSONL) until the first `accept4`, to
skip past a noisy boot without losing the boot-time events from the
file. A quick A/B (`ab -n 300 -c 5`, 2-3 reps each, same custom QEMU +
active monitor both times): quiet ~1417-1685 req/s vs. live-view
~1423-1527 req/s -- the two ranges overlap; any live-view overhead is
within this machine's run-to-run noise, not a clear, separate cost.

## Phase 7 result

Investigation: `docs/phase7_boot_sync_investigation.md`. Implementation
and verification: same doc's §13, plus `legacy/qemu_patch/` (`0003-fw_cfg.c.diff`,
updated `vmi-syscall-monitor.{c,h}`).

> **Correction (Phase 10-0)**: the "Root cause" paragraph below says the
> multiboot header has `MULTIBOOT_HEADER_HAS_ADDR` set. It doesn't. The
> booted image is an ELF32 wrapper with header `flags = 0x3`, so QEMU loads it
> via `load_elf()` + `rom_copy()`. Both paths stage the kernel into
> `FW_CFG_KERNEL_DATA`, so the fix and all Phase 7 results stand. The text is
> kept as written. See `docs/phase10_0_investigation.md` §2.

**Problem**: Phase 6's boot-time capture depended on winning a
200ms-interval polling race against boot -- it worked *sometimes*
(observed 0 to 289+ boot-time events, run to run) but never
guaranteed capturing the guest's actual first syscall.

**Root cause, found by reading the actual QEMU source this project
builds (not assumed)**: Unikraft's kernel image carries a multiboot
header (confirmed: magic `0x1BADB002` at file offset 52) with
`MULTIBOOT_HEADER_HAS_ADDR` set, so QEMU's `load_multiboot()`
(`hw/i386/multiboot.c`) stages the kernel bytes into the `fw_cfg` device
(selector `FW_CFG_KERNEL_DATA`) rather than writing them into guest RAM
itself. A tiny, `bootindex=0` option ROM (`multiboot_dma.bin` -- this
machine type has fw_cfg DMA enabled by default, confirmed against the
actual class defaults) issues one DMA request during SeaBIOS's
boot-order processing; QEMU's own `fw_cfg_dma_transfer()`
(`hw/nvram/fw_cfg.c`) is what actually performs the guest-RAM write, in
one synchronous, host-side C function call. A 0xcc planted before this
one-shot event is silently overwritten by it; one planted after never
is again.

**Fix**: hook that exact function. Right after
`fw_cfg_dma_transfer()`'s existing copy loop, if the just-completed
transfer was `FW_CFG_KERNEL_DATA` (and only that selector), call a new
`vmi_monitor_kernel_loaded()` (`target/i386/kvm/vmi-syscall-monitor.c`)
which arms and verifies the breakpoint right there -- reusing the same
remove/insert/readback logic Phase 6 already had (factored out into a
shared `vmi_arm_once()` helper, not duplicated). No vCPU pause/resume
dance is needed: this hook already runs synchronously on the vCPU's own
thread, inside the guest's own triggering MMIO/PIO exit, so there is no
window for the guest to run another instruction between "kernel bytes
just landed" and "0xcc is in place". The old 200ms polling loop is kept,
unmodified in behavior, as an automatic fallback -- it stands itself
down the moment boot-sync succeeds (in every observed run, within 3
polling attempts, ~600ms, before it could have mattered).

**Verified, not just implemented**:
- **10/10 fresh boots** armed via the deterministic path and captured an
  **identical** 289-event sequence starting with `brk` -- not just
  "usually", every single time in this environment.
- **Offset-0 ground-truth match**: compared against the existing Phase 4
  in-guest strace log (`CONFIG_LIBSYSCALL_SHIM_STRACE`) with a stricter
  bar than Phase 4 used -- element-by-element from index 0, not "longest
  match anywhere". **134/134 comparable events matched exactly, in
  order, from the very first syscall.** (The sequence "diverges" after
  that only because 3 syscall numbers aren't in this project's
  pre-existing name table and log as `syscall_N` instead of by name --
  the raw numbers still match; a small orthogonal gap, not a capture
  problem.)
- HTTP-request capture (the Phase 6 steady-state path, untouched by this
  change) still produces the exact same known-good per-request syscall
  pattern.
- Benchmark (`ab -n 300 -c 5`, 3 reps): 1407-1683 req/s, indistinguishable
  from Phase 6 alone (~1416-1685 req/s in earlier sessions) -- expected,
  since this only changes a few hundred milliseconds of one-time boot
  behavior, not the steady-state hot path.
- One genuinely unresolved detail, reported rather than hidden: the BQL
  (QEMU's global lock) was empirically found to be held at this hook's
  call site in every run, which doesn't match a literal reading of
  `kvm-all.c`'s "Called outside BQL" comments for this exit path; the
  code handles both cases correctly regardless (checks
  `qemu_mutex_iothread_locked()` and only locks if needed), so this
  doesn't affect correctness, but the precise reason for the discrepancy
  wasn't fully chased down.

## Phase 8 result

Goal: show whether each syscall actually succeeded, like Unikraft's
`CONFIG_LIBSYSCALL_SHIM_STRACE` output (`openat(...) = No such file or
directory (-2)`), not just that it was issued.

**Return hook**: `_ukplat_syscall` (`plat/common/x86/syscall.S`) ends in
`jmp *%rcx` (`0x1010da` in this build). At that instruction every
register has been popped back from the saved `struct __regs` and `%rax`
holds the return value. A second breakpoint there goes through exactly the
same in-QEMU int3 -> step-over -> reinsert path as the entry hook
(`vmi_monitor_is_hook_addr()`, with a per-vCPU record of which address is
being stepped over), and is armed and read back together with the entry
breakpoint by both the Phase 7 boot-sync path and the polling fallback.
`legacy/run_capture_inline.py` finds the address by disassembling from
`_ukplat_syscall` (`objdump`, first `jmp *%rcx`) and passes it as
`VMI_MONITOR_RET_ADDR`. If that variable is unset, QEMU behaves exactly
as in Phase 7.

**Entry/return pairing**: the entry is held (arguments + entry time) until
its return, matched on the application's `%rsp` and `%rcx`. Both are
identical at the two hooks: at entry they are the caller's stack and the
`syscall` return rip, and at exit syscall.S has restored exactly those.
Because of this, a blocking syscall stays correctly paired even if the
guest switches threads meanwhile, without assuming per-vCPU LIFO order.
Entries that never return (`exit_group`, or the `epoll_wait` blocked at VM
shutdown) are flushed on `RUN_STATE_SHUTDOWN` as `"ret": null,
"unfinished": "shutdown"`. The pending table holds 64 entries; if it ever
fills, the oldest is evicted and logged as unfinished.

**Log format** (one line per syscall, written when it *returns*, which is
the same ordering as Unikraft's own strace):

```json
{"ts": 1791770511.40, "cpu": 0, "rip": "0x101000", "num": 257, "syscall": "openat",
 "args": ["0xffffff9c", "0x1000181de0", "0x80000", "0x0"], "ret": -2, "err": "ENOENT", "dur_us": 58}
```

`ts` is still the entry time. `ret` is the signed 64-bit `rax`. `err` is
present only for -4095..-1 (the -errno range; names come from the host's
glibc, which is valid because the guest uses the Linux x86_64 errno ABI).
`dur_us` is entry-to-return wall time *including* monitoring overhead
(each hook costs ~50us here), so it is meaningful for long blocking calls
(`epoll_wait` showed 1.6s / 3.8s idle waits between curls) but not as a
precise per-syscall cost. Live view: `name(args) = -2 ENOENT (No such
file or directory)  <58us>`.

**Verified** (`--port 8081`, 3 curls): 339 events, 338 with a return
value plus 1 unfinished (the final blocked `epoll_wait`), and 0
unmatched returns in the debug log. Values agree with an in-guest strace
run of the same workload: the libcrypt search path is all `ENOENT` until
`newfstatat("/usr/lib") = 0`, `openat("/etc/ld.so.cache") = fd`,
`read(...) = 832` per ELF header, `connect(AF_UNIX) = ENOENT`,
`pread64 = 612`, `writev = 850` (0x352), and `recvfrom = 78`. The last one
is 77 in the strace run only because `localhost:8080` is one character
shorter than `localhost:8081` in the Host header. One expected difference:
`brk` returns real addresses here (`brk(0x402421000) = 0x402421000`)
whereas an older strace-enabled build showed `ENOSYS`; that build printed
brk in the generic, non-`HAVE_uk_syscall_brk` form, i.e. it did not provide
brk, while the current binary does (`brk-1` in `provided_syscalls.in`).

**Overhead** (re-measured 2026-10-13 with
`legacy/bench_overhead_inline.py --ret --alternate 5 --requests 300 --concurrency 5
--csv logs/bench_p8_ab.csv`):

- A = monitor off: patched QEMU, `VMI_MONITOR_*` unset.
- B = proposed method: same patched QEMU, `VMI_MONITOR_ADDR=0x101000` and
  `VMI_MONITOR_RET_ADDR=0x1010da`. Both addresses were resolved with
  `nm`/`objdump`, the same way `legacy/run_capture_inline.py` does it.
- Same QEMU binary, same unikernel image and same host for A and B.
- Trials run in the order A1,B1,A2,B2,...,A5,B5. Each trial boots a fresh
  instance, waits 3s, sends 50 warmup requests (discarded), then runs one
  `ab -n 300 -c 5 http://localhost:8080/`, so each instance sees 350
  requests in total, well under the ~1,500 at which it falls over.

| condition | n | req/s mean | stddev | min | max | vs A |
|---|---|---|---|---|---|---|
| A. monitor off | 5 | 14,500.8 | 2,195.0 | 11,205.7 | 16,860.6 | 100% |
| B. entry + return capture | 5 | 929.0 | 25.4 | 899.3 | 951.0 | **6.4%** |

Mean latency (ab "Time per request", mean): A 0.35 ms, B 5.39 ms. ab's
percentiles have only 1 ms resolution: A's p50/p99 are 0-1 ms, B's p50 is
4-5 ms and its p99 is 5-6 ms. 0 failed requests in all 10 trials. Raw
per-trial rows are in `logs/bench_p8_ab.csv`; full ab output, JSONL and
debug logs are in `logs/bench_p8_raw/`, which is not committed.

Monitor-validity check for B: all 5 trials are valid. Each trial had to
meet all of these:

- More than 0 JSONL events: 3,597-3,828 per trial.
- All events carry a return value except one unfinished `epoll_wait` at
  shutdown.
- Exactly 350 `accept4`, i.e. every warmup and measured request was seen.
- `readback=0xcc confirmed` for both hook addresses.
- No arm failure, `NOT 0xcc`, give-up or `no matching entry` lines in the
  debug log.

The event count varies between trials only in the
`epoll_wait`/`gettimeofday`/`clock_gettime` idle-loop counts. The
per-request syscalls (`accept4`, `recvfrom`, `writev`, `pread64`, ...)
are identical in every trial.

Caveats:

- A's run is very short: 300 requests take ~20-27 ms. That window is
  sensitive to host noise, which explains A's 15% coefficient of variation
  versus B's 2.7%. The host was not idle: a kind Kubernetes cluster and
  otel/MISP containers were running, and the CPU governor was
  `powersave`. A's absolute number is therefore the least certain figure
  here. The ~94% drop does not depend on it: even A's slowest trial is
  11.8x B's fastest.
- B's numbers include the debug log, which writes and flushes one line per
  hook hit. That is what Phase 8 does by default.
- The older figures (844-942 req/s with return capture, 1,358-1,632 with
  `--no-ret`) came from 3 reps on one instance, without alternation and
  without a same-session baseline. They are superseded by the table
  above. `--no-ret` was not re-measured in this run.

Environment:

- Host: Intel Core i7-9700K (8 cores / 8 threads, 3.6 GHz base, 4.9 GHz
  max), 15 GiB RAM.
- OS and kernel: Ubuntu 22.04.5 LTS, Linux 5.15.0-198-generic.
- QEMU: 6.2.0 with the patch in `legacy/qemu_patch/`, binary
  `/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64`.
- Tools: kraft 0.12.16, ApacheBench 2.3, guest image
  `.unikraft/build/nginx_qemu-x86_64`.

**Compatibility**: with return capture on, lines are in *completion*
order rather than entry order (identical for this single-threaded
workload), and an unfinished line may appear at the end. `validate_strace.py`
only reads `syscall` and is unaffected. `legacy/bench_overhead_inline.py`
sets `VMI_MONITOR_RET_ADDR` only with `--ret`; without it, it still
measures the entry-only mechanism.

## Phase 9: overhead breakdown

Goal: find out where the Phase 8 slowdown goes. Phase 8 ran at 6.4% of the
unmonitored throughput in `logs/bench_p8_ab.csv`.

**Switches** (QEMU side, `legacy/qemu_patch/target/i386/kvm/vmi-syscall-monitor.c`;
details in `legacy/qemu_patch/README.md`). Each one removes one stage from the
per-hit path, and with all of them unset the behavior is Phase 8's:

- `VMI_MONITOR_NO_REGS`: skip `cpu_synchronize_state()` and every register
  read. Skipping the sync also avoids writing the registers back before
  the next `KVM_RUN`.
- `VMI_MONITOR_NO_LOG`: no JSONL formatting or writing.
- `VMI_MONITOR_NO_DEBUGLOG`: no per-hit debug line.

Entry and return hits are always counted and written as one `[stats]`
line at shutdown, so every run can be checked for a live monitor.

**Conditions**: all use the same patched binary and image. C1-C4 arm both
hooks (0x101000 / 0x1010da).

| | switches | what runs per hook hit |
|---|---|---|
| C0 | `VMI_MONITOR_*` unset | nothing (monitor off) |
| C1 | NO_REGS + NO_LOG + NO_DEBUGLOG | trap -> remove -> single-step -> reinsert |
| C2 | NO_LOG + NO_DEBUGLOG | C1 + register sync/read, entry/return pairing |
| C3 | NO_DEBUGLOG | C2 + JSONL |
| C4 | none (= Phase 8) | C3 + per-hit debug log |

**Method**:

```
python3 legacy/bench_overhead_inline.py --breakdown 5 --requests 300 --concurrency 5 \
    --csv logs/bench_breakdown.csv
```

- 5 rounds, each in the order C0->C1->C2->C3->C4.
- Each trial boots a fresh instance, waits 3s, sends 50 warmup requests,
  then runs one `ab -n 300 -c 5`, so each instance sees 350 requests.
- Run on 2026-10-13, 02:24-02:26 JST.

**Validity**: all 25 trials are valid. Each trial had to meet these:

- C1-C4: `entry_hits` > 0 and `entry_hits - ret_hits` = 1 every time (the
  `epoll_wait` still blocked at shutdown).
- C2-C4: `ret_unmatched=0`.
- C3/C4: exactly 350 `accept4`, and the JSONL line count equals
  `entry_hits`.
- Both hooks confirmed armed, with no failure, `[error]` or
  `no matching entry` lines.
- 0 failed requests.

Raw rows are in `logs/bench_breakdown.csv`; ab output and logs are in
`logs/bench_breakdown_raw/`, which is not committed.

**Throughput**:

| | n | req/s mean | stddev | min | max | vs C0 |
|---|---|---|---|---|---|---|
| C0 off | 5 | 18,593.3 | 574.7 | 17,825.3 | 19,300.0 | 100% |
| C1 traps only | 5 | 1,041.6 | 40.2 | 1,009.0 | 1,093.4 | 5.60% |
| C2 + registers | 5 | 951.8 | 46.0 | 897.7 | 1,002.9 | 5.12% |
| C3 + JSONL | 5 | 917.3 | 68.1 | 868.4 | 1,020.1 | 4.93% |
| C4 + debug log (Phase 8) | 5 | 861.6 | 43.0 | 820.4 | 914.4 | 4.63% |

**Per-syscall cost**:

- Time per request is `1/(req/s)`.
- Syscalls per request is `(entry_hits - 291) / 350`. The 291 boot-time
  syscalls before the first `accept4` were identical in all 10 C3/C4
  JSONL logs, and 350 is the number of requests per instance (warmup +
  measured). The idle-loop syscalls between and after the two ab runs
  are not excluded.
- The average is 10.57 syscalls per request over C1-C4, with a per-trial
  range of 9.72-11.42.

Two ways to turn the time differences into a cost per syscall:

1. Divide the difference between condition means of time-per-request by
   the C1-C4 average syscalls per request.
2. Per trial, compute (time per request - C0 mean) / that trial's own
   syscalls per request, then average per condition.

| stage | method 1 | method 2 |
|---|---|---|
| C0->C1 trap mechanism | 907.3 us/req -> **85.9 us/syscall** | **90.0 +/- 1.2** |
| C1->C2 register sync/read | 91.5 us/req -> **8.7 us/syscall** | **1.7** |
| C2->C3 JSONL write | 42.1 us/req -> **4.0 us/syscall** | **6.5** |
| C3->C4 per-hit debug log | 68.2 us/req -> **6.5 us/syscall** | **5.4** |
| total C0->C4 | 1,109.1 us/req -> 105.0 us/syscall | 103.6 +/- 1.3 |

Cumulative overhead per syscall under method 2 is C1 90.0 +/- 1.2, C2
91.7 +/- 0.7, C3 98.2 +/- 2.0 and C4 103.6 +/- 1.3 us. Within a condition
these spread by only 1-2 us. Under method 1, by contrast, req/s spreads by
4-7% because it is driven by how many syscalls each trial happened to
make (see below). Method 2 is therefore the more reliable split. Both
methods agree on the main result: **the trap mechanism alone is ~86-90 of
the ~104 us per syscall (~87%)**. What the monitor does with the data
(register sync, JSONL and debug log) adds about 14 us, or ~13%.

Each syscall costs 4 VM exits to QEMU userspace (int3 + single-step at
both hooks), so C1's ~90 us is about 22 us per exit. That is far more than
a bare KVM exit. The likely causes, not measured individually here: each
step-over does `kvm_remove_breakpoint()` / `kvm_insert_breakpoint()`
(guest memory write + `KVM_SET_GUEST_DEBUG`), `cpu_single_step()` (another
`KVM_SET_GUEST_DEBUG`) and a readback verify. Reducing that path (e.g.
avoiding remove/single-step/reinsert per hit) is where any significant
speedup would have to come from. Logging-side optimizations can recover
at most ~13%.

**Caveats / anomalies**:

- *Syscalls per request vary between trials and correlate with req/s.* The
  difference is in the `epoll_wait`/`gettimeofday`/`clock_gettime` idle
  loop: how many connections one `epoll_wait` returns depends on timing.
  Examples: C3 round 4 had 3,708 hits and 1,020 req/s, against
  4,125-4,185 hits and ~870 req/s in the other C3 rounds; C2 rounds 2/4/5
  had 4,203-4,290 hits and 898-931 req/s. This is why C2-C4 overlap in
  req/s and why method 1's C1->C2 figure (8.7 us) is inflated. The C2
  trials happened to average more syscalls per request (10.89 vs C1's
  10.08), possibly because a slower handler batches less per
  `epoll_wait`.
- C0 has no hit counter, so its syscalls per request is not measured. The
  per-syscall figures assume the request path is the same; C0's 53.8 us
  per request is subtracted as a whole.
- The C4 (Phase 8) mean is 861.6 req/s, lower than `bench_p8_ab.csv`'s 929.0.
  Per syscall the two runs agree (~103 us in both). The earlier B trials
  just made fewer syscalls per request (3,597-3,828 events vs 3,819-4,185
  here).
- C0 is higher than in `bench_p8_ab.csv` (18,593 vs 14,501 req/s) and
  steadier (stddev 3.1% vs 15%), most likely because of the host changes
  below. The two runs' absolute numbers should not be mixed.

**Environment**:

- Host: Intel Core i7-9700K (8C/8T, 3.6 GHz base / 4.9 GHz max), 15 GiB
  RAM, Ubuntu 22.04.5 LTS, Linux 5.15.0-198-generic.
- QEMU 6.2.0 + `legacy/qemu_patch/`, rebuilt with the Phase 9 switches. The same
  binary was used for all conditions.
- Tools: kraft 0.12.16, ApacheBench 2.3.
- Host preparation: CPU governor `performance` on all 8 CPUs (default here
  is `powersave`). The 5 long-running containers (kind-control-plane,
  otel jaeger/collector/prometheus, misp-docker-db-1) were stopped for the
  run and restarted afterwards.
- Remaining load: CPU was ~100% idle before the run (`vmstat`). The load
  average was still ~2.0-2.35 because of a D-state
  `kworker/...acpi_thermal_pm` that uses no CPU. A second login session
  was open.

## Phase 10-0 result

Goal: check, before writing any code, whether syscall capture can move from
the patched QEMU to (a) a guest-side Unikraft library hooked into the
syscall shim and (b) a distro QEMU sharing guest RAM as a file. Full
citations: `docs/phase9_0_investigation.md`.

**What was done**: read the Unikraft 0.20.0 tree in `../.unikraft/unikraft`
and the QEMU 6.2 sources for the paths involved, and booted the verified
image (`backup_verified_build/` md5) once on the **unmodified**
`/usr/bin/qemu-system-x86_64` (6.2+dfsg-2ubuntu6.31) through a probe wrapper
that adds `-object memory-backend-file,...,mem-path=/dev/shm/vmiprobe.mem,share=on
-machine memory-backend=vmimem` (`kraft run --qemu <wrapper>`, port 8090).

**Confirmed**:

- Hooks: `uk_syscall_entertab_prio(fn, prio)` / `uk_syscall_exittab_prio(fn, prio)`
  place a `static const` function pointer in a linker-collected table; fn
  takes `struct uk_syscall_{enter,exit}_ctx *` (`execenv`, `nested_depth`,
  `flags`). These are static data, active from image load, so they see `brk`.
  At exit, `orig_rax`, the arguments and `rax` (= return value) are all in
  `execenv->regs`, the same values Unikraft's strace prints.
- The same tables also run for native in-kernel `uk_syscall_r_*` calls, with
  `execenv == NULL` and `flags == 0`. The hook must filter on
  `UK_SYSCALL_*_CTX_BINARY_SYSCALL`.
- TLS: `__thread` in the hook is Unikraft's per-thread TLS (switched before
  the enter table, back after the exit table), so a per-thread entry
  timestamp pairs correctly across blocking calls.
- `.bss` is zero before the first syscall: the image is an ELF32 multiboot
  wrapper whose header has no `HAS_ADDR`, so QEMU's ELF path builds the
  kernel buffer with `rom_copy()`, which zero-fills `p_memsz - p_filesz`.
  **This contradicts the Phase 7 doc's claim that `HAS_ADDR` is set.** Phase
  7's fix is unaffected, since both paths end in the same `FW_CFG_KERNEL_DATA`.
- Clock: `ukplat_monotonic_clock()` is `rdtsc` + multiply, no port I/O.
- kraftkit argv recorded. kraftkit also invokes the binary with `-version`
  and `-accel help`. The second `-machine` is merged, HTTP works (3x 200).
- Shared file: a symbol's address is its file offset. All 15 read-only
  sections are byte-identical to the ELF. In `.text`, 37 bytes differ, all
  boot page tables (`x86_bpt_*`) plus one boot relocation, none on the
  syscall path. A `.bss` variable read from the host advanced in real time.
  Readable with `O_RDONLY`/`PROT_READ` as a normal user. 64 MiB is below
  any PCI hole.
- All 16 NET-group syscalls are in `provided_syscalls.in`.

**Unresolved / unverified**:

- Exact upstream Unikraft commit (`~1eee9d4` in the config is the
  enclosing catalog repo's sha, not Unikraft's).
- That this host's KVM does not trap `rdtsc` (needs root to trace).
- Whether LTO keeps hook functions in a dedicated `.text.vmitrace` section.
- Why kraftkit no longer passes `-initrd` (HTTP works without it).
- SMP: the build is single-lcpu. Per-lcpu rings are proposed, not tested.

**Found along the way**: the shared file survives `kraft stop`/`kraft rm`
(it must be removed by the wrapper/collector), and is created `0640` by the
QEMU user. `../.unikraft/build/config` still has
`CONFIG_LIBSYSCALL_SHIM_STRACE=y` from Phase 4 even though the binary is the
non-strace backup.

## Phase 10-1 result

Goal: the guest half of the unmodified-QEMU design. A Unikraft library
writes selected syscalls into a ring buffer in guest RAM, and Unikraft
itself is not modified. Details: `docs/phase10_1_guest_library.md`.

**What was done**:

- `tools/guest_build.py vendor` copied Unikraft, lib-lwip, lib-libelf,
  app-elfloader and the extracted lwip origin out of `../.unikraft` into
  `/home/matsu/vmitrace-build/vendor`. The sha256 of all 2,213 files is in
  `guest/vendor.sha256`.
- `tools/guest_build.py build <base|net|file|time|all>` writes a Kraftfile
  that points at those copies (and at `guest/lib-vmitrace` for non-base
  variants) and runs `kraft build`.
- `guest/lib-vmitrace` registers `vt_enter`/`vt_exit` with
  `uk_syscall_entertab_prio`/`uk_syscall_exittab_prio`.
- Layout, as decided for 10-0 §7:
  - Constant 64-byte header in a page-aligned PROGBITS `.vmitrace`.
  - 512-bit bitmap in `.rodata`, computed at compile time from
    `LIBVMITRACE_GROUP_{ALL,NET,FILE,TIME}`.
  - Per-lcpu `write_idx`/`dropped` and the 96-byte records in a NOBITS
    `.bss.vmitrace_ring`.
  - Hook code in its own `.vmitrace_text`.
  - `exit`/`exit_group` also get an entry-only record.

**Confirmed**:

- kraftkit 0.12.16 accepts local paths for every `source:`.
- The `base` build has the same program headers and handler addresses as
  `backup_verified_build/`. It is not byte-identical: embedded paths and the
  version string shift `.rodata`.
- LTO kept the three hook functions inside `.vmitrace_text`. The hooks read
  the bitmap from memory and call only `ukplat_monotonic_clock` (`rdtsc`) and
  `uk_sys_gettid` (one TLS load).
- On `/usr/bin/qemu-system-x86_64` + `memory-backend-file,share=on`, the ALL
  build:
  - 288 records after boot and 341 after 3 curls, 0 bad seq.
  - The first record is `brk`.
  - The first request reads `accept4 = 7 ... recvfrom = 78, openat = 8,
    pread64 = 612, writev = 850 ... close`, i.e. the Phase 8 values.
  - A 2.5 s `epoll_wait` was paired correctly across the block.
- NET build: the bitmap is exactly the 16 NET syscalls, and only those were
  recorded (26 records).
- Decision 7: after `unlink()` of the shared file, an existing ring-only
  mmap keeps working and tmpfs space is freed when QEMU exits. **Not adopted
  as default**: a reader that restarts could never reopen the file. Kept the
  wrapper + pidfile cleanup (comparison in the doc, §4).

**Unexpected, recorded**:

- lib-lwip downloads the moving `UNIKRAFT-2_1_x` branch zip at build time. A
  fresh download + patches yields a different `sockets.h` (`TCP_KEEP*`
  values) than the verified tree. The build script seeds the copied tree
  and its stamps instead.
- The first ring placement (`INSERT AFTER .bss`) landed after `_end`. Moved
  into `.bss` via the `.bss.` input-section prefix.

**Unresolved**: the `vmitrace` group (needs root, comes with the collector in
10-3); moving Phase 1-8 code to `legacy/` (planned with 10-2); RDTSC exiting
unverified; SMP untested; overhead not measured yet (10-5).

## Notes for later phases

- `legacy/attach_gdbstub.py`'s `mon.sock` is plain QEMU **HMP** text protocol
  (not QMP/JSON) — verified empirically. It echoes input with ANSI
  cursor-movement escapes like a readline TTY; `hmp_command()` strips
  these and returns the clean reply text.
- The gdbstub binds **loopback-only** (`tcp:127.0.0.1:<port>`), not
  `tcp::<port>` (which binds `0.0.0.0` and would expose full guest
  memory/register read-write on the network — verified via `ss -tlnp`
  that the bare `tcp::PORT` form does this; switched to the explicit
  loopback form).
- `kraft ps -l -o json` (note `-l`) is required to get the `machine_id`
  field used to resolve `~/.local/share/kraftkit/runtime/<machine_id>/`;
  plain `kraft ps -o json` omits it.
- Attaching via HMP `gdbserver` to an already-running (non `-S`) guest
  does **not** pause it — `target remote` showed the VM already executing
  (idle-looping in `ukplat_lcpu_halt_irq`), consistent with the plan.
- Breakpoint is a plain software `break` (int3 patch), not `hbreak` --
  keep it that way (KVM's hardware-breakpoint path has known upstream
  reliability bugs).
- Always re-resolve the instance's `mon.sock` path via a live `kraft ps`
  at run time; stale `mon.sock` files are left on disk after an instance
  dies and must not be reused.
- Do not touch `/home/matsu/kvm-vmi` or the host kernel — explicitly out
  of scope for this tool (see plan).
