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
- **Phase 5 (capture from boot, not just after-the-fact attach): investigated, blocked.** See below. `run_capture.py` still only captures from whenever it attaches (a few seconds into an already-running guest); `run_capture_from_boot.py` documents why racing kraftkit's own boot sequence doesn't currently work.
- **Phase 6 (move capture inside QEMU, remove gdb/RSP): done.** See below. A patched QEMU (`qemu_patch/`) captures syscalls via a `KVM_EXIT_DEBUG` branch inside `kvm_handle_debug()` itself -- no external gdb process, no RSP protocol, no VM-wide debug-stop. ~90% throughput drop vs baseline (down from ~99% with the gdb/RSP mechanism) and, as a side effect, reliably captures from very early boot (Phase 5's original goal), because arming no longer depends on racing an external process against kraftkit's own resume.
- **Phase 7 (deterministic capture from the very first syscall): done.** See below. Roots-caused *why* Phase 6's boot-time capture was probabilistic (a one-shot QEMU-internal memory write, not an external race) and hooked that exact event (`fw_cfg_dma_transfer()` in `hw/nvram/fw_cfg.c`) instead of polling for it. 10/10 fresh boots captured an identical, deterministic 289-event sequence starting with the guest's actual first syscall, confirmed via an offset-0 exact match against Unikraft's own in-guest strace ground truth (134/134 comparable events identical). No measurable overhead change vs Phase 6.

## Phase 1 result

Hook point: `_ukplat_syscall` (`.unikraft/unikraft/plat/common/x86/syscall.S`),
the literal target of the guest's `syscall` instruction. At this address,
registers hold the raw Linux x86_64 syscall ABI: `rax`=number,
`rdi,rsi,rdx,r10,r8,r9`=args 1-6.

Steps that worked end to end:

```
kraft run -d -p 8080:80 --name vmitest .
python3 attach_gdbstub.py vmitest        # -> prints PORT=1234
gdb -q -nx -x phase1_manual_test.gdb     # attaches, sets breakpoint, waits
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
provided), `monitor.py` (gdb-Python auto-continuing capture), and
`run_capture.py` (orchestrator: start/attach -> capture for a duration ->
detach -> stop+remove -> report) all work end to end:

```
python3 run_capture.py --name vmicapture --duration 15 --log logs/capture.jsonl
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
  both `attach_gdbstub.py` and `run_capture.py`.
- `gdb.lookup_global_symbol()` cannot find `_ukplat_syscall` because it's
  an assembly-only label with no DWARF debug_info (searches DWARF only).
  Fixed by using `gdb.decode_line("*_ukplat_syscall")` to validate/resolve
  the same way the CLI's `break` command does (which works on plain ELF
  symbols too) instead of the Python symbol-lookup API.

## Phase 3 result

`bench_overhead.py` runs `ab` A/B (baseline: no gdbstub; monitored: VMI
breakpoint active on every syscall) against the *same* running instance,
switching conditions by attaching/detaching the gdbstub mid-run rather than
rebooting between conditions:

```
python3 bench_overhead.py --name vmibench --reps 5 --requests 500 --concurrency 5
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
eventually exhausts something. `bench_overhead.py` now tolerates a failed
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
`run_capture.py` with the same single-`curl` workload for the VMI side.

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
not just from whenever `run_capture.py` happens to attach (which Phase 4
showed is several seconds and ~289 syscalls late).

Discovered that kraftkit launches QEMU with `-S` (paused at reset) and
only resumes it itself, over its own QMP connection, a short but
consistent **~90-100ms** after the monitor socket appears (measured
directly). `run_capture_from_boot.py` races that window: pre-load gdb's
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
  monitor.py at all). Confirmed by omission: the identical race without
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
  monitor.py's Python `gdb.Breakpoint` subclass) and regardless of
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
code can call directly). Implementation: `qemu_patch/` (source-level
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

**Overhead** (`bench_overhead_inline.py`, 3 reps x 200 req, concurrency
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
during implementation** (see `qemu_patch/README.md` for full build
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
  `qemu_patch/README.md`).
- `kraft run --qemu <path>` / `KRAFTKIT_QEMU` env var / `qemu:` in
  `~/.config/kraftkit/config.yaml` all point kraftkit at a custom-built
  QEMU binary -- no kraftkit source changes needed.

**Live terminal view (added after the initial Phase 6 implementation)**:
`run_capture_inline.py` now tails its own JSONL output file (a plain
Python re-implementation of `tail -f`, polling every 50ms) and prints
each event to the terminal as `[HH:MM:SS.mmm] name(args...)`, in
addition to writing the JSONL as before -- the two are not exclusive.
No change to the QEMU-side hot path (`vmi_monitor_breakpoint_hit()` in
`qemu_patch/target/i386/kvm/vmi-syscall-monitor.c`) was needed or made;
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
and verification: same doc's §13, plus `qemu_patch/` (`0003-fw_cfg.c.diff`,
updated `vmi-syscall-monitor.{c,h}`).

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

## Notes for later phases

- `attach_gdbstub.py`'s `mon.sock` is plain QEMU **HMP** text protocol
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
