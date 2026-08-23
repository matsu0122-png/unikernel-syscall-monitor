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
