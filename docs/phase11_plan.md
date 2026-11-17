# Phase 11 plan: agentless selective trapping

Started 2026-11-14. Results go into README "Phase 11 result".

## Why (decided 2026-11-14)

- Requirement (restated): set traps selectively at build time (e.g. network
  syscalls only), do not modify QEMU, have a separate program receive the events
  from QEMU, and send them to Jaeger via OTel. **Agentless: no code in the guest.**
- Phase 10's `lib-vmitrace` is a guest agent. Unikraft runs everything in ring 0,
  so a compromised guest can rewrite or bypass it. The host is the only place a
  record cannot be erased from inside.
- Syscalls do not cause VM exits by themselves. In Unikraft, `syscall` jumps
  to `_ukplat_syscall` in the same ring 0. The monitor creates the exits (traps) to
  observe the syscalls. An exit is not a sign of an attack. Attacks show up as
  unusual syscalls, arguments or sequences after a compromise, for example an
  outgoing `connect`.
- Position: VMI is practical when it is slow-tolerant, low-frequency or after the
  fact. Full tracing is not practical (1.1% throughput here). So the research claim
  is **selective, low-frequency trapping for unikernels**: trap rarely used syscalls
  only, so normal traffic causes no exits.
- Software breakpoints were chosen over hardware ones. Hardware breakpoints cannot
  be removed by the guest but are limited to 4; removal of 0xCC is detected instead.

## Done (2026-11-14)

1. Experiments (`agentless/experiments/`, README "Can the guest remove a
   breakpoint?"):
   - Guest writes to DR0-3/6/7 do not remove host hbreaks. The guest sees only its
     own copy: DR7 0x400.
   - The guest reads 0xCC and can remove it (CR0.WP cleared, `0xe9` written back).
   - Host single-step is lost at a MOV DR. Never single-step guest-chosen code.
2. Prototype (`agentless/`): `gen_traps.py`, `rsp.py`, `vmi_trap.py`,
   `bench_agentless.py`.
3. Results:
   - Records match Phase 8's names and return values.
   - Jaeger receives connection traces.
   - Throughput: NET 5.2%, NETFD 2.1%, ALL 1.1% of base. `connect,socket` only:
     no measurable cost.
   - About 300 us per stop, of which about 160 us is the tool's handling.
   - A trap removed by the guest was detected in 0.27 s and re-armed.

## Done (2026-11-15): Phase 11-2, traps baked in at build time

User's request: set the traps selectively at build time (e.g. network only).
Option A was chosen: write 0xCC into the image after linking, with no guest
code. `agentless/bake_traps.py` + `agentless/qemu-trap.sh`; results in README
"Phase 11-2 result". It is fail-closed: a baked image does not run without the
host tool.

Open from 11-2:
- Should the build step run inside `kraft build` (a Kconfig choice instead of a
  separate command)? Upstream Unikraft has no post-link hook used here yet.
- ~~`connect`/`socket` are not "never used": nginx calls them at startup.~~
  Done 2026-11-16: startup is not recorded (below).
- Tool exit = the service stops at the next selected syscall. Decide whether
  that is wanted, or the tool should hand over before exiting.

## Done (2026-11-16): startup is not monitored

User's decision: syscalls at boot need not be monitored. Records start at
nginx's first `accept4` (no network input before it; startup code is the
checked image). Use case behind it: always-on, low-frequency detection in
production, where a hit on a "never while serving" syscall is an alert.
The boundary is baked (`bake_traps.py --startup-boundary`, default accept4)
because a host breakpoint inserted before boot is overwritten by the kernel
load. `vmi_trap.py --startup skip|record`. README "Startup is not recorded".
Result: the rare image (`socket,connect`) gives 0 records in normal
operation. Performance rerun: serving and boot unchanged, startup stops
constant per selection (README "Performance with startup not recorded").

## Done (2026-11-18): Phase 11-3, trap handling inside an unmodified QEMU

User's question: the gdbstub path is slower than Phase 8 (patched QEMU) for
any trap that fires while serving; could Phase 8's in-QEMU handling live in
a separate program attached to the unmodified QEMU? A KVM exit only returns
to QEMU's vCPU thread, so the program has to run in QEMU's process. User
accepted `LD_PRELOAD` (distro binary unchanged, library interposes libc's
`ioctl`) as within "unmodified QEMU".

`agentless/kvmtrap/` (`libvmitrap.c`, `kvmtrap.py`), `agentless/qemu-kvmtrap.sh`,
`bench_baked.py --wrapper kvmtrap` + condition `phase8`. README "Phase 11-3
result". ALL (every syscall, entry + return): 3,885 req/s vs Phase 8 717 and
gdbstub 133 in the same session; records identical to Phase 8; about 1.5 us
of QEMU CPU per stop; boot 2.6-2.8 s.

Open from 11-3:
- guest-side trap removal test (11's `--test-guest-untrap` used the gdbstub;
  needs another way to redirect the guest, or a guest-side test image);
- multi-vCPU (locking is in place, untested), a syscall blocking in another
  thread while the exit trap is armed (emulation makes it safe in principle);
- pending entries are dropped when QEMU exits (vmi_trap.py emitted them);
- the Python reader caps at about 9,000 records/s (100% CPU): under
  sustained NETFD keep-alive load (51,900 syscalls/s) 81% of records were
  lost at the ring; OTLP export itself dropped nothing (README "Sustained
  load with OTLP"). Options: a faster reader (C/Go, or JSONL-only path),
  spans to an OTel Collector, or sampling;
- the selective "never while serving" claim now has a cheap fallback:
  tracing every request is practical again, so "what to watch" is a policy
  choice rather than a performance necessity.

## Next

- **Behavioural check for removed or bypassed traps**, as in Phase 10-6's
  `accept4_mismatch`: host connections vs. trapped `accept4`. It catches what the
  1-second byte check misses: a removal reverted between checks, or a bypass of the
  dispatcher.
- **Decide what to watch.** Pick the "never while serving" syscalls for nginx
  (connect, socket, execve, ...; 33 occur only at startup in the ALL run). Measure normal operation with
  that set, and run a simulated attack that triggers it.
- **Cost per stop.** Superseded by 11-3 for the in-process path (about
  1.5 us per stop). For the gdbstub path: measured 2026-11-17 (README "Where the cost of one stop
  goes"): about 150 us is QEMU's `vm_stop`/`vm_start` (outside any client),
  `g` is required (`P` is not applied without it; `p` does not help), each
  round trip is 30-60 us, Python adds about 35 us, and C-states are not the
  cause. The floor through the gdbstub is about 240 us. Left to do: drop `m`
  (arguments are already in rdi.. at the site), and maybe a C client.
- **Untested paths:**
  - a syscall blocking in another thread (`exit_step_overs`);
  - the guest's own `int3` (`foreign_trap`);
  - long runs, and Phase 10-5 supplementary conditions (performance governor,
    other containers stopped);
  - AMD.
- **Hardware breakpoints as unremovable sentinels** on up to 4 critical sites,
  next to the software traps (not built).
- Also possible: hash only the trapped bytes through Phase 10's shared-memory file
  instead of HMP `xp`. That would need the wrapper; not needed so far.

## Session notes

- Stop a background `vmi_trap.py` by PID. `pkill -f` with its command line also
  matches the shell that started it, and kills that shell.
- The gdbstub stays listening after a detach: pass the same `--port` to reuse it.
