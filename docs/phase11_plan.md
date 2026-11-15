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
- `connect`/`socket` are not "never used": nginx calls them at startup (AF_UNIX
  connect x4, ENOENT). Normal operation must be split into startup and serving
  when choosing what to watch.
- Tool exit = the service stops at the next selected syscall. Decide whether
  that is wanted, or the tool should hand over before exiting.

## Next

- **Behavioural check for removed or bypassed traps**, as in Phase 10-6's
  `accept4_mismatch`: host connections vs. trapped `accept4`. It catches what the
  1-second byte check misses: a removal reverted between checks, or a bypass of the
  dispatcher.
- **Decide what to watch.** Pick the "never in normal operation" syscalls for nginx
  (connect, socket, openat outside the docroot, ...). Measure normal operation with
  that set, and run a simulated attack that triggers it.
- **Cost per stop.** Fewer round trips: read r12 and rsp with `p` instead of `g`,
  or batch the commands; keep the exit trap armed while hits are frequent. Measure
  where the remaining ~140 us goes (KVM exit, QEMU gdbstub, TCP).
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
