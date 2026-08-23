#!/usr/bin/env python3
"""Attempt to capture syscalls starting from the guest's very first
instruction of boot, not just after it's already running (which is what
run_capture.py does -- see README's Phase 4 note that attaching a few
seconds into an already-booted guest misses ~289 boot-time syscalls).

STATUS: the race against kraftkit's own auto-resume is solved (see
below), but the actual syscall capture does NOT currently work -- this
script reliably reports 0 events even though the guest boots
successfully. Root-caused, not yet fixed; documented here rather than
silently shipped as working. See "Known limitation" below before using
this for anything real -- run_capture.py (attach-after-boot) is the tool
that actually works today.

How the race itself works: kraftkit launches QEMU with `-S` (paused at
reset) and only resumes it itself, over its own QMP connection, a short
but consistent ~90-100ms after the monitor socket appears (confirmed
empirically). This script wins that race:

  1. Pre-load gdb's debug symbols and pre-arm the syscall breakpoint (as
     a *pending* breakpoint -- gdb only needs the symbol table for this,
     not a live target) *before* the instance even starts, overlapping
     with kraft's multi-second Docker/rootfs build.
  2. Start the instance, and poll (tight loop, no `kraft ps` subprocess
     calls -- those are too slow for this race) for its new runtime dir
     and mon.sock to appear.
  3. The instant mon.sock exists, connect over HMP and issue `gdbserver`
     -- this doesn't touch run state, just adds a listener to the
     already-paused guest.
  4. Hand that port to the pre-loaded gdb and issue `target remote` +
     `continue` immediately -- this reliably attaches while the guest is
     still sitting at the literal CPU reset vector (confirmed: gdb
     reports PC 0xfff0), before kraftkit's own resume ever fires.

Known limitation (confirmed, not yet solved): attaching and continuing
from that very first paused-at-reset state means gdb's software
breakpoint (the int3 patch at `_ukplat_syscall`, 0x101000) is never
actually written into guest memory -- confirmed by reading raw memory at
that address (`x/8xb 0x101000`) before and after letting the guest run
all the way to its idle loop: the original instruction bytes are still
there, never replaced with 0xCC, and `info breakpoints` shows no hit
count. This reproduces identically whether the breakpoint is a Python
gdb.Breakpoint (monitor.py) or a plain CLI `break` command, and whether
it's set before or after `target remote` -- so it isn't specific to this
project's Python API usage. Giving the guest a head start (tried 20ms and
150ms) before arming the breakpoint didn't help either: RIP was
identical (0x52c) in both cases, suggesting the CPU doesn't reach a state
where 0x101000 becomes writable within that window (likely something
about addressing before the kernel's own long-mode/paging setup
completes, though the exact QEMU/KVM-level mechanism wasn't pinned down).
Meanwhile attaching *after* kraftkit's own auto-resume (i.e. giving up
the race) reliably lands somewhere the guest has *already* run past all
boot syscalls -- this build's boot is apparently fast enough that it
completes before any external process can react to the "running" state
transition. Net effect: there's currently no window where the breakpoint
is both writable and still ahead of boot's syscalls.

Also confirmed and fixed along the way (kept even though the above is
unresolved): publishing a host port (`-p`) while resuming the guest
ourselves during kraftkit's own management window causes kraftkit to
fail the whole `kraft run` with a spurious "port already in use" error
and kill the instance. Avoided here by not publishing a port during the
race (this script does not take `-p`).

For an actually-reliable full boot-to-request syscall trace today, use
Unikraft's own in-guest tracer instead of this tool: uncomment
`CONFIG_LIBSYSCALL_SHIM_STRACE` in the Kraftfile, rebuild, and read it
off the guest's console log (see README's Phase 4 for the exact steps --
this is how that phase's ground-truth log, and the boot trace the user
supplied in this project's own history, were produced).

Usage:
    python3 run_capture_from_boot.py --name vmiboot --duration 15 --log logs/capture_from_boot.jsonl

Must be run inside `sg docker -c "sg kvm -c '...'"` (or with those groups
already active) since it shells out to `kraft`.
"""
import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_DIR = HERE.parent

sys.path.insert(0, str(HERE))
from attach_gdbstub import (  # noqa: E402
    KRAFTKIT_RUNTIME_DIR,
    find_free_port,
    hmp_command,
    _recv_until_prompt,
)
from gdb_session import (  # noqa: E402
    launch_gdb_preloaded,
    attach_preloaded_gdb,
    stop_gdb_capture,
    drain_gdb_output,
)
from run_capture import stop_and_remove  # noqa: E402


def wait_for_new_runtime_dir(before: set, timeout: float = 60.0) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        diff = set(os.listdir(KRAFTKIT_RUNTIME_DIR)) - before
        if diff:
            return KRAFTKIT_RUNTIME_DIR / next(iter(diff))
    raise TimeoutError("no new kraftkit runtime dir appeared in time")


def wait_for_path(path: Path, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
    raise TimeoutError(f"{path} did not appear in time")


def connect_hmp(mon_sock: Path, timeout: float = 60.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while time.monotonic() < deadline:
        try:
            sock.connect(str(mon_sock))
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            continue
    raise TimeoutError(f"could not connect to {mon_sock} in time")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="vmibootcapture", help="kraft instance name")
    parser.add_argument("--duration", type=float, default=15.0, help="capture duration in seconds, timed from attach")
    parser.add_argument("--log", default=str(HERE / "logs" / "capture_from_boot.jsonl"))
    parser.add_argument("--include", default="", help="comma-separated syscall numbers to include (default: all)")
    parser.add_argument("--exclude", default="", help="comma-separated syscall numbers to exclude")
    parser.add_argument("--max-events", type=int, default=None)
    args = parser.parse_args()

    env = dict(os.environ)
    env["VMI_LOG_PATH"] = args.log
    if args.include:
        env["VMI_INCLUDE_NRS"] = args.include
    if args.exclude:
        env["VMI_EXCLUDE_NRS"] = args.exclude
    if args.max_events:
        env["VMI_MAX_EVENTS"] = str(args.max_events)

    print("[run_capture_from_boot] pre-loading gdb symbols + arming pending breakpoint (no target yet)")
    gdb_proc = launch_gdb_preloaded(env)
    # Let gdb finish loading the ~22M debug binary and print "breakpoint
    # armed" -- this overlaps with kraft's own Docker rootfs build below,
    # so it costs nothing against the actual boot race.
    time.sleep(1.5)

    before = set(os.listdir(KRAFTKIT_RUNTIME_DIR))
    print(f"[run_capture_from_boot] starting instance {args.name!r} (kraftkit launches it paused via qemu -S)")
    # No -p: publishing a host port while we resume the guest ourselves
    # during kraftkit's own management window makes `kraft run` fail with
    # a spurious "port already in use" error and kill the instance (see
    # module docstring). Since the breakpoint doesn't fire yet anyway
    # (see "Known limitation"), there's currently nothing to reach over
    # a published port in this script regardless.
    kraft_proc = subprocess.Popen(
        ["kraft", "run", "-d", "--name", args.name, "."],
        cwd=str(PROJECT_DIR),
    )

    runtime_dir = wait_for_new_runtime_dir(before)
    mon_sock = runtime_dir / "mon.sock"
    wait_for_path(mon_sock)
    t_mon = time.perf_counter()

    hmp_sock = connect_hmp(mon_sock)
    _recv_until_prompt(hmp_sock)  # discard the initial banner + first prompt
    port = find_free_port()
    reply = hmp_command(hmp_sock, f"gdbserver tcp:127.0.0.1:{port}")
    t_gdbserver = time.perf_counter()
    print(
        f"[run_capture_from_boot] gdbserver armed on 127.0.0.1:{port} "
        f"({t_gdbserver - t_mon:.4f}s after mon.sock appeared) -- {reply!r}"
    )

    attach_preloaded_gdb(gdb_proc, port)
    t_attach = time.perf_counter()
    print(f"[run_capture_from_boot] target remote + continue sent ({t_attach - t_mon:.4f}s after mon.sock appeared)")
    hmp_sock.close()

    kraft_proc.wait(timeout=60)  # let kraft's own CLI invocation finish its bookkeeping

    try:
        gdb_proc.wait(timeout=args.duration)
        print("[run_capture_from_boot] gdb exited on its own before the duration elapsed (check --max-events?)")
        drain_gdb_output(gdb_proc)
    except subprocess.TimeoutExpired:
        print(f"[run_capture_from_boot] duration ({args.duration}s) elapsed, detaching gdb")
        stop_gdb_capture(gdb_proc)

    print(f"[run_capture_from_boot] stopping/removing instance {args.name!r}")
    stop_and_remove(args.name)

    log_path = Path(args.log)
    n_events = sum(1 for _ in open(log_path)) if log_path.exists() else 0
    print(f"[run_capture_from_boot] captured {n_events} events -> {log_path}")
    if n_events == 0:
        print(
            "[run_capture_from_boot] WARNING: 0 events despite the guest booting "
            "successfully -- this is the known, unresolved breakpoint-insertion "
            "limitation documented in this script's module docstring, not "
            "necessarily a new bug. Use run_capture.py for a capture that "
            "actually works (attach-after-boot)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
