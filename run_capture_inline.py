#!/usr/bin/env python3
"""Phase 6: capture syscalls via the QEMU-inline monitor (no gdb, no RSP).

Starts the unikernel with `kraft run --qemu <custom qemu-system-x86_64>`,
pointing at a QEMU build patched with the inline syscall monitor
(target/i386/kvm/vmi-syscall-monitor.c -- see
docs/phase6_inline_qemu_design.md). The custom binary reads
VMI_MONITOR_ADDR / VMI_MONITOR_LOG from its own environment at startup;
this script sets those in the subprocess environment `kraft run` inherits
and (assumed, verified empirically on first run) forwards to the
qemu-system-x86_64 child it execs.

Usage:
    # interactive: runs until Ctrl-C, printing syscalls to the terminal
    # as they happen while also writing the full JSONL as before
    python3 run_capture_inline.py --name vmiinline

    # fixed-duration, non-interactive (old behavior, still supported)
    python3 run_capture_inline.py --name vmiinline --duration 15 \
        --log logs/capture_inline.jsonl \
        --qemu /home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64

    # suppress the live terminal view entirely (JSONL still written) --
    # useful when scripting or when comparing overhead with/without it
    python3 run_capture_inline.py --name vmiinline --duration 15 --quiet

    # only start printing once nginx has actually accepted a connection,
    # to skip the (potentially large) burst of boot-time syscalls
    python3 run_capture_inline.py --name vmiinline --show-after-ready

If --addr is omitted, resolves _ukplat_syscall via `nm` against the
project's .dbg build (same method Phase 1/2 used), not a hardcoded
constant.

Real-time display design (see docs/phase6_inline_qemu_design.md and the
project README's Phase 6 section for the full writeup): this does NOT
add any new IPC between QEMU and Python. The QEMU-side hot path
(vmi_monitor_breakpoint_hit() in vmi-syscall-monitor.c) is completely
unmodified -- it still only appends one line to the JSONL file, exactly
as before. This script polls that same file for new lines (a plain
Python re-implementation of `tail -f`) and prints each one as it
appears. The JSONL file remains the single source of truth; the
terminal view is just another reader of it, same as `tail -f
logs/whatever.jsonl` would be.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_DIR = HERE.parent
DEFAULT_QEMU = "/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64"

TAIL_POLL_S = 0.05          # how often to check the JSONL file for new lines
ARM_CHECK_TIMEOUT_S = 5.0   # how long to wait for the "armed" debug-log line before giving up on printing it


def instance_is_running(name: str) -> bool:
    out = subprocess.run(
        ["kraft", "ps", "-o", "json"], capture_output=True, text=True, check=True
    )
    instances = json.loads(out.stdout) or []
    return any(inst.get("name") == name for inst in instances)


def resolve_syscall_addr() -> int:
    dbg = PROJECT_DIR / ".unikraft" / "build" / "nginx_qemu-x86_64.dbg"
    out = subprocess.run(["nm", str(dbg)], capture_output=True, text=True, check=True)
    for line in out.stdout.splitlines():
        if line.endswith(" T _ukplat_syscall"):
            return int(line.split()[0], 16)
    raise RuntimeError(f"_ukplat_syscall not found in {dbg}")


def start_instance(name: str, qemu_path: str, addr: int, log_path: str) -> None:
    env = dict(os.environ)
    env["VMI_MONITOR_ADDR"] = hex(addr)
    env["VMI_MONITOR_LOG"] = str(Path(log_path).resolve())

    cmd = ["kraft", "run", "-d", "-p", "8080:80", "--name", name, "--qemu", qemu_path, "."]
    print(f"[run_capture_inline] {' '.join(cmd)}")
    print(f"[run_capture_inline] env VMI_MONITOR_ADDR={env['VMI_MONITOR_ADDR']} "
          f"VMI_MONITOR_LOG={env['VMI_MONITOR_LOG']}")
    subprocess.run(cmd, cwd=str(PROJECT_DIR), env=env, check=True)
    time.sleep(1.5)


def stop_and_remove(name: str) -> None:
    subprocess.run(["kraft", "stop", name], check=False)
    subprocess.run(["kraft", "rm", name], check=False)


def wait_for_armed_message(debug_log_path: Path, timeout_s: float) -> bool:
    """Best-effort: peek at <log>.debug.log for the "readback=0xcc
    confirmed" line vmi_try_arm() writes on a successful (verified) arm,
    just so the terminal banner can say "breakpoint armed" instead of
    guessing. Not required for correctness -- the monitor keeps
    re-arming/re-verifying on its own regardless of whether this
    check sees it in time (see vmi-syscall-monitor.c's vmi_try_arm());
    this is purely cosmetic for the startup banner."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if debug_log_path.exists():
            text = debug_log_path.read_text(errors="ignore")
            if "readback=0xcc confirmed" in text or "first real hit observed" in text:
                return True
        time.sleep(0.1)
    return False


def format_event(evt: dict) -> str:
    ts = evt.get("ts", 0.0)
    t = datetime.fromtimestamp(ts).strftime("%H:%M:%S") + f".{int((ts % 1) * 1000):03d}"
    name = evt.get("syscall", f"syscall_{evt.get('num')}")
    args = ", ".join(evt.get("args", []))
    return f"[{t}] {name}({args})"


def tail_lines(path: Path, deadline: float | None):
    """Generator: yields each new complete line appended to `path`, from
    the very start of the file (so anything QEMU already wrote before we
    got here -- e.g. boot-time syscalls -- is replayed too, not just
    lines appended after this call). Blocks (polling) waiting for new
    lines, like `tail -f`. Stops (returns) once `deadline`
    (time.monotonic() value) is reached, if given."""
    while not path.exists():
        if deadline is not None and time.monotonic() >= deadline:
            return
        time.sleep(TAIL_POLL_S)

    with open(path, "r") as f:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                return
            pos = f.tell()
            line = f.readline()
            if not line or not line.endswith("\n"):
                # either nothing new yet, or QEMU is mid-write on a
                # partial line -- rewind and retry rather than yielding
                # a truncated line.
                f.seek(pos)
                time.sleep(TAIL_POLL_S)
                continue
            yield line


def run_interactive(log_path: Path, duration: float | None, show_after_ready: bool) -> int:
    deadline = time.monotonic() + duration if duration is not None else None
    ready_seen = not show_after_ready
    n_events = 0

    print("[VMI] monitoring syscalls (tailing "
          f"{log_path}{f', auto-stop in {duration}s' if duration else ''})")
    print("[VMI] press Ctrl-C to stop\n")

    try:
        for line in tail_lines(log_path, deadline):
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate a torn line if we ever race a write; JSONL file itself is unaffected
            n_events += 1
            if not ready_seen:
                if evt.get("syscall") == "accept4":
                    ready_seen = True
                    print("[VMI] first connection accepted -- nginx is ready, "
                          "showing syscalls from here on\n")
                else:
                    continue
            print(format_event(evt), flush=True)
    except KeyboardInterrupt:
        print("\n[VMI] Ctrl-C received, stopping...")

    return n_events


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="vmiinline")
    parser.add_argument("--duration", type=float, default=None,
                         help="auto-stop after this many seconds; omit to run until Ctrl-C")
    parser.add_argument("--log", default=str(HERE / "logs" / "capture_inline.jsonl"))
    parser.add_argument("--qemu", default=DEFAULT_QEMU)
    parser.add_argument("--addr", default=None, help="hex address, e.g. 0x101000 (default: resolved via nm)")
    parser.add_argument("--quiet", action="store_true",
                         help="don't print syscalls to the terminal (JSONL is still written); "
                              "for scripting, or for an apples-to-apples overhead comparison "
                              "against the live-display mode")
    parser.add_argument("--show-after-ready", action="store_true",
                         help="suppress terminal output until the first accept4 (i.e. nginx's "
                              "first accepted connection) -- boot-time syscalls still go into "
                              "the JSONL file, just not to the terminal")
    args = parser.parse_args()

    if not Path(args.qemu).is_file():
        print(f"[run_capture_inline] ERROR: --qemu path does not exist: {args.qemu}", file=sys.stderr)
        return 1

    addr = int(args.addr, 0) if args.addr else resolve_syscall_addr()
    print(f"[run_capture_inline] _ukplat_syscall = {hex(addr)}")

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        log_path.unlink()  # start fresh so line counts below are for this run only
    debug_log_path = Path(str(log_path) + ".debug.log")
    if debug_log_path.exists():
        debug_log_path.unlink()  # this one isn't unlinked by QEMU between runs either

    if instance_is_running(args.name):
        print(f"[run_capture_inline] ERROR: instance {args.name!r} already running; "
              f"stop it first (this script always starts its own)", file=sys.stderr)
        return 1

    print("[VMI] starting Unikraft VM...")
    start_instance(args.name, args.qemu, addr, str(log_path))

    if wait_for_armed_message(debug_log_path, ARM_CHECK_TIMEOUT_S):
        print(f"[VMI] breakpoint armed at _ukplat_syscall ({hex(addr)})")
    else:
        print(f"[VMI] breakpoint arm not yet confirmed after {ARM_CHECK_TIMEOUT_S}s "
              f"(still retrying inside QEMU -- see {debug_log_path.name}); continuing anyway")

    try:
        if args.quiet:
            print(f"[run_capture_inline] --quiet: not tailing to terminal; "
                  f"{'auto-stop in ' + str(args.duration) + 's' if args.duration else 'press Ctrl-C to stop'}")
            try:
                if args.duration is not None:
                    time.sleep(args.duration)
                else:
                    while True:
                        time.sleep(3600)
            except KeyboardInterrupt:
                print("\n[VMI] Ctrl-C received, stopping...")
            n_events = sum(1 for _ in open(log_path)) if log_path.exists() else 0
        else:
            n_events = run_interactive(log_path, args.duration, args.show_after_ready)
    finally:
        print(f"[run_capture_inline] stopping/removing instance {args.name!r}")
        stop_and_remove(args.name)

    total_events = sum(1 for _ in open(log_path)) if log_path.exists() else n_events
    print(f"[run_capture_inline] captured {total_events} events -> {log_path}")
    if total_events == 0:
        print("[run_capture_inline] WARNING: 0 events captured -- check that "
              "VMI_MONITOR_ADDR reached the QEMU process (see its stderr/log "
              "for 'vmi-monitor: enabled' / 'breakpoint armed and VERIFIED')",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
