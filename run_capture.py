#!/usr/bin/env python3
"""Orchestrator for Phase 2: start/attach -> capture for a duration -> JSONL.

Usage:
    python3 run_capture.py --name vmitest --duration 30 --log logs/capture.jsonl
    python3 run_capture.py --name vmitest --duration 30 --include 0,1,232  # read,write,epoll_wait

If --name isn't already running (per `kraft ps`), starts it with
`kraft run -d -p 8080:80 --name <name> .` from PROJECT_DIR and stops+removes
it again at the end. If it's already running, this script leaves it running
and only detaches gdb at the end (does not stop/remove someone else's
instance).

Must be run inside `sg docker -c "sg kvm -c '...'"` (or with those groups
already active) since it shells out to `kraft`.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_DIR = HERE.parent

sys.path.insert(0, str(HERE))
from attach_gdbstub import (  # noqa: E402
    find_instance_runtime_dir,
    find_free_port,
    attach_gdbserver,
)
from gdb_session import launch_gdb_capture, stop_gdb_capture, drain_gdb_output  # noqa: E402


def instance_is_running(name: str) -> bool:
    out = subprocess.run(
        ["kraft", "ps", "-o", "json"], capture_output=True, text=True, check=True
    )
    # `kraft ps -o json` prints literal `null` (not `[]`) when nothing is running.
    instances = json.loads(out.stdout) or []
    return any(inst.get("name") == name for inst in instances)


def start_instance(name: str) -> None:
    subprocess.run(
        ["kraft", "run", "-d", "-p", "8080:80", "--name", name, "."],
        cwd=str(PROJECT_DIR),
        check=True,
    )
    # Give the unikernel a moment to finish booting before we attach.
    time.sleep(1.5)


def stop_and_remove(name: str) -> None:
    subprocess.run(["kraft", "stop", name], check=False)
    subprocess.run(["kraft", "rm", name], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="vmicapture", help="kraft instance name")
    parser.add_argument("--duration", type=float, default=30.0, help="capture duration in seconds")
    parser.add_argument("--log", default=str(HERE / "logs" / "capture.jsonl"))
    parser.add_argument("--include", default="", help="comma-separated syscall numbers to include (default: all)")
    parser.add_argument("--exclude", default="", help="comma-separated syscall numbers to exclude")
    parser.add_argument("--max-events", type=int, default=None)
    args = parser.parse_args()

    we_started_it = not instance_is_running(args.name)
    if we_started_it:
        print(f"[run_capture] starting instance {args.name!r}")
        start_instance(args.name)
    else:
        print(f"[run_capture] instance {args.name!r} already running, attaching only")

    runtime_dir = find_instance_runtime_dir(args.name)
    port = find_free_port()
    attach_gdbserver(runtime_dir / "mon.sock", port)
    print(f"[run_capture] gdbstub attached on 127.0.0.1:{port}")

    env = dict(os.environ)
    env["VMI_LOG_PATH"] = args.log
    if args.include:
        env["VMI_INCLUDE_NRS"] = args.include
    if args.exclude:
        env["VMI_EXCLUDE_NRS"] = args.exclude
    if args.max_events:
        env["VMI_MAX_EVENTS"] = str(args.max_events)

    print(f"[run_capture] launching gdb capture on port {port}")
    proc = launch_gdb_capture(port, env)

    try:
        proc.wait(timeout=args.duration)
        print("[run_capture] gdb exited on its own before the duration elapsed (check --max-events?)")
        drain_gdb_output(proc)
    except subprocess.TimeoutExpired:
        print(f"[run_capture] duration ({args.duration}s) elapsed, detaching gdb")
        stop_gdb_capture(proc)

    if we_started_it:
        print(f"[run_capture] stopping/removing instance {args.name!r}")
        stop_and_remove(args.name)
    else:
        print(f"[run_capture] leaving instance {args.name!r} running (was already running before this script)")

    log_path = Path(args.log)
    n_events = sum(1 for _ in open(log_path)) if log_path.exists() else 0
    print(f"[run_capture] captured {n_events} events -> {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
