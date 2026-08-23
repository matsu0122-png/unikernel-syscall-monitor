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
    python3 run_capture_inline.py --name vmiinline --duration 15 \
        --log logs/capture_inline.jsonl \
        --qemu /home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64

If --addr is omitted, resolves _ukplat_syscall via `nm` against the
project's .dbg build (same method Phase 1/2 used), not a hardcoded
constant.
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
DEFAULT_QEMU = "/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64"


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="vmiinline")
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--log", default=str(HERE / "logs" / "capture_inline.jsonl"))
    parser.add_argument("--qemu", default=DEFAULT_QEMU)
    parser.add_argument("--addr", default=None, help="hex address, e.g. 0x101000 (default: resolved via nm)")
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

    if instance_is_running(args.name):
        print(f"[run_capture_inline] ERROR: instance {args.name!r} already running; "
              f"stop it first (this script always starts its own)", file=sys.stderr)
        return 1

    print(f"[run_capture_inline] starting instance {args.name!r} with custom QEMU")
    start_instance(args.name, args.qemu, addr, str(log_path))

    print(f"[run_capture_inline] capturing for {args.duration}s "
          f"(send requests to http://localhost:8080/ now)")
    time.sleep(args.duration)

    print(f"[run_capture_inline] stopping/removing instance {args.name!r}")
    stop_and_remove(args.name)

    n_events = sum(1 for _ in open(log_path)) if log_path.exists() else 0
    print(f"[run_capture_inline] captured {n_events} events -> {log_path}")
    if n_events == 0:
        print("[run_capture_inline] WARNING: 0 events captured -- check that "
              "VMI_MONITOR_ADDR reached the QEMU process (see its stderr/log "
              "for 'vmi-monitor: enabled' / 'breakpoint armed and VERIFIED')",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
