#!/usr/bin/env python3
"""Phase 6: three-way A/B/C throughput benchmark.

    A. baseline_custom -- our custom-built QEMU (target/i386/kvm/
       vmi-syscall-monitor.c compiled in), monitor DISABLED
       (VMI_MONITOR_ADDR unset). Same binary as (B); isolates exactly the
       cost of the monitoring mechanism itself, not incidental
       differences between our debug build and the distro package.
    B. inline -- same custom QEMU, monitor ENABLED (breakpoint armed,
       int3-in-QEMU capture active, no gdb/RSP involved at all).
    C. gdb_rsp -- the existing Phase 1-4 mechanism: stock system QEMU +
       external gdb attached over RSP, running monitor.py (see
       bench_overhead.py, which this reuses the same ab-parsing/attach
       helpers from).

Unlike bench_overhead.py (which switches conditions on ONE running
instance to control for boot-time variance), A/B/C here each need a
genuinely different QEMU process/binary, so each condition boots its own
fresh instance. To keep boot variance from confounding the comparison,
each instance is given a fixed settle time after boot before any ab run
starts (boot time itself is never included in the measured window).

Usage:
    python3 bench_overhead_inline.py --reps 3 --requests 200 --concurrency 5 \
        --qemu /home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64
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

from attach_gdbstub import find_instance_runtime_dir, find_free_port, attach_gdbserver  # noqa: E402
from gdb_session import launch_gdb_capture, stop_gdb_capture  # noqa: E402
from bench_overhead import run_ab, run_ab_reps, summarize, print_summary  # noqa: E402
from run_capture_inline import resolve_syscall_addr  # noqa: E402

DEFAULT_QEMU = "/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64"
BOOT_SETTLE_S = 3.0


def kraft_run(name: str, qemu_path: str, env_extra: dict) -> None:
    env = dict(os.environ)
    env.update(env_extra)
    cmd = ["kraft", "run", "-d", "-p", "8080:80", "--name", name]
    if qemu_path:
        cmd += ["--qemu", qemu_path]
    cmd.append(".")
    subprocess.run(cmd, cwd=str(PROJECT_DIR), env=env, check=True)
    time.sleep(BOOT_SETTLE_S)


def stop_and_remove(name: str) -> None:
    subprocess.run(["kraft", "stop", name], check=False)
    subprocess.run(["kraft", "rm", name], check=False)


def run_condition_custom_qemu(label: str, name: str, qemu_path: str, addr: int,
                               monitor_enabled: bool, args) -> list:
    env_extra = {}
    if monitor_enabled:
        env_extra["VMI_MONITOR_ADDR"] = hex(addr)
        env_extra["VMI_MONITOR_LOG"] = str(HERE / "logs" / f"bench_inline_{name}.jsonl")
    print(f"[bench3] starting {label} instance {name!r} (custom qemu, "
          f"monitor={'ON' if monitor_enabled else 'off'})")
    kraft_run(name, qemu_path, env_extra)
    try:
        run_ab(50, args.concurrency)  # warmup, discard
        print(f"[bench3] {label}: {args.reps} reps of ab -n {args.requests} -c {args.concurrency}")
        reps = run_ab_reps(args.requests, args.concurrency, args.reps, label)
    finally:
        stop_and_remove(name)
    return reps


def run_condition_gdb(args) -> list:
    name = "vmibench3gdb"
    print(f"[bench3] starting gdb_rsp instance {name!r} (stock qemu + external gdb)")
    kraft_run(name, None, {})  # no --qemu: kraftkit's own default resolution (same as run_capture.py)
    try:
        runtime_dir = find_instance_runtime_dir(name)
        port = find_free_port()
        attach_gdbserver(runtime_dir / "mon.sock", port)
        env = dict(os.environ)
        env["VMI_LOG_PATH"] = str(HERE / "logs" / "bench_inline_gdb.jsonl")
        gdb_proc = launch_gdb_capture(port, env)
        time.sleep(1.0)  # let the breakpoint arm before benchmarking
        try:
            run_ab(50, args.concurrency)  # warmup, discard
            print(f"[bench3] gdb_rsp: {args.reps} reps of ab -n {args.requests} -c {args.concurrency}")
            reps = run_ab_reps(args.requests, args.concurrency, args.reps, "gdb_rsp")
        finally:
            stop_gdb_capture(gdb_proc)
    finally:
        stop_and_remove(name)
    return reps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--qemu", default=DEFAULT_QEMU)
    parser.add_argument("--out", default=str(HERE / "logs" / "bench_overhead_inline_result.json"))
    args = parser.parse_args()

    if not Path(args.qemu).is_file():
        print(f"ERROR: --qemu path does not exist: {args.qemu}", file=sys.stderr)
        return 1

    addr = resolve_syscall_addr()
    print(f"[bench3] _ukplat_syscall = {hex(addr)}")

    results = {}

    baseline_reps = run_condition_custom_qemu(
        "baseline_custom", "vmibench3base", args.qemu, addr, False, args)
    results["baseline_custom"] = {"per_rep": baseline_reps, "summary": summarize(baseline_reps)}
    print_summary("A. baseline_custom (custom qemu, monitor disabled)", results["baseline_custom"]["summary"])

    inline_reps = run_condition_custom_qemu(
        "inline", "vmibench3inline", args.qemu, addr, True, args)
    results["inline"] = {"per_rep": inline_reps, "summary": summarize(inline_reps)}
    print_summary("B. inline (custom qemu, VMI monitor active, no gdb)", results["inline"]["summary"])

    gdb_reps = run_condition_gdb(args)
    results["gdb_rsp"] = {"per_rep": gdb_reps, "summary": summarize(gdb_reps)}
    print_summary("C. gdb_rsp (stock qemu + external gdb/RSP, existing Phase 1-4 tool)", results["gdb_rsp"]["summary"])

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "requests": args.requests, "concurrency": args.concurrency, "reps": args.reps,
        **results,
    }, indent=2))
    print(f"\n[bench3] wrote {out_path}")

    rps_a = results["baseline_custom"]["summary"]["requests_per_sec"]["mean"]
    rps_b = results["inline"]["summary"]["requests_per_sec"]["mean"]
    rps_c = results["gdb_rsp"]["summary"]["requests_per_sec"]["mean"]
    print("\n=== Summary ===")
    print(f"A. baseline_custom : {rps_a:9.1f} req/s")
    print(f"B. inline monitor  : {rps_b:9.1f} req/s ({-100*(rps_a-rps_b)/rps_a:+.1f}% vs A)")
    print(f"C. gdb/RSP monitor : {rps_c:9.1f} req/s ({-100*(rps_a-rps_c)/rps_a:+.1f}% vs A)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
