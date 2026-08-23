#!/usr/bin/env python3
"""Phase 3: A/B benchmark of HTTP throughput/latency, baseline (no
gdbstub) vs monitored (VMI breakpoint active on every syscall).

Usage:
    python3 bench_overhead.py --reps 5 --requests 2000 --concurrency 10

Runs `ab -n <requests> -c <concurrency> http://localhost:8080/` <reps>
times under each condition against the SAME running instance (attaching/
detaching the gdbstub between conditions, not restarting the unikernel),
so boot-time variance doesn't confound the comparison. Reports
requests/sec and time-per-request (mean, p50, p90, p99) as mean +/-
stddev across repetitions for each condition.

Must be run inside `sg docker -c "sg kvm -c '...'"` (or with those groups
already active).
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from attach_gdbstub import find_instance_runtime_dir, find_free_port, attach_gdbserver  # noqa: E402
from gdb_session import launch_gdb_capture, stop_gdb_capture  # noqa: E402
from run_capture import instance_is_running, start_instance, stop_and_remove  # noqa: E402

URL = "http://localhost:8080/"

AB_PATTERNS = {
    "requests_per_sec": re.compile(r"Requests per second:\s+([\d.]+)"),
    "mean_ms": re.compile(r"Time per request:\s+([\d.]+)\s+\[ms\]\s+\(mean\)"),
    "p50_ms": re.compile(r"^\s*50%\s+(\d+)", re.MULTILINE),
    "p90_ms": re.compile(r"^\s*90%\s+(\d+)", re.MULTILINE),
    "p99_ms": re.compile(r"^\s*99%\s+(\d+)", re.MULTILINE),
    "failed_requests": re.compile(r"Failed requests:\s+(\d+)"),
}


def run_ab(requests: int, concurrency: int) -> dict:
    out = subprocess.run(
        ["ab", "-n", str(requests), "-c", str(concurrency), URL],
        capture_output=True, text=True, timeout=120,
    )
    text = out.stdout
    result = {}
    for key, pattern in AB_PATTERNS.items():
        m = pattern.search(text)
        if m is None:
            raise RuntimeError(f"could not parse {key!r} from ab output:\n{text}")
        result[key] = float(m.group(1))
    return result


def run_ab_reps(requests: int, concurrency: int, reps: int, label: str) -> list:
    """Run `reps` repetitions, tolerating a rep failing outright (e.g. the
    guest crashing under load -- observed happening at 2000 req/c10 against
    this 64M single-worker unikernel, independent of VMI monitoring).
    A failed rep is logged and skipped rather than losing all prior data."""
    results = []
    for i in range(reps):
        try:
            results.append(run_ab(requests, concurrency))
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            print(f"[bench] WARNING: {label} rep {i + 1}/{reps} failed, skipping: {e}")
    if not results:
        raise RuntimeError(f"all {reps} reps of {label!r} failed -- nothing to report")
    if len(results) < reps:
        print(f"[bench] {label}: {len(results)}/{reps} reps succeeded")
    return results


def summarize(reps: list) -> dict:
    keys = reps[0].keys()
    return {
        key: {
            "mean": statistics.mean(r[key] for r in reps),
            "stddev": statistics.stdev(r[key] for r in reps) if len(reps) > 1 else 0.0,
        }
        for key in keys
    }


def print_summary(label: str, summary: dict) -> None:
    print(f"\n== {label} ==")
    for key, stats in summary.items():
        print(f"  {key:20s} {stats['mean']:10.3f} +/- {stats['stddev']:.3f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="vmibench")
    parser.add_argument("--reps", type=int, default=5)
    # NOTE: 2000 req / concurrency 10 was observed to crash this 64M
    # single-worker unikernel outright (guest panic mid-`open()`, in the
    # unmonitored baseline condition -- unrelated to VMI tooling). Default
    # to a scale confirmed stable (500/5); raise deliberately if exploring
    # this unikernel's load limits, that's a separate investigation.
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--out", default=str(HERE / "logs" / "bench_overhead_result.json"))
    args = parser.parse_args()

    we_started_it = not instance_is_running(args.name)
    if we_started_it:
        print(f"[bench] starting instance {args.name!r}")
        start_instance(args.name)
    time.sleep(1.0)

    print(f"[bench] warming up ({args.name!r})")
    run_ab(50, args.concurrency)  # untimed warmup, discard result

    print(f"[bench] baseline: {args.reps} reps of ab -n {args.requests} -c {args.concurrency}")
    baseline_reps = run_ab_reps(args.requests, args.concurrency, args.reps, "baseline")
    baseline_summary = summarize(baseline_reps)
    print_summary("baseline (no gdbstub)", baseline_summary)

    print("[bench] attaching gdbstub + monitor.py for the monitored condition")
    runtime_dir = find_instance_runtime_dir(args.name)
    port = find_free_port()
    attach_gdbserver(runtime_dir / "mon.sock", port)
    env = dict(os.environ)
    env["VMI_LOG_PATH"] = str(HERE / "logs" / "bench_monitor_capture.jsonl")
    gdb_proc = launch_gdb_capture(port, env)
    time.sleep(1.0)  # let the breakpoint arm before benchmarking

    try:
        print(f"[bench] monitored: {args.reps} reps of ab -n {args.requests} -c {args.concurrency}")
        monitored_reps = run_ab_reps(args.requests, args.concurrency, args.reps, "monitored")
    finally:
        print("[bench] detaching gdbstub")
        stop_gdb_capture(gdb_proc)

    monitored_summary = summarize(monitored_reps)
    print_summary("monitored (VMI breakpoint active)", monitored_summary)

    if we_started_it:
        print(f"[bench] stopping/removing instance {args.name!r}")
        stop_and_remove(args.name)

    result = {
        "requests": args.requests,
        "concurrency": args.concurrency,
        "reps": args.reps,
        "baseline": {"per_rep": baseline_reps, "summary": baseline_summary},
        "monitored": {"per_rep": monitored_reps, "summary": monitored_summary},
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"\n[bench] wrote {out_path}")

    rps_baseline = baseline_summary["requests_per_sec"]["mean"]
    rps_monitored = monitored_summary["requests_per_sec"]["mean"]
    if rps_baseline > 0:
        pct = 100.0 * (rps_baseline - rps_monitored) / rps_baseline
        print(f"[bench] throughput change under monitoring: {-pct:+.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
