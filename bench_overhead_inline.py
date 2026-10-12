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

    # Phase 8: also arm the return hook (VMI_MONITOR_RET_ADDR) in B
    python3 bench_overhead_inline.py --ret ...

    # A/B only, alternating A,B,A,B,... with a fresh instance per trial
    # (one ab run per instance, after a warmup), raw rows to CSV
    python3 bench_overhead_inline.py --ret --alternate 5 --requests 300 \
        --concurrency 5 --csv logs/bench_p8_ab.csv

    # Phase 9: overhead breakdown, rounds of C0->C1->C2->C3->C4
    python3 bench_overhead_inline.py --breakdown 5 --requests 300 \
        --concurrency 5 --csv logs/bench_breakdown.csv

--alternate exists because this unikernel falls over after roughly 1,500
requests per instance, and because interleaving A and B spreads slow
drift on the host (other load, frequency scaling) over both conditions
instead of biasing whichever ran later. In B, each trial is checked for
the monitor actually being live: >0 JSONL events, and nothing in
<log>.debug.log about a failed arm or (with --ret) an unmatched return.
A trial failing that check is kept in the CSV and marked invalid, not
dropped.
"""
import argparse
import csv
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_DIR = HERE.parent
sys.path.insert(0, str(HERE))

from attach_gdbstub import find_instance_runtime_dir, find_free_port, attach_gdbserver  # noqa: E402
from gdb_session import launch_gdb_capture, stop_gdb_capture  # noqa: E402
from bench_overhead import URL, AB_PATTERNS, run_ab, run_ab_reps, summarize, print_summary  # noqa: E402
from run_capture_inline import resolve_syscall_addr, resolve_syscall_ret_addr  # noqa: E402

DEFAULT_QEMU = "/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/build/qemu-system-x86_64"
BOOT_SETTLE_S = 3.0
WARMUP_REQUESTS = 50

# Lines vmi-syscall-monitor.c writes to <log>.debug.log when a hook did
# not get armed, or (return hook) a return could not be paired.
DEBUG_FAILURE_MARKERS = (
    "failed",            # kvm_insert_breakpoint() / verification read / boot-sync arm FAILED
    "NOT 0xcc",
    "giving up",
    "reached max attempts",
    "no matching entry",
    "[error]",           # Phase 9: step-over remove/reinsert failures
)

# Phase 9 overhead breakdown: each condition adds one stage on top of the
# previous one. C1-C4 all arm both the entry and the return hook.
BREAKDOWN_CONDITIONS = {
    "C0": None,  # monitor off
    "C1": {"VMI_MONITOR_NO_REGS": "1", "VMI_MONITOR_NO_LOG": "1", "VMI_MONITOR_NO_DEBUGLOG": "1"},
    "C2": {"VMI_MONITOR_NO_LOG": "1", "VMI_MONITOR_NO_DEBUGLOG": "1"},
    "C3": {"VMI_MONITOR_NO_DEBUGLOG": "1"},
    "C4": {},    # Phase 8 default
}
STATS_RE = re.compile(r"\[stats\] \w+: entry_hits=(\d+) ret_hits=(\d+) ret_unmatched=(\d+)")


def kraft_run(name: str, qemu_path: str, env_extra: dict) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("VMI_MONITOR_")}
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


def monitor_env(addr: int, ret_addr, log_path: Path) -> dict:
    env = {"VMI_MONITOR_ADDR": hex(addr), "VMI_MONITOR_LOG": str(log_path)}
    if ret_addr is not None:
        env["VMI_MONITOR_RET_ADDR"] = hex(ret_addr)
    return env


def run_condition_custom_qemu(label: str, name: str, qemu_path: str, addr: int,
                               monitor_enabled: bool, args, ret_addr=None) -> list:
    env_extra = {}
    if monitor_enabled:
        env_extra = monitor_env(addr, ret_addr, HERE / "logs" / f"bench_inline_{name}.jsonl")
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


def run_ab_saving(requests: int, concurrency: int, out_path: Path) -> dict:
    """run_ab(), but keeps ab's full output and also parses the
    connection-time "Total:" row (mean/max), which the percentiles alone
    don't show."""
    out = subprocess.run(["ab", "-n", str(requests), "-c", str(concurrency), URL],
                         capture_output=True, text=True, timeout=120)
    out_path.write_text(out.stdout + out.stderr)
    result = {}
    for key, pattern in AB_PATTERNS.items():
        m = pattern.search(out.stdout)
        if m is None:
            raise RuntimeError(f"could not parse {key!r} from ab output (see {out_path})")
        result[key] = float(m.group(1))
    m = re.search(r"^Total:\s+(\d+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+(\d+)", out.stdout, re.MULTILINE)
    result["total_mean_ms"], result["total_max_ms"] = (float(m.group(2)), float(m.group(5))) if m else (None, None)
    return result


def check_monitor(log_path: Path, addr: int, ret_addr) -> dict:
    """Did the monitor really run in this trial? Read after the instance
    is stopped, so QEMU has flushed the unfinished entries too."""
    debug_path = Path(str(log_path) + ".debug.log")
    events = ret_events = accept4 = 0
    if log_path.exists():
        for line in open(log_path):
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            events += 1
            ret_events += evt.get("ret") is not None
            accept4 += evt.get("syscall") == "accept4"
    debug = debug_path.read_text(errors="ignore") if debug_path.exists() else ""
    problems = sorted({m for m in DEBUG_FAILURE_MARKERS if m in debug})
    if events == 0:
        problems.append("0 JSONL events")
    if not debug:
        problems.append("no debug.log")
    hooks = [addr] + ([ret_addr] if ret_addr is not None else [])
    for h in hooks:
        if f"readback=0xcc confirmed at {h:#x}" not in debug:
            problems.append(f"arm at {h:#x} never confirmed")
    if ret_addr is not None and ret_events == 0:
        problems.append("no events with a return value")
    return {"events": events, "ret_events": ret_events, "accept4": accept4,
            "valid": not problems, "problems": problems}


def check_breakdown(cond: str, log_path: Path, addr: int, ret_addr: int, expect_accept4: int) -> dict:
    """Phase 9 validity check: the [stats] hit counters must show both hooks
    firing in step (entry - ret is 0 or 1: the epoll_wait still blocked at
    shutdown), and in the conditions that write JSONL every request must
    show up as one accept4."""
    debug_path = Path(str(log_path) + ".debug.log")
    debug = debug_path.read_text(errors="ignore") if debug_path.exists() else ""
    problems = sorted({m for m in DEBUG_FAILURE_MARKERS if m in debug})
    for h in (addr, ret_addr):
        if f"readback=0xcc confirmed at {h:#x}" not in debug:
            problems.append(f"arm at {h:#x} never confirmed")
    m = STATS_RE.search(debug)
    entry = ret = None
    if m is None:
        problems.append("no [stats] line")
    else:
        entry, ret = int(m.group(1)), int(m.group(2))
        if entry == 0:
            problems.append("0 entry hits")
        if not 0 <= entry - ret <= 1:
            problems.append(f"entry/ret hits differ by {entry - ret}")
    accept4 = None
    if cond in ("C3", "C4"):
        accept4 = sum(1 for line in open(log_path) if '"syscall": "accept4"' in line) \
            if log_path.exists() else 0
        if accept4 != expect_accept4:
            problems.append(f"accept4={accept4}, expected {expect_accept4}")
        events = sum(1 for _ in open(log_path)) if log_path.exists() else 0
        if entry is not None and events != entry:
            problems.append(f"JSONL has {events} events but {entry} entry hits")
    return {"entry_hits": entry, "ret_hits": ret, "accept4": accept4,
            "valid": not problems, "problems": problems}


def run_breakdown(args, addr: int, ret_addr: int) -> int:
    raw_dir = HERE / "logs" / "bench_breakdown_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for rnd in range(1, args.breakdown + 1):
        for cond, switches in BREAKDOWN_CONDITIONS.items():
            name = f"vmibd{cond.lower()}r{rnd}"
            env_extra, log_path = {}, None
            if switches is not None:
                log_path = raw_dir / f"{cond}_round{rnd}.jsonl"
                for p in (log_path, Path(str(log_path) + ".debug.log")):
                    p.unlink(missing_ok=True)
                env_extra = {**monitor_env(addr, ret_addr, log_path), **switches}
            print(f"\n[bench3] round {rnd}/{args.breakdown} {cond}: starting {name!r} "
                  f"({' '.join(f'{k}={v}' for k, v in env_extra.items()) or 'monitor off'})")
            kraft_run(name, args.qemu, env_extra)
            ab, error = None, ""
            try:
                run_ab(WARMUP_REQUESTS, args.concurrency)  # warmup, discard
                ab = run_ab_saving(args.requests, args.concurrency,
                                   raw_dir / f"{cond}_round{rnd}.ab.txt")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                error = str(e).splitlines()[0]
                print(f"[bench3] WARNING: round {rnd} {cond} failed: {error}")
            finally:
                stop_and_remove(name)
            row = {"condition": cond, "round": rnd,
                   "req_per_s": ab and ab["requests_per_sec"],
                   "mean_latency_ms": ab and ab["mean_ms"],
                   "entry_hits": "", "ret_hits": "", "valid": ab is not None,
                   "failed_requests": ab and ab["failed_requests"],
                   "accept4": "", "note": error}
            if switches is not None:
                chk = check_breakdown(cond, log_path, addr, ret_addr,
                                      WARMUP_REQUESTS + args.requests)
                row.update({k: "" if chk[k] is None else chk[k]
                            for k in ("entry_hits", "ret_hits", "accept4")})
                row["valid"] = row["valid"] and chk["valid"]
                row["note"] = "; ".join(filter(None, [error] + chk["problems"]))
            print(f"[bench3] -> {row}")
            rows.append(row)

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n[bench3] wrote {csv_path}")

    print("\n=== req/s by condition (valid rounds only) ===")
    base = None
    for cond in BREAKDOWN_CONDITIONS:
        vals = [r["req_per_s"] for r in rows if r["condition"] == cond and r["valid"]]
        if not vals:
            print(f"{cond}: no valid rounds")
            continue
        mean = statistics.mean(vals)
        base = base or mean
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        print(f"{cond}: n={len(vals)} mean={mean:.1f} sd={sd:.1f} min={min(vals):.1f} "
              f"max={max(vals):.1f} ({100 * mean / base:.1f}% of C0)")
    return 0


def run_alternating(args, addr: int, ret_addr) -> int:
    raw_dir = HERE / "logs" / "bench_p8_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for trial in range(1, args.alternate + 1):
        for cond in ("A", "B"):
            name = f"vmibenchalt{cond.lower()}{trial}"
            env_extra, log_path = {}, None
            if cond == "B":
                log_path = raw_dir / f"B_trial{trial}.jsonl"
                for p in (log_path, Path(str(log_path) + ".debug.log")):
                    p.unlink(missing_ok=True)
                env_extra = monitor_env(addr, ret_addr, log_path)
            print(f"\n[bench3] trial {trial}/{args.alternate} condition {cond}: "
                  f"starting {name!r} ({' '.join(f'{k}={v}' for k, v in env_extra.items()) or 'monitor off'})")
            kraft_run(name, args.qemu, env_extra)
            ab, error = None, ""
            try:
                run_ab(WARMUP_REQUESTS, args.concurrency)  # warmup, discard
                ab = run_ab_saving(args.requests, args.concurrency,
                                   raw_dir / f"{cond}_trial{trial}.ab.txt")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                error = str(e).splitlines()[0]
                print(f"[bench3] WARNING: trial {trial} {cond} failed: {error}")
            finally:
                stop_and_remove(name)
            row = {"condition": cond, "trial": trial,
                   "req_per_s": ab and ab["requests_per_sec"],
                   "mean_latency_ms": ab and ab["mean_ms"],
                   "p50_ms": ab and ab["p50_ms"], "p99_ms": ab and ab["p99_ms"],
                   "failed_requests": ab and ab["failed_requests"],
                   "ab_total_mean_ms": ab and ab["total_mean_ms"],
                   "ab_total_max_ms": ab and ab["total_max_ms"],
                   "events": "", "ret_events": "", "accept4": "",
                   "monitor_valid": "", "note": error}
            if cond == "B":
                chk = check_monitor(log_path, addr, ret_addr)
                row.update({k: chk[k] for k in ("events", "ret_events", "accept4")})
                row["monitor_valid"] = chk["valid"]
                row["note"] = "; ".join(filter(None, [error] + chk["problems"]))
            if ab is None:
                row["monitor_valid"] = False if cond == "B" else ""
            print(f"[bench3] -> {row}")
            rows.append(row)

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n[bench3] wrote {csv_path}")

    print("\n=== req/s by condition (B: valid trials only) ===")
    means = {}
    for cond in ("A", "B"):
        vals = [r["req_per_s"] for r in rows if r["condition"] == cond and r["req_per_s"]
                and r["monitor_valid"] is not False]
        if not vals:
            print(f"{cond}: no usable trials")
            continue
        means[cond] = statistics.mean(vals)
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        print(f"{cond}: n={len(vals)} mean={means[cond]:.1f} sd={sd:.1f} "
              f"min={min(vals):.1f} max={max(vals):.1f}")
    if len(means) == 2:
        print(f"B / A = {100 * means['B'] / means['A']:.1f}%")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--qemu", default=DEFAULT_QEMU)
    parser.add_argument("--out", default=str(HERE / "logs" / "bench_overhead_inline_result.json"))
    parser.add_argument("--ret", action="store_true",
                         help="also set VMI_MONITOR_RET_ADDR (Phase 8 return-value capture) in the "
                              "monitored condition; address resolved via objdump like "
                              "run_capture_inline.py")
    parser.add_argument("--alternate", type=int, default=0, metavar="N",
                         help="run only A (monitor off) and B (monitor on), alternating "
                              "A,B,A,B,... for N trials each; fresh instance + warmup + one ab "
                              "run per trial; --reps is ignored")
    parser.add_argument("--breakdown", type=int, default=0, metavar="N",
                         help="Phase 9: N rounds of C0 (off), C1 (traps only), C2 (+registers), "
                              "C3 (+JSONL), C4 (+per-hit debug log = Phase 8 default); fresh "
                              "instance + warmup + one ab run per trial; implies --ret")
    parser.add_argument("--csv", default=str(HERE / "logs" / "bench_overhead_inline_alternate.csv"),
                         help="raw per-trial output for --alternate")
    args = parser.parse_args()

    if not Path(args.qemu).is_file():
        print(f"ERROR: --qemu path does not exist: {args.qemu}", file=sys.stderr)
        return 1

    addr = resolve_syscall_addr()
    print(f"[bench3] _ukplat_syscall = {hex(addr)}")
    ret_addr = resolve_syscall_ret_addr(addr) if args.ret or args.breakdown else None
    if ret_addr is not None:
        print(f"[bench3] syscall return hook = {hex(ret_addr)}")

    if args.breakdown:
        return run_breakdown(args, addr, ret_addr)
    if args.alternate:
        return run_alternating(args, addr, ret_addr)

    results = {}

    baseline_reps = run_condition_custom_qemu(
        "baseline_custom", "vmibench3base", args.qemu, addr, False, args)
    results["baseline_custom"] = {"per_rep": baseline_reps, "summary": summarize(baseline_reps)}
    print_summary("A. baseline_custom (custom qemu, monitor disabled)", results["baseline_custom"]["summary"])

    inline_reps = run_condition_custom_qemu(
        "inline", "vmibench3inline", args.qemu, addr, True, args, ret_addr)
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
