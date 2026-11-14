#!/usr/bin/env python3
"""Throughput of agentless selective trapping (Phase 11).

    collector/.venv/bin/python agentless/bench_agentless.py [--reps 3] [-n 300] [-c 5]

Per condition: a fresh `kraft run` instance (unmodified image, distro QEMU),
one warm-up curl, vmi_trap.py attached (except `base`), then `ab -n N -c C`
REPS times. Fresh instances keep each condition below the TIME_WAIT limit
(Phase 10-7: about 3,100 connections in 120 s).
"""

import argparse
import csv
import json
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT.parent
PY = str(ROOT / "collector" / ".venv" / "bin" / "python")

CONDITIONS = {
    "base": None,
    "rare": ["--syscalls", "connect,socket"],
    "net": ["--group", "NET"],
    "netfd_noret": ["--group", "NETFD", "--no-ret"],
    "netfd": ["--group", "NETFD"],
    "all": ["--group", "ALL"],
}


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ab(url, n, c):
    out = sh("ab", "-q", "-n", str(n), "-c", str(c), url).stdout
    rps = float(re.search(r"Requests per second:\s+([\d.]+)", out).group(1))
    failed = int(re.search(r"Failed requests:\s+(\d+)", out).group(1))
    mean = float(re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)", out).group(1))
    return rps, failed, mean


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("-n", type=int, default=300)
    ap.add_argument("-c", type=int, default=5)
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--host-port", type=int, default=8092)
    ap.add_argument("--gdb-port", type=int, default=1250)
    ap.add_argument("--out", default=str(ROOT / "logs" / "bench_p11.csv"))
    a = ap.parse_args()
    url = f"http://127.0.0.1:{a.host_port}/"
    raw = ROOT / "logs" / "bench_p11_raw"
    raw.mkdir(exist_ok=True)

    rows = []
    for cond in a.conditions.split(","):
        name = f"p11{cond.replace('_', '')}{int(time.time()) % 100000}"
        r = sh("kraft", "run", "-d", "-p", f"{a.host_port}:80", "--name", name, ".", cwd=APP)
        if r.returncode:
            sys.exit(f"kraft run failed: {r.stderr[-500:]}")
        time.sleep(3)
        sh("curl", "-s", "-o", "/dev/null", url)
        tool = None
        if CONDITIONS[cond] is not None:
            tool = subprocess.Popen(
                [PY, str(HERE / "vmi_trap.py"), "--instance", name, "--port", str(a.gdb_port),
                 "--jsonl", str(raw / f"{cond}.jsonl"), "--stats", str(raw / f"{cond}.stats.json"),
                 *CONDITIONS[cond]],
                stderr=open(raw / f"{cond}.err", "w"))
            time.sleep(3)
        for rep in range(a.reps):
            rps, failed, mean = ab(url, a.n, a.c)
            rows.append({"condition": cond, "rep": rep, "rps": rps, "failed": failed,
                         "mean_ms": mean})
            print(f"{cond:12s} rep {rep}: {rps:9.1f} req/s  failed {failed}  mean {mean} ms",
                  flush=True)
        if tool is not None:
            tool.send_signal(signal.SIGINT)
            tool.wait(timeout=60)
            st = json.loads((raw / f"{cond}.stats.json").read_text())
            rows[-1]["stats"] = json.dumps({k: st.get(k) for k in (
                "entries", "exits", "unmatched_exits", "exit_step_overs", "nr_mismatch",
                "foreign_traps", "alerts", "mean_stop_handling_us", "integrity_checks",
                "mean_check_ms")})
            print(f"{cond:12s} stats {rows[-1]['stats']}", flush=True)
        sh("kraft", "stop", name)
        sh("kraft", "rm", name)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["condition", "rep", "rps", "failed", "mean_ms", "stats"])
        w.writeheader()
        w.writerows(rows)
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
