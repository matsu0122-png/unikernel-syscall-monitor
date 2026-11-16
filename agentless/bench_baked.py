#!/usr/bin/env python3
"""Performance of baked selective trapping (Phase 11-2).

    python3 agentless/bake_traps.py --group NET   # etc., see SELECTIONS
    collector/.venv/bin/python agentless/bench_baked.py [--rounds 2] [--reps 3] [-n 400]

Per condition, concurrency and round: a fresh `kraft run --qemu agentless/qemu-trap.sh`
instance of the base image (qemu-trap.sh passes it straight to QEMU) or of a
baked image from agentless/build/<dir>/. Measured:

  boot_s     kraft run start -> first HTTP 200 (includes, for baked images,
             QEMU paused while vmi_trap.py checks the code and registers
             every site, and the startup syscalls' traps)
  per ab run (ab -n N -c C, C in --conc):
    rps, mean / p50 / p90 / p99 latency, failed
    records    JSONL records the tool wrote during the run, per request
    tool_cpu   vmi_trap.py user+sys CPU during the run, us per request
    qemu_cpu   QEMU user+sys CPU during the run, us per request
  per instance (vmi_trap.py --stats): stops, mean stop handling, checks

Rounds alternate the condition order to spread drift. Fresh instances keep
each instance below the TIME_WAIT limit (Phase 10-7: about 3,100
connections in 120 s; one stall seen at ~2,000): reps * N is capped at 1,500. A run
where ab gives up is recorded as stalled and ends that instance.
"""

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT.parent
BASE_IMAGE = APP / ".unikraft" / "build" / "nginx_qemu-x86_64"
HZ = os.sysconf("SC_CLK_TCK")

# condition -> (image dir under agentless/build or None for base, extra env)
CONDITIONS = {
    "base": (None, {}),
    "rare": ("rare", {}),                 # socket,connect: startup only (not recorded)
    "net": ("net", {}),
    "net_otlp": ("net", {"VMI_TRAP_OTEL": "otlp"}),
    "netfd_noret": ("netfd", {"VMI_TRAP_ARGS": "--no-ret"}),
    "netfd": ("netfd", {}),
    "file": ("file", {}),
    "all": ("all", {}),
}


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def cpu_s(pid):
    if pid is None:
        return None
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except OSError:
        return None
    return (int(f[11]) + int(f[12])) / HZ      # utime, stime


def pgrep1(pattern):
    out = sh("pgrep", "-f", "--", pattern).stdout.split()
    return int(out[0]) if len(out) == 1 else None


def kraft_pid(name):
    try:
        ps = json.loads(sh("kraft", "ps", "-l", "-o", "json").stdout)
    except ValueError:
        return None
    pids = [m.get("pid") for m in ps if m.get("name") == name]
    return int(pids[0]) if len(pids) == 1 and pids[0] else None


def lines(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def ab(url, n, c):
    """None when ab gave up (lwIP TIME_WAIT stall, Phase 10-7)."""
    out = sh("ab", "-s", "10", "-n", str(n), "-c", str(c), url).stdout
    if "Requests per second" not in out:
        return None
    g = lambda rx: re.search(rx, out).group(1)
    pct = dict(re.findall(r"^\s+(\d+)%\s+(\d+)", out, re.M))
    return {"rps": float(g(r"Requests per second:\s+([\d.]+)")),
            "failed": int(g(r"Failed requests:\s+(\d+)")),
            "mean_ms": float(g(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)")),
            "p50_ms": int(pct["50"]), "p90_ms": int(pct["90"]), "p99_ms": int(pct["99"])}


def wait_http(url, limit_s=60):
    t_end = time.time() + limit_s
    while time.time() < t_end:
        r = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "1", url)
        if r.stdout == "200":
            return True
        time.sleep(0.05)
    return False


def run_condition(cond, c, rnd, a, raw, workdir):
    img_dir, extra_env = CONDITIONS[cond]
    image = BASE_IMAGE if img_dir is None else HERE / "build" / img_dir / BASE_IMAGE.name
    if img_dir is not None and not Path(f"{image}.traps.json").exists():
        sys.exit(f"{image}: not baked (run agentless/bake_traps.py)")
    tag = f"{cond}-c{c}-r{rnd}"
    jsonl = raw / f"{tag}.jsonl"
    stats = raw / f"{tag}.stats.json"
    for p in (jsonl, stats):
        p.unlink(missing_ok=True)
    env = dict(os.environ, VMI_TRAP_OTEL="none", VMI_TRAP_JSONL=str(jsonl))
    env.update(extra_env)
    env["VMI_TRAP_ARGS"] = (env.get("VMI_TRAP_ARGS", "") + f" --stats {stats}").strip()

    name = f"p11b{cond.replace('_', '')}{int(time.time()) % 100000}"
    url = f"http://127.0.0.1:{a.host_port}/"
    t0 = time.time()
    r = sh("kraft", "run", "-d", "--qemu", str(HERE / "qemu-trap.sh"),
           "-p", f"{a.host_port}:80", "--name", name, str(image), "/usr/bin/nginx",
           cwd=workdir, env=env)
    if r.returncode:
        sys.exit(f"{tag}: kraft run failed: {r.stderr[-800:]}")
    ok = wait_http(url)
    boot_s = time.time() - t0
    if not ok:
        sh("kraft", "rm", "--force", name)
        sys.exit(f"{tag}: no HTTP 200 within 60 s")

    tool = None if img_dir is None else pgrep1(f"vmi_trap.py .*--stats {stats}")
    qemu = kraft_pid(name)
    if img_dir is not None and tool is None:
        sys.exit(f"{tag}: vmi_trap.py not found")
    print(f"{tag:16s} boot {boot_s:.2f} s  (tool pid {tool}, qemu pid {qemu})", flush=True)

    rows = []
    for rep in range(a.reps):
        rec0, tc0, qc0 = lines(jsonl), cpu_s(tool), cpu_s(qemu)
        res = ab(url, a.n, c)
        if res is None:
            print(f"{tag:16s} rep {rep}: ab gave up (stall); rest of this instance skipped",
                  flush=True)
            rows.append(dict(condition=cond, round=rnd, conc=c, rep=rep, stalled=1,
                             boot_s=round(boot_s, 3)))
            break
        time.sleep(0.2)                       # last records reach the JSONL
        rec1, tc1, qc1 = lines(jsonl), cpu_s(tool), cpu_s(qemu)
        res.update(stalled=0, condition=cond, round=rnd, conc=c, rep=rep, boot_s=round(boot_s, 3),
                   records_per_req=round((rec1 - rec0) / a.n, 2),
                   tool_cpu_us_per_req=(round((tc1 - tc0) / a.n * 1e6, 1)
                                        if tool else None),
                   qemu_cpu_us_per_req=(round((qc1 - qc0) / a.n * 1e6, 1)
                                        if qemu else None))
        rows.append(res)
        print(f"{tag:16s} c={c} rep {rep}: {res['rps']:9.1f} req/s  mean {res['mean_ms']} ms "
              f"p99 {res['p99_ms']} ms  rec/req {res['records_per_req']}  "
              f"tool {res['tool_cpu_us_per_req']} us/req  qemu {res['qemu_cpu_us_per_req']} "
              f"us/req  failed {res['failed']}", flush=True)

    st = {}
    if tool is not None:
        os.kill(tool, signal.SIGINT)
        t_end = time.time() + 60
        while time.time() < t_end and Path(f"/proc/{tool}").exists():
            time.sleep(0.1)
        if stats.exists():
            st = json.loads(stats.read_text())
    sh("kraft", "stop", name)
    sh("kraft", "rm", name)
    keep = ("stops", "entries", "exits", "unmatched_exits", "nr_mismatch", "foreign_traps",
            "alerts", "mean_stop_handling_us", "integrity_checks", "mean_check_ms",
            "startup", "startup_stops")
    s = json.dumps({k: st.get(k) for k in keep}) if st else ""
    if s:
        print(f"{tag:16s} stats {s}", flush=True)
    for row in rows:
        row["stats"] = s
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("-n", type=int, default=400)
    ap.add_argument("--conc", default="1,5", help="ab -c values")
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--host-port", type=int, default=8093)
    ap.add_argument("--out", default=str(ROOT / "logs" / "bench_p11_baked.csv"))
    ap.add_argument("--raw", default=str(ROOT / "logs" / "bench_p11_raw" / "baked"),
                    help="per-instance JSONL and stats")
    a = ap.parse_args()
    a.conc = [int(x) for x in a.conc.split(",")]
    conds = a.conditions.split(",")
    for cnd in conds:
        if cnd not in CONDITIONS:
            sys.exit(f"unknown condition {cnd}; have {list(CONDITIONS)}")
    if a.reps * a.n > 1500:
        sys.exit("reps * n > 1500: TIME_WAIT stall per instance (seen at ~2,000)")
    raw = Path(a.raw).resolve()       # kraft runs in a temporary directory
    raw.mkdir(parents=True, exist_ok=True)

    rows = []
    with tempfile.TemporaryDirectory(prefix="bench_baked_") as workdir:  # no Kraftfile
        for rnd in range(a.rounds):
            order = conds if rnd % 2 == 0 else conds[::-1]
            for cond in order:
                for c in a.conc:
                    rows += run_condition(cond, c, rnd, a, raw, workdir)

    fields = ["condition", "round", "conc", "rep", "stalled", "rps", "failed", "mean_ms", "p50_ms",
              "p90_ms", "p99_ms", "records_per_req", "tool_cpu_us_per_req",
              "qemu_cpu_us_per_req", "boot_s", "stats"]
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
