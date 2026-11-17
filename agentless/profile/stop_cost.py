#!/usr/bin/env python3
"""Where does the cost of one trap stop go? (Phase 11 overhead analysis)

    collector/.venv/bin/python agentless/profile/stop_cost.py --instance prof1 \\
        --host-port 8093 --gdb-port 1261 [--rounds 3] [-n 1000]

One running instance (unmodified image), one trap on writev (called once
per keep-alive request), `ab -k -c 1`. Each variant attaches a client,
runs ab, detaches; rounds alternate the order. Added latency per stop =
(mean latency - base mean latency) / stops per request.

Variants (the client side shrinks step by step):
  base         no client
  c_null       C client: g, P rip, c                         (minimum that works)
  c_null_spin  same, busy-polling the socket (no wakeup on the client side)
  c_read       C: g, m (saved regs), P, c                    (= vmi_trap --no-ret)
  c_ret        C: entry g, m, Z0 exit, P, c; exit g, z0, c   (= vmi_trap)
  py_noret     vmi_trap.py --no-ret
  py_ret       vmi_trap.py
"""
import argparse
import csv
import json
import re
import signal
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AG = HERE.parent
ROOT = AG.parent
PY = str(ROOT / "collector" / ".venv" / "bin" / "python")

traps = json.loads((AG / "traps.json").read_text())
W = traps["sites"]["20"]                       # writev
assert W["name"] == "writev"
SITE, TARGET, EXIT = W["site"], W["target"], traps["exit_site"]


def probe(mode, port, spin=0):
    return [str(HERE / "rsp_probe"), "--port", str(port), "--site", hex(SITE),
            "--target", hex(TARGET), "--exit", hex(EXIT), "--mode", mode, "--spin", str(spin)]


def pytool(inst, port, raw, extra):
    return [PY, str(AG / "vmi_trap.py"), "--instance", inst, "--port", str(port),
            "--syscalls", "writev", "--check-interval-s", "0", "--profile",
            "--jsonl", str(raw / "py.jsonl"), "--stats", str(raw / "py.stats.json"), *extra]


def ab(url, n):
    out = subprocess.run(["ab", "-q", "-k", "-s", "10", "-n", str(n), "-c", "1", url],
                         capture_output=True, text=True).stdout
    g = lambda pat: float(re.search(pat, out).group(1))  # noqa: E731
    return {"rps": g(r"Requests per second:\s+([\d.]+)"),
            "mean_ms": g(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)"),
            "complete": int(g(r"Complete requests:\s+(\d+)")),
            "failed": int(g(r"Failed requests:\s+(\d+)"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    ap.add_argument("--host-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("-n", type=int, default=1000)
    ap.add_argument("--variants", default="base,c_null,c_null_spin,c_read,c_ret,py_noret,py_ret")
    ap.add_argument("--out", default=str(ROOT / "logs" / "p11_stop_cost.csv"))
    ap.add_argument("--raw", default=str(ROOT / "logs" / "p11_stop_cost_raw"))
    a = ap.parse_args()
    raw = Path(a.raw)
    raw.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{a.host_port}/"
    variants = a.variants.split(",")
    cmds = {"c_null": probe("null", a.gdb_port), "c_null_spin": probe("null", a.gdb_port, 1),
            "c_read": probe("read", a.gdb_port), "c_ret": probe("ret", a.gdb_port),
            "py_noret": pytool(a.instance, a.gdb_port, raw, ["--no-ret"]),
            "py_ret": pytool(a.instance, a.gdb_port, raw, [])}
    rows = []
    for rnd in range(a.rounds):
        order = variants if rnd % 2 == 0 else variants[::-1]
        for v in order:
            proc = None
            if v != "base":
                out = open(raw / f"{v}.r{rnd}.json", "w")
                proc = subprocess.Popen(cmds[v], stdout=out,
                                        stderr=open(raw / f"{v}.r{rnd}.err", "w"))
                time.sleep(2.5 if v.startswith("py") else 1.0)
            r = ab(url, a.n)
            row = {"variant": v, "round": rnd, **r}
            if proc is not None:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=30)
                if v.startswith("py"):
                    st = json.loads((raw / "py.stats.json").read_text())
                    (raw / f"{v}.r{rnd}.json").write_text(json.dumps(st, indent=1))
                    row["stops"] = st["stops"]
                    row["handling_us"] = st.get("mean_stop_handling_us")
                    row["detail"] = json.dumps(st.get("rsp_profile_us"))
                else:
                    st = json.loads((raw / f"{v}.r{rnd}.json").read_text())
                    row["stops"] = st["stops"]
                    he, hx = st["handling_entry"], st["handling_exit"]
                    row["handling_us"] = round((he["mean_us"] * he["n"] + hx["mean_us"] * hx["n"])
                                               / max(1, he["n"] + hx["n"]), 1)
                    row["detail"] = json.dumps({k: st[k]["mean_us"] for k in
                                                ("g", "m", "P", "Z0", "z0", "c_send")
                                                if st[k]["n"]})
            rows.append(row)
            print(json.dumps(row), flush=True)
            time.sleep(0.5)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["variant", "round", "rps", "mean_ms", "complete",
                                          "failed", "stops", "handling_us", "detail"])
        w.writeheader()
        w.writerows(rows)

    base = [r["mean_ms"] for r in rows if r["variant"] == "base"]
    b = sum(base) / len(base)
    print(f"\nbase mean latency {b * 1000:.1f} us")
    print(f"{'variant':12s} {'lat us':>8s} {'stops/req':>9s} {'added/stop us':>13s} "
          f"{'client us/stop':>14s} {'outside client':>14s}")
    for v in variants[1:]:
        rs = [r for r in rows if r["variant"] == v]
        lat = sum(r["mean_ms"] for r in rs) / len(rs) * 1000
        spr = sum(r["stops"] / r["complete"] for r in rs) / len(rs)
        add = (lat - b * 1000) / spr
        hu = sum(r["handling_us"] for r in rs) / len(rs)
        print(f"{v:12s} {lat:8.1f} {spr:9.2f} {add:13.1f} {hu:14.1f} {add - hu:14.1f}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
