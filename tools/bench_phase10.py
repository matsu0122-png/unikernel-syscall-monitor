#!/usr/bin/env python3
"""Phase 10-5 benchmarks.

perf  9 conditions, alternated round by round (as Phase 8's re-measurement):
      every trial boots a fresh instance, waits 3 s, sends 50 warmup
      requests, then one `ab -n 300 -c 5`, then stops the instance.
        base          base build (no lib-vmitrace), wrapper (shared RAM)
        net-i  net-ii    NET   build, (i) nobody reads / (ii) collector->Jaeger
        netfd-i netfd-ii NETFD build, same
        all-i  all-ii    ALL   build, same
        legacy-p8     patched QEMU 6.2 (legacy/qemu_patch), entry+return
                      hooks, JSONL + debug log (= Phase 8 / Phase 9 C4)
        legacy-c1     same QEMU, traps only (= Phase 9 C1)
      The two legacy conditions use the Phase 1-9 image in ../.unikraft.

loss  ring capacity x collector poll interval x load: ALL builds with
      LIBVMITRACE_RING_ORDER 10/12/14, --poll-ms 1/10/100, ab -c 1/5/20,
      -n 1000 after the 50 warmup (1,050 requests per instance, under the
      ~1,500 at which this nginx build falls over). Collector --otel none,
      started before boot.

All instances listen on :8090 (the long-running `vmiinline` holds :8080).

    python3 tools/bench_phase10.py perf --rounds 5 --csv logs/bench_p10_perf.csv
    python3 tools/bench_phase10.py loss --csv logs/bench_p10_loss.csv
"""

import argparse
import csv
import grp
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
APP = REPO.parent
sys.path.insert(0, str(REPO / "legacy"))
sys.path.insert(0, str(REPO / "collector"))

from bench_overhead import AB_PATTERNS  # noqa: E402
from bench_overhead_inline import (BREAKDOWN_CONDITIONS, DEFAULT_QEMU,  # noqa: E402
                                   check_breakdown, monitor_env)
from vmitrace_reader import GuestRing, Manifest  # noqa: E402

PORT = 8090
URL = f"http://localhost:{PORT}/"
BUILD_ROOT = Path(os.environ.get("VMITRACE_BUILD_ROOT", "/home/matsu/vmitrace-build"))
SHM_DIR = Path("/dev/shm/vmitrace")
WRAPPER = HERE / "qemu-wrapper.sh"
COLLECTOR = REPO / "collector" / "vmitrace_collector.py"
VENV_PY = REPO / "collector" / ".venv" / "bin" / "python"
BOOT_SETTLE_S = 3.0
WARMUP = 50
LEGACY_ENTRY = 0x101000
LEGACY_RET = 0x1010da

PERF_CONDITIONS = {
    "base":      dict(kind="vmitrace", build="base",  read=False),
    "net-i":     dict(kind="vmitrace", build="net",   read=False),
    "net-ii":    dict(kind="vmitrace", build="net",   read=True),
    "netfd-i":   dict(kind="vmitrace", build="netfd", read=False),
    "netfd-ii":  dict(kind="vmitrace", build="netfd", read=True),
    "all-i":     dict(kind="vmitrace", build="all",   read=False),
    "all-ii":    dict(kind="vmitrace", build="all",   read=True),
    "legacy-p8": dict(kind="legacy", switches=BREAKDOWN_CONDITIONS["C4"], cond="C4"),
    "legacy-c1": dict(kind="legacy", switches=BREAKDOWN_CONDITIONS["C1"], cond="C1"),
}


def log(msg):
    print(f"[bench10] {msg}", flush=True)


# --- host state, Phase 9 format ---

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def host_state():
    govs = sh("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c")
    return {
        "time": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "cpu": sh("lscpu | sed -n 's/^Model name: *//p'"),
        "cpus": os.cpu_count(),
        "mem": sh("free -g | awk '/Mem:/{print $2\" GiB\"}'"),
        "os": sh(". /etc/os-release; echo $PRETTY_NAME"),
        "kernel": platform.release(),
        "governor": " ".join(govs.split()),
        "loadavg": sh("cat /proc/loadavg"),
        "vmstat_idle_pct": sh("vmstat 1 3 | tail -1 | awk '{print $15}'"),
        "containers": sh("docker ps --format '{{.Names}} ({{.Image}})'").splitlines(),
        "qemu_processes": sh("pgrep -a qemu-system | cut -c1-120").splitlines(),
        "qemu_distro": sh("/usr/bin/qemu-system-x86_64 --version | head -1"),
        "kraft": sh("kraft version 2>/dev/null | head -1"),
        "ab": sh("ab -V | head -1"),
        "logins": sh("who | wc -l"),
    }


# --- ab ---

def run_ab(n, c, out_path=None, timeout=180):
    out = subprocess.run(["ab", "-n", str(n), "-c", str(c), URL],
                         capture_output=True, text=True, timeout=timeout)
    if out_path:
        Path(out_path).write_text(out.stdout + out.stderr)
    res = {}
    for key, pat in AB_PATTERNS.items():
        m = pat.search(out.stdout)
        if m is None:
            raise RuntimeError(f"cannot parse {key} from ab output")
        res[key] = float(m.group(1))
    m = re.search(r"Time taken for tests:\s+([\d.]+)", out.stdout)
    res["time_taken_s"] = float(m.group(1)) if m else None
    return res


# --- instances ---

def kraft_run_vmitrace(name, build, group):
    env = dict(os.environ, VMITRACE_NAME=name, VMITRACE_GROUP=group)
    env = {k: v for k, v in env.items() if not k.startswith("VMI_MONITOR_")}
    subprocess.run(["kraft", "run", "-d", "--qemu", str(WRAPPER), "-p",
                    f"{PORT}:80", "--name", name, "."],
                   cwd=BUILD_ROOT / build, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def kraft_run_legacy(name, env_extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VMI_MONITOR_")}
    env.update(env_extra)
    subprocess.run(["kraft", "run", "-d", "--qemu", DEFAULT_QEMU, "-p",
                    f"{PORT}:80", "--name", name, "."],
                   cwd=APP, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop(name):
    subprocess.run(["kraft", "stop", name], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    subprocess.run(["kraft", "rm", name], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def start_collector(name, manifest, raw, tag, otel, poll_ms):
    args = [str(VENV_PY), str(COLLECTOR), "--manifest", str(manifest),
            "--instance", name, "--jsonl", str(raw / f"{tag}.jsonl"),
            "--stats", str(raw / f"{tag}.stats.json"), "--poll-ms", str(poll_ms),
            "--otel", otel]
    if otel == "otlp":
        args += ["--otlp-endpoint", "localhost:14317"]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=open(raw / f"{tag}.collector.log", "w"))


def wait_collector(p, timeout=60):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        pid, status, ru = os.wait4(p.pid, os.WNOHANG)
        if pid:
            p.returncode = os.waitstatus_to_exitcode(status)
            return p.returncode, ru.ru_utime + ru.ru_stime
        time.sleep(0.1)
    p.send_signal(signal.SIGINT)
    _, status, ru = os.wait4(p.pid, 0)
    p.returncode = os.waitstatus_to_exitcode(status)
    return p.returncode, ru.ru_utime + ru.ru_stime


def snapshot(name, manifest):
    """write_idx of a running vmitrace guest (+ accept4 count while the ring
    still holds every record). Read once, after the measurement."""
    mem = SHM_DIR / f"{name}.mem"
    man = Manifest(manifest)
    ring = GuestRing(str(mem), man)
    try:
        st = ring.header_status()
        widx = ring.write_idx(0)
        accept4 = eagain = boot = requests = None
        if st == "ok" and widx <= man.capacity:
            recs = ring.poll(0)
            acc = [r for r in recs if r.nr == 288]
            accept4 = sum(r.ret >= 0 for r in acc)
            eagain = len(acc) - accept4
            requests = sum(r.nr == 45 and r.ret > 0 for r in recs)   # recvfrom
            boot = next((i for i, r in enumerate(recs) if r.nr == 288), None)
        return {"header": st, "write_idx": widx, "accept4": accept4,
                "accept4_failed": eagain, "requests_seen": requests,
                "boot_records": boot}
    finally:
        ring.close()


# --- perf ---

def perf_trial(cond, spec, rnd, raw, group, requests=300):
    tag = f"{cond}_r{rnd}"
    name = f"p10{cond.replace('-', '')}r{rnd}"
    row = {"condition": cond, "round": rnd, "req_per_s": None,
           "mean_latency_ms": None, "failed_requests": None, "valid": False,
           "write_idx": None, "emitted": None, "lost": None, "rejects": None,
           "offset_resets": None, "offset_uncertainty_ns": None,
           "collector_cpu_s": None, "accept4": None, "accept4_failed": None,
           "requests_seen": None, "boot_records": None,
           "entry_hits": None, "note": ""}
    problems = []
    coll = None
    if spec["kind"] == "vmitrace":
        manifest = BUILD_ROOT / spec["build"] / ".unikraft/build/manifest.json"
        if spec["read"]:
            coll = start_collector(name, manifest, raw, tag, "otlp", 10)
            time.sleep(0.3)
        kraft_run_vmitrace(name, spec["build"], group)
    else:
        log_path = raw / f"{tag}.jsonl"
        for p in (log_path, Path(str(log_path) + ".debug.log")):
            p.unlink(missing_ok=True)
        kraft_run_legacy(name, {**monitor_env(LEGACY_ENTRY, LEGACY_RET, log_path),
                                **spec["switches"]})
    time.sleep(BOOT_SETTLE_S)
    try:
        run_ab(WARMUP, 5)
        ab = run_ab(requests, 5, raw / f"{tag}.ab.txt")
        row.update(req_per_s=ab["requests_per_sec"], mean_latency_ms=ab["mean_ms"],
                   failed_requests=ab["failed_requests"])
        if ab["failed_requests"]:
            problems.append(f"{ab['failed_requests']:.0f} failed requests")
        if spec["kind"] == "vmitrace" and spec["build"] != "base" and not spec["read"]:
            snap = snapshot(name, manifest)
            row.update(write_idx=snap["write_idx"], accept4=snap["accept4"],
                       accept4_failed=snap["accept4_failed"],
                       requests_seen=snap["requests_seen"],
                       boot_records=snap["boot_records"])
            if snap["header"] != "ok":
                problems.append(f"header {snap['header']}")
            if not snap["write_idx"]:
                problems.append("write_idx 0")
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        problems.append(str(e).splitlines()[0])
    finally:
        stop(name)
    if coll is not None:
        rc, cpu = wait_collector(coll)
        row["collector_cpu_s"] = round(cpu, 3)
        st_path = raw / f"{tag}.stats.json"
        if rc != 0 or not st_path.exists():
            problems.append(f"collector rc={rc}")
        else:
            st = json.loads(st_path.read_text())
            c = st["counters"]
            rejects = sum(v for k, v in c.items() if k.startswith("invalid_")
                          or k in ("bad_seq", "write_idx_regress",
                                   "write_idx_implausible"))
            row.update(write_idx=st["write_idx"][0], emitted=st["emitted"],
                       lost=c.get("lost_overwritten", 0) + c.get("bad_seq", 0),
                       rejects=rejects, offset_resets=st["offset_resets"],
                       offset_uncertainty_ns=st["offset_uncertainty_ns"])
            evs = [json.loads(l) for l in open(raw / f"{tag}.jsonl")]
            acc = [e for e in evs if e["syscall"] == "accept4"]
            row["accept4"] = sum((e["ret"] or 0) >= 0 for e in acc)
            row["accept4_failed"] = len(acc) - row["accept4"]
            # One request = one recvfrom that returned data. ab sometimes
            # opens an extra connection at the end of a run that sends
            # nothing (accept4 ok, recvfrom = 0, close), so accept4 is not
            # a request count (Phase 10-5 finding).
            row["requests_seen"] = sum(e["syscall"] == "recvfrom"
                                       and (e["ret"] or 0) > 0 for e in evs)
            row["boot_records"] = next((i for i, e in enumerate(evs)
                                        if e["syscall"] == "accept4"), None)
            if st["emitted"] != st["write_idx"][0]:
                problems.append(f"emitted {st['emitted']} != write_idx {st['write_idx'][0]}")
            if st.get("shared_files_left"):
                problems.append("shared files left")
    if spec["kind"] == "legacy":
        chk = check_breakdown(spec["cond"], raw / f"{tag}.jsonl", LEGACY_ENTRY,
                              LEGACY_RET, WARMUP + requests)
        row["entry_hits"] = chk["entry_hits"]
        row["accept4"] = chk["accept4"]
        problems += chk["problems"]
        if spec["cond"] == "C4" and (raw / f"{tag}.jsonl").exists():
            names = [json.loads(l)["syscall"] for l in open(raw / f"{tag}.jsonl")]
            row["boot_records"] = names.index("accept4") if "accept4" in names else None
    elif spec["build"] != "base" and row["requests_seen"] is not None \
            and row["requests_seen"] != WARMUP + requests:
        problems.append(f"requests_seen={row['requests_seen']}, expected {WARMUP + requests}")
    row["valid"] = row["req_per_s"] is not None and not problems
    row["note"] = "; ".join(problems)
    return row


def cmd_perf(args):
    raw = REPO / "logs" / "bench_p10_raw" / args.raw_name
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "host_before.json").write_text(json.dumps(host_state(), indent=2))
    rows = []
    conds = args.only or list(PERF_CONDITIONS)
    for rnd in range(1, args.rounds + 1):
        for cond in conds:
            log(f"round {rnd}/{args.rounds} {cond}")
            row = perf_trial(cond, PERF_CONDITIONS[cond], rnd, raw, args.group,
                             args.requests)
            log(f"  -> {row}")
            rows.append(row)
            write_csv(args.csv, rows)
    (raw / "host_after.json").write_text(json.dumps(host_state(), indent=2))
    log(f"wrote {args.csv}")


# --- loss ---

def cmd_loss(args):
    raw = REPO / "logs" / "bench_p10_raw" / "loss"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "host_before.json").write_text(json.dumps(host_state(), indent=2))
    rows = []
    for order, build in ((10, "all-r10"), (12, "all"), (14, "all-r14")):
        manifest = BUILD_ROOT / build / ".unikraft/build/manifest.json"
        for poll in args.poll_ms:
            for conc in args.concurrency:
                tag = f"o{order}_p{poll}_c{conc}"
                name = f"p10loss{order}p{poll}c{conc}".replace(".", "")
                log(f"loss {tag}")
                problems = []
                coll = start_collector(name, manifest, raw, tag, "none", poll)
                time.sleep(0.3)
                kraft_run_vmitrace(name, build, args.group)
                time.sleep(BOOT_SETTLE_S)
                ab = None
                w0 = w1 = None
                try:
                    run_ab(WARMUP, conc)
                    w0 = snapshot(name, manifest)["write_idx"]
                    ab = run_ab(args.requests, conc, raw / f"{tag}.ab.txt")
                    w1 = snapshot(name, manifest)["write_idx"]
                    if ab["failed_requests"]:
                        problems.append(f"{ab['failed_requests']:.0f} failed requests")
                except (RuntimeError, subprocess.TimeoutExpired) as e:
                    problems.append(str(e).splitlines()[0])
                finally:
                    stop(name)
                rc, cpu = wait_collector(coll)
                st = json.loads((raw / f"{tag}.stats.json").read_text()) if rc == 0 else None
                if st is None:
                    problems.append(f"collector rc={rc}")
                row = {"ring_order": order, "capacity": 1 << order,
                       "poll_ms": poll, "concurrency": conc,
                       "req_per_s": ab and ab["requests_per_sec"],
                       "ab_time_s": ab and ab["time_taken_s"],
                       "records_during_ab": (w1 - w0) if w0 is not None and w1 is not None else None,
                       "syscalls_per_s": round((w1 - w0) / ab["time_taken_s"])
                       if ab and w0 is not None and w1 is not None else None,
                       "write_idx": st and st["write_idx"][0],
                       "emitted": st and st["emitted"],
                       "lost_overwritten": st and st["counters"].get("lost_overwritten", 0),
                       "bad_seq": st and st["counters"].get("bad_seq", 0),
                       "loss_rate": st and round(1 - st["emitted"] / st["write_idx"][0], 6),
                       "offset_resets": st and st["offset_resets"],
                       "offset_uncertainty_ns": st and st["offset_uncertainty_ns"],
                       "collector_cpu_s": round(cpu, 3),
                       "valid": ab is not None and st is not None and not problems,
                       "note": "; ".join(problems)}
                log(f"  -> {row}")
                rows.append(row)
                write_csv(args.csv, rows)
    (raw / "host_after.json").write_text(json.dumps(host_state(), indent=2))


# --- correctness ---

def cmd_correct(args):
    """N fresh boots of the ALL build, collector started before boot, one
    curl (the workload of logs/strace_ground_truth.log), then the offset-0
    comparison of tools/compare_strace.py."""
    raw = REPO / "logs" / "bench_p10_raw" / "correct"
    raw.mkdir(parents=True, exist_ok=True)
    manifest = BUILD_ROOT / "all" / ".unikraft/build/manifest.json"
    rows = []
    for k in range(1, args.boots + 1):
        tag, name = f"boot{k}", f"p10corr{k}"
        coll = start_collector(name, manifest, raw, tag, "none", 10)
        time.sleep(0.3)
        kraft_run_vmitrace(name, "all", args.group)
        time.sleep(BOOT_SETTLE_S)
        subprocess.run(["curl", "-s", "-o", "/dev/null", URL], check=False)
        time.sleep(1)
        stop(name)
        rc, _ = wait_collector(coll)
        res_path = raw / f"{tag}.compare.json"
        subprocess.run([sys.executable, str(HERE / "compare_strace.py"),
                        "--vmi", str(raw / f"{tag}.jsonl"),
                        "--strace", str(REPO / "logs" / "strace_ground_truth.log"),
                        "--json", str(res_path)],
                       stdout=subprocess.DEVNULL)
        res = json.loads(res_path.read_text())
        st = json.loads((raw / f"{tag}.stats.json").read_text())
        row = {"boot": k, "collector_rc": rc, "records": res["vmi_events"],
               "strace_events": res["strace_events"],
               "names_identical_from_0": res["name_match"],
               "first_name_mismatch": res["first_name_mismatch"],
               "ret_compared": res["ret_compared"], "ret_match": res["ret_match"],
               "ret_pointer": res["ret_pointer_not_compared"],
               "ret_time": res["ret_run_dependent"],
               "lost": st["counters"].get("lost_overwritten", 0),
               "offset_resets": st["offset_resets"],
               "offset_uncertainty_ns": st["offset_uncertainty_ns"]}
        log(f"  -> {row}")
        rows.append(row)
        write_csv(args.csv, rows)


def write_csv(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--group", default=os.environ.get("VMITRACE_GROUP")
                    or grp.getgrgid(os.getgid()).gr_name,
                    help="group for the shared files (default: vmitrace if "
                         "set in VMITRACE_GROUP, else the primary group)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("perf")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--only", nargs="*", choices=list(PERF_CONDITIONS))
    p.add_argument("--csv", default=str(REPO / "logs" / "bench_p10_perf.csv"))
    p.add_argument("--requests", type=int, default=300,
                   help="measured requests per trial (+50 warmup); keep the "
                        "total under ~1,500 per instance")
    p.add_argument("--raw-name", default="perf")
    l = sub.add_parser("loss")
    l.add_argument("--poll-ms", type=float, nargs="*", default=[1, 10, 100])
    l.add_argument("--concurrency", type=int, nargs="*", default=[1, 5, 20])
    l.add_argument("--requests", type=int, default=1000)
    l.add_argument("--csv", default=str(REPO / "logs" / "bench_p10_loss.csv"))
    c = sub.add_parser("correct")
    c.add_argument("--boots", type=int, default=10)
    c.add_argument("--csv", default=str(REPO / "logs" / "bench_p10_correct.csv"))
    args = ap.parse_args()
    {"perf": cmd_perf, "loss": cmd_loss, "correct": cmd_correct}[args.cmd](args)


if __name__ == "__main__":
    main()
