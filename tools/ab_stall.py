#!/usr/bin/env python3
"""Why does `ab -n 5000 -c 5` stall? One capture (Phase 10-7, tool use example).

Boots an instance with a collector reading from before boot, runs the given client,
keeps the client's output, /proc/net/tcp snapshots and a curl afterwards, then
summarizes the guest's syscalls.

    python3 tools/ab_stall.py run <tag> [--build all-r14] -- ab -s 5 -n 5000 -c 5 URL
    python3 tools/ab_stall.py show <tag>
"""

import argparse
import collections
import json
import mmap
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_phase10 as b  # noqa: E402

RAW = b.REPO / "logs" / "bench_p10_raw" / "ab_stall"
STATES = {"01": "ESTAB", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
          "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
          "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def host_states():
    """Sockets on the forwarded port: client side (ab) and server side (slirp)."""
    c = collections.Counter()
    live = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in open(path).read().splitlines()[1:]:
            f = line.split()
            lport = int(f[1].rsplit(":", 1)[1], 16)
            rport = int(f[2].rsplit(":", 1)[1], 16)
            if b.PORT in (lport, rport):
                side = "server" if lport == b.PORT else "client"
                st = STATES.get(f[3], f[3])
                c[f"{side}:{st}"] += 1
                if st not in ("TIME_WAIT", "LISTEN"):
                    live.append((side, st, f[4]))
    return dict(c), live[:20]


def qemu_info(name):
    """-> (qemu pid, monitor socket path) from the wrapper's sidecar."""
    meta = json.loads((b.SHM_DIR / f"{name}.json").read_text())
    pid = int(Path(meta["pidfile"]).read_text().strip())
    return pid, meta["monitor"].split(",")[0].replace("unix:", "")


def hmp(sock_path, line):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    time.sleep(0.2)
    s.sendall((line + "\n").encode())
    time.sleep(0.3)
    s.close()


def run(args):
    RAW.mkdir(parents=True, exist_ok=True)
    tag = args.tag
    for p in RAW.glob(f"{tag}.*"):
        p.unlink()
    name = "p10st" + "".join(c for c in tag if c.isalnum())[:20]
    man = b.BUILD_ROOT / args.build / ".unikraft/build/manifest.json"
    coll = None
    if args.build != "base":
        coll = b.start_collector(name, man, RAW, tag, "none", 10)
        time.sleep(0.3)
    group = b.grp.getgrgid(os.getgid()).gr_name
    env = dict(os.environ, VMITRACE_NAME=name, VMITRACE_GROUP=group)
    subprocess.run(["kraft", "run", "-d", "--qemu", str(b.WRAPPER), "-p", f"{b.PORT}:80",
                    "-M", args.mem, "--name", name, "."], cwd=b.BUILD_ROOT / args.build, env=env,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(b.BOOT_SETTLE_S)
    qpid, mon = qemu_info(name)
    meta_pidfile = json.loads((b.SHM_DIR / f"{name}.json").read_text())["pidfile"]
    if args.pcap:
        hmp(mon, f"object_add filter-dump,id=vtdump,netdev=hostnet0,file={RAW / (tag + '.pcap')},maxlen=96")
    limits = [l for l in Path(f"/proc/{qpid}/limits").read_text().splitlines() if "open files" in l]
    strace = None
    if args.strace:
        strace = subprocess.Popen(["strace", "-f", "-tt", "-q", "-p", str(qpid), "-o", str(RAW / f"{tag}.strace"),
                                   "-e", "trace=accept,accept4,setsockopt,listen"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
    cmd = [a.replace("URL", b.URL) for a in args.cmd]
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    samples = []
    pages = []
    mem_map = None
    if args.pages:
        fd = os.open(b.SHM_DIR / f"{name}.mem", os.O_RDONLY)
        mem_map = mmap.mmap(fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)
        os.close(fd)
    zero = bytes(4096)
    # a pipe could fill on a chatty client; ab and our clients print little
    while p.poll() is None and time.time() - t0 < args.limit:
        try:
            nfds = len(os.listdir(f"/proc/{qpid}/fd"))
        except OSError:              # QEMU exited (the guest crashed)
            nfds = None
        samples.append((round(time.time() - t0, 2), host_states()[0], nfds))
        if mem_map is not None:
            # guest RAM as the host sees it: pages that are no longer all zero.
            # write_idx would need the manifest, so the JSONL gives the count later.
            pages.append((time.time(), sum(mem_map[o:o + 4096] != zero
                                           for o in range(0, len(mem_map), 4096))))
        time.sleep(args.sample_s)
    states_stalled, conns = host_states()
    peak_fds = max((x[2] for x in samples if x[2] is not None), default=None)
    if strace:
        strace.terminate()
        strace.wait()
    if p.poll() is None:
        p.kill()
    out, err = p.communicate()
    t1 = time.time()
    probe = [subprocess.run(["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", b.URL],
                            capture_output=True, text=True).stdout for _ in range(3)]
    alive = Path(f"/proc/{qpid}").exists()
    vm_log = Path(meta_pidfile).parent / "vm.log"
    if vm_log.exists():
        (RAW / f"{tag}.vm.log").write_bytes(vm_log.read_bytes()[-20000:])
    b.stop(name)
    rc = b.wait_collector(coll)[0] if coll else None
    (RAW / f"{tag}.client.json").write_text(json.dumps({
        "cmd": cmd, "rc": p.returncode, "seconds": round(t1 - t0, 2), "start_wall": t0, "end_wall": t1,
        "stdout_tail": out[-1500:], "stderr_tail": err[-800:], "states_at_end": states_stalled,
        "conns_at_end": conns, "samples": samples[-8:], "probe_after": probe, "collector_rc": rc,
        "qemu_peak_fds": peak_fds, "qemu_limit": limits, "qemu_alive_at_end": alive, "pages": pages},
        indent=1))
    show(args)


def show(args):
    tag = args.tag
    c = json.load(open(RAW / f"{tag}.client.json"))
    print(f"== {tag}")
    print(f"   {' '.join(c['cmd'])[:90]}")
    print(f"   client rc {c['rc']}, {c['seconds']} s, alive {c.get('qemu_alive_at_end')}, {c['stderr_tail'].strip()[-120:]}")
    if not (RAW / f"{tag}.stats.json").exists():
        return
    st = json.load(open(RAW / f"{tag}.stats.json"))
    last = [l for l in c["stderr_tail"].replace("\r", "\n").splitlines() if l.strip()][-2:]
    print(f"== {tag}: {' '.join(c['cmd'])[:60]}\n   client rc {c['rc']}, {c['seconds']} s; {last}")
    print("   curl after:", c["probe_after"], "| host sockets at end:", c["states_at_end"],
          c["conns_at_end"][:6])
    print("   qemu alive at end", c.get("qemu_alive_at_end"), "fds peak", c.get("qemu_peak_fds"), c.get("qemu_limit"), "| last samples", c["samples"][-3:])
    print("   collector: emitted", st["emitted"], "write_idx", st["write_idx"][0], "lost",
          st["counters"].get("lost_overwritten", 0) + st["counters"].get("lost_output_queue", 0))
    ev = [json.loads(l) for l in open(RAW / f"{tag}.jsonl")]
    first = next(i for i, e in enumerate(ev) if e["syscall"] == "accept4")
    work = ev[first:]
    print("   syscalls:", dict(collections.Counter(e["syscall"] for e in work).most_common(14)))
    print("   errors:", dict(collections.Counter(
        f"{e['syscall']}:{e.get('err')}" for e in work if e.get("err")).most_common(10)))
    fds = {}
    max_open = closes = accepts = recv = 0
    series = []
    for e in work:
        ret = e["ret"] if e["ret"] is not None else -1
        if e["syscall"] in ("accept4", "openat") and ret >= 0:
            accepts += e["syscall"] == "accept4"
            fds[ret] = e["syscall"]
        elif e["syscall"] == "close" and ret == 0:
            closes += 1
            fds.pop(int(e["args"][0], 16), None)
        elif e["syscall"] == "recvfrom" and ret > 0:
            recv += 1
        max_open = max(max_open, len(fds))
        if accepts and accepts % 500 == 0 and (not series or series[-1][0] != accepts):
            series.append((accepts, len(fds), round(e["ts"] - work[0]["ts"], 3),
                           max(fds) if fds else None, recv))
    print(f"   accept4 ok {accepts}, requests read {recv}, close ok {closes}, "
          f"open fds at end {dict(sorted(fds.items()))}, max open {max_open}")
    print("   per 500 accepts (accepts, open fds, t, highest fd, requests):", series)
    gaps = sorted(((y["ts"] - x["ts"], x["idx"]) for x, y in zip(work, work[1:])), reverse=True)[:4]
    print("   largest gaps between syscalls (s, idx):", [(round(g, 3), i) for g, i in gaps],
          "last idx", work[-1]["idx"], "client ended", round(c["end_wall"] - work[-1]["ts"], 2),
          "s after the last syscall")
    tail = work[-args.tail:] if args.tail else []
    for e in tail:
        print(f"     {e['ts'] - tail[0]['ts']:9.4f} {e['syscall']:12s} {e['args'][:3]} -> {e['ret']} {e.get('err', '')}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="c", required=True)
    r = sub.add_parser("run")
    r.add_argument("--build", default="all-r14")
    r.add_argument("--pcap", action="store_true")
    r.add_argument("--mem", default="64M")
    r.add_argument("--pages", action="store_true", help="sample non-zero guest pages")
    r.add_argument("--sample-s", type=float, default=0.25)
    r.add_argument("--strace", action="store_true")
    r.add_argument("--tail", type=int, default=30)
    r.add_argument("--limit", type=float, default=60, help="kill the client after this many s")
    r.add_argument("tag")
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    s = sub.add_parser("show")
    s.add_argument("tag")
    s.add_argument("--tail", type=int, default=30)
    a = ap.parse_args()
    if a.c == "run":
        if a.cmd and a.cmd[0] == "--":
            a.cmd = a.cmd[1:]
        run(a)
    else:
        show(a)


if __name__ == "__main__":
    main()
