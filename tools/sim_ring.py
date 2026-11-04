#!/usr/bin/env python3
"""Collector capacity without a VM (Phase 10-7).

A separate process plays the guest: it follows the record protocol of
guest/lib-vmitrace/include/vmitrace/abi.h on a file in /dev/shm, at a fixed
rate, with the connection pattern of the ab workload (10 records per request).
The real collector reads it. This finds where the collector's limit is; only
bench_phase10.py measures the real guest.

    collector/.venv/bin/python tools/sim_ring.py --rate 160000 --records 14000 \\
        --collector-arg=--output=thread --otel none
"""

import argparse
import hashlib
import json
import mmap
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COLLECTOR = REPO / "collector" / "vmitrace_collector.py"
HDR, BM, STATE, RECS = 0x3000, 0x2000, 0x10000, 0x10040
MAGIC = 0x4543415254494d56
NONCE = (0x1111222233334444, 0x5555666677778888)
TAIL = struct.Struct("<QQIHH6QqQ")
SEQ = struct.Struct("<Q")
# nr, ret: one request on fd 7, as in the ALL build
PATTERN = ((232, 1), (288, 7), (54, 0), (232, 1), (45, 77), (257, -2),
           (20, 850), (45, 0), (3, 0), (232, 0))


def make_guest(path, man_path, cap):
    size = RECS + cap * 96
    with open(path, "wb") as f:
        f.truncate(-(-size // 4096) * 4096)
    words = [(1 << 64) - 1] * 8
    bitmap = struct.pack("<8Q", *words)
    hdr = struct.pack("<QIIIIQQQQQ", MAGIC, 2, 96, cap, 1, STATE, RECS, BM, *NONCE)
    fd = os.open(path, os.O_RDWR)
    os.pwrite(fd, hdr, HDR)
    os.pwrite(fd, bitmap, BM)
    os.close(fd)
    man = dict(manifest_version=1, build_id="sim",
               build_nonce=[f"{n:#018x}" for n in NONCE],
               abi=dict(magic=MAGIC, version=2, record_size=96, capacity=cap, nr_lcpu=1),
               expected=dict(header_addr=HDR, state_addr=STATE, records_addr=RECS,
                             bitmap_addr=BM),
               ring=dict(start=STATE, end=size, state_addr=STATE, records_addr=RECS),
               hash_regions=[dict(name="vmitrace_hdr", sha256=hashlib.sha256(hdr).hexdigest()),
                             dict(name="vmitrace_bitmap",
                                  sha256=hashlib.sha256(bitmap).hexdigest())],
               bitmap=dict(words=[f"{w:#018x}" for w in words], syscalls=[]))
    Path(man_path).write_text(json.dumps(man))


def play(path, cap, rate, records):
    """-> records/s actually achieved."""
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, 0)
    os.close(fd)
    t0 = time.monotonic_ns()
    per_ns = rate / 1e9
    for idx in range(records):
        off = RECS + (idx & (cap - 1)) * 96
        nr, ret = PATTERN[idx % len(PATTERN)]
        now = time.monotonic_ns()
        SEQ.pack_into(m, off, 0)
        TAIL.pack_into(m, off + 8, now - 1000, now, nr, 0, 0, 7, 4096, 0, 0, 0, 0, ret, 2)
        SEQ.pack_into(m, off, idx + 1)
        SEQ.pack_into(m, STATE, idx + 1)
        if idx & 15 == 0:
            while (time.monotonic_ns() - t0) * per_ns < idx:
                pass
    elapsed = time.monotonic_ns() - t0
    m.close()
    return records / (elapsed / 1e9)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--rate", type=float, default=160000)
    ap.add_argument("--records", type=int, default=14000)
    ap.add_argument("--capacity", type=int, default=4096)
    ap.add_argument("--otel", default="none")
    ap.add_argument("--otlp-endpoint", default="localhost:14317")
    ap.add_argument("--poll-ms", type=float, default=10)
    ap.add_argument("--collector-arg", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=300)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(dir="/dev/shm", prefix="vmitrace-sim") as d:
        mem, man = f"{d}/g.mem", f"{d}/manifest.json"
        make_guest(mem, man, a.capacity)
        cmd = [sys.executable, str(COLLECTOR), "--manifest", man, "--mem", mem,
               "--jsonl", f"{d}/o.jsonl", "--stats", f"{d}/s.json", "--otel", a.otel,
               "--otlp-endpoint", a.otlp_endpoint, "--poll-ms", str(a.poll_ms),
               *a.collector_arg]
        err = open(f"{d}/err.log", "w")
        p = subprocess.Popen(cmd, stderr=err)
        time.sleep(2.0 if a.otel != "none" else 0.5)
        achieved = play(mem, a.capacity, a.rate, a.records)
        time.sleep(0.2)
        t_stop = time.monotonic()
        if p.returncode is None:
            os.kill(p.pid, signal.SIGINT)
        _, status, ru = os.wait4(p.pid, 0)
        if status:
            sys.exit(Path(f"{d}/err.log").read_text())
        st = json.loads(Path(f"{d}/s.json").read_text())
        c = st["counters"]
        print(json.dumps({
            "rate": round(achieved), "written": a.records, "emitted": st["emitted"],
            "lost_overwritten": c.get("lost_overwritten", 0), "bad_seq": c.get("bad_seq", 0),
            "lost_output_queue": c.get("lost_output_queue", 0),
            "loss_pct": round(100 * (1 - st["emitted"] / a.records), 2),
            "peak_unread": st["peak_unread"][0], "max_poll_gap_ms": round(st["max_poll_gap_ms"], 1),
            "peak_output_queue": st["peak_output_queue"],
            "reader_cpu_s": round(st["reader_cpu_s"], 3),
            "writer_cpu_s": st["writer_cpu_s"] and round(st["writer_cpu_s"], 3),
            "total_cpu_s": round(ru.ru_utime + ru.ru_stime, 3),
            "exit_wait_s": round(time.monotonic() - t_stop, 2),
            "spans": st["traces"] and st["traces"]["spans"]}))


if __name__ == "__main__":
    main()
