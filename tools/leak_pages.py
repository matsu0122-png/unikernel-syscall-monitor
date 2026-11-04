#!/usr/bin/env python3
"""What is in the guest pages that grow per connection? Read-only, from the host
(Phase 10-7). Snapshots guest RAM after n1 and n2 connections, then looks at pages
that were all zero at n1 and are not at n2.

    python3 tools/leak_pages.py [--build all-r14] [--n1 1000] [--n2 2000]
"""
import argparse
import collections
import grp
import mmap
import os
import re
import string
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_phase10 as b  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--build", default="all-r14")
ap.add_argument("--n1", type=int, default=1000)
ap.add_argument("--n2", type=int, default=2000)
a = ap.parse_args()
name = "p10leakpg"
b.kraft_run_vmitrace(name, a.build, grp.getgrgid(os.getgid()).gr_name)
time.sleep(b.BOOT_SETTLE_S)
try:
    fd = os.open(b.SHM_DIR / f"{name}.mem", os.O_RDONLY)
    m = mmap.mmap(fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)
    os.close(fd)

    def drive(n, first):
        subprocess.run([sys.executable, str(Path(__file__).parent / "paced_client.py"), b.URL,
                        "--n", str(n), "--rate", "100000", "--unique-ports", str(first)], check=True,
                       capture_output=True)
    drive(a.n1, 1100)
    time.sleep(0.5)
    snap1 = bytes(m)
    drive(a.n2 - a.n1, 1100 + a.n1 + 50)
    time.sleep(0.5)
    snap2 = bytes(m)
finally:
    b.stop(name)
STATES = ["CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
          "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT"]
PCB_SIZE = 248         # sizeof(struct tcp_pcb) in this build, malloc'ed: its size leads the page
META = 32              # struct metadata_ifpages rounded up
head = struct.pack("<QQ", PCB_SIZE, 1)
for label, snap in (("n1", snap1), ("n2", snap2)):
    pcbs = [o for o in range(0, len(snap), 4096) if snap[o:o + 16] == head]
    states = collections.Counter()
    ports = set()
    for o in pcbs:
        st = struct.unpack_from("<I", snap, o + META + 0x20)[0]
        states[STATES[st] if st < len(STATES) else st] += 1
        if st == 10:
            ports.add(struct.unpack_from("<H", snap, o + META + 0x28)[0])
    print(f"{label}: {len(pcbs)} pages hold a tcp_pcb: {dict(states)}; "
          f"{len(ports)} distinct remote ports in TIME_WAIT, range "
          f"{min(ports, default=0)}-{max(ports, default=0)}")
zero = bytes(4096)
new = [o for o in range(0, len(snap2), 4096)
       if snap1[o:o + 4096] == zero and snap2[o:o + 4096] != zero]
changed = sum(snap1[o:o + 4096] != snap2[o:o + 4096] for o in range(0, len(snap2), 4096))
print(f"{a.n2 - a.n1} connections: {len(new)} newly non-zero pages, {changed} pages changed; "
      f"file offsets {new[0]:#x}..{new[-1]:#x}" if new else "no new pages")
nz = collections.Counter()
heads = collections.Counter()
words = collections.Counter()
printable = set(string.printable.encode())
for o in new:
    p = snap2[o:o + 4096]
    n = 4096 - p.count(0)
    nz[min(n // 256, 15) * 256] += 1
    heads[p[:16].hex()] += 1
    for w in re.findall(rb"[ -~]{6,}", p):
        words[w[:40]] += 1
print("non-zero bytes per page (bucket: pages):", sorted(nz.items()))
print("most common first 16 bytes:", heads.most_common(6))
print("most common strings:", words.most_common(14))
for o in new[len(new) // 2:len(new) // 2 + 2]:
    p = snap2[o:o + 4096]
    print(f"page {o:#x}:")
    used = [i for i in range(0, 4096, 16) if p[i:i + 16] != bytes(16)]
    for i in used[:14]:
        print(f"  {i:04x} {p[i:i + 16].hex(' ')}  {bytes(c if 32 <= c < 127 else 46 for c in p[i:i + 16]).decode()}")
    print(f"  ... {len(used)} of 256 lines non-zero")
