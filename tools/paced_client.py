#!/usr/bin/env python3
"""Sequential HTTP/1.0 requests at a fixed rate; each is a new connection unless
--keepalive. Stops at the first request that fails or takes over --timeout.

    python3 tools/paced_client.py URL --n 6000 --rate 200
"""
import argparse
import errno
import socket
import sys
import time
from urllib.parse import urlparse

ap = argparse.ArgumentParser()
ap.add_argument("url")
ap.add_argument("--n", type=int, default=5000)
ap.add_argument("--rate", type=float, default=200)
ap.add_argument("--timeout", type=float, default=5)
ap.add_argument("--unique-ports", type=int, metavar="FIRST",
                help="bind every connection to a new source port, from FIRST up")
a = ap.parse_args()
u = urlparse(a.url)
req = f"GET {u.path or '/'} HTTP/1.0\r\nHost: x\r\n\r\n".encode()
t0 = time.monotonic()
skipped = 0
for i in range(a.n):
    delay = t0 + i / a.rate - time.monotonic()
    if delay > 0:
        time.sleep(delay)
    try:
        while True:
            src = ("127.0.0.1", a.unique_ports + i + skipped) if a.unique_ports else None
            try:
                s = socket.create_connection((u.hostname, u.port), timeout=a.timeout, source_address=src)
                break
            except OSError as e:          # a listener on this host holds the port
                if not a.unique_ports or e.errno != errno.EADDRINUSE:
                    raise
                skipped += 1
        s.sendall(req)
        got = 0
        while True:
            d = s.recv(4096)
            if not d:
                break
            got += len(d)
        s.close()
        if not got:
            raise OSError("empty reply")
    except OSError as e:
        print(f"stopped after {i} requests, {time.monotonic() - t0:.1f} s: {e}", file=sys.stderr)
        sys.exit(1)
print(f"all {a.n} ok in {time.monotonic() - t0:.1f} s", file=sys.stderr)
