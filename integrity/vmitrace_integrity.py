#!/usr/bin/env python3
"""vmitrace integrity checker (Phase 10-6).

Runs as its own process (intended: its own user in group `vmitrace`), reads
the shared guest-RAM file read-only, and raises an alert when

  hash        a manifest hash region (header, bitmap, .vmitrace_text, both
              hook tables, _ukplat_syscall, ukplat_syscall_handler,
              ukplat_monotonic_clock, uk_sys_gettid) differs from the build;
              the alert names the first differing address and byte count
              (expected bytes come from the ELF the manifest describes)
  header      the guest header does not match the manifest (field-level)
  write_idx   write_idx goes backwards
  stalled     the host saw new connections to the instance's forwarded
              port since write_idx last moved, and write_idx has not moved
              for `--stall-checks` consecutive checks
  accept4     the host has seen more connections than the guest recorded
              successful accept4 (beyond --accept-tolerance plus records the
              checker itself lost to overwrite) for `--stall-checks` checks

The last two catch bypasses that leave every hashed byte intact (README
"Limits"): hooks unregistered by other means, LSTAR pointing elsewhere, a
guest that stops recording. They need a group that records accept4 (NET,
NETFD, ALL).

Host-side connections are counted from /proc/net/tcp and /proc/net/tcp6
(no root needed): every socket with local or remote port = the hostfwd port
(from the wrapper's sidecar), keyed by the client's ephemeral endpoint.
One side of each closed connection stays in TIME_WAIT for 60 s, so a 1 s
check interval sees every connection.

Alerts are edge-triggered (raised when a check turns bad, "restored" when
it turns good again), written to stderr and --alerts (JSONL), and sent to
OpenTelemetry as one span per alert ("vmitrace.integrity.alert", status
ERROR, with an event carrying the details), service "vmitrace-integrity".

    collector/.venv/bin/python integrity/vmitrace_integrity.py \\
        --manifest <build>/manifest.json --instance <name> \\
        --alerts alerts.jsonl [--otel otlp|none] [--interval 1]
"""

import argparse
import hashlib
import json
import mmap
import os
import re
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "collector"))
sys.path.insert(0, str(REPO / "tools"))

from vmitrace_reader import GuestRing, Manifest  # noqa: E402
from gen_manifest import Elf  # noqa: E402

PAGE = 4096
SYS_ACCEPT, SYS_ACCEPT4 = 43, 288


def log(msg):
    print(f"[integrity] {msg}", file=sys.stderr, flush=True)


class Regions:
    """Read-only mappings of just the pages that hold the hash regions."""

    def __init__(self, mem_path, regions, expected):
        self.regions = regions
        self.expected = expected                  # name -> bytes from ELF
        spans = sorted({(r["addr"] & ~(PAGE - 1),
                         -(-(r["addr"] + r["size"]) // PAGE) * PAGE)
                        for r in regions})
        merged = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        fd = os.open(mem_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.maps = [(lo, mmap.mmap(fd, hi - lo, mmap.MAP_SHARED,
                                        mmap.PROT_READ, offset=lo))
                         for lo, hi in merged]
        finally:
            os.close(fd)

    def read(self, addr, size):
        for lo, m in self.maps:
            if lo <= addr and addr + size <= lo + len(m):
                return bytes(m[addr - lo:addr - lo + size])
        raise KeyError(hex(addr))

    def check(self):
        """-> {name: None (ok) or details}"""
        out = {}
        for r in self.regions:
            got = self.read(r["addr"], r["size"])
            if hashlib.sha256(got).hexdigest() == r["sha256"]:
                out[r["name"]] = None
                continue
            exp = self.expected[r["name"]]
            diff = [i for i in range(r["size"]) if got[i] != exp[i]]
            first = diff[0] if diff else None
            out[r["name"]] = {
                "addr": hex(r["addr"]), "size": r["size"],
                "differing_bytes": len(diff),
                "first_diff_addr": hex(r["addr"] + first) if diff else None,
                "expected": exp[first:first + 8].hex() if diff else None,
                "found": got[first:first + 8].hex() if diff else None,
                "sha256": hashlib.sha256(got).hexdigest()}
        return out



PROC_TCP = ("/proc/net/tcp", "/proc/net/tcp6")


def host_connections(port, paths=PROC_TCP):
    """Ephemeral client endpoints of TCP sockets on `port` (not LISTEN)."""
    keys = set()
    for path in paths:
        try:
            with open(path) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4:
                continue
            local, remote, state = f[1], f[2], f[3]
            if state == "0A":                       # LISTEN
                continue
            lport = int(local.rsplit(":", 1)[1], 16)
            rport = int(remote.rsplit(":", 1)[1], 16)
            if lport == port:
                keys.add(remote)
            elif rport == port:
                keys.add(local)
    return keys


class ConnCounter:
    """Counts distinct connections over time from repeated snapshots.
    `source` returns the current set of connection keys (default: the
    forwarded port in /proc/net/tcp*); tests pass their own."""

    def __init__(self, source):
        self.source = source
        self.live = set()
        self.total = 0

    def update(self):
        now = self.source()
        new = now - self.live
        self.total += len(new)
        self.live = now
        return len(new)


def setup_otel(kind, endpoint, manifest, instance):
    if kind == "none":
        return None, None
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import \
        OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    provider = TracerProvider(resource=Resource.create({
        "service.name": "vmitrace-integrity",
        "vmitrace.instance": instance or "",
        "vmitrace.build_id": manifest.build_id}))
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    return provider, provider.get_tracer("vmitrace.integrity")


class Alerter:
    """Edge-triggered: emits "alert" when a check turns bad and "restored"
    when it turns good again. Every emitted record is also kept in
    `events`."""

    def __init__(self, path=None, tracer=None, quiet=False):
        self.f = open(path, "a", buffering=1) if path else None
        self.tracer = tracer
        self.quiet = quiet
        self.state = {}             # key -> bool (currently bad)
        self.count = 0
        self.events = []

    def update(self, key, bad, details=None):
        was = self.state.get(key, False)
        self.state[key] = bad
        if bad and not was:
            self._emit("alert", key, details)
        elif was and not bad:
            self._emit("restored", key, details)

    def _emit(self, kind, key, details):
        self.count += kind == "alert"
        rec = {"ts": time.time(), "kind": kind, "check": key,
               "details": details}
        self.events.append(rec)
        if not self.quiet:
            log(f"{kind.upper()} {key}: {json.dumps(details)}")
        if self.f:
            self.f.write(json.dumps(rec) + "\n")
        if self.tracer is not None:
            from opentelemetry.trace import Status, StatusCode
            now = time.time_ns()
            attrs = {"vmitrace.check": key, "vmitrace.kind": kind}
            span = self.tracer.start_span(f"vmitrace.integrity.{kind}",
                                          start_time=now, attributes=attrs)
            span.add_event("vmitrace.integrity." + kind, timestamp=now,
                           attributes={**attrs,
                                       "details": json.dumps(details)})
            if kind == "alert":
                span.set_status(Status(StatusCode.ERROR, key))
            span.end(end_time=now)


class Checker:
    """One integrity check per check_once() call."""

    def __init__(self, man, regions, ring, alerter, conns=None,
                 no_hash=False, stall_checks=2, accept_tolerance=3):
        self.man = man
        self.regions = regions
        self.ring = ring
        self.alerts = alerter
        self.conns = conns
        self.no_hash = no_hash
        self.stall_checks = stall_checks
        self.accept_tolerance = accept_tolerance
        self.checks = 0
        self.last_widx = ring.write_idx(0)
        self.guest_accepts = 0
        self.lost_before = 0
        self.stall_run = 0
        self.pending_conns = 0      # host connections since the ring last moved
        self.accept_run = 0
        self.host_base = None

    def check_once(self):
        self.checks += 1
        ring, alerts = self.ring, self.alerts
        # 1. hashes
        if not self.no_hash:
            for name, bad in self.regions.check().items():
                alerts.update("hash:" + name, bad is not None, bad)
        # 2. header (incl. nonce and bitmap)
        st = ring.header_status()
        alerts.update("header", st != "ok", {"status": st})
        # 3. ring progress and guest-side accepts (read here, never taken
        #    from the collector)
        widx = ring.write_idx(0)
        alerts.update("write_idx_regress", widx < self.last_widx,
                      {"was": self.last_widx, "now": widx})
        if st == "ok" or self.no_hash:
            for r in ring.poll(0):
                if r.nr in (SYS_ACCEPT, SYS_ACCEPT4) and r.ret >= 0:
                    self.guest_accepts += 1
        lost = ring.counters.get("lost_overwritten", 0) + \
            ring.counters.get("bad_seq", 0)
        # 4. behavioural consistency with host-side traffic
        if self.conns is not None:
            new_host = self.conns.update()
            if self.host_base is None:
                # connections before the first check are not compared
                self.host_base = self.conns.total - new_host
                self.guest_accepts = 0
                self.lost_before = lost
            # stalled: connections arrived since the ring last moved, and it
            # has not moved for stall_checks checks. A burst followed by
            # silence still counts; an idle guest without traffic does not.
            if widx != self.last_widx:
                self.pending_conns = 0
                self.stall_run = 0
            else:
                self.pending_conns += new_host
                if self.pending_conns > 0:
                    self.stall_run += 1
            alerts.update("stalled", self.stall_run >= self.stall_checks,
                          {"host_connections_since_ring_moved":
                               self.pending_conns,
                           "write_idx": widx, "checks": self.stall_run})
            host_seen = self.conns.total - self.host_base
            gap = host_seen - self.guest_accepts
            allowed = self.accept_tolerance + (lost - self.lost_before)
            self.accept_run = self.accept_run + 1 if gap > allowed else 0
            alerts.update("accept4_mismatch",
                          self.accept_run >= self.stall_checks,
                          {"host_connections": host_seen,
                           "guest_accept4": self.guest_accepts, "gap": gap,
                           "allowed": allowed})
        self.last_widx = widx

    def stats(self):
        return {"checks": self.checks, "alerts": self.alerts.count,
                "bad_now": sorted(k for k, v in self.alerts.state.items() if v),
                "write_idx": self.ring.write_idx(0),
                "guest_accept4": self.guest_accepts,
                "host_connections": (self.conns.total - self.host_base)
                if self.conns and self.host_base is not None else None,
                "reader_counters": dict(self.ring.counters)}


def expected_bytes(raw):
    """Expected bytes of every hash region, from the ELF the manifest was
    generated from, verified against the manifest hashes (a modified .dbg is
    refused)."""
    elf = Elf(raw["image"]["dbg"])
    out = {}
    for r in raw["hash_regions"]:
        b = elf.read(r["addr"], r["size"])
        if hashlib.sha256(b).hexdigest() != r["sha256"]:
            sys.exit(f"{raw['image']['dbg']} does not match the manifest "
                     f"for {r['name']}")
        out[r["name"]] = b
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--shm-dir", default="/dev/shm/vmitrace")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--stall-checks", type=int, default=2)
    ap.add_argument("--accept-tolerance", type=int, default=3)
    ap.add_argument("--alerts")
    ap.add_argument("--stats")
    ap.add_argument("--otel", choices=("otlp", "none"), default="otlp")
    ap.add_argument("--otlp-endpoint", default="localhost:14317")
    ap.add_argument("--no-hash", action="store_true",
                    help="test only: skip hash checks to exercise the "
                         "behavioural checks on their own")
    ap.add_argument("--wait-s", type=float, default=60)
    args = ap.parse_args()

    man = Manifest(args.manifest)
    expected = expected_bytes(man.raw)

    meta_path = Path(args.shm_dir) / f"{args.instance}.json"
    t0 = time.monotonic()
    meta = None
    while meta is None:
        try:
            meta = json.loads(meta_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() - t0 > args.wait_s:
                sys.exit(f"no {meta_path}")
            time.sleep(0.1)
    m = re.search(r"hostfwd=tcp:[^:]*:(\d+)-", meta.get("hostfwd", ""))
    port = int(m.group(1)) if m else None
    while os.stat(meta["mem_path"]).st_size < meta["mem_size"]:
        time.sleep(0.05)
    pid = None
    pf = Path(meta["pidfile"])
    while pid is None:
        try:
            pid = int(pf.read_text().strip())
        except (FileNotFoundError, ValueError):
            time.sleep(0.05)

    regions = Regions(meta["mem_path"], man.raw["hash_regions"], expected)
    ring = GuestRing(meta["mem_path"], man)
    conns = ConnCounter(lambda: host_connections(port)) if port else None
    log(f"watching {args.instance}: {len(man.raw['hash_regions'])} hash "
        f"regions, forwarded port {port}, qemu pid {pid}")

    provider, tracer = setup_otel(args.otel, args.otlp_endpoint, man,
                                  args.instance)
    alerter = Alerter(args.alerts, tracer)

    # wait until the kernel image is in RAM (header no longer all zero)
    while ring.header_status() == "not_loaded":
        time.sleep(0.01)
    checker = Checker(man, regions, ring, alerter, conns, args.no_hash,
                      args.stall_checks, args.accept_tolerance)

    stop = False

    def on_signal(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    while not stop:
        checker.check_once()
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log("QEMU exited")
            break
        except PermissionError:
            pass
        time.sleep(args.interval)

    stats = checker.stats()
    log("stats " + json.dumps(stats))
    if args.stats:
        Path(args.stats).write_text(json.dumps(stats, indent=2) + "\n")
    if provider is not None:
        provider.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
