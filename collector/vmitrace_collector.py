#!/usr/bin/env python3
"""vmitrace collector (Phase 10-3): guest ring -> JSONL + OpenTelemetry.

    collector/.venv/bin/python collector/vmitrace_collector.py \\
        --manifest <build>/manifest.json --instance <name> \\
        --jsonl logs/vmitrace.jsonl [--otel otlp|file|none]

--instance reads the wrapper's /dev/shm/vmitrace/<name>.json (mem path,
pidfile). The collector:

1. waits for the shared file to exist and reach its full size, then maps
   only the header page and the ring range, O_RDONLY / PROT_READ (no root);
2. waits until the guest header equals the manifest's (sha256), and refuses
   to read records while it does not;
3. polls every ring, validates each record (vmitrace_reader.py), and writes
   - JSONL compatible with the Phase 2-8 logs (ts, cpu, num, syscall,
     args, ret, err, dur_us; plus tid, idx), readable by validate_strace.py;
   - OTel spans (traces.py), with guest times shifted by the host-guest
     offset from timesync.OffsetEstimator (fresh records only; see there).
     Records
     already in the ring at start (or after a header mismatch) are held
     until the first fresh record anchors the offset; if none ever comes
     they are written at exit with "time_unanchored": true and an
     upper-bound offset;
4. when QEMU's pidfile process is gone: final drain, flush, statistics.
   It does not delete <name>.mem / <name>.json: the directory is 0750 and
   only the QEMU user may; tools/vmitrace-cleanup.sh (started by the
   wrapper as that user) does it. The collector only logs whether they
   are still there.

The JSONL file is capped (--max-jsonl-mb): when it reaches the cap it is
rotated to .1 (one generation), so disk use stays <= 2x the cap whatever the
guest does.
"""

import argparse
import errno as errno_mod
import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))          # syscall_table.py

from syscall_table import SYSCALL_TABLE  # noqa: E402
from timesync import OffsetEstimator  # noqa: E402
from vmitrace_reader import (F_ENTRY_ONLY, F_NO_ENTER_TS, GuestRing,  # noqa: E402
                             Manifest)

DEFAULT_SHM_DIR = "/dev/shm/vmitrace"


def log(msg):
    print(f"[collector] {msg}", file=sys.stderr, flush=True)


class CappedWriter:
    def __init__(self, path, max_bytes):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.f = open(self.path, "a", buffering=1)
        self.size = self.f.tell()
        self.rotations = 0

    def write(self, line):
        if self.size + len(line) > self.max_bytes:
            self.f.close()
            os.replace(self.path, self.path.with_name(self.path.name + ".1"))
            self.f = open(self.path, "w", buffering=1)
            self.size = 0
            self.rotations += 1
        self.f.write(line)
        self.size += len(line)

    def close(self):
        self.f.close()


class Names:
    """nr -> (name, nargs): syscall_table.py first (reused from Phase 2),
    then the build's syscall_nrs.h names recorded in the manifest."""

    def __init__(self, manifest):
        self.extra = manifest.syscall_names

    def __call__(self, nr):
        if nr in SYSCALL_TABLE:
            return SYSCALL_TABLE[nr]
        return (self.extra.get(nr, f"syscall_{nr}"), 6)


def setup_otel(kind, manifest, instance, endpoint, dump_path):
    if kind == "none":
        return None, None
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    res = Resource.create({"service.name": "vmitrace",
                           "vmitrace.instance": instance or "",
                           "vmitrace.build_id": manifest.build_id})
    provider = TracerProvider(resource=res)
    if kind == "otlp":
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import \
            OTLPSpanExporter
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    else:
        from file_exporter import JsonLinesSpanExporter
        exporter = JsonLinesSpanExporter(dump_path)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider, provider.get_tracer("vmitrace.collector")


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                    # exists, owned by another user
    return True


def wait_for(cond, what, timeout, interval=0.05):
    t0 = time.monotonic()
    while True:
        v = cond()
        if v:
            return v
        if time.monotonic() - t0 > timeout:
            raise TimeoutError(f"timed out waiting for {what}")
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--manifest", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--instance", help="name used by qemu-wrapper.sh")
    src.add_argument("--mem", help="shared memory file (no pidfile tracking)")
    ap.add_argument("--shm-dir", default=DEFAULT_SHM_DIR)
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--max-jsonl-mb", type=float, default=256)
    ap.add_argument("--otel", choices=("otlp", "file", "none"), default="otlp")
    ap.add_argument("--otlp-endpoint", default="localhost:4317")
    ap.add_argument("--otel-file", help="span dump for --otel file")
    ap.add_argument("--poll-ms", type=float, default=10.0)
    ap.add_argument("--stats", help="write final statistics JSON here")
    ap.add_argument("--wait-s", type=float, default=60.0,
                    help="how long to wait for the file / a valid header")
    args = ap.parse_args()

    man = Manifest(args.manifest)
    names = Names(man)

    meta = None
    if args.instance:
        meta_path = Path(args.shm_dir) / f"{args.instance}.json"

        def read_meta():
            # the wrapper renames a complete file into place; still, never
            # fail on a partial or unreadable one, just retry
            try:
                return json.loads(meta_path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        meta = wait_for(read_meta, str(meta_path), args.wait_s)
        mem_path = meta["mem_path"]
        want_size = meta["mem_size"]
    else:
        mem_path, want_size = args.mem, None

    def file_ready():
        try:
            st = os.stat(mem_path)
        except FileNotFoundError:
            return False
        return st.st_size >= (want_size or man.ring["end"])
    wait_for(file_ready, f"{mem_path} at full size", args.wait_s)

    pid = None
    if meta and meta.get("pidfile"):
        pf = Path(meta["pidfile"])
        pid = int(wait_for(lambda: pf.exists() and pf.read_text().strip(),
                           str(pf), args.wait_s))

    ring = GuestRing(mem_path, man)
    log(f"mapped {', '.join(f'{a:#x}+{n:#x}' for a, n in ring.mapped)} "
        f"of {mem_path} read-only; qemu pid {pid}")

    t_hdr = time.monotonic()
    while True:
        st = ring.header_status()
        if st == "ok":
            break
        if st != "not_loaded":
            ring.counters["header_mismatch_polls"] += 1
        if time.monotonic() - t_hdr > args.wait_s:
            log(f"header never matched the manifest: {st}")
            return 2
        time.sleep(0.01)
    log("guest header matches manifest")

    provider, tracer = setup_otel(args.otel, man, args.instance,
                                  args.otlp_endpoint, args.otel_file)
    tb = None
    if tracer is not None:
        from traces import TraceBuilder
        tb = TraceBuilder(tracer)

    out = CappedWriter(args.jsonl, int(args.max_jsonl_mb * 1024 * 1024))
    est = OffsetEstimator()
    pending = []             # records seen before the offset was anchored
    max_pending = 4 * man.capacity * man.nr_lcpu
    stop = False
    header_bad = False
    emitted = 0

    def on_signal(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    def guest_t(r):
        return r.ts_enter_ns if r.flags & F_ENTRY_ONLY else r.ts_exit_ns

    def take(recs, fresh, t_lo, t_hi):
        if fresh and recs:
            est.update([guest_t(r) for r in recs], t_lo, t_hi)
        offset = est.offset
        if offset is None:
            pending.extend(recs)
            if len(pending) > max_pending:
                ring.counters["lost_unanchored_overflow"] += len(pending) - max_pending
                del pending[:len(pending) - max_pending]
            return
        if pending:
            write(pending, offset, False)
            pending.clear()
        write(recs, offset, False)

    def write(recs, offset, unanchored):
        nonlocal emitted
        for r in recs:
            name, nargs = names(r.nr)
            args_hex = [hex(a) for a in r.args[:nargs]]
            g_start = r.ts_exit_ns if r.flags & F_NO_ENTER_TS else r.ts_enter_ns
            start = g_start + offset
            end = (r.ts_enter_ns if r.flags & F_ENTRY_ONLY else r.ts_exit_ns) + offset
            line = {"ts": start / 1e9, "cpu": r.lcpu, "num": r.nr,
                    "syscall": name, "args": args_hex}
            if r.flags & F_ENTRY_ONLY:
                line["ret"] = None
                line["unfinished"] = "no_return"
            else:
                line["ret"] = r.ret
                if -4096 < r.ret < 0:
                    line["err"] = errno_mod.errorcode.get(-r.ret, str(-r.ret))
                line["dur_us"] = (None if r.flags & F_NO_ENTER_TS
                                  else (r.ts_exit_ns - r.ts_enter_ns) // 1000)
            line["tid"] = r.tid
            line["idx"] = r.idx
            if unanchored:
                line["time_unanchored"] = True
            if r.unselected:
                line["unselected_nr"] = True
            out.write(json.dumps(line) + "\n")
            if tb is not None:
                tb.add(r, name, start, end, args_hex)
            emitted += 1

    t_prev = None            # host time just before the previous poll

    def poll_all(fresh):
        nonlocal t_prev
        t_start = time.time_ns()
        recs = []
        for lcpu in range(man.nr_lcpu):
            recs.extend(ring.poll(lcpu))
        take(recs, fresh and t_prev is not None, t_prev, time.time_ns())
        t_prev = t_start

    poll_s = args.poll_ms / 1000
    qemu_gone = False
    prev_ok = False          # previous poll succeeded -> new records are fresh
    while not stop:
        st = ring.header_status()
        if st != "ok":
            ring.counters["header_mismatch_polls"] += 1
            if not header_bad:
                log(f"guest header no longer matches the manifest ({st}); "
                    "not reading records until it does")
                header_bad = True
            prev_ok = False
        else:
            header_bad = False
            poll_all(prev_ok)
            prev_ok = True
        if pid is not None and not pid_alive(pid):
            qemu_gone = True
            break
        time.sleep(poll_s)

    # final drain: the mapping stays valid even after QEMU exits
    if ring.header_status() == "ok":
        poll_all(prev_ok)
    if pending:
        # never anchored: upper bound from the newest pending record
        ub = time.time_ns() - max(guest_t(r) for r in pending)
        ring.counters["time_unanchored"] += len(pending)
        write(pending, ub, True)
        pending.clear()

    if tb is not None:
        tb.flush()
    if provider is not None:
        provider.shutdown()
    out.close()

    stats = {
        "emitted": emitted,
        "counters": dict(ring.counters),
        "write_idx": [ring.write_idx(l) for l in range(man.nr_lcpu)],
        "dropped_guest": [ring.dropped(l) for l in range(man.nr_lcpu)],
        "capacity": man.capacity,
        "offset_ns": est.offset,
        "offset_anchored": est.offset is not None,
        "offset_uncertainty_ns": est.uncertainty,
        "offset_samples": est.samples,
        "offset_resets": est.resets,
        "jsonl_rotations": out.rotations,
        "traces": tb.stats if tb is not None else None,
        "qemu_exited": qemu_gone,
    }
    ring.close()

    if qemu_gone and meta:
        # Deletion is vmitrace-cleanup.sh's job; just record what we see.
        time.sleep(2)
        left = [p for p in (meta["mem_path"],
                            str(Path(args.shm_dir) / f"{args.instance}.json"))
                if os.path.exists(p)]
        stats["shared_files_left"] = left
        log(f"QEMU exited; shared files still present: {left or 'none'}")

    log("stats " + json.dumps(stats))
    if args.stats:
        Path(args.stats).write_text(json.dumps(stats, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
