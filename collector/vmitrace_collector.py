#!/usr/bin/env python3
"""vmitrace collector (Phase 10-3, 10-7): guest ring -> JSONL + OpenTelemetry.

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

The main thread only reads and validates. With --output thread (default),
another thread writes JSONL and spans, so slow output does not delay reading.
Their queue is bounded (--output-queue records): beyond it records are dropped
and counted as lost_output_queue, because the guest decides the rate and must
not decide how much host memory is used.
"""

import argparse
import errno as errno_mod
import gc
import json
import os
import signal
import queue
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))          # syscall_table.py

from syscall_table import SYSCALL_TABLE  # noqa: E402
from timesync import (DEFAULT_LOWER_MARGIN_NS, DEFAULT_WINDOW_NS,  # noqa: E402
                      LineOffsetEstimator, OffsetEstimator)
from vmitrace_reader import (F_ENTRY_ONLY, F_NO_ENTER_TS, GuestRing,  # noqa: E402
                             Manifest)

DEFAULT_SHM_DIR = "/dev/shm/vmitrace"
OTEL_QUEUE = 65536           # spans; BatchSpanProcessor's default is 2048
GIL_SWITCH_S = 0.001
GC_GEN0 = 100_000
BUSY_POLL_S = 0.001          # sleep after a poll that read over 1/8 of the ring


def log(msg):
    print(f"[collector] {msg}", file=sys.stderr, flush=True)


class CappedWriter:
    def __init__(self, path, max_bytes):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.f = open(self.path, "a")
        self.size = self.f.tell()
        self.rotations = 0

    def write(self, line):
        if self.size + len(line) > self.max_bytes:
            self.f.close()
            os.replace(self.path, self.path.with_name(self.path.name + ".1"))
            self.f = open(self.path, "w")
            self.size = 0
            self.rotations += 1
        self.f.write(line)
        self.size += len(line)

    def flush(self):
        self.f.flush()

    def close(self):
        self.f.close()


class InlineOutput:
    """Output on the reading thread."""

    def __init__(self, write):
        self.write = write
        self.peak_queued = 0
        self.error = None
        self.cpu_s = None

    def put(self, recs, offset, unanchored):
        self.write(recs, offset, unanchored)

    def close(self):
        pass


class ThreadOutput(threading.Thread):
    """Output on its own thread. `put` never waits. queued = put_records -
    done_records, each advanced by one thread only, so no lock is needed; a
    stale read only makes the bound slightly inexact."""

    def __init__(self, write, max_records, counters):
        super().__init__(name="output", daemon=True)
        self.write = write
        self.max_records = max_records
        self.counters = counters
        self.q = queue.SimpleQueue()
        self.put_records = 0
        self.done_records = 0
        self.peak_queued = 0
        self.error = None
        self.cpu_s = None
        self.start()

    def put(self, recs, offset, unanchored):
        queued = self.put_records - self.done_records
        if queued + len(recs) > self.max_records:
            self.counters["lost_output_queue"] += len(recs)
            return
        self.put_records += len(recs)
        self.peak_queued = max(self.peak_queued, queued + len(recs))
        self.q.put((recs, offset, unanchored))

    def run(self):
        try:
            while True:
                item = self.q.get()
                if item is None:
                    return
                self.write(*item)
                self.done_records += len(item[0])
        except Exception as e:     # reported by the main thread
            self.error = e
        finally:
            self.cpu_s = time.thread_time()

    def close(self):
        self.q.put(None)
        self.join()


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
    provider.add_span_processor(BatchSpanProcessor(exporter,
                                                   max_queue_size=OTEL_QUEUE))
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
    ap.add_argument("--output", choices=("thread", "inline"), default="thread")
    ap.add_argument("--output-queue", type=int, default=256 * 1024,
                    help="records waiting for output before new ones are dropped")
    ap.add_argument("--offset-window-s", type=float,
                    default=DEFAULT_WINDOW_NS / 1e9,
                    help="--offset-mode window: use the last N s; 0 = all data")
    ap.add_argument("--offset-mode", choices=("line", "window"), default="line",
                    help="line: constant rate against CLOCK_MONOTONIC_RAW, wall "
                         "clock added at each use; window: against the wall clock")
    ap.add_argument("--offset-lower-margin-us", type=float,
                    help="allowance for a vCPU pause (default: line "
                         f"{DEFAULT_LOWER_MARGIN_NS // 1000}, window 0)")
    ap.add_argument("--offset-log", help="write every poll's clock readings here")
    ap.add_argument("--stats", help="write final statistics JSON here")
    ap.add_argument("--wait-s", type=float, default=60.0,
                    help="how long to wait for the file / a valid header")
    args = ap.parse_args()

    if args.output == "thread":
        # The reader must get the GIL back quickly, and collections over the
        # queued records would stop it (measured with tools/sim_ring.py).
        sys.setswitchinterval(GIL_SWITCH_S)
        gc.set_threshold(GC_GEN0, 50, 100)
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
    line_mode = args.offset_mode == "line"
    if args.offset_lower_margin_us is not None:
        margin = int(args.offset_lower_margin_us * 1000)
    else:
        margin = DEFAULT_LOWER_MARGIN_NS if line_mode else 0
    if line_mode:
        est = LineOffsetEstimator(margin)
    else:
        est = OffsetEstimator(int(args.offset_window_s * 1e9) or None, margin)
    offset_log = open(args.offset_log, "w") if args.offset_log else None
    raw_clock = time.CLOCK_MONOTONIC_RAW
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
        nonlocal pending
        if fresh and recs:
            times = [guest_t(r) for r in recs]
            est.update(times, *((t_lo[0], t_hi[0]) if line_mode else (t_lo[1], t_hi[1])))
            if offset_log:
                offset_log.write(f"{t_lo[0]} {t_hi[0]} {t_lo[1]} {t_hi[1]} "
                                 f"{min(times)} {max(times)} {len(times)}\n")
        offset = est.offset
        if offset is not None and line_mode:
            offset += time.time_ns() - time.clock_gettime_ns(raw_clock)
        if offset is None:
            pending.extend(recs)
            if len(pending) > max_pending:
                ring.counters["lost_unanchored_overflow"] += len(pending) - max_pending
                del pending[:len(pending) - max_pending]
            return
        if pending:
            output.put(pending, offset, False)
            pending = []
        output.put(recs, offset, False)

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
        out.flush()

    if args.output == "thread":
        output = ThreadOutput(write, args.output_queue, ring.counters)
    else:
        output = InlineOutput(write)

    t_prev = None            # host time just before the previous poll

    def poll_all(fresh):
        nonlocal t_prev
        t_start = (time.clock_gettime_ns(raw_clock), time.time_ns())
        recs = []
        for lcpu in range(man.nr_lcpu):
            recs.extend(ring.poll(lcpu))
        take(recs, fresh and t_prev is not None, t_prev,
             (time.clock_gettime_ns(raw_clock), time.time_ns()))
        t_prev = t_start
        return len(recs)

    poll_s = args.poll_ms / 1000
    qemu_gone = False
    prev_ok = False          # previous poll succeeded -> new records are fresh
    max_gap_ns = 0
    t_loop = None
    got = 0
    busy_records = man.capacity * man.nr_lcpu // 8
    adaptive = args.output == "thread"
    while not stop:
        if output.error is not None:
            break
        now = time.monotonic_ns()
        if t_loop is not None:
            max_gap_ns = max(max_gap_ns, now - t_loop)
        t_loop = now
        st = ring.header_status()
        if st != "ok":
            ring.counters["header_mismatch_polls"] += 1
            if not header_bad:
                log(f"guest header no longer matches the manifest ({st}); "
                    "not reading records until it does")
                header_bad = True
            prev_ok = False
            got = 0
        else:
            header_bad = False
            got = poll_all(prev_ok)
            prev_ok = True
        if pid is not None and not pid_alive(pid):
            qemu_gone = True
            break
        time.sleep(BUSY_POLL_S if got > busy_records and adaptive else poll_s)

    # final drain: the mapping stays valid even after QEMU exits
    if ring.header_status() == "ok":
        poll_all(prev_ok)
    if pending:
        # never anchored: upper bound from the newest pending record
        ub = time.time_ns() - max(guest_t(r) for r in pending)
        ring.counters["time_unanchored"] += len(pending)
        output.put(pending, ub, True)
        pending = []
    reader_cpu_s = time.thread_time()
    output.close()
    if offset_log:
        offset_log.close()
    if output.error is not None:
        log(f"output failed: {output.error!r}")

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
        "offset_mode": args.offset_mode,
        "offset_lower_margin_ns": margin,
        "offset_slope_ppm": est.slope * 1e6 if line_mode else None,
        "offset_trims": est.trims if line_mode else None,
        "offset_anchored": est.offset is not None,
        "offset_uncertainty_ns": est.uncertainty,
        "offset_samples": est.samples,
        "offset_resets": est.resets,
        "offset_window_s": args.offset_window_s,
        "offset_history": est.history,
        "output": args.output,
        "reader_cpu_s": reader_cpu_s,
        "writer_cpu_s": output.cpu_s,
        "peak_unread": ring.peak_unread,
        "peak_output_queue": output.peak_queued,
        "max_poll_gap_ms": max_gap_ns / 1e6,
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

    # VmHWM belongs to this process; ru_maxrss would also count the RSS of
    # whoever started it, because exec keeps that high-water mark
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            stats["vmhwm_kb"] = int(line.split()[1])
    log("stats " + json.dumps(stats))
    if args.stats:
        Path(args.stats).write_text(json.dumps(stats, indent=2) + "\n")
    return 1 if output.error is not None else 0


if __name__ == "__main__":
    sys.exit(main())
