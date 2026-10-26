"""Unit tests for traces.TraceBuilder with synthetic syscall sequences.

Needs the OpenTelemetry SDK:

    collector/.venv/bin/python collector/test_traces.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import \
    InMemorySpanExporter  # noqa: E402
from opentelemetry.trace import StatusCode  # noqa: E402

from traces import TraceBuilder  # noqa: E402
from vmitrace_reader import F_ENTRY_ONLY, Record  # noqa: E402

MS = 1_000_000
NR = {"accept4": 288, "epoll_ctl": 233, "epoll_wait": 232, "recvfrom": 45,
      "openat": 257, "pread64": 17, "writev": 20, "setsockopt": 54,
      "close": 3, "shutdown": 48, "gettimeofday": 96, "exit_group": 231}
AT_FDCWD = 0xffffff9c


class Seq:
    """Feed a TraceBuilder records one millisecond apart."""

    def __init__(self, tb):
        self.tb = tb
        self.t = 1_000 * MS
        self.idx = 0

    def __call__(self, name, *args, ret=0, tid=2, flags=0, at=None):
        if at is not None:
            self.t = at
        a = tuple(args) + (0,) * (6 - len(args))
        rec = Record(0, self.idx, self.t, self.t + 100_000, NR[name], 0,
                     flags, a, ret, tid)
        self.tb.add(rec, name, self.t, self.t + 100_000,
                    [hex(x) for x in args])
        self.idx += 1
        self.t += MS


class TraceBuilderTest(unittest.TestCase):
    def setUp(self):
        self.exp = InMemorySpanExporter()
        p = TracerProvider()
        p.add_span_processor(SimpleSpanProcessor(self.exp))
        self.tb = TraceBuilder(p.get_tracer("t"))
        self.s = Seq(self.tb)

    def spans(self):
        return self.exp.get_finished_spans()

    def trace_of(self, root):
        tid = root.context.trace_id
        return [x for x in self.spans() if x.context.trace_id == tid]

    def roots(self, name="connection"):
        return [x for x in self.spans() if x.name == name and x.parent is None]

    def test_full_connection_all_group(self):
        s = self.s
        s("accept4", 5, ret=7)
        s("epoll_ctl", 3, 1, 7)
        s("epoll_wait", 3, ret=1)
        s("recvfrom", 7, ret=78)
        s("openat", AT_FDCWD, ret=8)
        s("pread64", 8, ret=612)
        s("writev", 7, ret=850)
        s("recvfrom", 7, ret=0)
        s("close", 7)
        (root,) = self.roots()
        members = {(x.name, x.attributes.get("vmitrace.attribution"))
                   for x in self.trace_of(root) if x is not root}
        self.assertEqual(members, {
            ("accept4", "accept"), ("epoll_ctl", "fd"), ("recvfrom", "fd"),
            ("openat", "inferred"), ("pread64", "inferred"),
            ("writev", "fd"), ("close", "fd")})
        close = next(x for x in self.spans() if x.name == "close")
        self.assertEqual(root.end_time, close.end_time)
        self.assertEqual(root.attributes["vmitrace.close_reason"], "by_close")
        ew = next(x for x in self.spans() if x.name == "epoll_wait")
        self.assertNotEqual(ew.context.trace_id, root.context.trace_id)
        self.assertEqual(self.tb.stats["closed_by_close"], 1)

    def test_net_group_ends_on_eof(self):
        s = self.s
        s("accept4", 5, ret=7)
        s("recvfrom", 7, ret=78)
        s("setsockopt", 7, 6, 1)
        last = s.t
        s("recvfrom", 7, ret=0)                 # peer closed, no close() seen
        s("accept4", 5, ret=7, at=last + 2000 * MS)   # next connection
        self.assertEqual(len(self.roots()), 1)  # first one finished
        first = self.roots()[0]
        self.assertEqual(first.end_time, last + 100_000)
        self.assertEqual(first.attributes["vmitrace.close_reason"],
                         "by_eof_or_shutdown")
        self.assertEqual(self.tb.stats["closed_fd_reused"], 0)
        self.tb.flush()
        self.assertEqual(len(self.roots()), 2)

    def test_close_after_eof_stays_in_connection(self):
        s = self.s
        s("accept4", 5, ret=7)
        s("recvfrom", 7, ret=0)
        s("close", 7)
        (root,) = self.roots()
        self.assertIn("close", [x.name for x in self.trace_of(root)])
        self.assertEqual(root.attributes["vmitrace.close_reason"], "by_close")

    def test_shutdown_then_other_syscall(self):
        s = self.s
        s("accept4", 5, ret=9)
        s("shutdown", 9, 1)
        s("gettimeofday", 0)                    # same thread, not about fd 9
        (root,) = self.roots()
        self.assertEqual(root.attributes["vmitrace.close_reason"],
                         "by_eof_or_shutdown")
        g = next(x for x in self.spans() if x.name == "gettimeofday")
        self.assertNotEqual(g.context.trace_id, root.context.trace_id)

    def test_idle_timeout(self):
        s = self.s
        s("accept4", 5, ret=9)
        end = s.t - MS + 100_000
        s("gettimeofday", 0, tid=3, at=s.t + 31_000 * MS)
        (root,) = self.roots()
        self.assertEqual(root.attributes["vmitrace.close_reason"], "idle")
        self.assertEqual(root.attributes["vmitrace.incomplete"], "idle timeout")
        self.assertEqual(root.end_time, end)

    def test_not_idle_before_timeout(self):
        s = self.s
        s("accept4", 5, ret=9)
        s("gettimeofday", 0, tid=3, at=s.t + 29_000 * MS)
        self.assertEqual(self.roots(), [])

    def test_fd_reused_without_close(self):
        s = self.s
        s("accept4", 5, ret=7)
        s("recvfrom", 7, ret=10)
        s("accept4", 5, ret=7)
        (root,) = self.roots()
        self.assertEqual(root.attributes["vmitrace.close_reason"], "fd_reused")
        self.assertEqual(self.tb.stats["connections"], 2)

    def test_errno_sets_error_status(self):
        self.s("openat", AT_FDCWD, ret=-2)
        sp = next(x for x in self.spans() if x.name == "openat")
        self.assertEqual(sp.status.status_code, StatusCode.ERROR)
        self.assertEqual(sp.attributes["syscall.errno"], 2)
        self.assertEqual(sp.attributes["syscall.errno_name"], "ENOENT")

    def test_entry_only_exit_group(self):
        self.s("exit_group", 0, flags=F_ENTRY_ONLY)
        sp = next(x for x in self.spans() if x.name == "exit_group")
        self.assertTrue(sp.attributes["vmitrace.no_return"])
        self.assertNotIn("syscall.ret", sp.attributes)
        self.assertNotEqual(sp.status.status_code, StatusCode.ERROR)

    def test_explicit_times(self):
        self.s("gettimeofday", 0, at=5_000 * MS)
        sp = next(x for x in self.spans() if x.name == "gettimeofday")
        self.assertEqual((sp.start_time, sp.end_time),
                         (5_000 * MS, 5_000 * MS + 100_000))

    def test_flush_ends_open_connections(self):
        self.s("accept4", 5, ret=7)
        self.tb.flush()
        (root,) = self.roots()
        self.assertEqual(root.attributes["vmitrace.incomplete"],
                         "open at collector exit")

    def test_event_loop_rolls_over(self):
        self.tb.loop_window_spans = 3
        for _ in range(7):
            self.s("gettimeofday", 0)
        self.tb.flush()
        self.assertEqual(len(self.roots("event-loop")), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
