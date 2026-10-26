"""Group syscall spans into OpenTelemetry traces (Phase 10-3/10-4).

One trace per connection: a synthetic root span "connection" starts with
the accept/accept4 that returned fd N. Its children are

- syscalls whose fd argument is N (recvfrom, writev, setsockopt, close,
  epoll_ctl's target fd, ...): attribution "fd";
- on the same thread, syscalls without such an fd that follow one of those
  before the next event-loop wait (openat/newfstatat/pread64 of the file
  being served): attribution "inferred". This is a heuristic that relies on
  nginx handling one connection at a time per thread between two
  epoll_wait calls.

The connection ends (root end time = the end of its last span) when

- close(N) returns 0;
- recvfrom(N) returns 0 (peer closed) or shutdown(N) returns 0: the
  connection is marked closing, and ends at the close(N) that normally
  follows, or at the next record of the same thread that is not about N.
  This lets groups without close (NET) still end their traces;
- nothing happened on it for `idle_ns` of guest time (default 30 s):
  ended with vmitrace.incomplete = "idle timeout".

Everything else goes into an "event-loop" trace, rolled over every
`loop_window_spans` spans or `loop_window_ns` so a trace never grows
without bound.

Span times are passed explicitly (host ns converted by the caller). A
syscall returning -errno gets status ERROR.
"""

import errno as errno_mod

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.trace import SpanKind, Status, StatusCode

# syscall name -> index of the argument holding the fd it acts on
FD_ARG = {
    "read": 0, "write": 0, "readv": 0, "writev": 0, "pread64": 0,
    "pwrite64": 0, "recvfrom": 0, "sendto": 0, "recvmsg": 0, "sendmsg": 0,
    "close": 0, "shutdown": 0, "setsockopt": 0, "getsockopt": 0,
    "getpeername": 0, "getsockname": 0, "fcntl": 0, "fstat": 0,
    "sendfile": 0, "ioctl": 0, "epoll_ctl": 2,
}
ACCEPT = ("accept", "accept4")
# Returning from one of these means the thread goes back to the event loop.
LOOP_WAIT = ("epoll_wait", "epoll_pwait", "epoll_pwait2", "poll", "ppoll",
             "select", "pselect6")
F_ENTRY_ONLY = 1


def errno_of(ret):
    return -ret if -4096 < ret < 0 else None


class _Conn:
    __slots__ = ("root", "tid", "last_end", "closing")

    def __init__(self, root, tid, start_ns):
        self.root = root
        self.tid = tid
        self.last_end = start_ns
        self.closing = False


class TraceBuilder:
    def __init__(self, tracer, loop_window_spans=200,
                 loop_window_ns=10_000_000_000, idle_ns=30_000_000_000):
        self.tracer = tracer
        self.loop_window_spans = loop_window_spans
        self.loop_window_ns = loop_window_ns
        self.idle_ns = idle_ns
        self.conns = {}        # fd -> _Conn
        self.current = {}      # tid -> fd being handled (inferred attribution)
        self.loop_root = None
        self.loop_start = 0
        self.loop_spans = 0
        self.last_end = 0
        self.stats = {"connections": 0, "closed_by_close": 0,
                      "closed_by_eof_or_shutdown": 0, "closed_idle": 0,
                      "closed_fd_reused": 0, "closed_open_at_flush": 0,
                      "loop_traces": 0, "spans": 0}

    # --- connection roots ---

    def _end_conn(self, fd, why, incomplete=None):
        c = self.conns.pop(fd)
        if incomplete:
            c.root.set_attribute("vmitrace.incomplete", incomplete)
        c.root.set_attribute("vmitrace.close_reason", why)
        c.root.end(end_time=c.last_end)
        self.stats["closed_" + why] += 1
        for tid, cur in list(self.current.items()):
            if cur == fd:
                self.current[tid] = None

    def _new_conn(self, fd, start_ns, rec):
        if fd in self.conns:                    # its close was not seen
            self._end_conn(fd, "fd_reused", "fd reused by accept")
        root = self.tracer.start_span(
            "connection", context=Context(), kind=SpanKind.SERVER,
            start_time=start_ns,
            attributes={"net.sock.fd": fd, "vcpu": rec.lcpu, "tid": rec.tid})
        self.conns[fd] = _Conn(root, rec.tid, start_ns)
        self.stats["connections"] += 1
        return self.conns[fd]

    def _expire(self, now_ns, tid, fd_of_rec):
        for fd, c in list(self.conns.items()):
            if c.closing and c.tid == tid and fd != fd_of_rec:
                self._end_conn(fd, "by_eof_or_shutdown")
            elif now_ns - c.last_end >= self.idle_ns:
                self._end_conn(fd, "idle", "idle timeout")

    # --- event loop ---

    def _loop(self, start_ns):
        if (self.loop_root is not None
                and (self.loop_spans >= self.loop_window_spans
                     or start_ns - self.loop_start >= self.loop_window_ns)):
            self.loop_root.end(end_time=max(self.last_end, self.loop_start))
            self.loop_root = None
        if self.loop_root is None:
            self.loop_root = self.tracer.start_span(
                "event-loop", context=Context(), kind=SpanKind.INTERNAL,
                start_time=start_ns)
            self.loop_start = start_ns
            self.loop_spans = 0
            self.stats["loop_traces"] += 1
        self.loop_spans += 1
        return self.loop_root

    # --- per record ---

    def add(self, rec, name, start_ns, end_ns, args_hex):
        ret = rec.ret
        entry_only = bool(rec.flags & F_ENTRY_ONLY)
        fd_idx = FD_ARG.get(name)
        fd = rec.args[fd_idx] if fd_idx is not None else None
        conn_fd = fd if fd in self.conns else None
        if name in ACCEPT and not entry_only and ret >= 0:
            conn_fd = None
        self._expire(start_ns, rec.tid, conn_fd)

        attribution = None
        conn = None
        if name in ACCEPT and not entry_only and ret >= 0:
            conn = self._new_conn(ret, start_ns, rec)
            self.current[rec.tid] = ret
            attribution = "accept"
        elif conn_fd is not None and conn_fd in self.conns:
            conn = self.conns[conn_fd]
            attribution = "fd"
            self.current[rec.tid] = None if conn.closing else conn_fd
        elif name in LOOP_WAIT:
            self.current[rec.tid] = None
        elif self.current.get(rec.tid) in self.conns:
            conn = self.conns[self.current[rec.tid]]
            attribution = "inferred"
        parent = conn.root if conn is not None else self._loop(start_ns)

        attrs = {"syscall.nr": rec.nr, "syscall.args": args_hex,
                 "vcpu": rec.lcpu, "tid": rec.tid, "vmitrace.idx": rec.idx}
        if entry_only:
            attrs["vmitrace.no_return"] = True
        else:
            attrs["syscall.ret"] = ret
        if attribution:
            attrs["vmitrace.attribution"] = attribution
        if rec.unselected:
            attrs["vmitrace.unselected_nr"] = True
        err = None if entry_only else errno_of(ret)
        if err:
            attrs["syscall.errno"] = err
            attrs["syscall.errno_name"] = errno_mod.errorcode.get(err, "?")

        span = self.tracer.start_span(
            name, context=trace.set_span_in_context(parent),
            kind=SpanKind.INTERNAL, start_time=start_ns, attributes=attrs)
        if err:
            span.set_status(Status(StatusCode.ERROR,
                                   errno_mod.errorcode.get(err, str(err))))
        span.end(end_time=end_ns)
        self.stats["spans"] += 1
        self.last_end = max(self.last_end, end_ns)

        if conn is not None:
            conn.last_end = max(conn.last_end, end_ns)
            if attribution == "fd" and not entry_only:
                if name == "close" and ret == 0:
                    self._end_conn(conn_fd, "by_close")
                elif ((name == "recvfrom" and ret == 0)
                      or (name == "shutdown" and ret == 0)):
                    conn.closing = True
                    self.current[rec.tid] = None

    def flush(self):
        """End every open root (collector exit / guest gone)."""
        for fd, c in list(self.conns.items()):
            if c.closing:
                self._end_conn(fd, "by_eof_or_shutdown")
            else:
                self._end_conn(fd, "open_at_flush", "open at collector exit")
        if self.loop_root is not None:
            self.loop_root.end(end_time=max(self.last_end, self.loop_start))
            self.loop_root = None
