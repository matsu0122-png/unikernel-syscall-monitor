"""Group syscall spans into OpenTelemetry traces (Phase 10-3).

One trace per connection: a synthetic root span "connection" starts with
the accept/accept4 that returned fd N and ends with the close(N) that
returned 0. Its children are

- syscalls whose fd argument is N (recvfrom, writev, setsockopt, close,
  epoll_ctl's target fd, ...): attribution "fd";
- on the same thread, syscalls without such an fd that follow one of those
  before the next event-loop wait (openat/newfstatat/pread64 of the file
  being served): attribution "inferred". This is a heuristic that relies on
  nginx handling one connection at a time per thread between two
  epoll_wait calls.

Everything else goes into an "event-loop" trace, rolled over every
`loop_window_spans` spans or `loop_window_ns` of guest time so a trace
never grows without bound.

Span times are passed explicitly (host nanoseconds converted from the
guest clock by the caller). A syscall returning -errno gets status ERROR.
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


def errno_of(ret):
    return -ret if -4096 < ret < 0 else None


class TraceBuilder:
    def __init__(self, tracer, loop_window_spans=200,
                 loop_window_ns=10_000_000_000):
        self.tracer = tracer
        self.loop_window_spans = loop_window_spans
        self.loop_window_ns = loop_window_ns
        self.conns = {}        # fd -> root span
        self.current = {}      # tid -> fd being handled (inferred attribution)
        self.loop_root = None
        self.loop_start = 0
        self.loop_spans = 0
        self.last_end = 0
        self.stats = {"connections": 0, "conn_reused_fd": 0,
                      "loop_traces": 0, "spans": 0}

    # --- roots ---

    def _new_conn(self, fd, start_ns, rec):
        old = self.conns.pop(fd, None)
        if old is not None:              # close(fd) was lost
            old.set_attribute("vmitrace.incomplete", "fd reused by accept")
            old.end(end_time=start_ns)
            self.stats["conn_reused_fd"] += 1
        root = self.tracer.start_span(
            "connection", context=Context(), kind=SpanKind.SERVER,
            start_time=start_ns,
            attributes={"net.sock.fd": fd, "vcpu": rec.lcpu, "tid": rec.tid})
        self.conns[fd] = root
        self.stats["connections"] += 1
        return root

    def _end_conn(self, fd, end_ns):
        root = self.conns.pop(fd)
        root.end(end_time=end_ns)
        for tid, cur in list(self.current.items()):
            if cur == fd:
                self.current[tid] = None

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
        fd_idx = FD_ARG.get(name)
        fd = rec.args[fd_idx] if fd_idx is not None else None
        attribution = None
        close_fd = None

        if name in ACCEPT and ret >= 0:
            parent = self._new_conn(ret, start_ns, rec)
            self.current[rec.tid] = ret
            attribution = "accept"
        elif fd is not None and fd in self.conns:
            parent = self.conns[fd]
            self.current[rec.tid] = fd
            attribution = "fd"
            if name == "close" and ret == 0:
                close_fd = fd
        elif name in LOOP_WAIT:
            self.current[rec.tid] = None
            parent = self._loop(start_ns)
        elif self.current.get(rec.tid) in self.conns:
            parent = self.conns[self.current[rec.tid]]
            attribution = "inferred"
        else:
            parent = self._loop(start_ns)

        attrs = {"syscall.nr": rec.nr, "syscall.args": args_hex,
                 "vcpu": rec.lcpu, "tid": rec.tid,
                 "vmitrace.idx": rec.idx}
        if rec.flags & 1:                         # VMITRACE_F_ENTRY_ONLY
            attrs["vmitrace.no_return"] = True
        else:
            attrs["syscall.ret"] = ret
        if attribution:
            attrs["vmitrace.attribution"] = attribution
        if rec.unselected:
            attrs["vmitrace.unselected_nr"] = True
        err = errno_of(ret) if not rec.flags & 1 else None
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
        if close_fd is not None:
            self._end_conn(close_fd, end_ns)

    def flush(self):
        """End every open root (collector exit / guest gone)."""
        end = self.last_end
        for fd in list(self.conns):
            self.conns[fd].set_attribute("vmitrace.incomplete",
                                         "open at collector exit")
            self._end_conn(fd, end)
        if self.loop_root is not None:
            self.loop_root.end(end_time=max(end, self.loop_start))
            self.loop_root = None
