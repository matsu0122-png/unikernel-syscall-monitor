"""Host-guest clock offset for vmitrace records (decision 3).

Guest records carry ukplat_monotonic_clock() (ns since guest boot). The host
wants wall-clock ns. offset = host_time - guest_time.

A record is *fresh* if it was not yet published when the previous poll read
write_idx (host time t_lo, taken just before that read) and was published
by the time this poll finished reading (t_hi). Its publication happened in
(t_lo, t_hi], and its guest timestamp g was taken just before publication,
so

    t_lo - g  <=  offset  <=  t_hi - g      (up to the hook's own runtime)

The upper ends are the "min(host - guest)" estimator of decision 3.
Intersecting all intervals also bounds the offset from below. The estimate
is the middle of the intersection, and its half-width is the uncertainty.

Only the last `window_ns` of intervals are intersected (Phase 10-7), so clock
drift ages out instead of eventually emptying the intersection. window_ns=None
intersects everything since the last reset (the behaviour up to 10-6).

If an interval does not overlap the current intersection (only possible
through clock drift or a wrong assumption), the intersection restarts from
that interval and `resets` is incremented. Phase 10-5 reports this count.
"""

from collections import deque

DEFAULT_WINDOW_NS = 60_000_000_000
BUCKET_NS = 1_000_000_000
HISTORY_EVERY_NS = 60_000_000_000
HISTORY_MAX = 1440


class OffsetEstimator:
    def __init__(self, window_ns=DEFAULT_WINDOW_NS):
        self.window_ns = window_ns
        self.lo = None
        self.hi = None
        self.resets = 0
        self.samples = 0
        self.buckets = deque()      # [bucket number, lo, hi], oldest first
        self.history = []           # [host ns, offset, uncertainty], sparse
        self.next_history = 0

    def update(self, guest_times, t_lo, t_hi):
        """Fold in the guest times of records that became visible between
        host times t_lo and t_hi (both ns, t_lo < t_hi)."""
        if not guest_times:
            return
        self.samples += len(guest_times)
        newest = max(guest_times)
        rlo, rhi = t_lo - min(guest_times), t_hi - newest
        if rlo > rhi:               # the batch itself does not fit the interval
            self.resets += 1
            self._restart(t_lo - newest, rhi, t_hi)
        elif self.lo is None:
            self._restart(rlo, rhi, t_hi)
        elif max(self.lo, rlo) > min(self.hi, rhi):
            self.resets += 1
            self._restart(rlo, rhi, t_hi)
        else:
            self.lo, self.hi = max(self.lo, rlo), min(self.hi, rhi)
            self._add(rlo, rhi, t_hi)
            self._expire(t_hi)
        if t_hi >= self.next_history and len(self.history) < HISTORY_MAX:
            self.history.append([t_hi, self.offset, self.uncertainty])
            self.next_history = t_hi + HISTORY_EVERY_NS

    def _restart(self, lo, hi, t_hi):
        self.buckets.clear()
        self.lo, self.hi = lo, hi
        self._add(lo, hi, t_hi)

    def _add(self, lo, hi, t_hi):
        if self.window_ns is None:
            return
        num = t_hi // BUCKET_NS
        if self.buckets and self.buckets[-1][0] == num:
            b = self.buckets[-1]
            b[1], b[2] = max(b[1], lo), min(b[2], hi)
        else:
            self.buckets.append([num, lo, hi])

    def _expire(self, t_hi):
        if self.window_ns is None:
            return
        oldest = (t_hi - self.window_ns) // BUCKET_NS
        if self.buckets[0][0] >= oldest:
            return
        while self.buckets[0][0] < oldest:
            self.buckets.popleft()
        self.lo = max(b[1] for b in self.buckets)
        self.hi = min(b[2] for b in self.buckets)

    @property
    def offset(self):
        return None if self.lo is None else (self.lo + self.hi) // 2

    @property
    def uncertainty(self):
        return None if self.lo is None else (self.hi - self.lo) // 2
