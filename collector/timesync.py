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

LineOffsetEstimator instead assumes a constant rate between the two clocks and
intersects the intervals after removing that rate. Feed it a host clock that NTP
does not adjust (CLOCK_MONOTONIC_RAW); the wall clock is added on top at each use.

A record's timestamp can be older than t_lo when the vCPU pauses between taking it
and publishing the record, which moves the true offset below t_lo - g. The upper
bound has no such case. `lower_margin_ns` widens the lower bound for this.
"""

from collections import deque

DEFAULT_WINDOW_NS = 60_000_000_000
BUCKET_NS = 1_000_000_000
HISTORY_EVERY_NS = 60_000_000_000
HISTORY_MAX = 1440
DEFAULT_LOWER_MARGIN_NS = 500_000


class OffsetEstimator:
    def __init__(self, window_ns=DEFAULT_WINDOW_NS, lower_margin_ns=0):
        self.window_ns = window_ns
        self.lower_margin_ns = lower_margin_ns
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
        margin = self.lower_margin_ns
        rlo, rhi = t_lo - min(guest_times) - margin, t_hi - newest
        if rlo > rhi:               # the batch itself does not fit the interval
            self.resets += 1
            self._restart(t_lo - newest - margin, rhi, t_hi)
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


def _hull(points, sign):
    """Convex hull of (t, y) sorted by t: lower (sign=1) or upper (sign=-1). Only
    these points can limit a line that stays below / above all of them."""
    out = []
    for t, y in points:
        while len(out) >= 2:
            (t1, y1), (t2, y2) = out[-2], out[-1]
            if sign * ((y2 - y1) * (t - t1) - (y - y1) * (t2 - t1)) >= 0:
                out.pop()
            else:
                break
        out.append((t, y))
    return out


class LineOffsetEstimator:
    """offset(t) = a + slope * t, through every interval of one guest boot.

    Each bucket keeps its tightest upper and lower bound. Among all lines passing
    between them, the one with the most room is used, and half that room is the
    uncertainty. With under `recent_ns` of data the rate cannot be told from noise,
    so the slope stays as it is unless no line fits. The margin only keeps a late
    record from breaking the fit: it does not move the estimate, which uses the
    bounds without it where they allow. Slow curvature only retires old buckets (`trims`). `resets` counts
    what no line through the last `recent_ns` can explain: a step in the offset, or
    a pause larger than the margin. Same interface as OffsetEstimator."""

    def __init__(self, lower_margin_ns=DEFAULT_LOWER_MARGIN_NS, bucket_ns=10 * BUCKET_NS,
                 recent_ns=60 * BUCKET_NS, max_buckets=720, max_slope=500e-6):
        self.lower_margin_ns = lower_margin_ns
        self.bucket_ns = bucket_ns
        self.recent_ns = recent_ns
        self.max_buckets = max_buckets
        self.max_slope = max_slope
        self.resets = 0
        self.trims = 0
        self.samples = 0
        self.slope = 0.0
        self.t0 = None
        self.y0 = 0
        self.a_lo = self.a_hi = 0.0  # line at t0, relative to y0
        self.t_last = None
        self.buckets = deque()       # [number, t of hi, hi, t of lo, lo]
        self.history = []
        self.next_history = 0

    def update(self, guest_times, t_lo, t_hi):
        if not guest_times:
            return
        self.samples += len(guest_times)
        newest = max(guest_times)
        rlo, rhi = t_lo - min(guest_times) - self.lower_margin_ns, t_hi - newest
        if rlo > rhi:                # the batch itself does not fit the interval
            self.resets += 1
            self._restart(t_hi, t_lo - newest - self.lower_margin_ns, rhi)
        elif self.t0 is None:
            self._restart(t_hi, rlo, rhi)
        else:
            lo = float(rlo - self.y0) - self.slope * (t_hi - self.t0)
            hi = float(rhi - self.y0) - self.slope * (t_hi - self.t0)
            fits = max(self.a_lo, lo) <= min(self.a_hi, hi)
            opened = self._add(t_hi, rlo, rhi)
            if not fits or opened:
                if not self._refit():
                    self.resets += 1
                    self._restart(t_hi, rlo, rhi)
            else:
                self.a_lo, self.a_hi = max(self.a_lo, lo), min(self.a_hi, hi)
        self.t_last = t_hi
        if t_hi >= self.next_history and len(self.history) < HISTORY_MAX:
            self.history.append([t_hi, self.offset, self.uncertainty])
            self.next_history = t_hi + HISTORY_EVERY_NS

    def _restart(self, t, lo, hi):
        """Keeps the slope: a step in the offset does not change the rate."""
        self.buckets.clear()
        self.t0, self.y0 = t, hi
        self.a_lo, self.a_hi = float(lo - hi), 0.0
        self._add(t, lo, hi)

    def _add(self, t, lo, hi):
        """-> True when a new bucket was opened."""
        num = t // self.bucket_ns
        if self.buckets and self.buckets[-1][0] == num:
            b = self.buckets[-1]
            if hi < b[2]:
                b[1], b[2] = t, hi
            if lo > b[4]:
                b[3], b[4] = t, lo
            return False
        self.buckets.append([num, t, hi, t, lo])
        if len(self.buckets) > self.max_buckets:
            self.buckets.popleft()
        return True

    def _best_line(self):
        """-> (room, slope, a_lo, a_hi): the line with the most room, or with the
        current slope while there is too little data to fit one."""
        hs = _hull([(b[1] - self.t0, float(b[2] - self.y0)) for b in self.buckets], 1)
        ls = _hull(sorted((b[3] - self.t0, float(b[4] - self.y0)) for b in self.buckets), -1)

        def room(m):
            a_hi = min(y - m * t for t, y in hs)
            a_lo = max(y - m * t for t, y in ls)
            return a_hi - a_lo, a_lo, a_hi
        if self.buckets[-1][1] - self.buckets[0][1] < self.recent_ns:
            held = room(self.slope)
            if held[0] >= 0:
                return (held[0], self.slope, held[1], held[2])
        lo, hi = -self.max_slope, self.max_slope
        for _ in range(60):          # room() is concave in the slope
            m1, m2 = lo + (hi - lo) / 3, hi - (hi - lo) / 3
            if room(m1)[0] < room(m2)[0]:
                lo = m1
            else:
                hi = m2
        m = (lo + hi) / 2
        r, a_lo, a_hi = room(m)
        return r, m, a_lo, a_hi

    def _refit(self):
        """-> False when no line fits even the recent buckets."""
        newest = self.buckets[-1][1]
        while True:
            r, m, a_lo, a_hi = self._best_line()
            if r >= 0:
                self.slope, self.a_lo, self.a_hi = m, a_lo, a_hi
                return True
            if newest - self.buckets[0][1] <= self.recent_ns or len(self.buckets) < 2:
                return False
            self.buckets.popleft()
            self.trims += 1

    @property
    def offset(self):
        if self.t0 is None:
            return None
        lo = min(self.a_lo + self.lower_margin_ns, self.a_hi)
        return self.y0 + int((lo + self.a_hi) / 2 + self.slope * (self.t_last - self.t0))

    @property
    def uncertainty(self):
        return None if self.t0 is None else int((self.a_hi - self.a_lo) / 2)
