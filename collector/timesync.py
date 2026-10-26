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

If an interval does not overlap the current intersection (only possible
through clock drift or a wrong assumption), the intersection restarts from
that interval and `resets` is incremented. Phase 10-5 reports this count.
"""


class OffsetEstimator:
    def __init__(self):
        self.lo = None
        self.hi = None
        self.resets = 0
        self.samples = 0

    def update(self, guest_times, t_lo, t_hi):
        """Fold in the guest times of records that became visible between
        host times t_lo and t_hi (both ns, t_lo < t_hi)."""
        for g in guest_times:
            rlo, rhi = t_lo - g, t_hi - g
            self.samples += 1
            if self.lo is None:
                self.lo, self.hi = rlo, rhi
            elif max(self.lo, rlo) > min(self.hi, rhi):
                self.resets += 1
                self.lo, self.hi = rlo, rhi
            else:
                self.lo, self.hi = max(self.lo, rlo), min(self.hi, rhi)

    @property
    def offset(self):
        return None if self.lo is None else (self.lo + self.hi) // 2

    @property
    def uncertainty(self):
        return None if self.lo is None else (self.hi - self.lo) // 2
