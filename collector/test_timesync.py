"""Unit tests for timesync.OffsetEstimator on synthetic polls.

    python3 collector/test_timesync.py
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from timesync import OffsetEstimator  # noqa: E402

MS = 1_000_000
S = 1_000_000_000


def simulate(true_offset, writes_host, poll_ns, jitter_ns=0, seed=1):
    """Guest writes records at the given host times; the host polls every
    poll_ns (+ jitter). Returns the estimator after feeding it exactly what
    the collector would see."""
    rng = random.Random(seed)
    est = OffsetEstimator()
    writes = sorted(writes_host)
    t_prev = None
    t = writes[0] - poll_ns // 2
    i = 0
    while i < len(writes):
        t_start = t
        t_end = t + 50_000                    # the poll itself takes 50 us
        new = []
        while i < len(writes) and writes[i] <= t_start:
            new.append(writes[i] - true_offset)   # guest time of the record
            i += 1
        if t_prev is not None and new:
            est.update(new, t_prev, t_end)
        t_prev = t_start
        t += poll_ns + (rng.randrange(jitter_ns) if jitter_ns else 0)
    return est


class OffsetEstimatorTest(unittest.TestCase):
    def test_empty(self):
        e = OffsetEstimator()
        self.assertIsNone(e.offset)
        self.assertIsNone(e.uncertainty)

    def test_single_interval_middle(self):
        e = OffsetEstimator()
        e.update([1000], 5000, 7000)          # offset in [4000, 6000]
        self.assertEqual((e.offset, e.uncertainty), (5000, 1000))

    def test_intersection_shrinks(self):
        e = OffsetEstimator()
        e.update([1000], 5000, 7000)          # [4000, 6000]
        e.update([2000], 6500, 9000)          # [4500, 7000] -> [4500, 6000]
        self.assertEqual((e.lo, e.hi), (4500, 6000))
        self.assertEqual(e.resets, 0)

    def test_upper_end_is_min_host_minus_guest(self):
        e = OffsetEstimator()
        for g, t_hi in ((100, 900), (300, 1150), (500, 1290)):
            e.update([g], 0, t_hi)
        self.assertEqual(e.hi, min(900 - 100, 1150 - 300, 1290 - 500))

    def test_disjoint_interval_resets(self):
        e = OffsetEstimator()
        e.update([0], 100, 200)               # [100, 200]
        e.update([0], 500, 600)               # [500, 600]: disjoint
        self.assertEqual(e.resets, 1)
        self.assertEqual((e.lo, e.hi), (500, 600))

    def test_simulated_polls_bracket_truth(self):
        true = 1_792_976_000 * 10**9
        rng = random.Random(7)
        writes = [true + 10**9 + rng.randrange(5 * 10**9) for _ in range(200)]
        for poll in (1 * MS, 10 * MS, 100 * MS):
            est = simulate(true, writes, poll, jitter_ns=poll // 5)
            self.assertLessEqual(est.lo, true, poll)
            self.assertGreaterEqual(est.hi, true, poll)
            self.assertLessEqual(abs(est.offset - true), est.uncertainty)
            # never worse than one polling interval (+ jitter + poll time)
            self.assertLessEqual(est.uncertainty, poll + poll // 5)
            self.assertEqual(est.resets, 0)

    def _drift(self, window_ns, ppm=50, hours=1):
        """Guest clock runs fast by `ppm`; one record per 3 s, 10 ms polling."""
        e = OffsetEstimator(window_ns)
        for t in range(0, hours * 3600, 3):
            host = 1000 * S + t * S
            guest = int((host - 1000 * S) * (1 + ppm / 1e6))
            e.update([guest], host - 5 * MS, host + 5 * MS)
        return e

    def test_window_absorbs_drift_that_resets_without_it(self):
        self.assertGreater(self._drift(None).resets, 0)
        self.assertEqual(self._drift(60 * S).resets, 0)

    def test_window_follows_the_current_offset(self):
        e = self._drift(60 * S)
        host, guest = 1000 * S + 3597 * S, int(3597 * S * (1 + 50 / 1e6))
        self.assertLess(abs(e.offset - (host - guest)), 10 * MS)
        self.assertGreater(len(e.history), 50)

    def test_window_forgets_old_intervals(self):
        e = OffsetEstimator(10 * S)
        e.update([0], 0, 1 * MS)                   # narrow, soon expired
        e.update([5 * S], 5 * S, 5 * S + 9 * MS)
        self.assertEqual(e.resets, 0)
        self.assertEqual((e.lo, e.hi), (0, 1 * MS))
        e.update([40 * S], 40 * S, 40 * S + 9 * MS)
        self.assertEqual(e.hi - e.lo, 9 * MS)      # only the last interval

    def test_batch_equals_records_one_by_one(self):
        a, b = OffsetEstimator(), OffsetEstimator()
        a.update([100, 150, 180], 150, 300)
        for g in (100, 150, 180):
            b.update([g], 150, 300)
        self.assertEqual((a.lo, a.hi, a.samples, a.resets),
                         (b.lo, b.hi, b.samples, b.resets))

    def test_batch_wider_than_its_interval_resets(self):
        e = OffsetEstimator()
        e.update([0, 500], 100, 200)
        self.assertEqual(e.resets, 1)
        self.assertEqual((e.lo, e.hi), (100 - 500, 200 - 500))

    def test_backlog_is_not_used(self):
        # Records written long before the first poll are not fresh: the
        # collector passes them with fresh=False, i.e. never calls update().
        e = OffsetEstimator()
        self.assertIsNone(e.offset)


if __name__ == "__main__":
    unittest.main(verbosity=2)
