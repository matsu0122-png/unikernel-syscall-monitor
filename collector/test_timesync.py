"""Unit tests for timesync.OffsetEstimator on synthetic polls.

    python3 collector/test_timesync.py
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from timesync import LineOffsetEstimator, OffsetEstimator  # noqa: E402

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


class LineOffsetEstimatorTest(unittest.TestCase):
    def run_line(self, e, ppm=26, seconds=3600, step=3, pause=None, jump=None):
        """Guest clock slower than the host by `ppm`. Poll interval 10 ms,
        write at a random point in it. -> truth at the last sample."""
        rng = random.Random(3)
        base = 10**15
        truth = None
        for t in range(0, seconds, step):
            host = base + t * S + rng.randrange(10 * MS)
            guest = int((host - base) * (1 - ppm / 1e6))
            truth = host - guest
            if jump is not None and t >= jump:
                truth += 50 * MS
                guest -= 50 * MS
            t_lo = host - rng.randrange(10 * MS)
            t_hi = t_lo + 10 * MS
            if pause is not None and t == pause[0]:
                t_lo = host + pause[1]      # published well after the timestamp
                t_hi = t_lo + 10 * MS
            e.update([guest], t_lo, t_hi)
        return truth

    def test_constant_rate_never_resets(self):
        for ppm in (0, 26, 200, -50):
            e = LineOffsetEstimator()
            truth = self.run_line(e, ppm)
            self.assertEqual(e.resets, 0, ppm)
            self.assertLess(abs(e.slope * 1e6 - ppm), 2, ppm)
            self.assertLess(abs(e.offset - truth), 3 * MS, ppm)

    def test_window_on_same_input_resets(self):
        e = OffsetEstimator(None)
        self.run_line(e)
        self.assertGreater(e.resets, 0)

    def test_pause_within_margin_does_not_reset(self):
        e = LineOffsetEstimator(lower_margin_ns=500_000)  # any margin above the pause
        self.run_line(e, pause=(1800, 300_000))
        self.assertEqual(e.resets, 0)

    def test_step_resets_once_and_recovers(self):
        e = LineOffsetEstimator()
        truth = self.run_line(e, jump=1800)
        self.assertEqual(e.resets, 1)
        self.assertLess(abs(e.offset - truth), 5 * MS)

    def test_slow_curvature_retires_old_data_without_reset(self):
        e = LineOffsetEstimator(lower_margin_ns=0)
        base = 10**15
        for t in range(0, 7200, 3):
            host = base + t * S
            # rate changes by 10 ppm halfway
            drift = 26 * t if t < 3600 else 26 * 3600 + 36 * (t - 3600)
            guest = host - base - drift * 1000
            e.update([guest], host - 1 * MS, host + 1 * MS)
        self.assertEqual(e.resets, 0)
        self.assertGreater(e.trims, 0)
        self.assertLess(abs(e.slope * 1e6 - 36), 3)

    def test_slope_held_until_enough_data(self):
        e = LineOffsetEstimator()
        truth = None
        rng = random.Random(5)
        for t in range(0, 30, 3):
            host = 10**15 + t * S
            lo = host - rng.randrange(10 * MS)
            e.update([t * S], lo, lo + 10 * MS)
            truth = host - t * S
            self.assertLess(abs(e.offset - truth), 10 * MS)
        self.assertEqual(e.slope, 0.0)

    def test_margin_moves_the_estimate_by_half(self):
        a, b = LineOffsetEstimator(lower_margin_ns=0), LineOffsetEstimator(lower_margin_ns=100_000)
        for e in (a, b):
            for t in range(0, 300, 3):
                host = 10**15 + t * S
                e.update([t * S], host - 5 * MS, host + 5 * MS)
        self.assertLess(abs(a.offset - b.offset - 50_000), 2)

    def test_same_interface_before_any_data(self):
        e = LineOffsetEstimator()
        self.assertIsNone(e.offset)
        self.assertIsNone(e.uncertainty)
        e.update([], 0, 1)
        self.assertEqual(e.samples, 0)

    def test_window_lower_margin(self):
        e = OffsetEstimator(lower_margin_ns=100)
        e.update([0], 500, 600)
        self.assertEqual((e.lo, e.hi), (400, 600))


if __name__ == "__main__":
    unittest.main(verbosity=2)
