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

    def test_backlog_is_not_used(self):
        # Records written long before the first poll are not fresh: the
        # collector passes them with fresh=False, i.e. never calls update().
        e = OffsetEstimator()
        self.assertIsNone(e.offset)


if __name__ == "__main__":
    unittest.main(verbosity=2)
