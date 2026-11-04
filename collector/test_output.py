"""Unit tests for the collector's output stage.

    python3 collector/test_output.py
"""

import sys
import threading
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vmitrace_collector import ThreadOutput  # noqa: E402


class ThreadOutputTest(unittest.TestCase):
    def test_keeps_order_and_args(self):
        got = []
        t = ThreadOutput(lambda r, o, u: got.append((r, o, u)), 100, Counter())
        t.put([1, 2], 5, False)
        t.put([3], 6, True)
        t.close()
        self.assertEqual(got, [([1, 2], 5, False), ([3], 6, True)])
        self.assertIsNone(t.error)
        self.assertIsNotNone(t.cpu_s)

    def test_put_does_not_wait_and_full_queue_counts_loss(self):
        release = threading.Event()
        got = []

        def slow(r, o, u):
            release.wait()
            got.append(r)
        c = Counter()
        t = ThreadOutput(slow, 10, c)
        t.put(list(range(6)), 0, False)
        t.put(list(range(4)), 0, False)        # exactly full
        t.put([99], 0, False)                  # over: dropped and counted
        self.assertEqual(c["lost_output_queue"], 1)
        self.assertEqual(t.peak_queued, 10)
        release.set()
        t.close()
        self.assertEqual(sum(len(r) for r in got), 10)

    def test_writer_failure_is_reported(self):
        def bad(r, o, u):
            raise OSError("disk full")
        t = ThreadOutput(bad, 10, Counter())
        t.put([1], 0, False)
        t.close()
        self.assertIsInstance(t.error, OSError)


if __name__ == "__main__":
    unittest.main(verbosity=2)
