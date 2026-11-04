#!/usr/bin/env python3
"""Replay one-hour runs under variants of the line estimator (Phase 10-7).

Each record's estimated time moves by the difference between the variant's offset
and the live collector's offset at the same poll, so nothing is measured again.
Then every accept4 is checked against its curl window.

    collector/.venv/bin/python tools/replay_offset_variants.py <longrun raw dir> [live variant]
"""

import json
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_offset import read_log  # noqa: E402
from timesync import LineOffsetEstimator  # noqa: E402


class MarginForResetsOnly(LineOffsetEstimator):
    """Estimate from the bounds without the margin, where they allow."""

    @property
    def offset(self):
        if self.t0 is None:
            return None
        lo = min(self.a_lo + self.lower_margin_ns, self.a_hi)
        return self.y0 + int((lo + self.a_hi) / 2 + self.slope * (self.t_last - self.t0))


class UpperBiased(LineOffsetEstimator):
    """Estimate at a fixed fraction of the unwidened interval (0 = lower bound)."""
    fraction = 0.0

    @property
    def offset(self):
        if self.t0 is None:
            return None
        lo = min(self.a_lo + self.lower_margin_ns, self.a_hi)
        return self.y0 + int(lo + self.fraction * (self.a_hi - lo)
                             + self.slope * (self.t_last - self.t0))


VARIANTS = {
    "A margin 500 us, reset test only": lambda: MarginForResetsOnly(500_000),
    "B margin 500 us, also moves the estimate": lambda: LineOffsetEstimator(500_000),
    "C margin 100 us, reset test only": lambda: MarginForResetsOnly(100_000),
    "D margin 100 us, also moves the estimate (adopted)": lambda: LineOffsetEstimator(100_000),
    "E no margin": lambda: LineOffsetEstimator(0),
    "F margin 500 us, estimate at the lower bound": lambda: UpperBiased(500_000),
}


def offsets(rows, make):
    e = make()
    out = []
    for r in rows:
        e.update(list({r[4], r[5]}), r[0], r[1])
        out.append(e.offset)
    return out, e


def hindsight(rows):
    e = LineOffsetEstimator(0, max_buckets=10**6, recent_ns=0)
    for r in rows:
        e.update(list({r[4], r[5]}), r[0], r[1])
    mid = (e.a_lo + e.a_hi) / 2
    return [e.y0 + int(mid + e.slope * (r[1] - e.t0)) for r in rows]


def main():
    d = Path(sys.argv[1])
    live_name = sys.argv[2] if len(sys.argv) > 2 else "A"
    rows = read_log(d / "line.offset.log")
    live_make = next(v for k, v in VARIANTS.items() if k.startswith(live_name))
    live, e = offsets(rows, live_make)
    st = json.load(open(d / "line.stats.json"))
    print(f"replay of the live estimator: uncertainty {e.uncertainty} ns, stats "
          f"{st['offset_uncertainty_ns']} ns; samples {sum(r[6] for r in rows)}, "
          f"emitted {st['emitted']}")
    ends = []
    total = 0
    for r in rows:
        total += r[6]
        ends.append(total)
    cur = [tuple(map(int, l.split())) for l in open(d / "curl_times.txt")]
    acc = []
    for line in open(d / "line.jsonl"):
        x = json.loads(line)
        if x["syscall"] == "accept4" and (x["ret"] or 0) >= 0:
            acc.append((x["ts"], x["idx"]))
    assert len(acc) == len(cur), (len(acc), len(cur))
    t5 = cur[0][0] + 300 * 10**9
    results = {k: offsets(rows, m)[0] for k, m in VARIANTS.items()}
    results["H hindsight line, no estimator (floor)"] = hindsight(rows)
    print("| variant | outside, all | after 5 min | early / late after 5 min | worst after 5 min, us | after 20 min | resets | error from hindsight after 20 min: mean / max, us |")
    print("|---|---|---|---|---|---|---|---|")
    ref = results["H hindsight line, no estimator (floor)"]
    n20 = next(i for i, r in enumerate(rows) if r[1] - rows[0][1] > 1200 * 10**9)
    t20 = cur[0][0] + 1200 * 10**9
    for k, off in results.items():
        early = late = n = after5 = after20 = 0
        worst = 0.0
        for (ts, idx), (b, a, _) in zip(acc, cur):
            p = bisect_right(ends, idx)
            t = ts * 1e9 + (off[p] - live[p])
            miss = max(b - t, t - a, 0)
            n += miss > 0
            if b > t5:
                after5 += miss > 0
                early += t < b
                late += t > a
                worst = max(worst, miss)
            if b > t20:
                after20 += miss > 0
        res = "-" if k.startswith("H") else next(
            offsets(rows, m)[1].resets for q, m in VARIANTS.items() if q == k)
        d20 = [(a - b) / 1000 for a, b in zip(off[n20:], ref[n20:])]
        print(f"| {k} | {n}/{len(acc)} | {after5} | {early} / {late} | {worst / 1000:.0f} | {after20} | {res} | "
              f"{sum(d20) / len(d20):+.0f} / {max(map(abs, d20)):.0f} |")


if __name__ == "__main__":
    main()
