#!/usr/bin/env python3
"""Time-offset analysis from the collector's --offset-log (Phase 10-7).

Every log line is one poll: raw_lo raw_hi wall_lo wall_hi guest_min guest_max n
(raw = CLOCK_MONOTONIC_RAW, wall = CLOCK_REALTIME, all ns).

    collector/.venv/bin/python tools/analyze_offset.py long <longrun raw dir>
    collector/.venv/bin/python tools/analyze_offset.py short <perf raw dir>
"""

import json
import statistics as stt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))
from timesync import LineOffsetEstimator, OffsetEstimator  # noqa: E402


def read_log(path):
    return [tuple(map(int, l.split())) for l in open(path)]


def fit(xs, ys):
    mx, my = stt.mean(xs), stt.mean(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    r = [y - (a + b * x) for x, y in zip(xs, ys)]
    return a, b, (sum(e * e for e in r) / len(r)) ** 0.5, max(map(abs, r)), r


def linearity(rows, period_s=60):
    """Lowest upper bound per period, against both host clocks."""
    out = {}
    for name, hi_col in (("wall", 3), ("raw", 1)):
        t0 = rows[0][hi_col]
        y0 = rows[0][hi_col] - rows[0][5]
        mins = {}
        for r in rows:
            k = (r[hi_col] - t0) // (period_s * 10**9)
            y = r[hi_col] - r[5] - y0
            if k not in mins or y < mins[k][1]:
                mins[k] = ((r[hi_col] - t0) / 1e9, y / 1000)
        xs = [v[0] for v in mins.values()]
        ys = [v[1] for v in mins.values()]
        _, b, rms, mx, res = fit(xs, ys)
        out[name] = {"points": len(xs), "slope_us_per_s": b, "rms_us": rms, "max_us": mx,
                     "series": list(zip(xs, ys, res))}
    return out


def replay(rows, make, clock):
    """-> estimator, [(poll, offset against the wall clock)]."""
    e = make()
    trace = []
    for r in rows:
        lo, hi = (r[0], r[1]) if clock == "raw" else (r[2], r[3])
        e.update(list({r[4], r[5]}), lo, hi)
        off = e.offset + ((r[3] - r[1]) if clock == "raw" else 0)
        trace.append(off)
    e.samples = sum(r[6] for r in rows)
    return e, trace


def reference(rows):
    """Hindsight: one line through the whole run against the raw clock. Returns
    wall offset per poll, or None if no line fits."""
    e = LineOffsetEstimator(lower_margin_ns=0, max_buckets=10**6, recent_ns=0)
    for r in rows:
        e.update(list({r[4], r[5]}), r[0], r[1])
    if e.resets or e.trims:
        return None, e
    mid = (e.a_lo + e.a_hi) / 2
    return [e.y0 + mid + e.slope * (r[1] - e.t0) + (r[3] - r[1]) for r in rows], e


def errors(trace, ref, skip=1):
    d = [a - b for a, b in zip(trace[skip:], ref[skip:])]
    return {"rms_us": (sum(x * x for x in d) / len(d)) ** 0.5 / 1000,
            "max_us": max(map(abs, d)) / 1000}


def bracket(jsonl, curl_times):
    """Host-measured [before curl, after curl] of each request against the
    estimated wall time of its accept4. Independent of the offset logic."""
    acc = [json.loads(l) for l in open(jsonl)]
    acc = [e["ts"] for e in acc if e["syscall"] == "accept4" and (e["ret"] or 0) >= 0]
    cur = [tuple(map(int, l.split())) for l in open(curl_times)]
    if len(acc) != len(cur):
        return {"accepts": len(acc), "curls": len(cur), "matched": False}
    out = 0
    worst = 0.0
    for ts, (b, a, _) in zip(acc, cur):
        n = ts * 1e9
        miss = max(b - n, n - a, 0)
        out += miss > 0
        worst = max(worst, miss)
    return {"accepts": len(acc), "outside": out, "worst_outside_us": worst / 1000}


def long_run(d):
    d = Path(d)
    rows = read_log(d / "line.offset.log")
    print(f"polls with records: {len(rows)}, {(rows[-1][1] - rows[0][1]) / 1e9:.0f} s")
    lin = linearity(rows)
    for k in ("wall", "raw"):
        v = lin[k]
        print(f"upper bound vs {k}: {v['points']} points, slope {v['slope_us_per_s']:.3f} ppm, "
              f"residual rms {v['rms_us']:.0f} us, max {v['max_us']:.0f} us")
    print("t_s  wall_resid_us raw_resid_us")
    for (x, _, rw), (_, _, rr) in list(zip(lin["wall"]["series"], lin["raw"]["series"]))[::5]:
        print(f"{x:6.0f} {rw:10.0f} {rr:10.0f}")
    print(f"wall - raw change over the run: "
          f"{((rows[-1][3] - rows[-1][1]) - (rows[0][3] - rows[0][1])) / 1e6:.2f} ms")
    ref, re_ = reference(rows)
    print("hindsight line:", "none fits" if ref is None else
          f"slope {re_.slope * 1e6:.3f} ppm, half-width {re_.uncertainty / 1000:.0f} us")
    print("\n| method | live offset_resets | live trims | replay resets (same input) | error rms us | error max us | error after 5 min, max us | accept4 outside curl bracket | worst outside us |")
    print("|---|---|---|---|---|---|---|---|---|")
    for tag, make, clock in (
            ("window60", lambda: OffsetEstimator(60 * 10**9), "wall"),
            ("window20", lambda: OffsetEstimator(20 * 10**9), "wall"),
            ("window0", lambda: OffsetEstimator(None), "wall"),
            ("line", lambda: LineOffsetEstimator(), "raw")):
        st = json.load(open(d / f"{tag}.stats.json"))
        e, tr = replay(rows, make, clock)
        err = errors(tr, ref) if ref else {"rms_us": float("nan"), "max_us": float("nan")}
        n5 = next((i for i, r in enumerate(rows) if r[1] - rows[0][1] > 300 * 10**9), 1)
        late = errors(tr, ref, n5) if ref else {"max_us": float("nan")}
        br = bracket(d / f"{tag}.jsonl", d / "curl_times.txt")
        print(f"| {tag} | {st['offset_resets']} | {st.get('offset_trims')} | {e.resets} | {err['rms_us']:.0f} | "
              f"{err['max_us']:.0f} | {late['max_us']:.0f} | {br.get('outside')}/{br['accepts']} | "
              f"{br.get('worst_outside_us', 0):.0f} |")
    st = json.load(open(d / "line.stats.json"))
    print("line live: slope ppm", st["offset_slope_ppm"], "uncertainty us", st["offset_uncertainty_ns"] / 1000)


def short_runs(d):
    d = Path(d)
    margins = (0, 100, 200, 500, 1000, 2000)
    totals = {m: [0, 0, 0] for m in margins}
    trials = 0
    live = {}
    worst = []
    for p in sorted(d.glob("*.offset.log")):
        rows = read_log(p)
        if len(rows) < 2:
            continue
        trials += 1
        tag = p.name.replace(".offset.log", "")
        st = json.load(open(d / f"{tag}.stats.json"))
        live[tag] = st["offset_resets"]
        for m in margins:
            w, _ = replay(rows, lambda: OffsetEstimator(60 * 10**9, m * 1000), "wall")
            l, _ = replay(rows, lambda: LineOffsetEstimator(lower_margin_ns=m * 1000), "raw")
            totals[m][0] += w.resets
            totals[m][1] += l.resets
            totals[m][2] += w.resets > 0
        # how far each lower bound sits above the tightest upper bound
        hi = min(r[3] - r[5] for r in rows)
        excess = max(r[2] - r[4] - hi for r in rows)
        worst.append((excess / 1000, tag))
    print("trials", trials, "live resets (window 60 s, margin 0):",
          {k: v for k, v in live.items() if v} or 0)
    print("| lower margin us | replay resets, window | trials with a reset | replay resets, line |")
    print("|---|---|---|---|")
    for m in margins:
        print(f"| {m} | {totals[m][0]} | {totals[m][2]} | {totals[m][1]} |")
    worst.sort(reverse=True)
    print("lower bound above the lowest upper bound, largest us:",
          [(round(a), t) for a, t in worst[:6]])
    print("median us:", round(stt.median(a for a, _ in worst)))


if __name__ == "__main__":
    {"long": long_run, "short": short_runs}[sys.argv[1]](sys.argv[2])
