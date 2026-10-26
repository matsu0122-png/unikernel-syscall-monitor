#!/usr/bin/env python3
"""Summarize the Phase 10-5 benchmark CSVs into Markdown tables.

Per-syscall cost uses Phase 9's method 2: for each valid trial,
(1e6 / req_per_s - mean over base trials of 1e6 / req_per_s) divided by
that trial's syscalls per request, then averaged per condition.

Syscalls per request = (all syscalls in the instance - those before the
first accept4) / 350 requests (50 warmup + 300 measured), as in Phase 9:
- all-i / all-ii: write_idx (every completed syscall is recorded);
- legacy-p8 / legacy-c1: entry_hits from QEMU's [stats] line;
- the "before first accept4" count comes from the same trial when its
  records are available, else the mean of the trials that have it;
- base / net-* / netfd-*: not observable (they do not record every
  syscall), so the mean of the all-* trials is used. This assumes the
  instrumented build does not change nginx's syscall pattern; the
  correctness check shows the ALL sequence matches the uninstrumented
  strace, which supports it but does not prove it for every trial.

    python3 tools/analyze_phase10.py [--perf logs/bench_p10_perf.csv]
                                     [--loss logs/bench_p10_loss.csv]
"""

import argparse
import csv
import statistics as stt
from collections import defaultdict

ORDER = ["base", "net-i", "net-ii", "netfd-i", "netfd-ii", "all-i", "all-ii",
         "legacy-p8", "legacy-c1"]
REQS = 350          # overridden by --reqs (warmup + measured requests)


def num(v):
    if v in (None, "", "None"):
        return None
    try:
        return float(v)
    except ValueError:
        return None


def mean_sd(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    return stt.mean(xs), (stt.stdev(xs) if len(xs) > 1 else 0.0)


def fmt(x, d=1):
    return "-" if x is None else f"{x:,.{d}f}"


THROUGHPUT_ONLY = False


def throughput_ok(r):
    """--throughput-only: a trial counts if ab finished without failed
    requests and the collector ran, even if the collector lost records
    (loss is reported separately)."""
    note = r["note"]
    return (num(r["req_per_s"]) is not None and "failed requests" not in note
            and "collector rc" not in note and "header" not in note
            and "write_idx 0" not in note)


def perf(path):
    rows = list(csv.DictReader(open(path)))
    by = defaultdict(list)
    for r in rows:
        by[r["condition"]].append(r)
    ok = throughput_ok if THROUGHPUT_ONLY else (lambda r: r["valid"] == "True")
    valid = {c: [r for r in rs if ok(r)] for c, rs in by.items()}

    base_t = [1e6 / num(r["req_per_s"]) for r in valid.get("base", [])]
    t0 = stt.mean(base_t)
    base_rps = stt.mean(num(r["req_per_s"]) for r in valid["base"])

    boots = [num(r["boot_records"]) for c in ("all-i", "all-ii")
             for r in valid.get(c, []) if num(r["boot_records"]) is not None]
    boot_all = stt.mean(boots) if boots else 291
    lboots = [num(r["boot_records"]) for r in valid.get("legacy-p8", [])
              if num(r["boot_records"]) is not None]
    boot_legacy = stt.mean(lboots) if lboots else 291

    def spr(c, r):
        if c in ("all-i", "all-ii"):
            b = num(r["boot_records"])
            return (num(r["write_idx"]) - (b if b is not None else boot_all)) / REQS
        if c.startswith("legacy"):
            b = num(r["boot_records"])
            return (num(r["entry_hits"]) - (b if b is not None else boot_legacy)) / REQS
        return None

    all_spr = [spr(c, r) for c in ("all-i", "all-ii") for r in valid.get(c, [])]
    spr_assumed = stt.mean(all_spr)

    out = []
    out.append("| condition | n valid / run | req/s mean | stddev | min | max | vs base | mean latency ms |")
    out.append("|---|---|---|---|---|---|---|---|")
    for c in ORDER:
        if c not in by:
            continue
        rps = [num(r["req_per_s"]) for r in valid[c]]
        m, sd = mean_sd(rps)
        lat, _ = mean_sd([num(r["mean_latency_ms"]) for r in valid[c]])
        out.append(f"| {c} | {len(valid[c])}/{len(by[c])} | {fmt(m)} | {fmt(sd)} | "
                   f"{fmt(min(rps) if rps else None)} | {fmt(max(rps) if rps else None)} | "
                   f"{fmt(100 * m / base_rps if m else None)}% | {fmt(lat, 3)} |")

    out.append("")
    out.append(f"Base time per request (mean of {len(base_t)}): {t0:.2f} us. "
               f"Records before the first accept4: ALL {boot_all:.1f}, legacy {boot_legacy:.1f}. "
               f"Syscalls per request assumed for base/net/netfd: {spr_assumed:.2f} "
               f"(mean of {len(all_spr)} all-* trials).")
    out.append("")
    out.append("| condition | syscalls/request (source) | added us/request | added us/syscall (method 2), mean +/- sd | records/request | added us/record |")
    out.append("|---|---|---|---|---|---|")
    for c in ORDER:
        if c not in by or c == "base":
            continue
        costs, sprs, adds, rpr = [], [], [], []
        for r in valid[c]:
            t = 1e6 / num(r["req_per_s"])
            s = spr(c, r)
            src = "own trial"
            if s is None:
                s, src = spr_assumed, "all-* mean"
            sprs.append(s)
            adds.append(t - t0)
            costs.append((t - t0) / s)
            if c.startswith(("net", "netfd")) and num(r["write_idx"]) is not None:
                # NET/NETFD: boot records counted in their own trial when read
                b = num(r["boot_records"])
                if b is not None:
                    rpr.append((num(r["write_idx"]) - b) / REQS)
            elif c.startswith("all"):
                rpr.append(s)
        cm, csd = mean_sd(costs)
        sm, _ = mean_sd(sprs)
        am, _ = mean_sd(adds)
        rm, _ = mean_sd(rpr)
        per_rec = am / rm if (am is not None and rm) else None
        out.append(f"| {c} | {fmt(sm, 2)} ({src}) | {fmt(am, 2)} | "
                   f"{fmt(cm, 2)} +/- {fmt(csd, 2)} | {fmt(rm, 2)} | {fmt(per_rec, 2)} |")

    out.append("")
    out.append("| condition | write_idx mean | emitted = write_idx | lost | rejects | offset_resets | offset_uncertainty us (max) | collector CPU s (mean) | requests seen | accept4 ok / failed |")
    out.append("|---|---|---|---|---|---|---|---|---|---|")
    for c in ORDER:
        if c not in by or c in ("base",) or c.startswith("legacy"):
            continue
        rs = valid[c]
        wm, _ = mean_sd([num(r["write_idx"]) for r in rs])
        em = (f"{sum(num(r['emitted']) == num(r['write_idx']) for r in rs)}/{len(rs)} trials"
              if c.endswith("-ii") else None)
        lost = sum(num(r["lost"]) or 0 for r in rs) if c.endswith("-ii") else None
        rej = sum(num(r["rejects"]) or 0 for r in rs) if c.endswith("-ii") else None
        res = sum(num(r["offset_resets"]) or 0 for r in rs) if c.endswith("-ii") else None
        unc = max([(num(r["offset_uncertainty_ns"]) or 0) for r in rs] or [0]) / 1000 if c.endswith("-ii") else None
        cpu, _ = mean_sd([num(r["collector_cpu_s"]) for r in rs])
        acc = sorted({(r["accept4"], r["accept4_failed"]) for r in rs})
        reqs = sorted({r["requests_seen"] for r in rs})
        out.append(f"| {c} | {fmt(wm, 0)} | {em if em is not None else 'n/a (no reader)'} | "
                   f"{fmt(lost, 0)} | {fmt(rej, 0)} | {fmt(res, 0)} | {fmt(unc, 1)} | "
                   f"{fmt(cpu, 2)} | {', '.join(reqs)} | {', '.join(f'{a}/{b}' for a, b in acc)} |")
    bad = [r for r in rows if r["valid"] != "True"]
    if bad:
        out.append("")
        out.append("Invalid trials: " + "; ".join(
            f"{r['condition']} r{r['round']}: {r['note']}" for r in bad))
    return "\n".join(out)


def loss(path):
    rows = list(csv.DictReader(open(path)))
    out = ["| capacity | poll ms | ab -c | req/s | syscalls/s during ab | records | lost | loss rate | offset_resets | offset unc. us | collector CPU s | valid |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lost = (num(r["lost_overwritten"]) or 0) + (num(r["bad_seq"]) or 0)
        out.append(f"| {r['capacity']} | {r['poll_ms']} | {r['concurrency']} | "
                   f"{fmt(num(r['req_per_s']), 0)} | {fmt(num(r['syscalls_per_s']), 0)} | "
                   f"{fmt(num(r['write_idx']), 0)} | {fmt(lost, 0)} | "
                   f"{fmt(100 * (num(r['loss_rate']) or 0), 2)}% | {r['offset_resets']} | "
                   f"{fmt((num(r['offset_uncertainty_ns']) or 0) / 1000, 1)} | "
                   f"{r['collector_cpu_s']} | {r['valid']}{(' ' + r['note']) if r['note'] else ''} |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--perf")
    ap.add_argument("--loss")
    ap.add_argument("--reqs", type=int, default=350,
                    help="requests per instance (warmup + measured)")
    ap.add_argument("--throughput-only", action="store_true",
                    help="count trials whose collector lost records")
    a = ap.parse_args()
    global REQS, THROUGHPUT_ONLY
    REQS = a.reqs
    THROUGHPUT_ONLY = a.throughput_only
    if a.perf:
        print(perf(a.perf))
    if a.loss:
        print()
        print(loss(a.loss))


if __name__ == "__main__":
    main()
