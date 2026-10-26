#!/usr/bin/env python3
"""Offset-0 comparison of a vmitrace JSONL against Unikraft's in-guest strace.

Unlike validate_strace.py (names only, longest common run anywhere), this
walks both sequences from index 0 and compares, element by element:

- the syscall name;
- the return value, where the strace text has a comparable one:
  "OK" = 0, "<msg> (-N)" = -N, "fd:N"/"pid:N"/"N" = N, "0x.." = value.
  "va:0x.." (an address, e.g. brk) depends on the build's memory layout and
  is counted as "pointer, not compared".
- time() returns the wall-clock second of the run, so it is counted as
  "run-dependent, not compared".

    python3 tools/compare_strace.py --vmi run.jsonl \\
        [--strace logs/strace_ground_truth.log] [--json out.json]
"""

import argparse
import json
import re
import sys

RUN_DEPENDENT = {"time"}
LINE_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\(.*\)\s*=\s*(.*)$")


def parse_ret(text):
    """-> (kind, value) with kind in int|pointer|unknown."""
    t = text.strip()
    if t == "OK":
        return "int", 0
    m = re.search(r"\((-\d+)\)$", t)
    if m:
        return "int", int(m.group(1))
    m = re.fullmatch(r"(?:fd|pid):(-?\d+)", t)
    if m:
        return "int", int(m.group(1))
    if re.fullmatch(r"-?\d+", t):
        return "int", int(t)
    if re.fullmatch(r"0x[0-9a-fA-F]+", t):
        return "int", int(t, 16)
    if t.startswith("va:"):
        return "pointer", t
    return "unknown", t


def parse_strace(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            clean = "".join(c for c in line if c.isprintable())
            m = LINE_RE.search(clean)
            if m:
                out.append((m.group(1),) + parse_ret(m.group(2)))
    return out


def parse_vmi(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def compare(vmi, st):
    n = min(len(vmi), len(st))
    res = {"vmi_events": len(vmi), "strace_events": len(st), "compared": n,
           "name_match": 0, "first_name_mismatch": None,
           "ret_compared": 0, "ret_match": 0, "ret_mismatches": [],
           "ret_pointer_not_compared": 0, "ret_run_dependent": 0,
           "ret_unknown": 0}
    for i in range(n):
        name, kind, val = st[i]
        v = vmi[i]
        if v["syscall"] != name:
            res["first_name_mismatch"] = {"index": i, "vmi": v["syscall"],
                                          "strace": name}
            break
        res["name_match"] += 1
        if kind == "pointer":
            res["ret_pointer_not_compared"] += 1
        elif name in RUN_DEPENDENT:
            res["ret_run_dependent"] += 1
        elif kind == "unknown" or v.get("ret") is None:
            res["ret_unknown"] += 1
        else:
            res["ret_compared"] += 1
            if v["ret"] == val:
                res["ret_match"] += 1
            else:
                res["ret_mismatches"].append(
                    {"index": i, "syscall": name, "vmi": v["ret"],
                     "strace": val})
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--vmi", required=True)
    ap.add_argument("--strace", default="logs/strace_ground_truth.log")
    ap.add_argument("--json")
    args = ap.parse_args()
    res = compare(parse_vmi(args.vmi), parse_strace(args.strace))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=2)
    mm = res["ret_mismatches"]
    print(f"names: {res['name_match']}/{res['compared']} identical from index 0"
          + (f"; first mismatch at {res['first_name_mismatch']}"
             if res["first_name_mismatch"] else ""))
    print(f"returns: {res['ret_match']}/{res['ret_compared']} identical, "
          f"{res['ret_pointer_not_compared']} pointers and "
          f"{res['ret_run_dependent']} time() not compared, "
          f"{res['ret_unknown']} unknown")
    for x in mm[:20]:
        print(f"  ret mismatch #{x['index']} {x['syscall']}: vmi={x['vmi']} "
              f"strace={x['strace']}")
    return 0 if res["first_name_mismatch"] is None and not mm else 1


if __name__ == "__main__":
    sys.exit(main())
