#!/usr/bin/env python3
"""Compare current report.json per-unit fuzzy% against a baseline snapshot.

Usage:
  lbl_verify.py snapshot          # write baseline from current report
  lbl_verify.py check             # list any unit that regressed vs baseline
Baseline stored at build/GSAE01/lbl_baseline.json
"""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "build/GSAE01/report.json"
BASE = ROOT / "build/GSAE01/lbl_baseline.json"


def load_report():
    d = json.load(open(REPORT))
    return {u["name"]: u["measures"].get("fuzzy_match_percent") for u in d["units"]}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    cur = load_report()
    if cmd == "snapshot":
        json.dump(cur, open(BASE, "w"))
        print(f"snapshot: {len(cur)} units")
        return
    base = json.load(open(BASE))
    regressions = []
    for name, pct in cur.items():
        b = base.get(name)
        if b is not None and pct is not None and pct < b - 1e-6:
            regressions.append((name, b, pct))
    if not regressions:
        print(f"OK: no regressions across {len(cur)} units")
        return
    print(f"REGRESSIONS ({len(regressions)}):")
    for name, b, pct in sorted(regressions, key=lambda x: x[2] - x[1]):
        print(f"  {name}: {b:.3f} -> {pct:.3f}")
    sys.exit(1)


if __name__ == "__main__":
    main()
