#!/usr/bin/env python3
"""pragma_coverage_audit.py -- flag low-fuzzy fns compiling pragma-ON in
files that use scheduling/peephole OFF elsewhere.

The triage rule (harvester-7's CFchuckobj find, validated at scale by
harvester-6): in DLL files with PARTIAL pragma coverage, a low-fuzzy fn
sitting OUTSIDE the wrapped regions is often compiling sched/peephole-ON
against an OFF target. The per-fn #1 wrap alone is routinely +12..+27pp,
and it UNMASKS ordinary recipe-class residuals (#74 masks, #112 folds,
#20 compounds) that the scheduler scramble was hiding. First two scaled
hits: fn_80295918 62.03->96.53 (+34.5pp total), OptionsScreen_run
73.53->99.35 (+25.8pp total).

Method: for every <max-fuzzy fn >= min-size in report.json, locate its
definition in the unit's .c, compute the EFFECTIVE pragma state at that
line with the stack model (recipe #1: on/off PUSH, reset POPS), and flag
fns whose state is ON for either pragma in a file containing at least one
'#pragma scheduling off'.

CAVEATS (A/B mandatory, both directions per #1/#68):
- ON can be CORRECT: jump-table switches die under peephole-off; audio
  TUs are peephole-ON targets (#68 scope note); some fns want sched-off
  ONLY (the both-off variant can score WORSE until shapes are fixed --
  fn_80295918 both-off 80.3 vs sched-only 88.9 pre-fix, then both-off
  won after the #74/#20 fixes landed).
- The wrap is the START of the work, not the end: expect the unmasked
  residual to decompose into playbook classes.
- SJIS carriers (track/intersect.c, baddie/Tumbleweed.c) need byte-wise
  edits.

Usage:
  python3 tools/pragma_coverage_audit.py [--max-fuzzy 99.7] [--min-size 200]
      [--unit-filter SUBSTR] [--top N]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VERSION = "GSAE01"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-fuzzy", type=float, default=99.7)
    ap.add_argument("--min-size", type=int, default=200)
    ap.add_argument("--unit-filter", default="")
    ap.add_argument("--top", type=int, default=60)
    args = ap.parse_args()

    report = json.load(open(REPO / "build" / VERSION / "report.json"))
    cands = []
    for u in report["units"]:
        if args.unit_filter and args.unit_filter not in u["name"]:
            continue
        for f in u.get("functions", []):
            pct = f.get("fuzzy_match_percent")
            if pct is None:
                continue
            size = int(f.get("size", 0))
            if pct < args.max_fuzzy and size >= args.min_size:
                cands.append((u["name"], f["name"], pct, size))

    results = []
    for unit, fn, pct, size in cands:
        p = REPO / ("src/" + unit.split("/", 1)[1] + ".c")
        if not p.exists():
            continue
        data = p.read_bytes().decode("latin1")
        m = re.search(r"^[A-Za-z_][\w \*]*\b" + re.escape(fn) + r"\s*\(", data, re.M)
        if not m:
            continue
        if "#pragma scheduling off" not in data:
            continue
        sched = [True]
        peep = [True]
        for lm in re.finditer(
            r"^#pragma (scheduling|peephole) (on|off|reset)", data[: m.start()], re.M
        ):
            st = sched if lm.group(1) == "scheduling" else peep
            if lm.group(2) == "reset":
                if len(st) > 1:
                    st.pop()
            else:
                st.append(lm.group(2) == "on")
        if sched[-1] or peep[-1]:
            state = "sched=%s peep=%s" % (
                "ON" if sched[-1] else "off",
                "ON" if peep[-1] else "off",
            )
            score = size * (100.0 - pct) / 100.0
            results.append((score, pct, size, unit, fn, state))

    results.sort(reverse=True)
    print(
        "=== %d flagged fns (pragma-ON in pragma-bearing files, "
        "<%s%%, >=%dB) ===" % (len(results), args.max_fuzzy, args.min_size)
    )
    for score, pct, size, unit, fn, state in results[: args.top]:
        print(
            "  unmB %7.1f  %6.2f%%  %5dB  %-14s  %s  [%s]"
            % (score, pct, size, state, fn, unit)
        )


if __name__ == "__main__":
    main()
