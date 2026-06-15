#!/usr/bin/env python3
"""Quick fuzzy% lookup. Usage:
  fpct.py <substr-of-unit> [<substr-of-fn>]   list matching fns with pct
  fpct.py --unit <unit-substr>                list all <100% fns in unit
"""
import json, sys
from pathlib import Path

rep = json.load(open(Path(__file__).resolve().parent.parent / "build/GSAE01/report.json"))

def rows():
    for u in rep["units"]:
        for f in u.get("functions", []):
            p = f.get("fuzzy_match_percent")
            if p is None:
                continue
            yield u["name"], f.get("name") or "", p, int(f.get("size") or 0)

args = [a for a in sys.argv[1:]]
unit_only = False
if args and args[0] == "--unit":
    unit_only = True
    args = args[1:]
usub = args[0] if args else ""
fsub = args[1] if len(args) > 1 else ""
out = []
for un, fn, p, sz in rows():
    if usub.lower() not in un.lower():
        continue
    if fsub and fsub.lower() not in fn.lower():
        continue
    if unit_only and p >= 100:
        continue
    out.append((p, sz, un, fn))
out.sort()
for p, sz, un, fn in out:
    print(f"{p:9.4f} {sz:5d} {un} :: {fn}")
print(f"# {len(out)} fns", file=sys.stderr)
