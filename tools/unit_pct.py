#!/usr/bin/env python3
"""Per-function fuzzy_match_percent for a unit from report.json.
Usage: unit_pct.py <unit e.g. main/vecmath.c | main/main/vecmath> [substr]"""
import json, sys
def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr); return 1
    want = sys.argv[1]; filt = sys.argv[2] if len(sys.argv) > 2 else None
    d = json.load(open("build/GSAE01/report.json"))
    def cfg(rn): return (rn[5:] if rn.startswith("main/") else rn) + ".c"
    t = next((u for u in d["units"] if cfg(u["name"]) == want or u["name"] == want), None)
    if t is None:
        print(f"unit not found: {want}", file=sys.stderr); return 2
    fns = sorted(t.get("functions", []), key=lambda f: f.get("fuzzy_match_percent", 0))
    n100 = sum(1 for f in fns if f.get("fuzzy_match_percent", 0) >= 100)
    for f in fns:
        if filt and filt not in f["name"]: continue
        print(f"{f.get('fuzzy_match_percent',0):7.3f} {int(f.get('size',0)):6d} {f['name']}")
    print(f"--- {n100}/{len(fns)} at 100% : {cfg(t['name'])}")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
