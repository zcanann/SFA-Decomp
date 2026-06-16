#!/usr/bin/env python3
"""Fuzzy% lookup against a freshly-generated objdiff report (bypasses ninja
report.json which can be blocked by unrelated broken units). Regenerate the
report first with: build/tools/objdiff-cli report generate -o /tmp/myreport.json

Usage: fpct2.py <substr-of-unit> [<substr-of-fn>]
"""
import json, sys
from pathlib import Path

rep = json.load(open("/tmp/myreport.json"))
usub = sys.argv[1] if len(sys.argv) > 1 else ""
fsub = sys.argv[2] if len(sys.argv) > 2 else ""
out = []
for u in rep["units"]:
    un = u["name"]
    if usub.lower() not in un.lower():
        continue
    for f in u.get("functions", []):
        fn = f.get("name", "")
        p = f.get("fuzzy_match_percent")
        if p is None:
            continue
        if fsub and fsub.lower() not in fn.lower():
            continue
        out.append((p, int(f.get("size") or 0), un, fn))
out.sort()
for p, sz, un, fn in out:
    print(f"{p:9.4f} {sz:5d} {un} :: {fn}")
print(f"# {len(out)} fns", file=sys.stderr)
