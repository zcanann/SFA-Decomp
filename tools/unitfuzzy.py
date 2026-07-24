#!/usr/bin/env python3
"""Fast, race-free true-fuzzy score for ONE unit (and its functions).

Why this exists: the usual `rm -f build/GSAE01/report.json && ninja
build/GSAE01/report.json` regenerates all ~1200 units and writes a SHARED file.
With several matching agents running, peers delete that file seconds after it
appears, so a measurement randomly fails or -- worse -- a sweep silently records
holes. This instead writes a throwaway one-unit objdiff project and asks
objdiff-cli for a report over just that unit: ~0.15s, no shared state, and the
SAME metric as report.json (true fuzzy_match_percent), unlike `objdiff-cli diff`
one-shot percentages which undercount.

    python3 tools/unitfuzzy.py zlb                 # unit + every sub-100 function
    python3 tools/unitfuzzy.py main/objprint.c --all
    python3 tools/unitfuzzy.py Hcurves --symbol RomCurve_func1C

Exit status is 0 on success, 1 if the unit could not be measured (e.g. its .o
has not been built yet) -- never a silent zero.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def objdiff_cli() -> Path:
    p = REPO / "build" / "tools" / "objdiff-cli.exe"
    return p if p.is_file() else REPO / "build" / "tools" / "objdiff-cli"


def find_unit(version: str, query: str) -> dict:
    cfg = json.loads((REPO / "build" / version / "config.json").read_text())
    q = query.replace("\\", "/")
    cands = []
    for u in cfg["units"]:
        name = u["name"].replace("\\", "/")
        if q in (name, Path(name).stem) or name.endswith(q) or Path(name).stem == Path(q).stem:
            cands.append(u)
    if not cands:
        sys.exit(f"unit not found: {query}")
    # prefer an exact name match when several fuzzy-match
    for u in cands:
        if u["name"].replace("\\", "/") == q:
            return u
    if len(cands) > 1:
        sys.exit("ambiguous unit '%s': %s" % (query, ", ".join(u["name"] for u in cands)))
    return cands[0]


def measure(unit: dict, version: str):
    target = (REPO / unit["object"]).resolve()
    base = (REPO / unit["object"].replace(f"build/{version}/obj/",
                                          f"build/{version}/src/")).resolve()
    if not base.is_file():
        raise RuntimeError(f"not built yet: {base}")
    report_name = "main/" + unit["name"].replace("\\", "/").rsplit(".", 1)[0]
    with tempfile.TemporaryDirectory() as td:
        proj = Path(td)
        (proj / "objdiff.json").write_text(json.dumps({
            "min_version": "2.0.0-beta.5",
            "build_target": False,
            "build_base": False,
            "units": [{
                "name": report_name,
                "target_path": str(target),
                "base_path": str(base),
                "metadata": {"complete": False, "auto_generated": False,
                             "source_path": unit["name"]},
            }],
        }, indent=1))
        out = proj / "r.json"
        r = subprocess.run([str(objdiff_cli()), "report", "generate",
                            "-p", str(proj), "-o", str(out), "-f", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0 or not out.is_file():
            raise RuntimeError("objdiff-cli failed: " + (r.stderr.strip() or "no output"))
        data = json.loads(out.read_text())
    for u in data["units"]:
        if u["name"].endswith(report_name.split("/")[-1]):
            return u
    raise RuntimeError("unit missing from generated report")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("unit")
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--all", action="store_true", help="list every function, not just sub-100")
    ap.add_argument("--symbol", action="append", default=[], help="only these functions")
    ap.add_argument("--quiet", action="store_true", help="print just the unit fuzzy")
    args = ap.parse_args()

    try:
        u = measure(find_unit(args.version, args.unit), args.version)
    except RuntimeError as exc:
        sys.exit(str(exc))
    fz = u["measures"].get("fuzzy_match_percent")
    if fz is None:
        sys.exit("no fuzzy_match_percent for this unit (object mismatch?)")
    if args.quiet:
        print(f"{fz:.5f}")
        return 0
    print(f"{u['name']}  fuzzy={fz:.5f}")
    fns = u.get("functions") or []
    for f in sorted(fns, key=lambda f: float(f["fuzzy_match_percent"])):
        pct = float(f["fuzzy_match_percent"])
        if args.symbol and f["name"] not in args.symbol:
            continue
        if args.symbol or args.all or pct < 100.0:
            print(f"  {pct:8.3f}  {f['size']:>6}B  {f['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
