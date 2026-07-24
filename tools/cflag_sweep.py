#!/usr/bin/env python3
"""Sweep TU-level cflag profiles for one unit, gating on true objdiff fuzzy.

The purged per-function optimization pragmas are only re-expressible as TU-level
cflags (see CLAUDE.md). When a unit is a single function -- or a TU re-split has
isolated the region -- the right profile is found by trying them all. This does
that mechanically and reports the ranked result, so a unit can be declared
flag-inert with evidence instead of by guesswork.

    python3 tools/cflag_sweep.py main/worldplanet_lighting.c worldplanet_lighting

configure.py is always restored (and re-run) on exit, including on error/Ctrl-C.
Profiles that fail to build, or whose report has no fuzzy for the unit (objdiff
report generation is all-or-nothing and can lose a race with a concurrent
build), are reported as BUILD-FAIL / NO-MEASURE rather than silently dropped.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def write_conf(path: Path, text: str) -> None:
    """Path.write_text(newline=) needs py3.10; this box runs 3.9."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)

def run(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, cwd=REPO, capture_output=True, text=True)


def measure(unit_suffix: str, version: str):
    report = REPO / "build" / version / "report.json"
    if report.exists():
        report.unlink()
    run(f"bash tools/locked_ninja.sh build/{version}/report.json")
    if not report.exists():
        return None
    try:
        data = json.loads(report.read_text())
    except Exception:
        return None
    for unit in data["units"]:
        if unit["name"].endswith(unit_suffix):
            return unit["measures"].get("fuzzy_match_percent")
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("object_key", help='configure.py Object path, e.g. main/worldplanet_lighting.c')
    ap.add_argument("unit_suffix", help='report.json unit name suffix, e.g. worldplanet_lighting')
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--obj", help="object path to force-rebuild (default: derived from object_key)")
    args = ap.parse_args()

    obj = args.obj or f"build/{args.version}/src/{args.object_key[:-2]}.o"
    conf = REPO / "configure.py"
    orig = conf.read_text(encoding="utf-8")

    m = re.search(r'Object\((\w+), "' + re.escape(args.object_key) + r'", cflags=(\w+)\)', orig)
    if not m:
        sys.exit(f"no simple `Object(<status>, \"{args.object_key}\", cflags=...)` line in configure.py")
    status, current = m.group(1), m.group(2)
    old_line = f'Object({status}, "{args.object_key}", cflags={current})'
    profiles = sorted(set(re.findall(r"^(cflags_dll[a-z_0-9]*) =", orig, re.M)))
    print(f"unit={args.unit_suffix}  current={current}  profiles={len(profiles)}\n")

    results = []
    try:
        for prof in profiles:
            write_conf(conf, orig.replace(old_line, f'Object({status}, "{args.object_key}", cflags={prof})'))
            if run("python3 configure.py").returncode != 0:
                print(f"{prof:<62} CONFIGURE-FAIL")
                continue
            objp = REPO / obj
            if objp.exists():
                objp.unlink()
            if run(f"bash tools/locked_ninja.sh {obj}").returncode != 0 or not objp.exists():
                print(f"{prof:<62} BUILD-FAIL")
                continue
            fz = measure(args.unit_suffix, args.version)
            print(f"{prof:<62} {f'{fz:.5f}' if fz is not None else 'NO-MEASURE'}")
            if fz is not None:
                results.append((fz, prof))
    finally:
        write_conf(conf, orig)
        run("python3 configure.py")
        objp = REPO / obj
        if objp.exists():
            objp.unlink()
        run(f"bash tools/locked_ninja.sh {obj}")
        measure(args.unit_suffix, args.version)
        print("\n-- configure.py restored --")

    results.sort(reverse=True)
    print("\nranked:")
    for fz, prof in results[:10]:
        flag = "  <= current" if prof == current else ""
        print(f"  {fz:.5f}  {prof}{flag}")
    if results:
        best, bprof = results[0]
        cur = next((f for f, p in results if p == current), None)
        if cur is not None and best > cur:
            print(f"\nWIN: {bprof} {cur:.5f} -> {best:.5f}")
        else:
            print(f"\nflag-inert: nothing beats {current} ({cur if cur is None else f'{cur:.5f}'})")


if __name__ == "__main__":
    main()
