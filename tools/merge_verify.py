#!/usr/bin/env python3
"""Post-merge verification: markers, duplicate symbol names, build gate, DOL sha, report deltas.

Usage:
    python3 tools/merge_verify.py [--expect-dol SHA] [--baseline path/to/report.json]

Checks, in order of how cheaply they fail:
  1. no conflict markers anywhere in tracked sources
  2. no address in symbols.txt carrying two different names (the rename-collision
     class a merge introduces silently: one side renames fn_8XXXXXXX -> semanticName
     and the other keeps the old name, and git conflicts on neither)
  3. ninja EXIT=0
  4. main.dol sha matches the expected retail hash
  5. report.json measures vs a baseline copy
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RETAIL_DOL = "e750e8e894707a52446118a4b84f1b58b677b269"
MARKERS = ("\n<<<<<<<", "\n=======", "\n>>>>>>>")


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kw)


def check_markers():
    """Conflict markers in tracked files. Uses git ls-files, not a shell glob:
    zsh expands an unquoted --include=*.c and silently produces a false zero."""
    files = sh("git", "ls-files", "src", "include", "config", "tools").stdout.split()
    bad = []
    for f in files:
        p = ROOT / f
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        n = t.count(MARKERS[0])
        if n:
            bad.append((n, f))
    return bad


def check_duplicate_symbol_names():
    """An address in symbols.txt with two distinct names.

    A merge where one side renames fn_801FE560 -> dbegg_probeSurface and the other
    does not produces exactly this, and neither the compiler nor git flags it.
    """
    path = ROOT / "config" / "GSAE01" / "symbols.txt"
    if not path.exists():
        return []
    by_addr = collections.defaultdict(set)
    pat = re.compile(r"^\s*([A-Za-z_][\w$]*)\s*=\s*\.?\w+:(0x[0-9A-Fa-f]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pat.match(line)
        if m:
            by_addr[m.group(2).lower()].add(m.group(1))
    return sorted((a, sorted(n)) for a, n in by_addr.items() if len(n) > 1)


def measures():
    p = ROOT / "build" / "GSAE01" / "report.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())["measures"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect-dol", default=RETAIL_DOL)
    ap.add_argument("--baseline")
    ap.add_argument("--skip-build", action="store_true")
    a = ap.parse_args()
    fail = False

    bad = check_markers()
    print(f"[1] conflict markers: {'CLEAN' if not bad else str(len(bad)) + ' FILES'}")
    for n, f in bad[:20]:
        print(f"      {n:3d}  {f}")
    fail |= bool(bad)

    dup = check_duplicate_symbol_names()
    print(f"[2] symbols.txt one-address-two-names: {'CLEAN' if not dup else str(len(dup)) + ' COLLISIONS'}")
    for addr, names in dup[:20]:
        print(f"      {addr}  {' | '.join(names)}")
    fail |= bool(dup)

    if a.skip_build:
        print("[3] build: SKIPPED")
        return 1 if fail else 0

    # `timeout` is not installed on this box and returns 127 without building, so
    # never wrap this. Go through the build mutex so a parallel matching agent
    # cannot corrupt .ninja_log / race the .d writes underneath us.
    r = sh("bash", "--noprofile", "--norc", "tools/locked_ninja.sh")
    print(f"[3] ninja EXIT={r.returncode}")
    if r.returncode:
        print("      " + "\n      ".join(r.stderr.strip().splitlines()[-12:]))
        return 1
    fail |= bool(r.returncode)

    dol = ROOT / "build" / "GSAE01" / "main.dol"
    got = hashlib.sha1(dol.read_bytes()).hexdigest() if dol.exists() else "MISSING"
    ok = got == a.expect_dol
    print(f"[4] main.dol sha: {got} {'== retail' if ok else '!= EXPECTED ' + a.expect_dol}")
    fail |= not ok

    m = measures()
    if m:
        print(f"[5] fuzzy {m['fuzzy_match_percent']:.6f}  fns {m['matched_functions']}  "
              f"complete {m['complete_units']}/{m['total_units']}  data {m['matched_data_percent']:.5f}")
        if a.baseline and pathlib.Path(a.baseline).exists():
            b = json.loads(pathlib.Path(a.baseline).read_text())["measures"]
            for k, fmt in (("fuzzy_match_percent", "%+.6f"), ("matched_functions", "%+d"),
                           ("complete_units", "%+d"), ("matched_data_percent", "%+.5f")):
                print(f"      {k:24s} {fmt % (m[k] - b[k])}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
