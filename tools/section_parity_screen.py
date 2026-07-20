#!/usr/bin/env python3
"""Section-parity screen.

Compares the retail carved object (build/GSAE01/obj/<unit>.o, READ-ONLY) against our
built object (build/GSAE01/src/<unit>.o) on per-section SIZE, ignoring .note.split and
purely-symbolic sections. A unit with full parity is promotable IN PRINCIPLE; a unit
whose .sdata2/.sdata/.sbss/.rodata sizes differ has a TU-boundary problem that no code
fix touches, and is NOT promotable no matter what it scores.

Usage:
  section_parity_screen.py                 # screen every NonMatching unit with a report entry
  section_parity_screen.py --min-fuzzy 90  # restrict by fuzzy score
  section_parity_screen.py <unit> ...      # screen named units
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build", "GSAE01")
READELF = os.path.join(ROOT, "build", "binutils", "powerpc-eabi-readelf")

IGNORE = {
    "",
    ".note.split",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".comment",
    ".note.GNU-stack",
}


def sections(path):
    out = subprocess.run(
        [READELF, "-S", "-W", path], capture_output=True, text=True
    ).stdout
    res = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        rb = line.find("]")
        parts = line[rb + 1 :].split()
        if len(parts) < 5:
            continue
        name, typ = parts[0], parts[1]
        if name in IGNORE or typ in ("NULL", "REL", "RELA", "SYMTAB", "STRTAB"):
            continue
        try:
            size = int(parts[4], 16)
        except ValueError:
            continue
        res[name] = size
    return res


def obj_rel(unit):
    parts = unit.split("/")
    if len(parts) > 1 and parts[0] in ("main", "track"):
        return "/".join(parts[1:])
    return unit


def screen(unit):
    rel = obj_rel(unit)
    retail = os.path.join(BUILD, "obj", rel + ".o")
    ours = os.path.join(BUILD, "src", rel + ".o")
    if not os.path.exists(retail):
        return None, "no retail carve"
    if not os.path.exists(ours):
        return None, "not built"
    r, o = sections(retail), sections(ours)
    diffs = []
    for name in sorted(set(r) | set(o)):
        rs, os_ = r.get(name, 0), o.get(name, 0)
        if rs != os_:
            diffs.append("%s retail=0x%X ours=0x%X" % (name, rs, os_))
    return (not diffs), ("; ".join(diffs) if diffs else "PARITY")


def main():
    argv = sys.argv[1:]
    min_fuzzy = 0.0
    args = []
    i = 0
    while i < len(argv):
        if argv[i] == "--min-fuzzy":
            min_fuzzy = float(argv[i + 1])
            i += 2
            continue
        args.append(argv[i])
        i += 1

    if args:
        units = args
    else:
        rep = json.load(open(os.path.join(BUILD, "report.json")))
        units = []
        for u in rep["units"]:
            if u["metadata"].get("auto_generated") or u["metadata"].get("complete"):
                continue
            if u["measures"].get("fuzzy_match_percent", 0.0) < min_fuzzy:
                continue
            units.append(u["name"])

    clean, dirty = [], []
    for unit in units:
        ok, msg = screen(unit)
        (clean if ok else dirty).append((unit, msg))

    print("== SECTION-CLEAN (promotable in principle): %d ==" % len(clean))
    for u, _ in clean:
        print("  " + u)
    print("== NOT CLEAN: %d ==" % len(dirty))
    for u, m in dirty:
        print("  %-55s %s" % (u, m))


if __name__ == "__main__":
    main()
