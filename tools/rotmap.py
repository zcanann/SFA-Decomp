"""Register-rotation mapper: when target and current differ ONLY (or mostly)
by register numbering, align the two instruction streams and extract the
register correspondence — which target reg maps to which current reg, with
counts and first-def context. The output is the raw data for attacking the
#108 rotation class: a consistent T->C permutation with identical opcodes
means the webs are right and only the allocator's ordering differs.

Usage:
  python3 tools/rotmap.py <unit> <symbol>

Output: per register-pair (T,C): occurrence count, first line of use, and
the defining instruction shape; plus a summary permutation table and any
non-register differences (real divergences that must be fixed FIRST).
"""
from __future__ import annotations

import argparse
import difflib
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble
from ndiff import normalize

REG_RE = re.compile(r"\b([rf]\d+)\b")


def reg_skeleton(instr: str) -> str:
    return REG_RE.sub("R", instr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("unit")
    ap.add_argument("symbol")
    ap.add_argument("-v", "--version", default="GSAE01")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    config_path = repo_root / "build" / args.version / "config.json"
    objdump_path = repo_root / "build" / "binutils" / "powerpc-eabi-objdump"
    unit = resolve_unit(load_units(config_path), args.unit)
    target_object = repo_root / Path(unit["object"])
    current_object = repo_root / Path(unit["object"].replace(
        f"build/{args.version}/obj/", f"build/{args.version}/src/"))

    t = [x for x in normalize(strip_preamble(objdump_symbol(objdump_path, target_object, args.symbol))) if not x.startswith("RELOC")]
    c = [x for x in normalize(strip_preamble(objdump_symbol(objdump_path, current_object, args.symbol))) if not x.startswith("RELOC")]

    # align on register-skeletons so pure renames pair up
    ts = [reg_skeleton(x) for x in t]
    cs = [reg_skeleton(x) for x in c]
    sm = difflib.SequenceMatcher(None, ts, cs, autojunk=False)

    pair_counts: Counter = Counter()
    pair_first: dict = {}
    structural = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                ti, ci = t[i1 + k], c[j1 + k]
                tregs, cregs = REG_RE.findall(ti), REG_RE.findall(ci)
                if len(tregs) == len(cregs):
                    for a, b in zip(tregs, cregs):
                        if a != b:
                            pair_counts[(a, b)] += 1
                            pair_first.setdefault((a, b), (i1 + k, ti, ci))
        else:
            structural.append((tag, t[i1:i2], c[j1:j2]))

    print(f"streams: T={len(t)} C={len(c)} | skeleton-aligned, "
          f"{len(structural)} structural region(s)")
    if structural:
        print("\nSTRUCTURAL (fix these first — not pure rotation):")
        for tag, tt, cc in structural[:8]:
            print(f"  {tag} T:{tt[:4]}")
            print(f"      C:{cc[:4]}")

    print("\nregister correspondence (T -> C, count, first def/use):")
    # group: consistent mappings vs conflicting
    by_t = defaultdict(list)
    for (a, b), n in sorted(pair_counts.items(), key=lambda kv: -kv[1]):
        by_t[a].append((b, n))
    for a in sorted(by_t, key=lambda r: (r[0], int(r[1:]))):
        maps = by_t[a]
        flag = "" if len(maps) == 1 else "  <-- INCONSISTENT (web split or alignment noise)"
        first = pair_first[(a, maps[0][0])]
        print(f"  {a:5s} -> " + ", ".join(f"{b}({n})" for b, n in maps) +
              flag + f"   e.g. line {first[0]}: {first[1]}")


if __name__ == "__main__":
    main()
