#!/usr/bin/env python3
"""ext_vein_screen.py [--all]

Tree-wide screen for the isolated-ext-insert vein (see
memory/two-factor-interaction-law.md). For every sub-100 function in
report.json it runs the multiset.py mnemonic-delta classifier and prints a
RANKED table, ISOLATED EXT/SIGNEDNESS handles first -- the one proven-paying
two-factor shape (objseq's ext-insert scored flips).

Stage 1 (this tool): mnemonic-delta class per function.
Stage 2 (manual): ndiff the top EXT/SIGNEDNESS candidates -- if the surviving
regions are saved-reg numbering perms (r26<->r28, li<->mr) or a frame/
displacement divergence, the add-IR fix CASCADES => DEMOTE. Only a handle
ISOLATED from coloring with a plausible clean-C source is a real candidate.

  --all   also print PURE-REG-PERM / ZERO-REUSE / BRANCH-SENSE rows.

Reads build/GSAE01/report.json (fn set) + config.json (unit resolution) and
disassembles retail obj vs our src obj via function_objdump. No build needed;
READ-ONLY.
"""
import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import (
    load_units,
    resolve_unit,
    objdump_symbol,
    strip_preamble,
)
from multiset import mnem_counts, deltas, classify

RANK = {
    "SIGNEDNESS-HANDLE": 0,
    "EXT-HANDLE-T": 0,
    "EXT-HANDLE-C": 1,
    "MIXED": 2,
    "BRANCH-SENSE": 3,
    "ZERO-REUSE-CAP": 4,
    "PURE-REG-PERM": 5,
}


def cfg_queries(report_name):
    n = report_name
    if n.startswith("main/"):
        n = n[len("main/"):]
    return [n + ".c", Path(report_name).name + ".c"]


def main():
    show_all = "--all" in sys.argv[1:]
    units = load_units(Path("build/GSAE01/config.json"))
    objdump = Path("build/binutils/powerpc-eabi-objdump")
    report = json.load(open("build/GSAE01/report.json"))

    rows = []
    for u in report["units"]:
        if u.get("metadata", {}).get("auto_generated"):
            continue
        subs = [
            f for f in u.get("functions", [])
            if f.get("fuzzy_match_percent", 100.0) < 100.0
        ]
        if not subs:
            continue
        unit = None
        for q in cfg_queries(u["name"]):
            try:
                unit = resolve_unit(units, q)
                break
            except SystemExit:
                continue
        if unit is None:
            continue
        obj = Path(unit["object"])
        src = Path(unit["object"].replace("/obj/", "/src/"))
        if not src.exists():
            continue
        for f in subs:
            sym = f["name"]
            try:
                tgt = strip_preamble(objdump_symbol(objdump, obj, sym))
                cur = strip_preamble(objdump_symbol(objdump, src, sym))
            except Exception:
                continue
            et, ec = deltas(mnem_counts(tgt), mnem_counts(cur))
            label, promising = classify(et, ec)
            rows.append((label, promising, f["fuzzy_match_percent"],
                         unit["name"], sym, et, ec))

    rows.sort(key=lambda r: (RANK.get(r[0], 9), -r[2]))
    hist = Counter(r[0] for r in rows)
    npro = sum(1 for r in rows if r[1])

    for label, promising, fuzzy, unit, sym, et, ec in rows:
        if not show_all and label in ("PURE-REG-PERM",):
            continue
        flag = " *PROMISING*" if promising else ""
        print(f"{fuzzy:7.3f}  {label:17s}{flag:12s}  {unit:40s} {sym}"
              f"  T={et} C={ec}")
    print(f"\n-- {len(rows)} sub-100 fns screened; histogram={dict(hist)}; "
          f"stage-1 promising={npro} (RUN NDIFF ON THESE) --")


if __name__ == "__main__":
    main()
