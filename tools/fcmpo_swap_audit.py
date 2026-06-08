#!/usr/bin/env python3
"""fcmpo operand-swap audit (recipe #81 store-clamp discriminator).

Finds sub-100% functions whose target binary and current build disagree ONLY
in the OPERAND ORDER of one or more `fcmpo` instructions (a CLEAN same-register
swap: target `fcmpo cr0,f1,f0` vs current `fcmpo cr0,f0,f1`). These are the
recipe #81 FP-clamp launder candidates.

DISCRIMINATOR (calibrated over ~20 A/Bs, miner-4 — see CLAUDE.md recipe #81):
  WORKS  — a STORE-clamp (`if (x op lbl) x = lbl;`, or decrement/fmadds then
           `if (x op lbl) x = lbl;`) with a clean same-register swap launders
           reliably: spell ONE reference of the limit as `*(f32 *)&lbl`
           (compare- OR store-side; A/B both, the winning side varies per fn).
  RESIST — named-`lim` embedded-assign clamps; no-store reload compares;
           computed-limit compares; whole-register SHIFTS (f2,f1<->f1,f0, NOT
           a same-register swap — that's the #82 expression-temp tier); and
           multi-clamp blocks sharing one constant across swapped AND already-
           matched clamps (laundering the shared constant flips the matched
           siblings — high regression risk).

This tool reports, per candidate:
  - fuzzy%, size, the count of clean swaps, and whether each swap looks like a
    STORE-clamp (a `stfs` appears within a few instructions of the fcmpo) — the
    `storeclamp=N` count is the high-confidence subset.

Usage:
  python3 tools/fcmpo_swap_audit.py [--min-pct 90] [--max-pct 99.999]
                                    [--max-size 2500] [--unit-filter SUBSTR]
                                    [--store-only]
Reads build/GSAE01/report.json (refresh it first:
  rm -f build/GSAE01/report.json && ninja build/GSAE01/report.json).
Compares the dtk TARGET object (build/GSAE01/obj/...) against the CURRENT
build object (build/GSAE01/src/...) for each function symbol.
"""
import argparse
import json
import os
import re
import subprocess

OBJDUMP = "build/binutils/powerpc-eabi-objdump"
INSN_RE = re.compile(r"\s+[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*)")


def disasm(obj, sym):
    try:
        out = subprocess.run(
            [OBJDUMP, "-d", "--disassemble=" + sym, obj],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception:
        return None
    lines = []
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if m:
            lines.append((m.group(1), m.group(2).strip()))
    return lines


def is_storeclamp(insns, idx):
    """A stfs within +/-3 instructions of the fcmpo => store-clamp shape."""
    lo, hi = max(0, idx - 3), min(len(insns), idx + 4)
    return any(mn == "stfs" for mn, _ in insns[lo:hi])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-pct", type=float, default=90.0)
    ap.add_argument("--max-pct", type=float, default=99.999)
    ap.add_argument("--max-size", type=int, default=2500)
    ap.add_argument("--unit-filter", default=None)
    ap.add_argument("--store-only", action="store_true",
                    help="only report candidates with >=1 store-clamp swap")
    args = ap.parse_args()

    report = json.load(open("build/GSAE01/report.json"))
    hits = []
    for unit in report["units"]:
        sp = unit.get("metadata", {}).get("source_path")
        if not sp or not sp.startswith("src/"):
            continue
        if args.unit_filter and args.unit_filter not in sp:
            continue
        name = sp[4:]
        tobj = f"build/GSAE01/obj/{name[:-2]}.o"
        cobj = f"build/GSAE01/src/{name[:-2]}.o"
        if not (os.path.exists(tobj) and os.path.exists(cobj)):
            continue
        for fn in unit.get("functions", []):
            fp = fn.get("fuzzy_match_percent", 100.0)
            if fp >= args.max_pct or fp < args.min_pct:
                continue
            if int(fn["size"]) > args.max_size:
                continue
            sym = fn["name"]
            t = disasm(tobj, sym)
            c = disasm(cobj, sym)
            if not t or not c or abs(len(t) - len(c)) > 4:
                continue
            tf = [i for i, (mn, _) in enumerate(t) if mn == "fcmpo"]
            cf = [i for i, (mn, _) in enumerate(c) if mn == "fcmpo"]
            if len(tf) != len(cf) or not tf:
                continue
            swaps = 0
            store = 0
            for ti, ci in zip(tf, cf):
                to = t[ti][1].split(",")
                co = c[ci][1].split(",")
                if to[-2:] == co[-2:][::-1] and to != co:
                    swaps += 1
                    if is_storeclamp(t, ti):
                        store += 1
            if swaps and (store or not args.store_only):
                hits.append((fp, int(fn["size"]), swaps, store, name, sym))

    hits.sort(key=lambda h: (-h[3], -h[0]))
    print(f"{'pct':>7} {'size':>6} {'swap':>4} {'store':>5}  unit / fn")
    for fp, sz, swaps, store, name, sym in hits:
        print(f"{fp:7.2f} {sz:6} {swaps:4} {store:5}  {name} {sym}")
    print(f"\n{len(hits)} candidates"
          f" ({sum(1 for h in hits if h[3])} with store-clamp swaps)")


if __name__ == "__main__":
    main()
