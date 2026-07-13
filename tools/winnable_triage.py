#!/usr/bin/env python3
"""Batch-classify every sub-100 game function: target vs current instruction
counts. Flags C>T (current has removable surplus = winnable) vs T==C
(reg-perm/length-welded) vs T>C. Reads .o directly (never stale)."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble
from ndiff import normalize, regions, regs_only_diff

REPO = Path(__file__).resolve().parent.parent
VER = "GSAE01"
objdump = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
if not objdump.is_file():
    objdump = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"

report = json.load(open(REPO / f"build/{VER}/report.json"))
units_cfg = load_units(REPO / "build" / VER / "config.json")

# collect sub-100 game fns: (fuzzy, unit_name_in_report, sym)
targets = []
for u in report["units"]:
    un = u.get("name", "")
    if not un.startswith("main/"):
        continue
    for f in u.get("functions", []):
        fz = f.get("fuzzy_match_percent", 100.0)
        if fz < 100.0 and fz >= float(sys.argv[1] if len(sys.argv) > 1 else 90.0):
            targets.append((fz, un, f.get("name", "")))
targets.sort()

def basename_c(report_unit):
    # report unit is main/<path>.c doubled -> config uses build/GSAE01/src/main/<path>.o
    p = report_unit[len("main/"):]
    if p.endswith(".c"):
        p = p[:-2]
    return p

winnable = []
welded = 0
shorter = 0
errors = 0
for fz, un, sym in targets:
    p = basename_c(un)
    unit = None
    for q in (un, un[len("main/"):], Path(p).name + ".c", Path(p).name):
        try:
            unit = resolve_unit(units_cfg, q)
            break
        except BaseException:
            continue
    if unit is None:
        errors += 1
        continue
    try:
        tobj = REPO / Path(unit["object"])
        cobj = REPO / Path(unit["object"].replace(f"build/{VER}/obj/", f"build/{VER}/src/"))
        t = normalize(strip_preamble(objdump_symbol(objdump, tobj, sym)))
        c = normalize(strip_preamble(objdump_symbol(objdump, cobj, sym)))
    except Exception:
        errors += 1
        continue
    if not t or not c:
        errors += 1
        continue
    d = len(c) - len(t)  # >0 => current has surplus = winnable
    # count non-regperm regions
    regs = regions(t, c)
    nonperm = sum(1 for (tag, i1, i2, j1, j2) in regs
                  if not regs_only_diff(t[i1:i2], c[j1:j2]))
    if d > 0:
        winnable.append((d, nonperm, fz, len(t), len(c), un, sym))
    elif d == 0:
        welded += 1
    else:
        shorter += 1

winnable.sort(reverse=True)  # biggest surplus first
print(f"sub-100 examined: {len(targets)}  errors: {errors}")
print(f"  C>T (winnable surplus): {len(winnable)}")
print(f"  T==C (length-welded/regperm): {welded}")
print(f"  T>C (current shorter): {shorter}")
print("\nWINNABLE (surplus_instrs, nonperm_regions, fuzzy, T_len, C_len, unit, sym):")
for d, nonperm, fz, tl, cl, un, sym in winnable:
    print(f"  +{d:3d} np={nonperm:2d} {fz:6.2f} T{tl}/C{cl} {un.replace('main/','')} {sym}")
