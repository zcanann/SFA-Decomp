#!/usr/bin/env python3
"""A-slot signature detector.

Finds functions where our FP multiply has the pool constant in the A slot and
retail has the variable there (or vice versa).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve()
REPO = Path(__file__).resolve().parent.parent
OBJDUMP = REPO / "build" / "binutils" / "powerpc-eabi-objdump"

FUNC_HDR = re.compile(r"^[0-9a-f]+ <(.+)>:$")
INSN = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
# multiply-family ops whose (A,C) operands we care about
MUL_OPS = {"fmuls", "fmul", "fmadds", "fmadd", "fmsubs", "fmsub",
           "fnmadds", "fnmsubs", "fdivs", "fdiv", "fadds", "fsubs"}
# for these, the multiply operand pair is operands[1],[2]; for div/add/sub it's [1],[2] too
# In UNLINKED objects the SDA21 reloc is unapplied, so a pool load reads as
# "lfs f0,0(0)" (base literal 0). Linked objects use r2/r13.
POOL_LOAD = re.compile(r"^(lfs|lfd)\s+(f\d+),\s*(-?(?:0x)?[0-9a-fA-F]+)\((0|r2|r13)\)")
ANY_FLOAT_DEF = re.compile(r"^(f\d+)")


def disassemble(obj: Path) -> dict[str, list[tuple[str, str]]]:
    cmd = [str(OBJDUMP), "-M", "gekko", "-drz", str(obj)]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError:
        return {}
    funcs: dict[str, list[tuple[str, str]]] = {}
    cur = None
    for line in out.splitlines():
        m = FUNC_HDR.match(line)
        if m:
            cur = m.group(1)
            funcs[cur] = []
            continue
        if cur is None:
            continue
        mi = INSN.match(line)
        if mi:
            funcs[cur].append((mi.group(1), mi.group(2).strip()))
    return funcs


def classify(insns: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """Return list of (op, classA, classB) for each multiply-family insn."""
    regclass: dict[str, str] = {}
    out = []
    for op, operands in insns:
        full = f"{op} {operands}"
        pm = POOL_LOAD.match(full)
        if pm:
            regclass[pm.group(2)] = "POOL"
            continue
        ops = [o.strip() for o in operands.split(",")]
        if op in MUL_OPS and len(ops) >= 3:
            a, b = ops[1], ops[2]
            out.append((op, regclass.get(a, "VAR"), regclass.get(b, "VAR")))
        # any float-defining instruction marks dest as VAR
        if ops and ANY_FLOAT_DEF.match(ops[0]) and op.startswith(("f", "lfs", "lfd", "ps_")):
            if not pm:
                regclass[ops[0]] = "VAR"
    return out


def main() -> None:
    cfg = json.load(open(REPO / "build" / "GSAE01" / "config.json"))
    report = json.load(open(REPO / "build" / "GSAE01" / "report.json"))

    # fuzzy per (unit, fn) and weighted missing bytes
    fnfuzzy: dict[str, dict[str, tuple[float, int]]] = {}
    for u in report["units"]:
        fns = u.get("functions") or []
        d = {}
        for f in fns:
            try:
                d[f["name"]] = (float(f["fuzzy_match_percent"]), int(f["size"]))
            except (KeyError, ValueError, TypeError):
                pass
        if d:
            # report.json prefixes unit names with "main/"; config.json does not
            key = u["name"]
            if key.startswith("main/"):
                key = key[len("main/"):]
            fnfuzzy[key] = d

    units = cfg["units"]

    def work(unit):
        # config.json names carry a ".c" suffix that report.json names lack
        name = unit["name"]
        if name.endswith(".c"):
            name = name[:-2]
        if name not in fnfuzzy:
            return []
        tgt = REPO / unit["object"]
        cur = REPO / unit["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
        if not tgt.is_file() or not cur.is_file():
            return []
        # only bother if unit has any sub-100 fn
        if not any(v[0] < 100.0 for v in fnfuzzy[name].values()):
            return []
        tf = disassemble(tgt)
        cf = disassemble(cur)
        hits = []
        for fn, (fz, size) in fnfuzzy[name].items():
            if fz >= 100.0:
                continue
            if fn not in tf or fn not in cf:
                continue
            tc = classify(tf[fn])
            cc = classify(cf[fn])
            if len(tc) != len(cc):
                # Positional alignment is meaningless when the FP-op counts
                # differ, but an A-slot swap still shows up as a per-op
                # orientation imbalance with the total held constant.
                tm = Counter((o, a, b) for o, a, b in tc if {a, b} == {"POOL", "VAR"})
                cm = Counter((o, a, b) for o, a, b in cc if {a, b} == {"POOL", "VAR"})
                swaps = []
                for o in {x[0] for x in list(tm) + list(cm)}:
                    tpv, tvp = tm[(o, "POOL", "VAR")], tm[(o, "VAR", "POOL")]
                    cpv, cvp = cm[(o, "POOL", "VAR")], cm[(o, "VAR", "POOL")]
                    if tpv + tvp == cpv + cvp and (tpv, tvp) != (cpv, cvp):
                        swaps.append((-1, o, f"tgt(P,V)={tpv}/(V,P)={tvp}",
                                      f"cur(P,V)={cpv}/(V,P)={cvp} [LENDIFF]"))
                if swaps:
                    hits.append(((100.0 - fz) / 100.0 * size, name, fn, fz, size, swaps))
                continue
            swaps = []
            for i, (t, c) in enumerate(zip(tc, cc)):
                if t[0] != c[0]:
                    continue
                # A-slot swap: classes are opposite orientation
                if t[1] != c[1] and t[2] != c[2] and {t[1], t[2]} == {c[1], c[2]} == {"POOL", "VAR"}:
                    swaps.append((i, t[0], f"tgt({t[1]},{t[2]})", f"cur({c[1]},{c[2]})"))
            if swaps:
                wb = (100.0 - fz) / 100.0 * size
                hits.append((wb, name, fn, fz, size, swaps))
        return hits

    allhits = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(work, units):
            allhits.extend(r)

    allhits.sort(reverse=True, key=lambda x: x[0])
    print(f"{'wB':>8}  {'fuzzy':>7} {'size':>6}  unit / fn")
    for wb, unit, fn, fz, size, swaps in allhits:
        print(f"{wb:8.1f}  {fz:7.3f} {size:6d}  {unit}  {fn}")
        for s in swaps:
            print(f"              idx{s[0]} {s[1]} {s[2]} -> {s[3]}")
    print(f"\nTOTAL CANDIDATES: {len(allhits)}")


if __name__ == "__main__":
    main()
