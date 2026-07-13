#!/usr/bin/env python3
"""Scan sub-100 fns for WRONG-VALUE bugs: regions where target and current share
the same mnemonic sequence but differ in an IMMEDIATE constant or a SYMBOL
reference (not reg-perm, not @NNN-vs-lbl pool-reloc noise). These are correctness
bugs in the decompiled C (wrong literal/arg/offset), fixable + byte-changing."""
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble
from ndiff import normalize, regions

REPO = Path(__file__).resolve().parent.parent
VER = "GSAE01"
objd = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
if not objd.is_file():
    objd = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"
report = json.load(open(REPO / f"build/{VER}/report.json"))
cfg = load_units(REPO / "build" / VER / "config.json")

MIN = float(sys.argv[1]) if len(sys.argv) > 1 else 95.0
targets = []
for u in report["units"]:
    un = u.get("name", "")
    if not un.startswith("main/"):
        continue
    for f in u.get("functions", []):
        fz = f.get("fuzzy_match_percent", 100.0)
        if MIN <= fz < 100.0:
            targets.append((fz, un, f.get("name", "")))
targets.sort()

# mask registers only (keep immediates + symbols visible)
maskreg = lambda s: re.sub(r"\b[rf]\d+\b", "R", s)
# immediate: a signed/hex number operand; symbol: a name token
imm_re = re.compile(r"(?:^|[ ,])(-?(?:0x[0-9a-fA-F]+|\d+))\b")
sym_re = re.compile(r"<([A-Za-z_][\w.@]*)>|\b(lbl_[0-9A-Fa-f]+|@\d+)\b")

def norm_pool(tok):
    # collapse @NNN and lbl_XXXX to a class so pool-reloc-only diffs are ignored
    if tok is None: return None
    if tok.startswith("@") or tok.startswith("lbl_"): return "POOL"
    return tok

def sig(instr):
    return maskreg(instr.split("#")[0]).strip()

hits = []
for fz, un, sym in targets:
    p = un[len("main/"):]
    if p.endswith(".c"): p = p[:-2]
    unit = None
    for q in (un, un[5:], Path(p).name + ".c", Path(p).name):
        try:
            unit = resolve_unit(cfg, q); break
        except BaseException:
            continue
    if unit is None: continue
    try:
        to = REPO / Path(unit["object"])
        co = REPO / Path(unit["object"].replace(f"build/{VER}/obj/", f"build/{VER}/src/"))
        t = normalize(strip_preamble(objdump_symbol(objd, to, sym)))
        c = normalize(strip_preamble(objdump_symbol(objd, co, sym)))
    except BaseException:
        continue
    if not t or not c: continue
    fn_hits = []
    for tag, i1, i2, j1, j2 in regions(t, c):
        if tag != "replace": continue
        tt, cc = t[i1:i2], c[j1:j2]
        if len(tt) != len(cc): continue  # length diff = structural, not value swap
        for a, b in zip(tt, cc):
            if sig(a) != sig(b):
                continue  # different mnemonic/shape (reg-perm or other) — skip
            # same masked shape: compare immediates + symbols
            ai = imm_re.findall(a); bi = imm_re.findall(b)
            asym = [norm_pool(m[0] or m[1]) for m in sym_re.findall(a)]
            bsym = [norm_pool(m[0] or m[1]) for m in sym_re.findall(b)]
            if ai != bi and set(ai) != set(bi):
                fn_hits.append((a.strip(), b.strip(), "IMM"))
            elif asym != bsym:
                fn_hits.append((a.strip(), b.strip(), "SYM"))
    if fn_hits:
        hits.append((fz, un[5:], sym, fn_hits))

hits.sort()
print(f"scanned {len(targets)} sub-100 fns >= {MIN}%; {len(hits)} with IMM/SYM value mismatches\n")
for fz, un, sym, fh in hits:
    print(f"=== {fz:.3f}  {un} {sym}  ({len(fh)} value-diffs) ===")
    for a, b, kind in fh[:6]:
        print(f"   [{kind}] T: {a}")
        print(f"         C: {b}")
