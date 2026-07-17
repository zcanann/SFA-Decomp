#!/usr/bin/env python3
"""Reloc-TARGET audit for functions that are NOT encoding-identical to retail.

tools/sda_reloc_check.py only compares functions whose normalized encodings match
retail, so a function that diverges in codegen can hide a wrong reloc target
underneath: fuzzy_match_percent scores the divergence, never the target, and the
DOL sha1 gate stays green because these units link the retail obj. The bug only
detonates on a TU flip.

Method: for each function present in both objects, resolve every relocation to a
(kind, value) pair and compare the MULTISET -- order-insensitive, so register
allocation, scheduling and peephole differences (which permute reloc order but
never change WHICH values a function touches) cannot manufacture a finding.

  MISSING  retail loads a value we never load  -> we lost a constant
  EXTRA    we load a value retail never loads  -> we invented a constant

Both are real bugs regardless of coloring. A pure count change on a value that
still appears (e.g. CSE folding two loads of 0.5 into one) is reported only under
--counts, since that is usually a legitimate codegen difference.

Reloc kinds covered beyond SDA21: ADDR32, ADDR16_HA/LO/16 (absolute address and
hi/lo pairs) and REL24 (call targets -- catches calling a neighbouring function).
REL24 targets compare by SYMBOL NAME, not value: a call's meaning is its callee.

Usage: python3 tools/reloc_target_audit.py [out.json] [--counts]
"""
import json, os, re, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sda_reloc_check import (Elf, Obj, dol_read, load_retail_addrs, fmt,
                             LBL_RE, IMM16, R_SDA21, R_REL24, ROOT)

R_ADDR32 = 1
VALUE_RELOCS = IMM16 | {R_ADDR32}
# A Ghidra-lifted callee name encodes the address it was lifted from.
FN_RE = re.compile(r"^(?:FUN|fun|fn)_([0-9A-Fa-f]{8})$")


def sym_addr(name, RA):
    a = RA.get(name)
    if a is None:
        g = LBL_RE.match(name)
        a = int(g.group(1), 16) if g else None
    return a


def call_key(name, RA):
    """Identify a callee by ADDRESS, falling back to name.

    The same callee is routinely spelled two ways: our source still calls the
    Ghidra-lifted `FUN_80259288` where retail's symbol map has already named that
    address `modelLightStruct_setDirection`. Both branch to the same place, so
    keying on the name alone reports every un-renamed alias as a wrong call.
    """
    a = RA.get(name)
    if a is None:
        g = FN_RE.match(name) or LBL_RE.match(name)
        a = int(g.group(1), 16) if g else None
    return ("addr", a) if a is not None else ("name", name)


def resolve(o, rel, RA, is_retail):
    """(kind, key) for one reloc, or None when not comparable.

    key is a resolved VALUE for data refs (so our @NNN and retail's lbl_ADDR
    naming of the same constant compare equal) and a NAME for calls.
    """
    off, typ, nm, add, shndx, val, sz = rel
    if typ == R_REL24:
        return ("call", call_key(nm, RA))
    if typ not in VALUE_RELOCS:
        return None
    if nm.startswith("jumptable_"):
        return None
    # Always read a fixed 4 bytes rather than the symbol's st_size. The two
    # objects legitimately disagree about a constant's declared size -- our pool
    # emits an anonymous `@NNN` of size 8 (double) where retail's carved map
    # names the same address `lbl_ADDR` of size 4 -- which would otherwise key
    # the SAME address as two different values and report a matched pair as one
    # EXTRA plus one MISSING. Comparing the leading 4 bytes still separates a
    # genuinely different constant (a double 1.0 and a float 1.0 differ here).
    n = 4
    local = shndx and shndx < 0xFF00
    # A datum carrying its own relocs (pointer tables) reads as zeros in our
    # unlinked object but as resolved addresses in retail's carved copy.
    if local and not is_retail and o.has_reloc(shndx, val + add, n):
        return None
    if local and not is_retail:
        v = o.value_of(shndx, val, add, n)
    else:
        a = sym_addr(nm, RA)
        if a is None:
            return None
        v = dol_read(a + add, n)
        if v is None and local:
            v = o.value_of(shndx, val, add, n)
    if v is None:
        return None
    return ("data%d" % n, v)


def main():
    counts = "--counts" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    RA = load_retail_addrs()
    units = [u for u in json.load(open(os.path.join(ROOT, "objdiff.json")))["units"]
             if "base_path" in u and "target_path" in u]
    rep = json.load(open(os.path.join(ROOT, "build/GSAE01/report.json")))
    pct = {u["name"]: u["measures"].get("fuzzy_match_percent", 0) for u in rep["units"]}

    findings, checked = [], 0
    for u in units:
        po, pr = u["base_path"], u["target_path"]
        if not (os.path.exists(os.path.join(ROOT, po)) and
                os.path.exists(os.path.join(ROOT, pr))):
            continue
        try:
            O, T = Obj(po), Obj(pr)
        except Exception:
            continue
        if O.text_i is None or T.text_i is None:
            continue
        ro, rt = O.text_relocs(), T.text_relocs()
        fo, ft = O.fns(), T.fns()
        for name in sorted(set(fo) & set(ft)):
            (so, szo), (sr, szr) = fo[name], ft[name]
            checked += 1
            mo, mt = {}, {}
            for rel, dst, obj, ret in ((r, mo, O, False) for r in ro if so <= r[0] < so + szo):
                k = resolve(obj, rel, RA, ret)
                if k:
                    dst[k] = dst.get(k, 0) + 1
            for rel, dst, obj, ret in ((r, mt, T, True) for r in rt if sr <= r[0] < sr + szr):
                k = resolve(obj, rel, RA, ret)
                if k:
                    dst[k] = dst.get(k, 0) + 1
            for k in set(mo) | set(mt):
                a, b = mo.get(k, 0), mt.get(k, 0)
                if a and b and not counts:
                    continue
                if a and b and a == b:
                    continue
                kind = "EXTRA" if not b else "MISSING" if not a else "COUNT"
                val = k[1] if k[0] == "call" else fmt(k[1])
                findings.append(dict(unit=u["name"], pct=pct.get(u["name"], 0),
                                     fn=name, kind=kind, ref=k[0], val=val,
                                     ours_n=a, retail_n=b))
    out = args[0] if args else "/dev/stdout"
    json.dump(findings, open(out, "w"), indent=1)
    sys.stderr.write("[fns checked: %d] [findings: %d]\n" % (checked, len(findings)))


main()
