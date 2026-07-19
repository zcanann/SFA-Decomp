#!/usr/bin/env python3
"""L9 wave-50: SDA *BASE REGISTER* mismatch screen.

The sharpest form of the reloc-target blind spot. An R_PPC_EMB_SDA21 reloc is
emitted as `lfs f0,0(0)` in BOTH objects -- the LINKER patches in the base
register from the target symbol's SECTION:

    .sdata2            -> r2  (_SDA2_BASE_)   read-only constant pool
    .sdata / .sbss     -> r13 (_SDA_BASE_)    mutable globals

So a retail read-only float constant that we reconstructed as a mutable global
`f32 gFoo = 0.0f;` produces IDENTICAL pre-link bytes but a DIFFERENT linked
instruction. fuzzy compares the pre-link bytes -> blind. And for an INCOMPLETE
unit the retail .o is what links, so main.dol's sha1 is blind too.

Value comparison does NOT catch this (the global's initialiser usually equals the
constant). Only the target SECTION does.
"""
import json, os, re, struct, sys, collections

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from sda_reloc_check import Obj, ROOT

R_SDA21 = 109
FP_OPS = {48, 49, 50, 51, 52, 53, 54, 55}


def retail_sections():
    """symbol -> section name, from the authoritative retail map."""
    m, dup = {}, set()
    for line in open(os.path.join(ROOT, "config/GSAE01/symbols.txt")):
        g = re.match(r"^(\S+) = \.(\w+):0x([0-9A-Fa-f]{8});", line)
        if not g:
            continue
        nm, sec = g.group(1), g.group(2)
        if nm in m and m[nm] != sec:
            dup.add(nm)
        m[nm] = sec
    for nm in dup:
        m.pop(nm, None)
    return m


def base_of(sec):
    if sec is None:
        return None
    s = sec.lstrip(".")
    if s.startswith("sdata2") or s.startswith("sbss2"):
        return "r2"
    if s.startswith("sdata") or s.startswith("sbss"):
        return "r13"
    return None


def main():
    RS = retail_sections()
    units = [u for u in json.load(open(os.path.join(ROOT, "objdiff.json")))["units"]
             if "base_path" in u and "target_path" in u]
    rows, nunits, nrel = [], 0, 0
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
        nunits += 1
        sides = {}
        for tag, X, ours in (("o", O, True), ("t", T, False)):
            txt, fns = X.text(), X.fns()
            per = collections.defaultdict(list)
            for off, typ, nm, add, shndx, val, sz in X.text_relocs():
                if typ != R_SDA21:
                    continue
                w = struct.unpack_from(">I", txt, off - (off % 4))[0]
                if (w >> 26) not in FP_OPS:
                    continue
                if ours and shndx and shndx < 0xFF00:
                    sec = X.e.sh[shndx]["name"]        # our own section table
                else:
                    sec = RS.get(nm)                   # retail map / our externs
                    if sec is None and shndx and shndx < 0xFF00:
                        sec = X.e.sh[shndx]["name"]
                b = base_of(sec)
                fn = next((f for f, (s, z) in fns.items() if s <= off < s + z), None)
                if fn:
                    per[fn].append((b, nm, sec))
            sides[tag] = per
        for fn in sorted(set(sides["o"]) & set(sides["t"])):
            ca = collections.Counter(b for b, _, _ in sides["o"][fn] if b)
            cb = collections.Counter(b for b, _, _ in sides["t"][fn] if b)
            nrel += sum(cb.values())
            if ca == cb:
                continue
            rows.append(dict(unit=u["name"], fn=fn,
                             ours=collections.Counter(
                                 f"{b}:{n}({s})" for b, n, s in sides["o"][fn] if b),
                             retail=collections.Counter(
                                 f"{b}:{n}({s})" for b, n, s in sides["t"][fn] if b),
                             ours_bases=dict(ca), retail_bases=dict(cb)))
    out = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout"
    json.dump(rows, open(out, "w"), indent=1)
    sys.stderr.write(f"[units {nunits}] [retail SDA21 fp relocs {nrel}] "
                     f"[base-class mismatches {len(rows)}]\n")


if __name__ == "__main__":
    main()
