#!/usr/bin/env python3
"""Structural diff of a function, aligned on the MNEMONIC stream.

structscan.py aligns the two instruction streams on the reloc-masked instruction
word, so a long register-recolour run defeats difflib's alignment and every
shifted row is reported as a mnemonic change.  Aligning on mnemonics alone
separates the two populations: STRUC counts real stream differences (a defect
reachable from source), recolour counts same-mnemonic operand differences.
The historical "recolour" label also includes immediates and relocation targets;
it does not by itself establish a register-allocation mismatch.

    python3 tools/strucdiff.py <unit> <symbol> [context]
"""
import sys
import os
import re
import json
import difflib
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import structscan as S

INSN_RE = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){4})\s*(.*)$')
RELOC_RE = re.compile(r'^\s*([0-9a-f]+):\s+(R_PPC\S+)\s+(\S+)')


def text_lines(obj, sym):
    out = subprocess.run([S.OD, "-M", "gekko", "-drz", "--disassemble=" + sym, obj],
                         capture_output=True, text=True).stdout
    got = []
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if m and len(m.group(2)) == 12:
            got.append([int(m.group(1), 16), m.group(3).strip(), ""])
            continue
        m = RELOC_RE.match(line)
        if m and got and S.relocation_belongs_to_instruction(
                got[-1][0], int(m.group(1), 16), m.group(2)):
            got[-1][2] = m.group(3)
    return ["%s%s" % (t, ("  <" + r + ">") if r else "") for _, t, r in got]


def obj_paths(unit, base_override=None):
    cfg = json.load(open(os.path.join(ROOT, "objdiff.json")))
    by = {u["name"].replace("\\", "/"): u for u in cfg["units"]}
    u = by.get(unit) or by.get("main/" + unit)
    if u is None:
        c = [k for k in by if unit in k]
        if len(c) != 1:
            raise SystemExit("unit %r matches %d entries in objdiff.json" % (unit, len(c)))
        u = by[c[0]]
    target = os.path.join(ROOT, u["target_path"])
    base = base_override or os.path.join(ROOT, u["base_path"])
    return target, base


def analyse(unit, sym, base_override=None):
    t, b = obj_paths(unit, base_override)
    a = S.words(t, sym)
    c = S.words(b, sym)
    at = text_lines(t, sym)
    ct = text_lines(b, sym)
    ma = [w[1] for w in a]
    mc = [w[1] for w in c]
    sm = difflib.SequenceMatcher(None, ma, mc, autojunk=False)
    rows = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                ai, cj = i1 + k, j1 + k
                same = (a[ai][0] == c[cj][0]) or S.reloc_equal(a[ai], c[cj])
                rows.append((" " if same else "r", ai, cj))
        elif tag == "replace":
            for k in range(max(i2 - i1, j2 - j1)):
                ai = i1 + k if i1 + k < i2 else None
                cj = j1 + k if j1 + k < j2 else None
                rows.append(("M", ai, cj))
        elif tag == "delete":
            for k in range(i1, i2):
                rows.append(("-", k, None))
        elif tag == "insert":
            for k in range(j1, j2):
                rows.append(("+", None, k))
    return rows, at, ct, len(a), len(c)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    unit, sym = sys.argv[1], sys.argv[2]
    ctx = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    base_override = os.environ.get("STRUCDIFF_BASE")
    rows, at, ct, na, nc = analyse(unit, sym, base_override)
    ns = sum(1 for m, _, _ in rows if m in "M+-")
    nr = sum(1 for m, _, _ in rows if m == "r")
    print("target %d / ours %d ; STRUC %d ; recolour %d" % (na, nc, ns, nr))
    keep = set()
    for i, (m, _, _) in enumerate(rows):
        if m in "M+-":
            for j in range(max(0, i - ctx), min(len(rows), i + ctx + 1)):
                keep.add(j)
    last = -1
    for i in sorted(keep):
        if last >= 0 and i != last + 1:
            print("   ...")
        m, ai, cj = rows[i]
        ta = at[ai] if ai is not None and ai < len(at) else ""
        tc = ct[cj] if cj is not None and cj < len(ct) else ""
        pa = ("%4d " % ai) if ai is not None else "     "
        print("%s %s%-50s | %s" % (m, pa, ta[:50], tc[:50]))
        last = i


if __name__ == "__main__":
    main()
