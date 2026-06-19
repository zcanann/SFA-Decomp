#!/usr/bin/env python3
"""Emit naming context for every lbl_ referenced by exactly one source file.

For a given source file, print each lbl_ symbol with:
  - symbols.txt section + size + meta
  - decoded value (float / double / string / bss-size / pointer-table)
  - the source lines that reference it (for semantic context)

Usage: lbl_unit_context.py <src/path/to/unit.c>
"""
from __future__ import annotations
import json, re, struct, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYMS = ROOT / "config/GSAE01/symbols.txt"
VALS = json.load(open("/tmp/lbl_values.json"))
LBL_RE = re.compile(r"\blbl_[0-9A-Fa-f]{4,}\b")


def sym_meta():
    out = {}
    for line in SYMS.read_text().splitlines():
        m = re.match(r"^(lbl_\w+)\s*=\s*(\.\w+):0x[0-9A-Fa-f]+;\s*//\s*(.*)$", line)
        if m:
            out[m.group(1)] = (m.group(2), m.group(3))
    return out


def parse_int(tok):
    tok = tok.strip()
    try:
        if tok.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in tok):
            return int(tok, 16)
    except Exception:
        return None
    return None


def describe(lbl):
    v = VALS.get(lbl)
    if not v or not v["vals"]:
        return "uninitialized (.bss/.sbss object)"
    kinds = [k for k, _ in v["vals"]]
    if kinds == ["float"]:
        return f"float {v['vals'][0][1]}"
    if kinds == ["double"]:
        return f"double {v['vals'][0][1]}"
    # try string
    bs = bytearray()
    relocs = []
    for kind, raw in v["vals"]:
        if kind == "string":
            return f"string {raw}"
        for t in raw.split(","):
            t = t.strip()
            if not t:
                continue
            iv = parse_int(t)
            if iv is None:
                relocs.append(t)
                continue
            if kind in ("4byte", "long", "word"):
                bs += struct.pack(">I", iv & 0xFFFFFFFF)
            elif kind in ("2byte", "short"):
                bs += struct.pack(">H", iv & 0xFFFF)
            elif kind == "byte":
                bs.append(iv & 0xFF)
    s = bytes(bs).split(b"\x00")[0]
    if len(s) >= 2 and all(32 <= c < 127 for c in s):
        return f"string-data {s.decode()!r}"
    if relocs:
        return f"pointer/struct table -> {relocs[:6]}{'...' if len(relocs)>6 else ''}"
    nfloats = sum(1 for k, _ in v["vals"] if k == "float")
    return f"data blob ({len(v['vals'])} words, {nfloats} floats)"


def main():
    src = Path(sys.argv[1])
    text = src.read_text(errors="ignore")
    lbls = sorted(set(LBL_RE.findall(text)))
    meta = sym_meta()
    lines = text.splitlines()
    print(f"# UNIT: {src}  ({len(lbls)} lbl_ symbols)\n")
    for lbl in lbls:
        sec, m = meta.get(lbl, ("?", "?"))
        print(f"## {lbl}  [{sec}]  {m}")
        print(f"   value: {describe(lbl)}")
        refs = [i + 1 for i, ln in enumerate(lines) if lbl in ln]
        shown = 0
        for ln_no in refs:
            ln = lines[ln_no - 1].strip()
            if "extern" in ln and ln.count(lbl) == 1 and "=" not in ln:
                continue  # skip bare extern decls
            print(f"     L{ln_no}: {ln[:140]}")
            shown += 1
            if shown >= 6:
                break
        print()


if __name__ == "__main__":
    main()
