#!/usr/bin/env python3
"""Scan retail vs source objects for unfolded conditional-branch pairs.

An unfolded pair is `bc <cond>, +8` immediately followed by `b <target>`, where
the `b` stays inside the same function and is a short branch. MWCC emits this
shape when a `switch` or a short-circuit ||/&& chain routes through an else
label; a plain `if (C) <jump>` folds to a single `bcond <target>`.

Long-branch expansions (|disp| >= 32KB) and relocated `b` (tail calls) are
excluded -- they are the bulk of raw hits and are not this family.
"""
import os
import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

OBJ_ROOT = 'build/GSAE01/obj'
SRC_ROOT = 'build/GSAE01/src'


def s24(v):
    return v - (1 << 24) if v & (1 << 23) else v


def text_funcs(path):
    """-> {funcname: (bytes, reloc_offsets_set)} for .text symbols."""
    out = {}
    with open(path, 'rb') as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name('.text')
        if text is None:
            return out
        text_idx = list(elf.iter_sections()).index(text)
        data = text.data()

        relocs = set()
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection) and sec.header['sh_info'] == text_idx:
                for r in sec.iter_relocations():
                    relocs.add(r['r_offset'])

        syms = []
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym['st_shndx'] == text_idx and sym['st_info']['type'] == 'STT_FUNC':
                    syms.append((sym['st_value'], sym['st_size'], sym.name))
        for start, size, name in syms:
            if size == 0:
                continue
            out[name] = (data[start:start + size], start, relocs)
    return out


def unfolded_sites(body, start, relocs):
    """Offsets (function-relative) of unfolded bc+8 / b pairs."""
    hits = []
    n = len(body) // 4
    words = [int.from_bytes(body[i * 4:i * 4 + 4], 'big') for i in range(n)]
    for i in range(n - 1):
        w1, w2 = words[i], words[i + 1]
        if (w1 >> 26) != 16:
            continue
        # BD == 8, AA == 0, LK == 0
        if (w1 & 0xFFFF) != 0x0008:
            continue
        if (w2 >> 26) != 18:
            continue
        if (w2 & 3) != 0:  # AA or LK set
            continue
        if (start + (i + 1) * 4) in relocs:  # relocated -> tail call, not this family
            continue
        disp = s24((w2 >> 2) & 0xFFFFFF) * 4
        if abs(disp) >= 0x8000:  # long-branch expansion
            continue
        target = (i + 1) * 4 + disp
        if not (0 <= target <= len(body)):  # must stay inside the function
            continue
        hits.append(i * 4)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--unit', help='restrict to units whose path contains this')
    ap.add_argument('--all', action='store_true', help='list agreeing functions too')
    args = ap.parse_args()

    units = []
    for r, _, fs in os.walk(SRC_ROOT):
        for f in fs:
            if not f.endswith('.o'):
                continue
            rel = os.path.relpath(os.path.join(r, f), SRC_ROOT)
            if os.path.exists(os.path.join(OBJ_ROOT, rel)):
                units.append(rel)
    units.sort()
    if args.unit:
        units = [u for u in units if args.unit in u]

    tot_r = tot_o = 0
    disagree = []
    for rel in units:
        try:
            rf = text_funcs(os.path.join(OBJ_ROOT, rel))
            of = text_funcs(os.path.join(SRC_ROOT, rel))
        except Exception as e:
            print(f'ERR {rel}: {e}', file=sys.stderr)
            continue
        for name in sorted(set(rf) & set(of)):
            rh = unfolded_sites(*rf[name])
            oh = unfolded_sites(*of[name])
            tot_r += len(rh)
            tot_o += len(oh)
            if len(rh) != len(oh):
                disagree.append((rel, name, len(rh), len(oh)))
            elif args.all and rh:
                print(f'  ok   {rel:50s} {name:40s} {len(rh)}')

    print(f'\nin-range unfolded pairs: retail {tot_r}  ours {tot_o}')
    print(f'functions disagreeing: {len(disagree)}\n')
    sub = [d for d in disagree if d[3] > d[2]]
    add = [d for d in disagree if d[2] > d[3]]
    print(f'--- SUBTRACTIVE (ours > retail: we have a contrived switch/chain) [{len(sub)}] ---')
    for rel, name, r, o in sorted(sub, key=lambda d: d[2] - d[3]):
        print(f'  {rel:48s} {name:44s} retail {r}  ours {o}')
    print(f'\n--- ADDITIVE (retail > ours) [{len(add)}] ---')
    for rel, name, r, o in sorted(add, key=lambda d: d[3] - d[2]):
        print(f'  {rel:48s} {name:44s} retail {r}  ours {o}')


if __name__ == '__main__':
    main()
