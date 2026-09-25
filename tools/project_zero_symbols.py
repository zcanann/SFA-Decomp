#!/usr/bin/env python3
"""Restore missing zero-section (.bss/.sbss) symbol splits in a projected version.

tools/version_progress.py maps zero-section RANGES between retail versions but does
not project the individual symbols inside them, so a non-EN config can carry one
coarse symbol where EN has several.  objdiff pairs data symbols by name, so every
byte of the coarse symbol scores as unmatched even though the layout is identical
and the compiled output is byte-for-byte correct.  That silently holds whole units
out of the completion count: dlls/engine/0/0.c is 75KB of exact code blocked by
2KB of unsplit .bss.

The split is derived from OUR OWN compiled object, never guessed: the built object
carries every symbol at its real section-relative offset, and the retail carve
agrees on the offsets it does define.  An anchor symbol present on both sides with
the same relative offset fixes the section base, so each missing symbol's absolute
address is base + its relative offset.  A version whose anchor offsets disagree is
reported and left untouched, because then the layout itself differs and this is the
wrong tool.

Attribute comments (align/data) are copied from the EN entry when one exists.

Usage:
  python3 tools/project_zero_symbols.py <unit-path> <version> [<version> ...]
  python3 tools/project_zero_symbols.py dlls/engine/0/0 GSAJ01 GSAP01 --apply

Without --apply it only reports what it would change.
"""
from __future__ import annotations
import os, re, subprocess, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OBJD = REPO / 'build' / 'binutils' / 'powerpc-eabi-objdump.exe'
if not OBJD.exists():
    OBJD = REPO / 'build' / 'binutils' / 'powerpc-eabi-objdump'
ZERO = ('.bss', '.sbss', '.sbss2')


def symbols(obj: Path, section: str) -> dict:
    out = subprocess.run([str(OBJD), '-t', str(obj)], capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        if '\t' not in line:
            continue
        left, right = line.split('\t', 1)
        head, tail = left.split(), right.split()
        if not head or len(tail) < 2 or head[-1] != section:
            continue
        name = tail[1]
        if name == section or name == '.hidden' or name.startswith('...'):
            continue
        found[name] = (int(head[0], 16), int(tail[0], 16))
    return found


def en_attributes(name: str) -> str:
    text = (REPO / 'config' / 'GSAE01' / 'symbols.txt').read_text(encoding='utf-8')
    hit = re.search(rf'^{re.escape(name)} = \.\w+:0x[0-9A-Fa-f]+; // type:object size:0x[0-9A-Fa-f]+(.*)$', text, re.M)
    return hit.group(1).rstrip() if hit else ''


def fix(unit: str, version: str, apply: bool) -> bool:
    retail = REPO / 'build' / version / 'obj' / f'{unit}.o'
    ours = REPO / 'build' / version / 'src' / f'{unit}.o'
    if not (retail.exists() and ours.exists()):
        print(f'{version}: missing objects for {unit}')
        return False
    path = REPO / 'config' / version / 'symbols.txt'
    with open(path, 'r', encoding='utf-8', newline='') as handle:
        text = handle.read()
    newline = '\r\n' if '\r\n' in text else '\n'
    adds, shrinks = [], []
    for section in ZERO:
        R, O = symbols(retail, section), symbols(ours, section)
        if not R or not O:
            continue
        shared = [n for n in R if n in O]
        if not shared:
            continue
        disagree = [n for n in shared if R[n][0] != O[n][0]]
        if disagree:
            print(f'{version} {section}: relative offsets disagree ({disagree[:3]}), skipping section')
            continue
        base = None
        for name in sorted(shared, key=lambda n: O[n][0]):
            hit = re.search(rf'^{re.escape(name)} = \{section}:0x([0-9A-Fa-f]+);', text, re.M)
            if hit:
                base = int(hit.group(1), 16) - R[name][0]
                break
        if base is None:
            print(f'{version} {section}: no anchor found in symbols.txt, skipping section')
            continue
        for name in sorted(set(O) - set(R), key=lambda n: O[n][0]):
            rel, size = O[name]
            if re.search(rf'^{re.escape(name)} = ', text, re.M):
                continue
            adds.append((section, base + rel, name, size))
        for name in sorted(set(R) & set(O), key=lambda n: O[n][0]):
            if R[name][1] > O[name][1]:
                shrinks.append((section, name, R[name][1], O[name][1]))
    if not (adds or shrinks):
        print(f'{version}: {unit} already split correctly')
        return True
    for section, name, old, new in shrinks:
        pattern = re.compile(rf'^({re.escape(name)} = \{section}:0x[0-9A-Fa-f]+; // type:object size:)0x{old:X}\b', re.M | re.I)
        text, count = pattern.subn(lambda m: m.group(1) + f'0x{new:X}', text)
        if count != 1:
            print(f'{version}: could not rewrite size of {name} ({count} hits)')
            return False
    lines = text.split(newline)
    for section, addr, name, size in adds:
        entry = f'{name} = {section}:0x{addr:08X}; // type:object size:0x{size:X}{en_attributes(name)}'
        index = None
        for i, line in enumerate(lines):
            hit = re.match(rf'^\S+ = \{section}:0x([0-9A-Fa-f]+);', line)
            if hit and int(hit.group(1), 16) > addr:
                index = i
                break
        if index is None:
            print(f'{version}: no insertion point for {name}')
            return False
        lines.insert(index, entry)
    text = newline.join(lines)
    print(f'{version}: {unit} -> {len(adds)} symbols added, {len(shrinks)} sizes corrected')
    for section, name, old, new in shrinks:
        print(f'    size {name}: 0x{old:X} -> 0x{new:X}')
    for section, addr, name, size in adds:
        print(f'    add  {name} = {section}:0x{addr:08X} size 0x{size:X}')
    if apply:
        with open(path, 'w', encoding='utf-8', newline='') as handle:
            handle.write(text)
    return True


def main() -> int:
    args = [a for a in sys.argv[1:] if a != '--apply']
    apply = '--apply' in sys.argv
    if len(args) < 2:
        print(__doc__)
        return 2
    unit, versions = args[0], args[1:]
    ok = True
    for version in versions:
        ok = fix(unit, version, apply) and ok
    if not apply:
        print('\n(report only; pass --apply to write)')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
