"""Remove terse import-/re-split-era one-line annotation comments while keeping
genuinely useful comments (the wmspiritplace standard):

  REMOVE a standalone one-line `/* ... */` comment when it is
    - a pure banner/separator (==== , ---- , #N, NxN, +NxN, N.Nf markers), or
    - immediately above a function definition / prototype / #pragma / extern /
      variable definition / closing brace / EOF -- i.e. a per-function or
      per-group annotation ("Trivial 4b 0-arg blr leaves.", "plain forwarder.",
      "dll_224_hitDetect: render iff ...", "fn_X(lbl); lbl = 0;").
  KEEP
    - multi-line comments (file headers, domain explanations, MWCC WHY notes),
    - one-line comments above a #define / #include / enum / typedef / struct /
      union / #if (domain documentation, e.g. "state->fxFlags: spawn the fx"),
    - `EN v1.0 0x.. size: ..` address annotations (conservative -- not listed
      for removal),
    - inline (trailing-code) comments and `//` comments.

Comments never affect codegen -> byte-neutral (verify with a full .o compare).
Byte-safe latin-1 I/O preserves any SJIS.

Usage: python3 tools/comment_cruft.py [--apply] [--filter SUBSTR]
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ONELINE = re.compile(r'^\s*/\*.*\*/\s*$')
KEEP_ANCHOR = re.compile(
    r'^\s*(#define|#include|#if|#ifdef|#ifndef|#endif|#else|#elif|'
    r'enum\b|typedef\b|struct\b|union\b)')
# banner / separator / pure-marker one-liners
BANNER = re.compile(r'^\s*/\*[\s*=_+.\-]*\*/\s*$')
MARKER = re.compile(r'^\s*/\*\s*([#+]?\d+(x\d+)?|\d+\.\d+f|[-=_*\s]+)\s*\*/\s*$')


def inner(line: str) -> str:
    s = line.strip()[2:-2].strip()
    return s


def anchor_is_keep(lines: list[str], start: int) -> bool:
    """Skip blanks + one-line comments; return True if the next real line is a
    keep-anchor declaration (so the comment run documents a decl/macro)."""
    n = len(lines)
    k = start
    while k < n and (lines[k].strip() == '' or ONELINE.match(lines[k])):
        k += 1
    if k >= n:
        return False
    return bool(KEEP_ANCHOR.match(lines[k]))


def process(path: Path, apply: bool):
    text = path.read_bytes().decode('latin-1')
    lines = text.split('\n')
    n = len(lines)
    drop = set()
    removed = 0
    for i, l in enumerate(lines):
        if not ONELINE.match(l):
            continue
        if 'EN v1.0' in l or 'EN v1.1' in l:
            continue  # keep address annotations
        if BANNER.match(l) or MARKER.match(l):
            drop.add(i)
            removed += 1
            continue
        if not anchor_is_keep(lines, i + 1):
            drop.add(i)
            removed += 1
    if not removed:
        return 0
    if apply:
        kept = [l for idx, l in enumerate(lines) if idx not in drop]
        out = []
        blanks = 0
        for l in kept:
            if l.strip() == '':
                blanks += 1
                if blanks > 1:
                    continue
            else:
                blanks = 0
            out.append(l)
        path.write_bytes('\n'.join(out).encode('latin-1'))
    return removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--filter', default='')
    args = ap.parse_args()
    files = sorted(list((REPO / 'src').rglob('*.c'))
                   + list((REPO / 'src').rglob('*.cp'))
                   + list((REPO / 'src').rglob('*.cpp')))
    files = [f for f in files if args.filter in str(f)]
    total = tfiles = 0
    for f in files:
        r = process(f, args.apply)
        if r:
            total += r
            tfiles += 1
    print(f"one-line cruft comments removed: {total} across {tfiles} files")


if __name__ == '__main__':
    main()
