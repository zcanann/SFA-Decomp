"""Strip import-era / re-split comment cruft from src (.c/.cp/.cpp):
  (1) every Ghidra `--INFO--` boilerplate block (Function/EN/JP/PAL Address+Size
      + TODO placeholders), but ONLY when every interior line is a known
      boilerplate field -- a block carrying unexpected prose is kept and flagged.
  (2) ORPHANED hand-written `EN v1.0 0x.. size: Nb  NAME: desc` annotations whose
      NAME function moved to another TU during the re-split (NAME not defined in
      this file). Valid annotations (NAME defined here) are kept verbatim.
File-header and inline code comments are left untouched.

Comments never affect codegen, so this is byte-neutral; verify with a full-tree
.o comparison after running (see --verify note in the repo task). The tool also
collapses runs of blank lines left by deletions to a single blank.

Usage:
  python3 tools/comment_clean.py [--apply] [--filter SUBSTR]
Without --apply: report counts per file (no edits).
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIELD = re.compile(
    r'^(--INFO--|Function:\s*\S+|EN( v1\.[01])? (Address|Size):.*|'
    r'JP (Address|Size):.*|PAL (Address|Size):.*)$')
# hand-written annotation: ".. size: 920b  babycloudrunner_SeqFn: range-check.."
ANNOT_NAME = re.compile(r'size:\s*\d+b\s+([A-Za-z_]\w*)\s*:')
DEF = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(')


def comment_text(line: str) -> str:
    s = line.strip()
    if s.startswith('/*'):
        s = s[2:].strip()
    if s.endswith('*/'):
        s = s[:-2].strip()
    return s.lstrip('*').strip()


def file_defs(lines: list[str]) -> set[str]:
    defs = set()
    for idx, l in enumerate(lines):
        if not l[:1].isalpha() and l[:1] != '_':
            continue
        m = DEF.match(l)
        if not m:
            continue
        if '=' in l.split('(')[0]:
            continue
        seg = '\n'.join(lines[idx:idx + 8]).split(';')[0]
        if '{' in seg:
            defs.add(m.group(1))
    return defs


def find_blocks(lines: list[str]):
    """Yield (start, end_inclusive, block_lines) for each /* ... */ comment."""
    n = len(lines)
    i = 0
    while i < n:
        if lines[i].lstrip().startswith('/*'):
            j = i
            while j < n and not lines[j].rstrip().endswith('*/'):
                j += 1
            yield i, j, lines[i:j + 1]
            i = j + 1
        else:
            i += 1


def process(path: Path, apply: bool):
    # latin-1 is a byte-exact 1:1 round-trip -- preserves any SJIS bytes
    orig = path.read_bytes().decode('latin-1')
    lines = orig.split('\n')
    defs = file_defs(lines)
    drop = set()
    replace: dict[int, list[str]] = {}
    n_info = n_orphan = n_kept_nonstd = 0
    for start, end, block in find_blocks(lines):
        is_info = any('--INFO--' in l for l in block)
        if is_info:
            if all(comment_text(l) == '' or FIELD.match(comment_text(l)) for l in block):
                for k in range(start, end + 1):
                    drop.add(k)
                n_info += 1
            else:
                # keep only the hand-written prose, drop boilerplate fields
                prose = [l for l in block[1:-1]
                         if comment_text(l) and not FIELD.match(comment_text(l))]
                for k in range(start, end + 1):
                    drop.add(k)
                if prose:
                    replace[start] = ['/*'] + prose + [' */']
                n_kept_nonstd += 1
            continue
        # hand-written annotation orphan check
        blk = '\n'.join(block)
        if 'EN v1.0' in blk:
            m = ANNOT_NAME.search(blk)
            if m and m.group(1) not in defs:
                for k in range(start, end + 1):
                    drop.add(k)
                n_orphan += 1
    if not drop:
        return (0, 0, n_kept_nonstd)
    if apply:
        kept = []
        for idx, l in enumerate(lines):
            if idx in replace:
                kept.extend(replace[idx])
            if idx not in drop:
                kept.append(l)
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
    return (n_info, n_orphan, n_kept_nonstd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--filter', default='')
    args = ap.parse_args()
    files = sorted(list((REPO / 'src').rglob('*.c')) + list((REPO / 'src').rglob('*.cp')) + list((REPO / 'src').rglob('*.cpp')))
    files = [f for f in files if args.filter in str(f)]
    t_info = t_orphan = t_nonstd = t_files = 0
    for f in files:
        info, orphan, nonstd = process(f, args.apply)
        if info or orphan or nonstd:
            t_files += 1
            t_info += info
            t_orphan += orphan
            t_nonstd += nonstd
            if nonstd:
                print(f"  FLAG non-standard --INFO-- kept: {f.relative_to(REPO)} ({nonstd})")
    print(f"\n--INFO-- blocks removed: {t_info}; orphan annotations removed: "
          f"{t_orphan}; non-standard --INFO-- kept/flagged: {t_nonstd}; "
          f"files touched: {t_files}")


if __name__ == '__main__':
    main()
