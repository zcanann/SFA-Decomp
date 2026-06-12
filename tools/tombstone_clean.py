"""Remove orphaned "tombstone" blocks left by the DLL re-split: a doc-comment
+ pragma wrapper (and sometimes a stray forward-decl) where a function body
USED to be but has since moved to another TU. They are pragma-balanced and
carry no code, so removing them is byte-neutral -- but every file is byte-gated
(rebuild the .o, compare bytes, auto-revert on any change) so matching % can
never regress.

A tombstone block =
    [optional leading doc-comment lines]
    #pragma <kind> off|on|N          (one or more pushes)
    [optional forward-decl `T fn(...);` lines]
    #pragma <kind> reset             (matching resets, depth back to 0)
with NO function body (no `{`) anywhere inside.

Per file, two passes maximise cleanup while staying byte-exact:
  A: delete the whole block (comment + pragmas + forward-decls). If the .o is
     byte-identical, keep it.
  B: if A changed bytes (a forward-decl was load-bearing), revert and retry
     keeping the forward-decl lines, dropping only comment + pragmas.
  If B still changes bytes, revert the file and report it.

Usage:
  python3 tools/tombstone_clean.py [--apply] [--filter SUBSTR] [--list]
Without --apply: dry-run (count blocks per file, no edits, no build).
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRAGMA = re.compile(r'^\s*#pragma\s+(\w+)\s+(\w+)')


def is_push(action: str) -> bool:
    return action in ('off', 'on') or action.isdigit()


def find_tombstones(lines: list[str]) -> list[tuple[int, int, int]]:
    """Return [(block_start, block_end_exclusive, firstpragma_idx)] for each
    tombstone. block_start includes the attached leading doc-comment."""
    n = len(lines)
    out = []
    i = 0
    while i < n:
        m = PRAGMA.match(lines[i])
        if not m or not is_push(m.group(2)):
            i += 1
            continue
        # scan the pragma region to its balanced reset, tracking real code
        depth = 0
        j = i
        has_code = False
        while j < n:
            mm = PRAGMA.match(lines[j])
            s = lines[j].strip()
            if mm:
                a = mm.group(2)
                if is_push(a):
                    depth += 1
                elif a == 'reset':
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
                continue
            if (s == '' or s.startswith('/*') or s.startswith('*')
                    or s.startswith('//') or s.endswith('*/')):
                j += 1
                continue
            if s.endswith(';') and '{' not in s:  # forward decl, not a body
                j += 1
                continue
            has_code = True
            j += 1
        if depth != 0 or has_code:
            i = j + 1
            continue
        region_end = j + 1  # inclusive of the final reset line
        # attach the preceding contiguous doc-comment block (only blanks allowed
        # between it and the first pragma)
        start = i
        k = i - 1
        while k >= 0 and lines[k].strip() == '':
            k -= 1
        # walk back over a /* ... */ comment block
        if k >= 0 and lines[k].strip().endswith('*/'):
            cend = k
            while k >= 0 and not lines[k].lstrip().startswith('/*'):
                k -= 1
            if k >= 0:
                start = k
        out.append((start, region_end, i))
        i = region_end
    return out


def strip_blocks(lines: list[str], blocks: list[tuple[int, int, int]],
                 keep_fwd_decls: bool) -> list[str]:
    drop = set()
    keep_lines = {}
    for start, end, _fp in blocks:
        for idx in range(start, end):
            drop.add(idx)
            if keep_fwd_decls:
                s = lines[idx].strip()
                if (s.endswith(';') and '{' not in s
                        and not PRAGMA.match(lines[idx])
                        and not s.startswith('/*') and not s.startswith('*')
                        and not s.startswith('//')):
                    keep_lines[idx] = lines[idx]
    out = []
    for idx, ln in enumerate(lines):
        if idx in drop:
            if idx in keep_lines:
                out.append(keep_lines[idx])
            continue
        out.append(ln)
    # collapse 3+ consecutive blank lines that removal may have created
    collapsed = []
    blanks = 0
    for ln in out:
        if ln.strip() == '':
            blanks += 1
            if blanks > 2:
                continue
        else:
            blanks = 0
        collapsed.append(ln)
    return collapsed


def obj_path(src: Path) -> Path:
    rel = src.relative_to(REPO / 'src')
    return REPO / 'build' / 'GSAE01' / 'src' / rel.with_suffix('.o')


def md5(p: Path):
    return hashlib.md5(p.read_bytes()).hexdigest() if p.exists() else None


def build(obj: Path) -> bool:
    r = subprocess.run(['ninja', str(obj.relative_to(REPO))], cwd=REPO,
                       capture_output=True, text=True, timeout=300)
    return r.returncode == 0


def process(src: Path, apply: bool) -> str:
    orig = src.read_text(errors='replace')
    lines = orig.split('\n')
    blocks = find_tombstones(lines)
    if not blocks:
        return ''
    if not apply:
        return f"{src.relative_to(REPO)}: {len(blocks)} tombstones"
    obj = obj_path(src)
    if not build(obj):
        return f"{src.relative_to(REPO)}: SKIP (baseline build failed)"
    base = md5(obj)
    for keep_fwd in (False, True):
        new = '\n'.join(strip_blocks(lines, blocks, keep_fwd))
        src.write_text(new)
        if build(obj) and md5(obj) == base:
            tag = '' if not keep_fwd else ' (kept fwd-decls)'
            return f"{src.relative_to(REPO)}: removed {len(blocks)} tombstones{tag}"
    src.write_text(orig)
    build(obj)
    return f"{src.relative_to(REPO)}: REVERTED (byte change, needs manual review)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--filter', default='')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args()

    files = sorted((REPO / 'src').rglob('*.c'))
    files = [f for f in files if args.filter in str(f)]
    total = 0
    for f in files:
        r = process(f, args.apply)
        if r:
            total += 1
            if args.list or args.apply:
                print(r, flush=True)
    if not args.apply:
        print(f"\n{total} files with tombstones "
              f"({sum(len(find_tombstones(f.read_text(errors='replace').split(chr(10)))) for f in files)} blocks)")


if __name__ == '__main__':
    main()
