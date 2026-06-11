#!/usr/bin/env python3
"""Phantom-identifier census for the naming campaign.

Lists every .c unit (or every function in one unit) carrying Ghidra
phantom identifiers (iVarN/uVarN/local_XX/param_N/uStack_XX/...), split
into REAL functions vs FUN_ drift bodies (v1.1 floaters - deliberately
out of naming scope; they get restructured at recovery time).

Usage:
  python3 tools/phantom_census.py                 # per-unit worklist (descending)
  python3 tools/phantom_census.py <unit.c>        # per-function counts for one unit

Naming-campaign procedure (per unit, byte-gated):
  1. Read each function; map every phantom to its role from the uses.
     Single-role webs get semantic names; genuinely multi-role merged
     register webs get honest neutral names (val/ref/work/fa..) - a
     misleading semantic name is worse than a vague one.
  2. Apply renames token-wise (re \\b boundaries) scoped to the fn body;
     byte-wise file IO (SJIS safety).
  3. Byte gate: stash the diff, rebuild the unit .o at HEAD, hash;
     re-apply, rebuild, hash; commit only on identical hashes
     (check .o mtime > .c mtime to dodge the stale-.o trap).
  4. Commit + push to main per batch; pull --rebase first.

Skip classes (document, don't guess):
  - FUN_ drift bodies (v1.1 addresses, float harmlessly).
  - *_v11_unused dead code.
  - FUN_-opaque semi-drift real fns (objprint_dolphin render fns,
    newshadows casters): partial treatment only - name structurally
    certain tokens (bitstream readers, counters, conv pairs), leave
    unknown pointers positional.
  - undefined8 param_1..8 passthrough chains (ABI register noise on
    modgfx-release-style fns): keep.
"""
import re, os, sys

PHANTOM = re.compile(r'\b(?:iVar\d+|uVar\d+|fVar\d+|local_[0-9a-f]+|puVar\d+|piVar\d+|pfVar\d+|psVar\d+|pbVar\d+|pcVar\d+|bVar\d+|sVar\d+|dVar\d+|cVar\d+|uStack_[0-9a-f]+|auStack_[0-9a-f]+|afStack_[0-9a-f]+|fStack_[0-9a-f]+|iStack_[0-9a-f]+|param_\d+)\b')
NAME = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def fn_counts(path):
    text = open(path, 'r', errors='replace').read()
    depth = 0
    fn = None
    pending = None
    counts = {}
    for l in text.split('\n'):
        if depth == 0:
            s = l.strip()
            if s and not s.startswith(('#', '/', '*', 'extern', 'typedef')) and '(' in l and ';' not in l:
                m = NAME.search(l)
                if m:
                    pending = m.group(1)
        for ch in l:
            if ch == '{':
                if depth == 0 and pending:
                    fn = pending
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth <= 0:
                    depth = 0
                    fn = None
        if fn and depth > 0:
            n = len(PHANTOM.findall(l))
            if n:
                counts[fn] = counts.get(fn, 0) + n
    return counts


def main():
    if len(sys.argv) > 1:
        for f, c in sorted(fn_counts(sys.argv[1]).items(), key=lambda x: -x[1]):
            tag = ' [drift]' if f.startswith('FUN_') else ''
            print(f'{c:6d} {f}{tag}')
        return
    rows = []
    for root, dirs, files in os.walk('src'):
        for fname in sorted(files):
            if not fname.endswith('.c'):
                continue
            path = os.path.join(root, fname)
            counts = fn_counts(path)
            real = sum(c for f, c in counts.items() if not f.startswith('FUN_'))
            rf = sum(1 for f in counts if not f.startswith('FUN_'))
            drift = sum(c for f, c in counts.items() if f.startswith('FUN_'))
            df = sum(1 for f in counts if f.startswith('FUN_'))
            if real or drift:
                rows.append((real, rf, drift, df, path))
    rows.sort(reverse=True)
    print(f'# units: {len(rows)}; real-fn tokens: {sum(r[0] for r in rows)}; '
          f'drift(FUN_) tokens: {sum(r[2] for r in rows)}')
    for real, rf, drift, df, path in rows:
        print(f'{real:6d} in {rf:3d} fns | drift {drift:6d} in {df:3d} | {path}')


if __name__ == '__main__':
    main()
