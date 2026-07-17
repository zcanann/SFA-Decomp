#!/usr/bin/env python3
"""Find externs our sources reference that nothing defines.

A unit that is not yet linked into the DOL can carry an `extern` naming a
symbol that exists nowhere: neither in config/GSAE01/symbols.txt nor as a
definition in any of our objects. Nothing catches these. The DOL sha1 gate
cannot see them (the object is not linked), and objdiff cannot compare a
reloc whose symbol it fails to resolve, so the unit's match percent is
computed as if the reference were fine. The bug only surfaces much later,
as a link error, when the unit is finally graduated.

The dominant source of these is a half-finished rename: a wave renames the
.sdata2/.sdata atoms in symbols.txt to lbl_<ADDR> but misses the source
consumers, which keep spelling the symbol with its old name. Those old
names carry the address as a suffix (`Vachuff_803DEE20`), so when a
dangling name ends in an 8-hex-digit address that resolves to a real
symbol, the repair is mechanical: rename the source reference to whatever
symbols.txt defines at that address. --fixable lists exactly that subset.

Objects whose source no longer exists are skipped -- see source_for().
Counting them roughly doubles every number here and buries the real
findings under danglers frozen into stale artifacts.

Usage:
  tools/dangling_extern_check.py            # every dangling extern
  tools/dangling_extern_check.py --fixable  # only the mechanically fixable
"""
import argparse
import collections
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NM = os.path.join(ROOT, 'build/binutils/powerpc-eabi-nm')
SYMS = os.path.join(ROOT, 'config/GSAE01/symbols.txt')
OBJS = os.path.join(ROOT, 'build/GSAE01/src')

SYM_RE = re.compile(r'\s*([A-Za-z_@$][\w@$.]*)\s*=\s*([.\w]+):0x([0-9A-Fa-f]+)')
SUFFIX_RE = re.compile(r'^(.+)_([0-9A-Fa-f]{8})_?$')


def load_symbols():
    names, by_addr = set(), {}
    with open(SYMS) as fh:
        for line in fh:
            m = SYM_RE.match(line)
            if m:
                names.add(m.group(1))
                by_addr.setdefault(int(m.group(3), 16), []).append(
                    (m.group(1), m.group(2)))
    return names, by_addr


def source_for(obj):
    """The source an object was built from, or None if it is an orphan.

    Renaming a unit leaves its old .o behind in the build tree; ninja no
    longer regenerates it, so its symbols are frozen at whatever the tree
    looked like before the rename. Those stale objects would otherwise
    dominate the report with danglers no source actually contains.
    """
    stem = os.path.splitext(os.path.relpath(obj, OBJS))[0]
    for ext in ('.c', '.cpp', '.cp', '.s', '.S'):
        path = os.path.join(ROOT, 'src', stem + ext)
        if os.path.exists(path):
            return path
    return None


def scan_objects():
    provided, undef = set(), collections.defaultdict(list)
    every = sorted(glob.glob(os.path.join(OBJS, '**', '*.o'), recursive=True))
    objs = [o for o in every if source_for(o)]
    orphans = len(every) - len(objs)
    if orphans:
        print('[skipped %d orphaned objects with no source]' % orphans)
    for obj in objs:
        out = subprocess.run([NM, obj], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'U':
                undef[parts[1]].append(obj)
            elif len(parts) >= 3 and parts[1] not in ('U', 'w'):
                provided.add(parts[2])
    return objs, provided, undef


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fixable', action='store_true',
                    help='only danglers whose <name>_<ADDR> suffix resolves')
    args = ap.parse_args()

    if not os.path.exists(NM):
        sys.exit('missing %s -- build binutils first' % NM)

    names, by_addr = load_symbols()
    objs, provided, undef = scan_objects()
    dangling = {s: v for s, v in undef.items()
                if s not in names and s not in provided}

    print('[objects %d] [symbols.txt %d] [defined by us %d] [dangling %d]'
          % (len(objs), len(names), len(provided), len(dangling)))

    fixable = 0
    for sym in sorted(dangling):
        users = ' '.join(sorted({os.path.relpath(u, ROOT) for u in dangling[sym]}))
        m = SUFFIX_RE.match(sym)
        target = by_addr.get(int(m.group(2), 16)) if m else None
        if target:
            fixable += 1
            print('%-38s -> %-28s %s' % (sym, '%s (%s)' % target[0], users))
        elif not args.fixable:
            print('%-38s -> %-28s %s' % (sym, '?', users))
    print('[mechanically fixable: %d]' % fixable)


if __name__ == '__main__':
    main()
