#!/usr/bin/env python3
"""File-scope type-disagreement census.

MWCC type-checks one TU at a time, so an `extern` in TU A that contradicts
the definition in TU B reaches no compiler diagnostic and no gate. Collect
every file-scope declaration of every symbol across src/ and include/ and
report the symbols whose declared types are not all the same.
"""
import collections
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A file-scope declaration starts at column 0. Capture the type text and the
# declarator, tolerating pointers, arrays and initialisers.
DECL = re.compile(
    r'^(extern\s+)?((?:const\s+|volatile\s+|static\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*'
    r'[A-Za-z_]\w*(?:\s*\*)*)\s+'
    r'(\**)\s*([A-Za-z_]\w*)\s*'
    r'((?:\[[^\]]*\])*)\s*(?:=|;)',
    re.M)

SKIP_TYPES = {'return', 'if', 'else', 'while', 'for', 'switch', 'case', 'do',
              'typedef', 'goto', 'break', 'continue', 'sizeof'}


def norm(base, stars, arr):
    """Normalise a declared type: drop qualifiers and array EXTENTS.

    An extent difference (`x[]` vs `x[8]`) is normal C, not a disagreement;
    an element-type difference is.
    """
    t = base.replace('const', '').replace('volatile', '').replace('static', '')
    t = re.sub(r'\s+', ' ', t).strip()
    t += stars
    t += '[]' * (arr.count('['))
    return t


def scan():
    decls = collections.defaultdict(set)
    where = collections.defaultdict(set)
    files = []
    for pat in ('src/**/*.c', 'src/**/*.h', 'include/**/*.h'):
        files += glob.glob(os.path.join(ROOT, pat), recursive=True)
    for path in files:
        try:
            text = open(path, 'rb').read().decode('latin-1')
        except OSError:
            continue
        # Strip block comments so a commented-out decl does not register.
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
        text = re.sub(r'//[^\n]*', '', text)
        rel = os.path.relpath(path, ROOT)
        for m in DECL.finditer(text):
            base, stars, name, arr = m.group(2), m.group(3), m.group(4), m.group(5)
            if base.split()[-1] in SKIP_TYPES or name in SKIP_TYPES:
                continue
            # A function declaration is not a data object.
            tail = text[m.end() - 1:m.end() + 2]
            t = norm(base, stars, arr)
            decls[name].add(t)
            where[(name, t)].add(rel)
    return decls, where


def main():
    decls, where = scan()
    bad = {n: t for n, t in decls.items() if len(t) > 1}
    print('[symbols %d] [disagreeing %d]' % (len(decls), len(bad)))
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name in sorted(bad):
        if only and only not in name:
            continue
        print('\n%s:' % name)
        for t in sorted(bad[name]):
            locs = sorted(where[(name, t)])
            print('   %-28s %s' % (t, ' '.join(locs[:4]) + (' ...' if len(locs) > 4 else '')))


if __name__ == '__main__':
    main()
