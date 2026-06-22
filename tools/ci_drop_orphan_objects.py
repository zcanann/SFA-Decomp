#!/usr/bin/env python3
"""Remove built .o files whose source .c no longer exists.

A restored CI build cache can carry per-unit .o files for sources that were
since renamed (especially case-only renames like DFpulley.c -> dfpulley.c):
the old-name .o lingers with a fresh cache mtime while the report step expects
the new-name .o, and ninja may not rebuild it, so the report fails to open the
new path. Dropping every built src .o whose source .c no longer exists forces
a clean recompile at the current name.

Usage: ci_drop_orphan_objects.py <built-src-dir>
  e.g. ci_drop_orphan_objects.py build/GSAE01/src
"""
import glob
import os
import sys


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    srcdir = sys.argv[1].rstrip('/')
    removed = 0
    for o in glob.glob(srcdir + '/**/*.o', recursive=True):
        c = 'src/' + o[len(srcdir) + 1:-2] + '.c'
        if not os.path.exists(c):
            os.remove(o)
            removed += 1
    print(f'ci_drop_orphan_objects: removed {removed} orphan .o files')


if __name__ == '__main__':
    main()
