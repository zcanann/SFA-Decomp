#!/usr/bin/env python3
"""Remove built .o files that no longer correspond to a compiled unit.

Two ways an object goes orphaned:

  * Its source was renamed (especially case-only renames like DFpulley.c ->
    dfpulley.c). A restored CI build cache carries the old-name .o with a fresh
    cache mtime while the report step expects the new-name .o, and ninja may
    not rebuild it, so the report fails to open the new path.

  * Its source was merged into a group TU -- some other .c now #includes it, so
    it is never compiled on its own again, yet the .c is still on disk. An
    existence check alone keeps this object forever, and its frozen symbol
    table masquerades as live data in any sweep over the built objects.

Dropping both classes forces a clean recompile at the current unit boundaries.

Usage: ci_drop_orphan_objects.py <built-src-dir>
  e.g. ci_drop_orphan_objects.py build/GSAE01/src
"""
import glob
import os
import re
import sys

GROUP_INCLUDE = re.compile(r'#\s*include\s*"([^"]+\.(?:c|cpp|cp))"')


def group_members():
    """Sources that are #included into a group TU, as repo-relative paths."""
    members = set()
    for src in glob.glob('src/**/*.c', recursive=True):
        try:
            text = open(src, 'rb').read().decode('latin-1')
        except OSError:
            continue
        for inc in GROUP_INCLUDE.findall(text):
            # A group include is written relative to the build directory
            # ("../src/main/..."), not to the including file, so resolve it
            # against both and keep whichever names a real source.
            cands = [os.path.normpath(os.path.join(os.path.dirname(src), inc))]
            if 'src/' in inc:
                cands.append(os.path.join('src', inc.split('src/', 1)[1]))
            for path in cands:
                if os.path.exists(path):
                    members.add(os.path.normpath(path))
                    break
    return members


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    srcdir = sys.argv[1].rstrip('/')
    merged = group_members()
    removed = 0
    for o in glob.glob(srcdir + '/**/*.o', recursive=True):
        stem = 'src/' + o[len(srcdir) + 1:-2]
        live = False
        for ext in ('.c', '.cpp', '.cp', '.s', '.S'):
            src = os.path.normpath(stem + ext)
            if os.path.exists(src):
                live = src not in merged
                break
        if not live:
            os.remove(o)
            removed += 1
    print(f'ci_drop_orphan_objects: removed {removed} orphan .o files')


if __name__ == '__main__':
    main()
