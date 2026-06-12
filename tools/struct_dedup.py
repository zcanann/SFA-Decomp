#!/usr/bin/env python3
"""Hoist byte-identical duplicated struct/typedef definitions into a shared
header, byte-gated per .c file (.o md5 unchanged, auto-revert on any change).

The skeleton-copy carve method (CLAUDE.md "Graduating a placeholder")
duplicates each donor's struct/typedef forest into every carved piece. When a
typedef is byte-identical across many TUs, it can live in one shared header
that each TU includes instead of carrying its own copy — pure source cleanup,
compile-time-only, so the .o is byte-identical.

MODEL
  --census : group typedef-struct/union definitions by (name, normalized
             layout); report IDENTICAL-layout duplicates (same name AND
             layout in >=2 TUs) and DIVERGENT same-name groups (same name,
             different layouts — rename-don't-unify territory, NOT hoisted).
  --hoist NAME --header H.h :
             for one IDENTICAL group, ensure the def exists in
             include/<H.h>, then in each TU: replace its local def with an
             #include "<H.h>" (deduped if already present) and rebuild the
             TU's .o. If the .o byte-changes or the build fails, revert that
             TU. The header is written once; only TUs whose .o is conserved
             keep the include.

GATE: per-TU .o md5 compare (recipe-wide convention). All file IO is
byte-wise (surrogateescape) for SJIS safety.
"""
import argparse
import collections
import glob
import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_NINJA = os.path.join(ROOT, 'build.ninja')


def read(p):
    with open(p, encoding='utf-8', errors='surrogateescape') as f:
        return f.read()


def write(p, t):
    with open(p, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(t)


def md5(p):
    return hashlib.md5(open(p, 'rb').read()).hexdigest() if os.path.exists(p) else None


def discover_tus():
    """src/.../*.c -> build/.../*.o from build.ninja."""
    text = read(BUILD_NINJA)
    text = re.sub(r'\$\n\s*', '', text)
    out = {}
    for m in re.finditer(r'^build (build/GSAE01/src/\S+\.o): \S+ (src/\S+\.c)',
                         text, re.M):
        out[m.group(2)] = m.group(1)
    return out


def find_typedefs(text):
    """Yield (name, full_span_text, start, end) for each top-level
    `typedef struct/union [Tag] { ... } Name[, ...];`."""
    for m in re.finditer(r'\btypedef\s+(?:struct|union)\s*(\w+)?\s*\{', text):
        brace = m.end() - 1
        depth = 0
        i = brace
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        tail = text[i + 1:i + 120]
        nm = re.match(r'\s*([\w\s\*,]+);', tail)
        if not nm:
            continue
        name = nm.group(1).strip().split(',')[0].lstrip('*').strip()
        end = i + 1 + nm.end()
        yield name, text[m.start():end], m.start(), end


def norm(s):
    return re.sub(r'\s+', ' ', s).strip()


def census():
    files = (glob.glob(os.path.join(ROOT, 'src/main/dll/*.c')) +
             glob.glob(os.path.join(ROOT, 'src/main/*.c')) +
             glob.glob(os.path.join(ROOT, 'src/main/audio/*.c')))
    by_name = collections.defaultdict(lambda: collections.defaultdict(list))
    for f in files:
        t = read(f)
        for name, span, _, _ in find_typedefs(t):
            by_name[name][norm(span)].append(os.path.relpath(f, ROOT))
    identical, divergent = [], []
    for name, variants in by_name.items():
        nfiles = sum(len(v) for v in variants.values())
        if nfiles < 2:
            continue
        if len(variants) == 1:
            identical.append((name, nfiles))
        else:
            divergent.append((name, nfiles, len(variants)))
    identical.sort(key=lambda x: -x[1])
    divergent.sort(key=lambda x: -x[1])
    return identical, divergent, by_name


def cmd_census(args):
    identical, divergent, _ = census()
    print(f'IDENTICAL-layout duplicates: {len(identical)}')
    for n, c in identical[:args.limit]:
        print(f'  {n}: {c} files')
    print(f'\nDIVERGENT same-name (rename-don\'t-unify, NOT hoisted): '
          f'{len(divergent)}')
    for n, c, h in divergent[:args.limit]:
        print(f'  {n}: {c} files, {h} layouts')


def cmd_hoist(args):
    name = args.name
    header_rel = args.header  # e.g. main/dll/fb_cmd.h
    header_path = os.path.join(ROOT, 'include', header_rel)
    identical, _, by_name = census()
    if name not in dict(identical):
        print(f'{name}: not an IDENTICAL-layout duplicate; refusing to hoist')
        sys.exit(1)
    variants = by_name[name]
    (the_norm, files) = next(iter(variants.items()))
    files = [f for v in variants.values() for f in v]
    # Recover an exact (non-normalized) def text from the first file.
    first = os.path.join(ROOT, files[0])
    deftext = None
    for nm, span, _, _ in find_typedefs(read(first)):
        if nm == name:
            deftext = span
            break
    assert deftext is not None

    # Write/append header (idempotent guard).
    guard = re.sub(r'\W', '_', header_rel).upper() + '_'
    if os.path.exists(header_path):
        htext = read(header_path)
    else:
        os.makedirs(os.path.dirname(header_path), exist_ok=True)
        htext = f'#ifndef {guard}\n#define {guard}\n\n#include "types.h"\n\n#endif\n'
    if f'}} {name};' not in htext and f'}}{name};' not in htext:
        htext = htext.replace('\n#endif\n', f'\n{deftext}\n\n#endif\n')
        write(header_path, htext)

    inc_line = f'#include "{header_rel}"\n'
    tus = discover_tus()
    kept = reverted = 0
    for rel in files:
        cpath = os.path.join(ROOT, rel)
        ofile = tus.get(rel)
        if not ofile:
            continue
        opath = os.path.join(ROOT, ofile)
        base = md5(opath)
        if base is None:
            continue
        orig = read(cpath)
        # Remove this TU's local def of `name`.
        new = orig
        for nm, span, s, e in find_typedefs(orig):
            if nm == name:
                new = orig[:s] + orig[e:]
                break
        if new == orig:
            continue  # not found (already hoisted?)
        # Add include if absent.
        if inc_line.strip() not in new:
            # place after the first #include block
            m = re.search(r'(#include[^\n]*\n)(?!.*#include)', new)
            insert_at = new.find('#include')
            if insert_at >= 0:
                # after first include line
                nl = new.find('\n', insert_at) + 1
                new = new[:nl] + inc_line + new[nl:]
            else:
                new = inc_line + new
        write(cpath, new)
        r = subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True,
                           text=True)
        if r.returncode != 0 or md5(opath) != base:
            write(cpath, orig)
            subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True)
            reverted += 1
        else:
            kept += 1
    print(f'{name}: hoisted into {kept} TUs, reverted {reverted}')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('census')
    c.add_argument('--limit', type=int, default=40)
    c.set_defaults(func=cmd_census)
    h = sub.add_parser('hoist')
    h.add_argument('--name', required=True)
    h.add_argument('--header', required=True)
    h.set_defaults(func=cmd_hoist)
    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
