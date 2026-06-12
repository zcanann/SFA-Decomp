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

    # SELF-CONTAINMENT GUARD: a struct that references an identifier defined
    # only in its .c (a #define array bound, a local-only type) cannot be
    # hoisted — moving it to a shared header breaks every OTHER file that
    # includes the header for a sibling struct (the bound is no longer in
    # scope). Refuse unless every UPPER_CASE identifier the body uses (the
    # macro-bound risk) is already present in the header's include closure.
    body_idents = set(re.findall(r'\b([A-Z][A-Z0-9_]{2,})\b', deftext))
    # identifiers already safe: those defined in the target header, or in any
    # header it includes (shallow check on include/ tree).
    hdr_dir = os.path.join(ROOT, 'include')
    safe = set()
    if os.path.exists(header_path):
        safe |= set(re.findall(r'#define\s+([A-Z][A-Z0-9_]+)', read(header_path)))
    # scan the donor .c's #defines: if the macro is LOCAL to the .c, it's a
    # blocker (it won't be in the shared header's scope for other consumers).
    donor_defines = set(re.findall(r'#define\s+([A-Z][A-Z0-9_]+)', read(first)))
    risky = (body_idents & donor_defines) - safe
    if risky:
        print(f'{name}: SKIP (references TU-local macro(s) {sorted(risky)}; '
              f'hoisting would break sibling consumers)')
        return

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
    # Snapshot: which consumers ALREADY include this header (siblings from a
    # prior hoist) — their .o must also stay byte-identical, so capture their
    # baselines too.
    edits = []  # (cpath, ofile, orig, base_md5)
    header_consumers = []
    for rel, ofile in tus.items():
        cpath = os.path.join(ROOT, rel)
        if not os.path.exists(cpath):
            continue
        if header_rel in read(cpath):
            header_consumers.append((rel, ofile))
    targets = list(dict.fromkeys(files + [r for r, _ in header_consumers]))
    for rel in targets:
        cpath = os.path.join(ROOT, rel)
        ofile = tus.get(rel)
        if not ofile:
            continue
        opath = os.path.join(ROOT, ofile)
        base = md5(opath)
        orig = read(cpath)
        new = orig
        for nm, span, s, e in find_typedefs(orig):
            if nm == name:
                new = orig[:s] + orig[e:]
                break
        if inc_line.strip() not in new:
            insert_at = new.find('#include')
            if insert_at >= 0:
                nl = new.find('\n', insert_at) + 1
                new = new[:nl] + inc_line + new[nl:]
            else:
                new = inc_line + new
        if new != orig:
            write(cpath, new)
        edits.append((cpath, ofile, orig, base))
    # Build EVERY edited .o; if any fails or byte-changes, revert the WHOLE
    # struct (all edits) — a cross-contamination on one consumer poisons all.
    ok = True
    for cpath, ofile, orig, base in edits:
        r = subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True,
                           text=True)
        opath = os.path.join(ROOT, ofile)
        if r.returncode != 0 or (base is not None and md5(opath) != base):
            ok = False
            break
    if not ok:
        for cpath, ofile, orig, base in edits:
            write(cpath, orig)
            subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True)
        # If this hoist authored a brand-new header that now has no consumer,
        # drop it so we don't leave an orphan.
        if os.path.exists(header_path):
            h = read(header_path)
            consumed = subprocess.run(['grep', '-rl', header_rel, 'src/'],
                                      cwd=ROOT, capture_output=True, text=True)
            if not consumed.stdout.strip():
                os.remove(header_path)
        print(f'{name}: REVERTED all {len(edits)} edits (a consumer .o broke)')
        return
    print(f'{name}: hoisted into {len(files)} TUs '
          f'({len(edits)} consumers gated, all conserved)')


def cmd_hoist_cluster(args):
    """Hoist a whole set of mutually-referencing IDENTICAL-layout structs into
    one header in dependency order, gated on every consumer .o staying
    byte-identical. Reverts the WHOLE cluster on any break (a struct that
    references a TU-local macro/sibling not in the cluster poisons it)."""
    names = args.names
    header_rel = args.header
    header_path = os.path.join(ROOT, 'include', header_rel)
    identical, _, by_name = census()
    ident_names = dict(identical)

    # Recover each struct's exact def text + the union of consumer files.
    defs = {}
    consumers = set()
    for name in names:
        if name not in by_name:
            print(f'{name}: not found; skipping cluster')
            return
        variants = by_name[name]
        files = [f for v in variants.values() for f in v]
        consumers.update(files)
        first = os.path.join(ROOT, files[0])
        for nm, span, _, _ in find_typedefs(read(first)):
            if nm == name:
                defs[name] = span
                break
    # Topological order: a struct that references another cluster member must
    # come AFTER it in the header.
    order = []
    remaining = list(names)
    guard_iter = 0
    while remaining and guard_iter < len(names) ** 2 + 5:
        guard_iter += 1
        for n in list(remaining):
            body = defs[n]
            deps = [m for m in remaining if m != n and re.search(r'\b' + re.escape(m) + r'\b', body)]
            if not deps:
                order.append(n)
                remaining.remove(n)
    order += remaining  # any cycle: append as-is

    # MACRO self-containment guard across the whole cluster.
    for n in names:
        donor_first = None
        for v in by_name[n].values():
            donor_first = v[0]
            break
        donor_defines = set(re.findall(r'#define\s+([A-Z][A-Z0-9_]+)',
                                       read(os.path.join(ROOT, donor_first))))
        body_macros = set(re.findall(r'\b([A-Z][A-Z0-9_]{2,})\b', defs[n]))
        risky = body_macros & donor_defines
        if risky:
            print(f'cluster {header_rel}: SKIP — {n} uses TU-local macro '
                  f'{sorted(risky)}')
            return

    # Write the header with all defs in dependency order.
    guard = re.sub(r'\W', '_', header_rel).upper() + '_'
    htext = f'#ifndef {guard}\n#define {guard}\n\n#include "types.h"\n\n'
    for n in order:
        htext += defs[n] + '\n\n'
    htext += '#endif\n'
    os.makedirs(os.path.dirname(header_path), exist_ok=True)
    write(header_path, htext)

    inc_line = f'#include "{header_rel}"\n'
    tus = discover_tus()
    edits = []
    for rel in sorted(consumers):
        cpath = os.path.join(ROOT, rel)
        ofile = tus.get(rel)
        if not ofile or not os.path.exists(cpath):
            continue
        opath = os.path.join(ROOT, ofile)
        base = md5(opath)
        orig = read(cpath)
        new = orig
        # remove every cluster struct's local def
        changed = True
        while changed:
            changed = False
            for nm, span, s, e in find_typedefs(new):
                if nm in names:
                    new = new[:s] + new[e:]
                    changed = True
                    break
        if inc_line.strip() not in new:
            ins = new.find('#include')
            if ins >= 0:
                nl = new.find('\n', ins) + 1
                new = new[:nl] + inc_line + new[nl:]
            else:
                new = inc_line + new
        if new != orig:
            write(cpath, new)
        edits.append((cpath, ofile, orig, base))

    ok = True
    for cpath, ofile, orig, base in edits:
        r = subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True,
                           text=True)
        if r.returncode != 0 or (base is not None and
                                 md5(os.path.join(ROOT, ofile)) != base):
            ok = False
            break
    if not ok:
        for cpath, ofile, orig, base in edits:
            write(cpath, orig)
            subprocess.run(['ninja', ofile], cwd=ROOT, capture_output=True)
        if os.path.exists(header_path):
            os.remove(header_path)
        print(f'cluster {header_rel}: REVERTED ({len(names)} structs, '
              f'{len(edits)} consumers — a .o broke)')
        return
    print(f'cluster {header_rel}: hoisted {len(names)} structs into '
          f'{len(edits)} consumers (all .o conserved)')


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
    hc = sub.add_parser('hoist-cluster')
    hc.add_argument('--names', required=True, nargs='+')
    hc.add_argument('--header', required=True)
    hc.set_defaults(func=cmd_hoist_cluster)
    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
