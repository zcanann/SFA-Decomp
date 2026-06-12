"""Group scattered file-scope declarations to the top of each TU (the
wmspiritplace standard): collect every `#include`, file-scope `extern ...;`, and
`STATIC_ASSERT(...);` that the import scattered BETWEEN function definitions and
hoist it into a grouped block in the header zone -- includes joined to the top
include group, externs+STATIC_ASSERTs placed just before the first function
definition (a point where all includes and local typedefs are already in scope,
so it always compiles). Duplicates are removed.

NEVER touches block-scope externs (inside function bodies -- recipe #57, where a
per-function extern override is load-bearing). Decls already in the header zone
(before the first function) are left in place, so a clean file is a no-op.

Reordering declarations emits no code, so this is byte-neutral -- but every file
is byte-gated (rebuild the .o, compare, auto-revert on any change or build
failure), so matching % cannot regress.

Usage: python3 tools/decl_group.py [--apply] [--filter SUBSTR] [--only LIST]
Without --apply: report scattered-decl counts per file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INCLUDE = re.compile(r'^#include\b')
EXTERN = re.compile(r'^extern\b')
SASSERT = re.compile(r'^STATIC_ASSERT\b')
# a function DEFINITION at file scope: ends in ')' or '{' and a body brace opens
DEF_OPEN = re.compile(r'^[A-Za-z_].*[\)\{]\s*$')


def depth_scan(lines):
    """Yield (idx, line, depth_before) tracking brace depth at file scope."""
    depth = 0
    for idx, l in enumerate(lines):
        yield idx, l, depth
        depth += l.count('{') - l.count('}')


TYPE_LINE = re.compile(r'^[A-Za-z_][\w \*]*$')


def first_fn_def(lines) -> int:
    """Index where the first file-scope function definition STARTS (opens a body
    brace), backing up to include a return-type-on-its-own-line (the Ghidra
    `undefined4\\nFUN_xxx(...)` shape)."""
    depth = 0
    n = len(lines)
    for idx, l in enumerate(lines):
        s = l.strip()
        if depth == 0 and s and s[0] not in '#/*' and '(' in s and '=' not in s.split('(')[0]:
            k = idx
            while k < n and k < idx + 12:
                if '{' in lines[k]:
                    start = idx
                    p = idx - 1
                    while p >= 0 and lines[p].strip() == '':
                        p -= 1
                    if p >= 0:
                        ps = lines[p].strip()
                        if (TYPE_LINE.match(ps) and ps not in ('else', 'do')
                                and not ps.endswith('*/')):
                            start = p
                    return start
                if ';' in lines[k]:
                    break
                k += 1
        depth += l.count('{') - l.count('}')
    return n


def collect_units(lines, start, end):
    """Return list of (kind, text, span) for file-scope include/extern/assert
    logical units within [start, end), with brace-depth = 0."""
    units = []
    depth = 0
    i = 0
    n = len(lines)
    while i < n:
        l = lines[i]
        s = l.strip()
        at_scope = (depth == 0)
        if start <= i < end and at_scope:
            if INCLUDE.match(s):
                units.append(('include', l, (i, i)))
                depth += l.count('{') - l.count('}'); i += 1; continue
            if EXTERN.match(s) or SASSERT.match(s):
                # capture multi-line until ';'
                j = i
                while j < n and ';' not in lines[j]:
                    j += 1
                kind = 'extern' if EXTERN.match(s) else 'assert'
                units.append((kind, '\n'.join(lines[i:j + 1]), (i, j)))
                for k in range(i, j + 1):
                    depth += lines[k].count('{') - lines[k].count('}')
                i = j + 1
                continue
        depth += l.count('{') - l.count('}')
        i += 1
    return units


def process(path: Path):
    text = path.read_bytes().decode('latin-1')
    lines = text.split('\n')
    ff = first_fn_def(lines)
    if ff >= len(lines):
        return None  # no function defs
    # scattered = file-scope include/extern/assert AFTER the first fn def
    scattered = collect_units(lines, ff, len(lines))
    if not scattered:
        return None
    return lines, ff, scattered


DECL_NAME = re.compile(r'([A-Za-z_]\w*)\s*[\(\[;=]')


def decl_symbol(text: str) -> str | None:
    m = DECL_NAME.search(re.sub(r'\s+', ' ', text.strip()))
    return m.group(1) if m else None


def conflicted_symbols(lines, ff) -> set[str]:
    """Symbols declared with 2+ distinct file-scope signatures anywhere in the
    file -- recipe #57 position-dependent pairs; never move/dedup these."""
    sigs: dict[str, set[str]] = {}
    for kind, t, _span in collect_units(lines, 0, len(lines)):
        if kind != 'extern':
            continue
        sym = decl_symbol(t)
        if sym:
            sigs.setdefault(sym, set()).add(re.sub(r'\s+', ' ', t.strip()))
    return {s for s, v in sigs.items() if len(v) > 1}


def apply_file(path: Path) -> tuple[int, int, int]:
    res = process(path)
    if res is None:
        return (0, 0, 0)
    lines, ff, scattered = res
    conflicted = conflicted_symbols(lines, ff)
    header_text = '\n'.join(lines[:ff])

    def safe(u):
        kind, t, _ = u
        if kind == 'extern' and decl_symbol(t) in conflicted:
            return False  # recipe #57 position-dependent pair
        if kind == 'assert':
            m = re.search(r'(?:offsetof|sizeof)\(\s*(\w+)', t)
            if m and re.search(r'\b' + re.escape(m.group(1)) + r'\b', header_text) is None:
                return False  # struct defined after insertion point -> leave in place
        return True

    scattered = [u for u in scattered if safe(u)]
    if not scattered:
        return (0, 0, 0)
    drop_spans = set()
    for _k, _t, (a, b) in scattered:
        for x in range(a, b + 1):
            drop_spans.add(x)
    # existing header-zone units (for dedup)
    header_units = collect_units(lines, 0, ff)
    seen_inc = {u[1].strip() for u in header_units if u[0] == 'include'}
    seen_ext = {re.sub(r'\s+', ' ', u[1].strip()) for u in header_units if u[0] != 'include'}

    new_includes, new_decls = [], []
    for kind, t, _span in scattered:
        if kind == 'include':
            key = t.strip()
            if key not in seen_inc:
                seen_inc.add(key); new_includes.append(t)
        else:
            key = re.sub(r'\s+', ' ', t.strip())
            if key not in seen_ext:
                seen_ext.add(key); new_decls.append(t)

    # rebuild: drop scattered lines; insert includes after last header include;
    # insert decls just before the first function definition.
    last_inc = -1
    depth = 0
    for idx, l in enumerate(lines):
        if depth == 0 and INCLUDE.match(l.strip()) and idx < ff:
            last_inc = idx
        depth += l.count('{') - l.count('}')
    out = []
    for idx, l in enumerate(lines):
        if idx in drop_spans:
            continue
        if idx == ff and new_decls:
            out.extend('\n'.join(new_decls).split('\n'))
            out.append('')
        out.append(l)
        if idx == last_inc and new_includes:
            out.extend('\n'.join(new_includes).split('\n'))
    # collapse blank runs
    collapsed, blanks = [], 0
    for l in out:
        if l.strip() == '':
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        collapsed.append(l)
    path.write_bytes('\n'.join(collapsed).encode('latin-1'))
    n_ext = sum(1 for k, _, _ in scattered if k == 'extern')
    n_inc = sum(1 for k, _, _ in scattered if k == 'include')
    n_sa = sum(1 for k, _, _ in scattered if k == 'assert')
    return (n_inc, n_ext, n_sa)


def obj_for(name: str, config) -> str | None:
    for u in config["units"]:
        if u["name"].replace("\\", "/") == name:
            return u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
    return None


def md5(p: Path):
    return hashlib.md5(p.read_bytes()).hexdigest() if p.exists() else None


def build(obj: str) -> bool:
    r = subprocess.run(["ninja", obj], cwd=REPO, capture_output=True, timeout=300)
    return b"FAILED" not in r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--filter', default='')
    ap.add_argument('--only', default='')
    args = ap.parse_args()
    config = json.loads((REPO / "build" / "GSAE01" / "config.json").read_text())
    name_to_obj = {}
    for u in config["units"]:
        name_to_obj[u["name"].replace("\\", "/")] = \
            u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")

    allow = None
    if args.only:
        allow = {l.strip() for l in Path(args.only).read_text().splitlines() if l.strip()}

    files = sorted((REPO / 'src' / 'main').rglob('*.c'))
    files = [f for f in files if args.filter in str(f)]
    if allow is not None:
        files = [f for f in files if str(f.relative_to(REPO)) in allow]

    t_inc = t_ext = t_sa = applied = reverted = 0
    for f in files:
        name = str(f.relative_to(REPO / 'src'))
        obj = name_to_obj.get(name)
        res = process(f)
        if res is None:
            continue
        if not args.apply:
            _, _, scattered = res
            print(f"{name}: {sum(1 for k,_,_ in scattered if k=='include')} inc, "
                  f"{sum(1 for k,_,_ in scattered if k=='extern')} extern, "
                  f"{sum(1 for k,_,_ in scattered if k=='assert')} assert")
            continue
        if not obj or not (REPO / obj).is_file():
            if obj and not build(obj):
                print(f"SKIP no-obj: {name}"); continue
        orig = f.read_bytes()
        base = md5(REPO / obj)
        inc, ext, sa = apply_file(f)
        if build(obj) and md5(REPO / obj) == base:
            applied += 1; t_inc += inc; t_ext += ext; t_sa += sa
        else:
            f.write_bytes(orig); build(obj)
            if md5(REPO / obj) != base:
                raise SystemExit(f"RESTORE FAILED: {name}")
            reverted += 1
            print(f"  REVERTED: {name}")
    if args.apply:
        print(f"\napplied {applied} (inc {t_inc}, extern {t_ext}, assert {t_sa}); "
              f"reverted {reverted}")


if __name__ == '__main__':
    main()
