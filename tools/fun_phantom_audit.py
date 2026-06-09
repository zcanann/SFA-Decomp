#!/usr/bin/env python3
"""
fun_phantom_audit.py -- classify Ghidra-drift FUN_<8hex> function DEFINITIONS.

A FUN_<addr> definition is a v1.1-Ghidra-import phantom: the real matched code
links under its canonical symbols.txt name, so the FUN_ def is dead clutter
UNLESS something still references it (then removing it breaks the build).

Classification per FUN_ DEFINITION:
  DEAD       -- not referenced anywhere in src (no call site, not address-taken),
                not present in symbols.txt -> safe to remove.
  REFERENCED -- called / address-taken somewhere -> do NOT remove (rename or leave).
  IN_SYMBOLS -- name appears in symbols.txt -> not a phantom, leave alone.

Usage:
  fun_phantom_audit.py [--path-filter SUBSTR] [--csv] [--defs-only] [--referenced]
"""
import os, re, sys, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
SYMBOLS = os.path.join(ROOT, "config", "GSAE01", "symbols.txt")

FUN_RE = re.compile(r'\bFUN_[0-9a-fA-F]{8}\b')
# A definition: a line whose FUN_ name is immediately followed by '(' ... ')' and
# the statement is NOT terminated by ';' before an opening brace (body follows).
# We detect by: line contains 'FUN_xxxx(' , does not start with 'extern',
# and the matching ')' is followed (same or next non-empty line) by '{'.

def load_symbols():
    names = set()
    if os.path.exists(SYMBOLS):
        with open(SYMBOLS, 'rb') as f:
            data = f.read().decode('utf-8', 'replace')
        for m in re.finditer(r'\bFUN_[0-9a-fA-F]{8}\b', data):
            names.add(m.group(0))
    return names

def iter_c_files(path_filter):
    for dirpath, _, files in os.walk(SRC):
        for fn in files:
            if not (fn.endswith('.c') or fn.endswith('.h')):
                continue
            p = os.path.join(dirpath, fn)
            if path_filter and path_filter not in os.path.relpath(p, ROOT):
                continue
            yield p

def find_defs(text):
    """Return dict name -> count of definitions in this text."""
    defs = {}
    lines = text.split('\n')
    for i, line in enumerate(lines):
        s = line.strip()
        m = re.search(r'\bFUN_([0-9a-fA-F]{8})\b\s*\(', s)
        if not m:
            continue
        name = 'FUN_' + m.group(1)
        if s.startswith('extern') or s.startswith('//') or s.startswith('*'):
            continue
        # skip pure declarations: line ends with ');'
        # definition: ends with '{' on this line, OR next non-empty line is '{',
        # OR ends with ')' (K&R / multiline) without ';'
        tail = s[m.end():]
        # statement terminator before any brace -> declaration
        if ';' in tail and '{' not in tail:
            continue
        if '{' in tail:
            defs[name] = defs.get(name, 0) + 1
            continue
        # look ahead for '{'
        j = i + 1
        decl = False
        while j < len(lines) and j < i + 8:
            nxt = lines[j].strip()
            if not nxt:
                j += 1
                continue
            if nxt.startswith('{') or nxt == '{':
                defs[name] = defs.get(name, 0) + 1
            elif nxt.endswith(';') or nxt.startswith(')') and nxt.endswith(';'):
                decl = True
            else:
                # K&R param decls or continued signature; keep scanning
                j += 1
                continue
            break
        # if we hit ';' it's a decl, ignore
    return defs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--path-filter', default='')
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--referenced', action='store_true', help='list referenced defs')
    ap.add_argument('--files', action='store_true', help='summarize per-file dead counts')
    args = ap.parse_args()

    symbols = load_symbols()

    # Pass 1: find all definitions and all references across ENTIRE src (refs are
    # global; a def in my lane may be called from anywhere).
    file_text = {}
    for p in iter_c_files(''):
        with open(p, 'rb') as f:
            file_text[p] = f.read().decode('utf-8', 'replace')

    # definitions (restricted to path filter for reporting)
    defs = {}  # name -> list of files defining it
    for p in iter_c_files(args.path_filter):
        for name, cnt in find_defs(file_text[p]).items():
            defs.setdefault(name, []).append(p)

    # references: any occurrence of FUN_xxxx that is NOT a definition-head and
    # NOT an extern decl line. Count call sites + address-taken across ALL files.
    # Build per-name reference count by scanning every FUN_ token and excluding
    # the def lines.
    def count_refs(name):
        pat = re.compile(r'\b' + name + r'\b')
        total = 0
        for p, text in file_text.items():
            for ln in text.split('\n'):
                st = ln.strip()
                if not pat.search(st):
                    continue
                # skip extern declarations and definition heads
                if st.startswith('extern'):
                    continue
                # a definition head: name '(' and (ends with { or ) )
                dm = re.search(r'\b' + name + r'\s*\(', st)
                if dm:
                    tail = st[dm.end():]
                    if '{' in tail or (';' not in tail):
                        # likely def head or multiline sig
                        # but a call also matches name( ... ) ; -> that has ';'
                        if ';' not in st and '{' not in tail:
                            # multiline signature of a def -> skip
                            continue
                        if '{' in tail:
                            continue
                # comment line
                if st.startswith('//') or st.startswith('*') or st.startswith('/*'):
                    continue
                total += 1
        return total

    rows = []
    for name in sorted(defs):
        if name in symbols:
            cls = 'IN_SYMBOLS'
            refs = -1
        else:
            refs = count_refs(name)
            cls = 'REFERENCED' if refs > 0 else 'DEAD'
        rows.append((name, cls, refs, defs[name]))

    dead = [r for r in rows if r[1] == 'DEAD']
    refd = [r for r in rows if r[1] == 'REFERENCED']
    insym = [r for r in rows if r[1] == 'IN_SYMBOLS']

    if args.files:
        from collections import Counter
        c = Counter()
        for name, cls, refs, files in dead:
            for fp in files:
                c[os.path.relpath(fp, ROOT)] += 1
        for fp, n in c.most_common():
            print(f"{n:5d}  {fp}")
        print(f"\nTOTAL dead defs: {len(dead)} across {len(c)} files")
        return

    if args.csv:
        print("name,class,refs,file")
        for name, cls, refs, files in rows:
            print(f"{name},{cls},{refs},{os.path.relpath(files[0], ROOT)}")
        return

    if args.referenced:
        for name, cls, refs, files in refd:
            print(f"{name}  refs={refs}  {[os.path.relpath(f,ROOT) for f in files]}")
        print(f"\nREFERENCED defs: {len(refd)}")
        return

    print(f"DEFINITIONS in lane '{args.path_filter or 'ALL'}': {len(rows)}")
    print(f"  DEAD       : {len(dead)}")
    print(f"  REFERENCED : {len(refd)}")
    print(f"  IN_SYMBOLS : {len(insym)}")

if __name__ == '__main__':
    main()
