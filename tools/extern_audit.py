#!/usr/bin/env python3
"""Audit extern declarations across src/ and include/.

Enumerates every `extern` declaration in src/**/*.c and every declaration in
include/**/*.h, joins on symbol name, canonicalizes signatures into
codegen-equivalence classes, and reports:

  REAL conflicts      - symbols whose extern decls disagree in a way that
                        CHANGES CODEGEN at call sites (return width/signedness
                        -> clrlwi/cmpwi-vs-cmplwi per recipes #3/#11/#58;
                        narrow vs wide params -> caller-side extsb/extsh;
                        f32 vs f64 params -> fmuls/frsp per recipe #24;
                        arg count -> dead-param register setup per recipe #9).
                        These are recipe #57 territory: the PER-FILE form is
                        load-bearing. Do NOT naively unify; use block-scope
                        extern overrides where consolidation is wanted.
  cosmetic conflicts  - decls that differ only in param names / typedef
                        aliases / pointer-target type. Codegen-identical;
                        safe to unify textually (still byte-verify).
  consistent dups     - same decl repeated across N files (header candidates).
  static candidates   - symbols marked scope:local in symbols.txt but
                        declared extern in src (rare; report-only).

NOTE on "extern decl in the same .c that defines it": that is a benign
forward declaration, NOT a static candidate -- these symbols are placed
globally by name via symbols.txt and must stay global.

Usage:
  python3 tools/extern_audit.py                      # full report
  python3 tools/extern_audit.py --symbol Foo         # one-symbol detail
  python3 tools/extern_audit.py --real-conflicts-only
  python3 tools/extern_audit.py --csv > report.csv
"""
import argparse
import os
import re
import sys
from collections import defaultdict

GHIDRA_PHANTOM = re.compile(
    r'^(DAT_|FUN_|UNK_|PTR_|LAB_|switchD)|^_?_savegpr|^lbl_[0-9a-fA-F]{8}$')

LINE_COMMENT = re.compile(r'//[^\n]*')
BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)


def strip_comments(text):
    return LINE_COMMENT.sub(' ', BLOCK_COMMENT.sub(' ', text))


def split_top_level_commas(s):
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append(''.join(cur))
    return parts


FNPTR_NAME = re.compile(r'\(\s*\*+\s*(\w+)\s*(?:\[[^\]]*\]\s*)*\)\s*\(')
FN_NAME = re.compile(r'(\w+)\s*\(')
VAR_NAME = re.compile(r'(\w+)\s*((?:\[[^\]]*\]\s*)*)$')
KEYWORDS = {'extern', 'static', 'const', 'volatile', 'struct', 'union',
            'enum', 'unsigned', 'signed', 'register', 'void', 'int', 'char',
            'short', 'long', 'float', 'double'}


def declarator_name(decl):
    decl = decl.strip().rstrip(';').strip()
    if not decl:
        return None
    m = FNPTR_NAME.search(decl)
    if m:
        return m.group(1)
    if '(' in decl:
        m = FN_NAME.search(decl)
        return m.group(1) if m else None
    decl = decl.split('=')[0].strip()
    m = VAR_NAME.search(decl)
    return m.group(1) if m else None


def normalize(s):
    return ' '.join(s.split())


# --- codegen-equivalence canonicalization -----------------------------------
# Width/signedness classes that matter for call-site / use-site codegen.
TYPE_CLASS = {
    'void': 'VOID',
    'int': 'S32', 's32': 'S32', 'long': 'S32', 'sint': 'S32', 'BOOL': 'S32',
    'bool32': 'S32', 'int3': 'S32',
    'u32': 'U32', 'uint': 'U32', 'ulong': 'U32', 'unsigned': 'U32',
    'undefined3': 'U32', 'undefined4': 'U32', 'uint3': 'U32', 'size_t': 'U32',
    'u8': 'U8', 'uchar': 'U8', 'byte': 'U8', 'undefined': 'U8',
    'undefined1': 'U8', 'bool': 'U8',
    's8': 'S8', 'sbyte': 'S8', 'char': 'CHAR',
    'u16': 'U16', 'ushort': 'U16', 'undefined2': 'U16', 'wchar16': 'U16',
    's16': 'S16', 'short': 'S16',
    'f32': 'F32', 'float': 'F32',
    'f64': 'F64', 'double': 'F64',
    'u64': 'U64', 'ulonglong': 'U64', 'undefined8': 'U64',
    's64': 'S64', 'longlong': 'S64',
}


def canon_type(t):
    """Map a type string to its codegen class. Any pointer -> PTR."""
    t = t.strip()
    if not t:
        return '?'
    if '*' in t or t.endswith(']') or t == 'code':
        return 'PTR'
    toks = [w for w in re.findall(r'[A-Za-z_]\w*', t)
            if w not in ('const', 'volatile', 'struct', 'union', 'enum',
                         'register', 'signed')]
    if not toks:
        return '?'
    if 'unsigned' in toks:
        rest = [w for w in toks if w != 'unsigned']
        if not rest or rest == ['int'] or rest == ['long']:
            return 'U32'
        if rest == ['char']:
            return 'U8'
        if rest == ['short']:
            return 'U16'
    name = toks[-1]
    # unknown typedef name: assume a struct/typedef passed by value -> AGG,
    # but single-word unknown types used as params are usually pointers in
    # disguise only if '*' present (handled above). Treat as AGG.
    return TYPE_CLASS.get(name, 'AGG:' + name)


def canon_signature(stmt, name):
    """Return a canonical signature string for an extern decl statement."""
    body = re.sub(r'^extern\s+', '', stmt.rstrip(';').strip())
    body = body.replace('[block-scope]', '').strip()
    idx = body.find(name)
    if idx < 0:
        return normalize(body)
    head = body[:idx]
    tail = body[idx + len(name):].strip()
    if FNPTR_NAME.search(body):
        return 'fnptr ' + normalize(body)
    if tail.startswith('('):
        # function: canonical return + param classes
        depth, end = 0, -1
        for i, ch in enumerate(tail):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        params = tail[1:end] if end > 0 else tail[1:]
        plist = []
        p = params.strip()
        if p in ('', 'void'):
            pclasses = ['(unprototyped)'] if p == '' else []
        else:
            pclasses = []
            for chunk in split_top_level_commas(p):
                chunk = chunk.strip()
                if chunk == '...':
                    pclasses.append('...')
                    continue
                # drop the param name (last identifier not part of type when
                # followed by nothing / [ )
                if '(' in chunk:  # fn-ptr param
                    pclasses.append('PTR')
                    continue
                m = VAR_NAME.search(chunk.split('=')[0].strip())
                tname = chunk
                if m and (m.group(2) or True):
                    cand = m.group(1)
                    rest = chunk[:m.start(1)].strip()
                    if rest and cand not in KEYWORDS:
                        tname = rest + (' []' if m.group(2) else '')
                pclasses.append(canon_type(tname))
        ret = canon_type(head)
        return 'fn %s (%s)' % (ret, ', '.join(pclasses))
    else:
        arr = ''
        if tail.startswith('['):
            arr = '[]' if re.match(r'\[\s*\]', tail) else '[N]'
        return 'var %s %s' % (canon_type(head + (' *' if head.strip().endswith('*') else '')), arr)


def collect_extern_decls(text):
    text = strip_comments(text)
    out = []
    for m in re.finditer(r'^([ \t]*)extern\b', text, re.M):
        start = m.start()
        top = m.group(1) == ''
        semi = text.find(';', start)
        brace = text.find('{', start)
        if semi == -1 or (brace != -1 and brace < semi):
            continue
        stmt = normalize(text[start:semi])
        line_no = text.count('\n', 0, start) + 1
        body = re.sub(r'^extern\s+', '', stmt)
        if '(' in body and not FNPTR_NAME.search(body):
            chunks = [body]
        else:
            chunks = split_top_level_commas(body)
        for ch in chunks:
            name = declarator_name(ch)
            if name and re.match(r'^[A-Za-z_]\w*$', name) and name not in KEYWORDS:
                out.append((name, stmt, line_no, top))
    return out


def collect_header_decls(text):
    """name -> set of canonical sigs declared in this header text."""
    text = strip_comments(text)
    found = {}
    for m in re.finditer(r'^[ \t]*(extern\b[^;{]*);', text, re.M):
        stmt = normalize(m.group(1))
        name = declarator_name(re.sub(r'^extern\s+', '', stmt))
        if name:
            found.setdefault(name, set()).add(canon_signature(stmt, name))
    for m in re.finditer(r'^[ \t]*((?:[A-Za-z_][\w \t\*]*?)\b\w+\s*\([^;{)]*\))\s*;', text, re.M):
        stmt = 'extern ' + normalize(m.group(1))
        name = declarator_name(re.sub(r'^extern\s+', '', stmt))
        if name:
            found.setdefault(name, set()).add(canon_signature(stmt, name))
    return found


def load_symbol_scopes(path):
    scopes = {}
    if not os.path.exists(path):
        return scopes
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'^(\w+)\s*=', line)
        if m:
            scopes[m.group(1)] = 'local' if 'scope:local' in line else 'global'
    return scopes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--src', default='src')
    ap.add_argument('--include', default='include')
    ap.add_argument('--symbols-txt', default='config/GSAE01/symbols.txt')
    ap.add_argument('--min-files', type=int, default=2)
    ap.add_argument('--symbol')
    ap.add_argument('--real-conflicts-only', action='store_true')
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--include-phantoms', action='store_true')
    ap.add_argument('--top', type=int, default=60)
    args = ap.parse_args()

    decls = defaultdict(list)  # name -> [(file, stmt, line, top)]
    for dirpath, _, files in os.walk(os.path.join(args.root, args.src)):
        for fn in sorted(files):
            if not fn.endswith('.c'):
                continue
            p = os.path.join(dirpath, fn)
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for name, stmt, line, top in collect_extern_decls(text):
                decls[name].append((p, stmt, line, top))

    header_decls = defaultdict(set)  # name -> set of canonical sigs
    header_where = defaultdict(list)
    for dirpath, _, files in os.walk(os.path.join(args.root, args.include)):
        for fn in sorted(files):
            if not fn.endswith('.h'):
                continue
            p = os.path.join(dirpath, fn)
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for name, sigs in collect_header_decls(text).items():
                header_decls[name] |= sigs
                header_where[name].append(p)

    scopes = load_symbol_scopes(os.path.join(args.root, args.symbols_txt))

    if args.symbol:
        s = args.symbol
        print(f'== {s} ==')
        print(f'symbols.txt scope: {scopes.get(s, "(absent)")}')
        for h in header_where.get(s, []):
            print(f'  header: {h}  sigs: {sorted(header_decls[s])}')
        by_sig = defaultdict(list)
        for p, stmt, line, top in decls.get(s, []):
            by_sig[canon_signature(stmt, s)].append((p, stmt, line, top))
        for sig, lst in sorted(by_sig.items()):
            print(f'  [{sig}]')
            for p, stmt, line, top in lst:
                bs = '' if top else ' [block-scope]'
                print(f'    {p}:{line}: {stmt}{bs}')
        return

    is_phantom = lambda n: GHIDRA_PHANTOM.search(n) is not None

    real_conf, cosmetic_conf, dup = [], [], []
    for name, lst in decls.items():
        if not args.include_phantoms and is_phantom(name):
            continue
        # block-scope decls are deliberate (recipe #57) -- exclude from
        # conflict math but note their presence
        top_lst = [(p, s, l) for p, s, l, top in lst if top]
        n_block = len(lst) - len(top_lst)
        files = sorted({p for p, _, _ in top_lst})
        if len(files) < args.min_files:
            continue
        sigs = defaultdict(set)
        for p, stmt, _ in top_lst:
            sigs[canon_signature(stmt, name)].add(p)
        texts = sorted({normalize(s) for _, s, _ in top_lst})
        in_header = name in header_decls
        row = (name, files, sorted(sigs), texts, in_header, n_block)
        if len(sigs) > 1:
            real_conf.append(row)
        elif len(texts) > 1:
            cosmetic_conf.append(row)
        else:
            dup.append(row)

    real_conf.sort(key=lambda r: (-len(r[2]), -len(r[1])))
    cosmetic_conf.sort(key=lambda r: -len(r[1]))
    dup.sort(key=lambda r: -len(r[1]))

    if args.csv:
        import csv
        w = csv.writer(sys.stdout)
        w.writerow(['class', 'symbol', 'n_files', 'n_canon_sigs',
                    'in_header', 'n_block_scope', 'canon_sigs'])
        for cls, rows in (('real-conflict', real_conf),
                          ('cosmetic-conflict', cosmetic_conf),
                          ('dup', dup)):
            for name, files, sigs, texts, ih, nb in rows:
                w.writerow([cls, name, len(files), len(sigs), ih, nb,
                            ' || '.join(sigs)])
        return

    n_syms = sum(1 for n in decls if args.include_phantoms or not is_phantom(n))
    n_ph = sum(1 for n in decls if is_phantom(n))
    print(f'extern symbols (non-phantom): {n_syms}   ghidra phantoms excluded: {n_ph}')
    print(f'declared in >= {args.min_files} files: {len(real_conf) + len(cosmetic_conf) + len(dup)}')
    print(f'  REAL codegen conflicts: {len(real_conf)}')
    print(f'  cosmetic-only variants: {len(cosmetic_conf)}')
    print(f'  fully consistent dups:  {len(dup)}')
    print()

    print(f'=== REAL CONFLICTS (codegen-relevant; recipe #57 -- DO NOT naively unify) === top {args.top}')
    for name, files, sigs, texts, ih, nb in real_conf[:args.top]:
        hdr = ' [IN-HEADER]' if ih else ''
        bs = f' [+{nb} block-scope]' if nb else ''
        print(f'{name}  ({len(files)} files, {len(sigs)} codegen classes){hdr}{bs}')
        for s in sigs:
            print(f'    {s}')
    print()

    if args.real_conflicts_only:
        return

    print(f'=== COSMETIC-ONLY VARIANTS (codegen-identical; textual unify is safe) === top {args.top}')
    for name, files, sigs, texts, ih, nb in cosmetic_conf[:args.top]:
        hdr = ' [IN-HEADER]' if ih else ''
        print(f'{len(files):4d} files  {name}{hdr}    [{sigs[0]}]')
    print()

    print(f'=== CONSISTENT DUPLICATES (header-consolidation candidates) === top {args.top}')
    for name, files, sigs, texts, ih, nb in dup[:args.top]:
        hdr = ' [ALREADY-IN-HEADER]' if ih else ''
        print(f'{len(files):4d} files  {name}{hdr}    {texts[0]}')
    print()

    print('=== STATIC CANDIDATES (scope:local in symbols.txt, extern in src) ===')
    count = 0
    for name, lst in sorted(decls.items()):
        if scopes.get(name) != 'local':
            continue
        if not args.include_phantoms and is_phantom(name):
            continue
        for p, stmt, line, top in lst:
            print(f'  {p}:{line}: {stmt}')
            count += 1
    if count == 0:
        print('  (none -- every extern-declared symbol is global in symbols.txt)')
    print()
    print('NOTE: same-file `extern` forward decls of globally-placed symbols are')
    print('benign and must NOT be made static (symbols place by name via symbols.txt).')


if __name__ == '__main__':
    main()
