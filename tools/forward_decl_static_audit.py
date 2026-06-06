#!/usr/bin/env python3
"""Audit redundant forward declarations and dead static definitions (task #171).

Class A -- redundant forward declarations:
  A top-level prototype / extern decl in a .c file whose symbol is ALSO
  declared in a header reachable through the file's #include closure, with a
  CODEGEN-EQUIVALENT signature (extern_audit.py canonicalization, recipes
  #3/#11/#14/#24/#58 aware). Removing such a decl leaves the header decl
  visible at every call site -> byte-identical .o.
  GUARD (recipe #57): when the .c decl and the header decl disagree in
  codegen class, the per-file form is LOAD-BEARING -- never flagged.

Class B -- dead static definitions:
  A `static` function definition with zero references elsewhere in its own
  TU (statics are invisible outside the TU). Sub-classes:
    dead-static-fn        plain static fn, unreferenced. MWCC may still EMIT
                          it; the audit checks the built .o -- candidates
                          whose symbol IS in the .o are flagged `emitted`
                          (removal would change .o bytes -> skip by default).
    dead-static-inline    `static inline` helper, unreferenced. Emits nothing;
                          report-only by default (often intentional API).
  GUARD: address-of / table references count as references (any word-boundary
  occurrence outside the def body counts).

Apply mode mirrors include_audit.py: per file, delete all approved candidate
lines, rebuild just that TU, byte-compare the .o, auto-revert on any change.

Usage:
  python3 tools/forward_decl_static_audit.py --audit [--filter SUBSTR] [--out F.json]
  python3 tools/forward_decl_static_audit.py --apply F.json [--filter SUBSTR] [--classes fwd,static]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extern_audit as EA

INCLUDE_DIRS = ['include', 'build/GSAE01/include']
BUILD_PREFIX = 'build/GSAE01'

STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def _blank_keep_newlines(m):
    return ''.join(c if c == '\n' else ' ' for c in m.group(0))


def strip_comments_strings(text):
    """LENGTH-PRESERVING mask of comments and string/char literals.

    Offsets and line numbers computed on the masked text are valid on the
    raw text (required for span-based removal).
    """
    text = re.sub(r'/\*.*?\*/', _blank_keep_newlines, text, flags=re.S)
    text = re.sub(r'//[^\n]*', _blank_keep_newlines, text)
    text = STRING_RE.sub(lambda m: m.group(0)[0] + ' ' * (len(m.group(0)) - 2)
                         + m.group(0)[0] if len(m.group(0)) >= 2 else m.group(0),
                         text)
    return text


def include_closure(path, memo, text_cache):
    """Set of resolved header paths transitively included by `path`."""
    if path in memo:
        return memo[path]
    memo[path] = set()  # cycle guard
    try:
        text = text_cache.get(path)
        if text is None:
            text = open(path, encoding='utf-8', errors='replace').read()
            text_cache[path] = text
    except OSError:
        return memo[path]
    out = set()
    for m in re.finditer(r'^[ \t]*#[ \t]*include[ \t]+[<"]([^">]+)[">]', text, re.M):
        rel = m.group(1)
        for base in [os.path.dirname(path)] + INCLUDE_DIRS:
            cand = os.path.normpath(os.path.join(base, rel))
            if os.path.isfile(cand):
                if cand not in out:
                    out.add(cand)
                    out |= include_closure(cand, memo, text_cache)
                break
    memo[path] = out
    return out


def header_sigs_for_closure(headers, hdr_decl_cache, text_cache):
    """name -> set of canonical sigs across all headers in the closure."""
    sigs = {}
    where = {}
    for h in headers:
        if h not in hdr_decl_cache:
            try:
                t = text_cache.get(h)
                if t is None:
                    t = open(h, encoding='utf-8', errors='replace').read()
                    text_cache[h] = t
                hdr_decl_cache[h] = EA.collect_header_decls(t)
            except OSError:
                hdr_decl_cache[h] = {}
        for name, s in hdr_decl_cache[h].items():
            sigs.setdefault(name, set()).update(s)
            where.setdefault(name, []).append(h)
    return sigs, where


def find_matching_brace(text, open_idx):
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


PROTO_HEAD_SKIP = re.compile(
    r'^\s*(typedef|#|STATIC_ASSERT|__declspec)\b')


def top_level_statements(text):
    """Yield (start, end, stmt_text, kind) for depth-0 statements.

    kind: 'decl' for `...;` statements, 'def' for `...{...}` blocks.
    Operates on comment/string-stripped text; offsets index into that text.
    """
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ' \t\r\n':
            i += 1
            continue
        if c == '#':  # preprocessor line (handle continuations)
            j = i
            while True:
                j = text.find('\n', j)
                if j == -1:
                    j = n
                    break
                if text[j - 1] == '\\':
                    j += 1
                    continue
                break
            i = j + 1
            continue
        # scan to the first ; or { at depth 0 (parens tracked)
        j = i
        pdepth = 0
        endc = None
        while j < n:
            ch = text[j]
            if ch in '([':
                pdepth += 1
            elif ch in ')]':
                pdepth -= 1
            elif ch == ';' and pdepth == 0:
                endc = ';'
                break
            elif ch == '{' and pdepth == 0:
                endc = '{'
                break
            j += 1
        if endc is None:
            break
        if endc == ';':
            yield (i, j, text[i:j + 1], 'decl')
            i = j + 1
        else:
            close = find_matching_brace(text, j)
            if close == -1:
                break
            # struct/enum/initializer defs end with `;` after `}`
            k = close + 1
            while k < n and text[k] in ' \t\r\n':
                k += 1
            if k < n and text[k] == ';':
                close = k
            yield (i, close, text[i:close + 1], 'def')
            i = close + 1


FN_DEF_HEAD = re.compile(r'^(static\s+)?(inline\s+)?[A-Za-z_][\w \t\*]*?\b(\w+)\s*\(', re.S)


def audit_file(path, memo, hdr_decl_cache, text_cache):
    raw = open(path, encoding='utf-8', errors='replace').read()
    text = strip_comments_strings(raw)
    closure = include_closure(path, memo, text_cache)
    hsigs, hwhere = header_sigs_for_closure(closure, hdr_decl_cache, text_cache)

    fwd_candidates = []
    statics = []
    defined_names = set()
    stmts = list(top_level_statements(text))

    for start, end, stmt, kind in stmts:
        s = ' '.join(stmt.split())
        if kind == 'def':
            head = s.split('{', 1)[0]
            if '(' in head and not PROTO_HEAD_SKIP.match(head) \
                    and not re.match(r'^\s*(struct|union|enum)\b[^(]*$', head) \
                    and '=' not in head.split('(')[0]:
                name = EA.declarator_name(head.rstrip())
                if name:
                    defined_names.add(name)
                    m = re.match(r'^\s*static\b', head)
                    if m:
                        inline = bool(re.search(r'\binline\b', head))
                        statics.append({'name': name, 'start': start,
                                        'end': end, 'inline': inline,
                                        'head': head.strip()[:120]})
            continue
        # decl statement
        if PROTO_HEAD_SKIP.match(s) or s.startswith('static') \
                or '=' in s.split('(')[0]:
            continue
        body = re.sub(r'^extern\s+', '', s.rstrip(';').strip())
        if not body:
            continue
        # function prototypes and extern var decls
        is_proto = '(' in body and not EA.FNPTR_NAME.search(body)
        is_extern_var = s.startswith('extern')
        if not (is_proto or is_extern_var):
            continue
        if is_proto and not re.search(r'\)\s*;?\s*$', s):
            continue
        chunks = [body] if is_proto else EA.split_top_level_commas(body)
        names = []
        for ch in chunks:
            nm = EA.declarator_name(ch)
            if nm and re.match(r'^[A-Za-z_]\w*$', nm) and nm not in EA.KEYWORDS:
                names.append(nm)
        if not names:
            continue
        # only single-declarator statements are auto-removable
        if len(names) != 1:
            continue
        name = names[0]
        if name not in hsigs:
            continue
        csig = EA.canon_signature('extern ' + body, name)
        header_sig_set = hsigs[name]
        if len(header_sig_set) == 1 and csig in header_sig_set:
            line = text.count('\n', 0, start) + 1
            fwd_candidates.append({
                'name': name, 'line': line, 'stmt': s[:160],
                'sig': csig, 'span': [start, end],
                'headers': sorted(set(hwhere.get(name, [])))[:3],
            })

    # dead-static analysis: count refs outside each static's own def span
    # and outside top-level decl statements naming it (its prototypes).
    dead = []
    for st in statics:
        drop_spans = [(st['start'], st['end'])]
        for start, end, stmt, kind in stmts:
            if kind == 'decl' and \
                    re.search(r'\b%s\s*\(' % re.escape(st['name']), stmt) and \
                    '=' not in stmt.split('(')[0]:
                nm = EA.declarator_name(
                    re.sub(r'^\s*(extern|static|inline)\s+', '',
                           ' '.join(stmt.split()).rstrip(';')))
                if nm == st['name']:
                    drop_spans.append((start, end))
        rest = text
        for s0, s1 in sorted(drop_spans, reverse=True):
            rest = rest[:s0] + rest[s1 + 1:]
        nrefs = len(re.findall(r'\b%s\b' % re.escape(st['name']), rest))
        if nrefs == 0:
            line = text.count('\n', 0, st['start']) + 1
            dead.append({'name': st['name'], 'line': line,
                         'inline': st['inline'], 'head': st['head'],
                         'span': [st['start'], st['end']]})

    return fwd_candidates, dead


def o_path_for(cpath):
    return os.path.join(BUILD_PREFIX, os.path.splitext(cpath)[0] + '.o')


def symbol_emitted(opath, name):
    try:
        out = subprocess.run(['objdump', '-t', opath], capture_output=True,
                             text=True, timeout=30).stdout
    except Exception:
        return None
    return bool(re.search(r'\b%s\b' % re.escape(name), out))


def o_hash(opath):
    try:
        # hash the disassembly + relocs, not the raw file (timestamps absent
        # in MWCC .o, but hash raw bytes is fine and strictest)
        return hashlib.md5(open(opath, 'rb').read()).hexdigest()
    except OSError:
        return None


def run_audit(args):
    memo, hdr_cache, text_cache = {}, {}, {}
    report = {}
    files = []
    for dirpath, _, fns in os.walk('src'):
        for fn in sorted(fns):
            if fn.endswith('.c'):
                p = os.path.join(dirpath, fn)
                if args.filter and args.filter not in p:
                    continue
                files.append(p)
    n_fwd = n_dead = 0
    for p in files:
        opath = o_path_for(p)
        if not os.path.isfile(opath):
            continue  # unbuilt TU -- no verification possible, skip
        try:
            fwd, dead = audit_file(p, memo, hdr_cache, text_cache)
        except Exception as e:
            print(f'PARSE-ERROR {p}: {e}', file=sys.stderr)
            continue
        for d in dead:
            if not d['inline']:
                d['emitted'] = symbol_emitted(opath, d['name'])
        if fwd or dead:
            report[p] = {'fwd': fwd, 'dead_static': dead}
            n_fwd += len(fwd)
            n_dead += len(dead)
    print(f'files with candidates: {len(report)}')
    print(f'  redundant forward decls: {n_fwd}')
    print(f'  dead statics: {n_dead}'
          f'  (plain: {sum(1 for v in report.values() for d in v["dead_static"] if not d["inline"])},'
          f' inline: {sum(1 for v in report.values() for d in v["dead_static"] if d["inline"])})')
    if args.out:
        json.dump(report, open(args.out, 'w'), indent=1)
        print(f'wrote {args.out}')
    if not args.out or args.verbose:
        for p in sorted(report, key=lambda x: -len(report[x]['fwd'])):
            v = report[p]
            print(f'\n{p}: {len(v["fwd"])} fwd, {len(v["dead_static"])} dead-static')
            for f in v['fwd'][:int(args.top)]:
                print(f'  fwd  L{f["line"]}: {f["stmt"]}')
            for d in v['dead_static']:
                tag = 'inline' if d['inline'] else ('EMITTED' if d.get('emitted') else 'unemitted')
                print(f'  dead [{tag}] L{d["line"]}: {d["head"]}')
    return report


def spans_to_removal(raw, spans):
    """Delete whole lines covering each (start,end) char span of `raw`.

    Returns the edited text, or None if any covered line carries OTHER code
    outside the span (same-line-code guard).
    """
    masked = strip_comments_strings(raw)
    drop_lines = set()
    for s0, s1 in spans:
        ls = raw.rfind('\n', 0, s0) + 1
        le = raw.find('\n', s1)
        if le == -1:
            le = len(raw)
        outside = masked[ls:s0] + masked[s1 + 1:le]
        if outside.strip():
            return None
        a = raw.count('\n', 0, ls)
        b = raw.count('\n', 0, le)
        drop_lines.update(range(a, b + 1))
    lines = raw.split('\n')
    return '\n'.join(l for i, l in enumerate(lines) if i not in drop_lines)


def run_apply(args):
    report = json.load(open(args.apply))
    classes = set(args.classes.split(','))
    memo, hdr_cache, text_cache = {}, {}, {}
    results = {'ok': [], 'reverted': [], 'skipped': []}
    for p in sorted(report):
        if args.filter and args.filter not in p:
            continue
        v = report[p]
        want_fwd = {(f['name'], f['stmt']) for f in v.get('fwd', [])} \
            if 'fwd' in classes else set()
        want_dead = {d['name'] for d in v.get('dead_static', [])
                     if not d['inline'] and d.get('emitted') is False} \
            if 'static' in classes else set()
        if not want_fwd and not want_dead:
            continue
        opath = o_path_for(p)
        before = o_hash(opath)
        if before is None:
            results['skipped'].append((p, 'no .o'))
            continue
        # re-audit FRESH (file may have drifted since the report was made)
        memo2 = dict(memo)
        try:
            fwd_now, dead_now = audit_file(p, memo2, hdr_cache, text_cache)
        except Exception as e:
            results['skipped'].append((p, f'parse: {e}'))
            continue
        memo.update(memo2)
        fwd = [f for f in fwd_now if (f['name'], f['stmt']) in want_fwd]
        dead = [d for d in dead_now if d['name'] in want_dead
                and not d['inline']]
        if not fwd and not dead:
            results['skipped'].append((p, 'candidates gone after re-audit'))
            continue
        orig = open(p, encoding='utf-8', errors='replace').read()

        def attempt(cands):
            txt = spans_to_removal(orig, [c['span'] for c in cands])
            if txt is None:
                return 'same-line-code'
            open(p, 'w', encoding='utf-8').write(txt)
            r = subprocess.run(['ninja', opath], capture_output=True, text=True)
            if r.returncode != 0:
                return 'build-fail'
            return 'ok' if o_hash(opath) == before else 'bytes-changed'

        all_c = fwd + dead
        verdict = attempt(all_c)
        if verdict == 'ok':
            results['ok'].append((p, len(fwd), len(dead)))
            print(f'OK {p}: -{len(fwd)} fwd, -{len(dead)} static')
            continue
        # greedy fallback: grow the kept set one candidate at a time
        kept = []
        for c in all_c:
            if attempt(kept + [c]) == 'ok':
                kept.append(c)
        verdict2 = attempt(kept) if kept else None
        if kept and verdict2 == 'ok':
            results['ok'].append((p, len(kept), 0))
            print(f'PARTIAL {p}: kept {len(kept)}/{len(all_c)} removals '
                  f'(first verdict: {verdict})')
        else:
            open(p, 'w', encoding='utf-8').write(orig)
            subprocess.run(['ninja', opath], capture_output=True)
            results['reverted'].append(p)
            print(f'REVERTED {p} ({verdict})')
    print(f"\napplied: {len(results['ok'])} files, "
          f"reverted: {len(results['reverted'])}, skipped: {len(results['skipped'])}")
    for p, why in results['skipped']:
        print(f'  skipped {p}: {why}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--audit', action='store_true')
    ap.add_argument('--apply', metavar='REPORT_JSON')
    ap.add_argument('--filter')
    ap.add_argument('--out')
    ap.add_argument('--top', default=10)
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--classes', default='fwd,static',
                    help='comma set: fwd,static')
    args = ap.parse_args()
    if args.audit:
        run_audit(args)
    elif args.apply:
        run_apply(args)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()
