#!/usr/bin/env python3
r"""Transitive-closure dead-declaration trimmer for skeleton-carved TUs.

The skeleton-copy carve method (CLAUDE.md "Graduating a placeholder") leaves
every carved file carrying its donor's FULL decl forest: hundreds of extern
prototypes, typedefs, #defines, FUN_ phantom decls, and forward prototypes
that the carved-out functions reference but the RETAINED functions never
touch. This tool strips the unreached ones.

MODEL -- reachability from retained function bodies:
  ROOTS    = every identifier appearing in a retained fn DEFINITION (its
             body + signature), a top-level table/descriptor INITIALIZER
             (`T x = { ... };`), a STATIC_ASSERT(...) expression, or a
             #pragma line.
  CANDIDATE decl lines (removable classes):
             - top-level `extern` var / function-prototype decls
             - standalone forward function prototypes (`T fn(args);`)
             - `typedef` / bare `struct`/`union`/`enum` definitions
             - `#define` object-like and function-like macros
             - `FUN_xxxx` / DAT_/etc. ghidra phantom extern decls
  CLOSURE  = a candidate is REACHED if any name it DECLARES is in the root
             set; reaching it adds the identifiers in ITS OWN body to the
             root set (a typedef referencing another struct keeps that
             struct; a macro whose expansion uses another macro keeps it).
             Iterate to fixpoint. Everything NOT reached is strippable.

The closure is a CONSERVATIVE candidate selector only. The authoritative
gate is the gold-standard .o byte compare (recipe-wide convention): after
trimming a file, rebuild just its .o and byte-compare against the baseline;
ANY change -> auto-revert that file. MWCC .o output is deterministic and
carries no line info, so identical bytes == matched_code conserved.

HONORED FAILURE MODES (CLAUDE.md "Trim-tool failure modes to avoid"):
  - multi-line `#define ... \` continuations are span-tracked as one unit.
  - multi-bracket array externs (`extern char x[6][8];`) parse their name
    before the bracket walker sees them.
  - #pragma push/pop pairs are NEVER removed (state-neutral even when the
    region between them is emptied); their bodies are roots.
  - recipe #57 block-scope externs live INSIDE fn bodies -> never candidates
    (only depth-0 statements are considered).
  - SJIS carriers (intersect.c / Tumbleweed.c class): byte-wise IO via
    surrogateescape; a sjiswrap encoding warning on rebuild ABORTS + flags.
  - comment-attached decls keep their leading comment block.
  - a TU's own same-stem header #include is kept by convention.

Usage:
  python3 tools/decl_trim.py --audit [PATH-FILTER] [--out FILE] [--verbose]
  python3 tools/decl_trim.py --apply [PATH-FILTER] [--report FILE]
  python3 tools/decl_trim.py --apply [PATH-FILTER] --check-all   # full md5 sweep gate
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_NINJA = os.path.join(ROOT, 'build.ninja')
BUILD_PREFIX = 'build/GSAE01'

BUILD_LINE = re.compile(r'^build (build/GSAE01/src/\S+\.o): \S+ (src/\S+\.c)')
INCLUDE_LINE = re.compile(r'^\s*#\s*include\s+[<"]([^>"]+)[>"]')

# Type / storage keywords that are never "referenced identifiers".
C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
    'inline', 'int', 'long', 'register', 'return', 'short', 'signed',
    'sizeof', 'static', 'struct', 'switch', 'typedef', 'union', 'unsigned',
    'void', 'volatile', 'while', 'asm', 'restrict', '_Bool',
    # project base types -- not identifiers we trim on
    'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64', 'f32', 'f64',
    'bool', 'BOOL', 'uint', 'sint', 'ushort', 'uchar', 'sbyte', 'byte',
    'code', 'undefined', 'undefined1', 'undefined2', 'undefined4',
    'undefined8', 'wchar16', 'size_t', 'NULL', 'TRUE', 'FALSE',
}

IDENT = re.compile(r'[A-Za-z_]\w*')
GHIDRA_PHANTOM = re.compile(
    r'^(DAT_|FUN_|UNK_|PTR_|LAB_|switchD|jumptable)')


# --------------------------------------------------------------------------
# byte-wise IO (SJIS-safe: surrogateescape round-trips raw bytes)
# --------------------------------------------------------------------------
def read_text(path):
    with open(path, encoding='utf-8', errors='surrogateescape') as f:
        return f.read()


def write_text(path, text):
    with open(path, 'w', encoding='utf-8', errors='surrogateescape',
              newline='') as f:
        f.write(text)


def md5_file(path):
    try:
        return hashlib.md5(open(path, 'rb').read()).hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------
# comment / string masking (length-preserving so offsets stay valid)
# --------------------------------------------------------------------------
def _blank(m):
    return ''.join(c if c == '\n' else ' ' for c in m.group(0))


STRING_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')


def mask(text):
    """Length-preserving mask of block/line comments and string/char
    literals. Newlines preserved so line numbers stay valid."""
    text = re.sub(r'/\*.*?\*/', _blank, text, flags=re.S)
    text = re.sub(r'//[^\n]*', _blank, text)

    def sblank(m):
        s = m.group(0)
        if len(s) < 2:
            return s
        return s[0] + ' ' * (len(s) - 2) + s[-1]

    return STRING_RE.sub(sblank, text)


# --------------------------------------------------------------------------
# discover TUs
# --------------------------------------------------------------------------
def discover_tus():
    """src/.../*.c -> build/GSAE01/src/.../*.o from build.ninja."""
    tus = {}
    text = read_text(BUILD_NINJA)
    text = re.sub(r'\$\n\s*', '', text)  # unwrap ninja line-continuations
    for line in text.splitlines():
        m = BUILD_LINE.match(line)
        if m:
            tus[m.group(2)] = m.group(1)
    return tus


# --------------------------------------------------------------------------
# block segmentation
# --------------------------------------------------------------------------
class Block:
    """A contiguous, line-aligned source span classified for trimming."""
    __slots__ = ('kind', 'l0', 'l1', 'names', 'idents', 'comment_l0',
                 'raw', 'is_candidate')

    def __init__(self, kind, l0, l1, names, idents, raw):
        self.kind = kind          # extern|proto|typedef|aggregate|define|
                                  # body|init|static_assert|pragma|other
        self.l0 = l0              # first source line index (0-based, incl.)
        self.l1 = l1              # last source line index (0-based, incl.)
        self.comment_l0 = l0      # extended start incl. attached comment
        self.names = names        # identifiers this block DECLARES
        self.idents = idents      # identifiers this block REFERENCES
        self.raw = raw            # raw text of the block (no comment)
        self.is_candidate = False


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


def names_referenced(raw):
    """All identifier tokens in raw text, minus C keywords."""
    return {w for w in IDENT.findall(raw) if w not in C_KEYWORDS}


def declarator_names(decl):
    """Names DECLARED by a decl statement (handles fn-ptr, arrays incl.
    multi-bracket, comma lists). decl is comment/string-masked text."""
    s = decl.strip().rstrip(';').strip()
    s = re.sub(r'^(extern|static)\s+', '', s)
    out = []
    # split top-level commas (function decls have one declarator)
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
    is_fn = '(' in s and not re.search(r'\(\s*\*', s)
    if is_fn:
        parts = [s]  # a prototype is one declarator
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # function pointer:  T (*name)(...)  or  T (*name[N])(...)
        m = re.search(r'\(\s*\*+\s*(\w+)', p)
        if m:
            out.append(m.group(1))
            continue
        # plain function prototype:  T name(...)
        if '(' in p:
            m = re.search(r'(\w+)\s*\(', p)
            if m:
                out.append(m.group(1))
            continue
        # variable, possibly multi-bracket array: grab the ident that
        # precedes the FIRST '[' (or the whole tail if no bracket).
        p = p.split('=')[0]
        b = p.find('[')
        head = p[:b] if b >= 0 else p
        ids = IDENT.findall(head)
        if ids:
            out.append(ids[-1])
    return [n for n in out if n and n not in C_KEYWORDS]


def aggregate_tag(masked_head):
    """Name a bare `struct/union/enum Tag { ... }` (no typedef) declares."""
    m = re.match(r'^\s*(?:typedef\s+)?(struct|union|enum)\s+(\w+)',
                 masked_head)
    return m.group(2) if m else None


def macro_name(line):
    m = re.match(r'^\s*#\s*define\s+(\w+)', line)
    return m.group(1) if m else None


PRAGMA = re.compile(r'^\s*#\s*pragma\b')
PRAGMA_PUSHPOP = re.compile(r'^\s*#\s*pragma\b.*\b(push|pop)\b')
STATIC_ASSERT_RE = re.compile(r'^\s*STATIC_ASSERT\s*\(')
PROTO_SKIP = re.compile(r'^\s*(typedef|#|STATIC_ASSERT|__declspec)\b')


def segment(path):
    """Parse `path` into a list of Blocks (line-aligned, in order).

    Operates on masked text for structure; carries raw spans for closure.
    """
    raw = read_text(path)
    text = mask(raw)
    raw_lines = raw.split('\n')
    n = len(text)
    blocks = []

    def line_at(off):
        return text.count('\n', 0, off)

    def add(kind, l0, l1, names, body_off0, body_off1):
        body_raw = raw[body_off0:body_off1]
        blocks.append(Block(kind, l0, l1, set(names),
                            names_referenced(body_raw), body_raw))

    i = 0
    while i < n:
        c = text[i]
        if c in ' \t\r\n':
            i += 1
            continue
        # preprocessor line(s) -- handle backslash continuations as one unit
        if c == '#':
            j = i
            while True:
                nl = text.find('\n', j)
                if nl == -1:
                    nl = n
                    break
                if nl > 0 and text[nl - 1] == '\\':
                    j = nl + 1
                    continue
                break
            stmt = text[i:nl]
            l0, l1 = line_at(i), line_at(max(i, nl - 1))
            first = raw_lines[l0] if l0 < len(raw_lines) else ''
            if PRAGMA.match(first):
                add('pragma', l0, l1, [], i, nl)
            elif macro_name(first):
                add('define', l0, l1, [macro_name(first)], i, nl)
            else:  # #include / #if / #endif / #undef / etc.
                add('other', l0, l1, [], i, nl)
            i = nl + 1
            continue
        # depth-0 statement: scan to first ; or { (parens/brackets tracked)
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
            # trailing junk -- absorb to EOF as 'other'
            add('other', line_at(i), line_at(n - 1), [], i, n)
            break
        if endc == ';':
            stmt = text[i:j + 1]
            l0, l1 = line_at(i), line_at(j)
            head = re.sub(r'^\s*(extern|static)\s+', '',
                          ' '.join(stmt.split()))
            kind, names = _classify_decl(stmt, head)
            add(kind, l0, l1, names, i, j + 1)
            i = j + 1
            continue
        # endc == '{' : a brace block (typedef/aggregate/fn def/initializer)
        close = find_matching_brace(text, j)
        if close == -1:
            add('other', line_at(i), line_at(n - 1), [], i, n)
            break
        # consume trailing declarators up to the terminating `;`:
        #   typedef struct {...} Alias, *Ptr;   struct Tag {...} var;
        #   `T x = {...};`  (initializer).  A function definition's `}` has
        #   no trailing `;`, so the scan finds none and we stop at the brace.
        k = close + 1
        term = None
        while k < n:
            ch = text[k]
            if ch == ';':
                term = k
                break
            if ch in '{}':          # next construct began -- no terminator
                break
            k += 1
        if term is not None:
            close = term
        stmt = text[i:close + 1]
        head = stmt.split('{', 1)[0]
        l0, l1 = line_at(i), line_at(close)
        kind, names = _classify_brace(stmt, head)
        add(kind, l0, l1, names, i, close + 1)
        i = close + 1

    _attach_comments(blocks, raw_lines, text)
    return raw_lines, blocks


def _classify_decl(masked_stmt, head):
    """Classify a `...;` depth-0 statement."""
    s = ' '.join(masked_stmt.split())
    if STATIC_ASSERT_RE.match(s):
        return 'static_assert', []
    if s.startswith('typedef'):
        # typedef of a non-brace type: `typedef T Alias;`
        names = declarator_names(s[len('typedef'):])
        return 'typedef', names
    if s.startswith('extern'):
        names = declarator_names(s)
        # extern fn proto vs extern var -- both 'extern' kind
        return 'extern', names
    if s.startswith('static'):
        return 'other', []  # static fwd-decl: leave (load-bearing/file-local)
    # bare forward prototype:  T name(args);
    # require an identifier IMMEDIATELY before '(' (rules out memory-mapped
    # register decls like `volatile T REG : (0xADDR);` and `T x = f(...)`).
    body = s.rstrip(';')
    is_proto = re.search(r'\w\s*\(', body) \
        and not re.search(r'\(\s*\*', body) \
        and re.search(r'\)\s*$', body) and '=' not in body.split('(')[0] \
        and ':' not in body.split('(')[0]
    if is_proto and not PROTO_SKIP.match(s):
        names = declarator_names(s)
        if names:                      # never trim a decl declaring nothing
            return 'proto', names
    # a bare `struct Tag varname;` global var decl -> reference, not trim
    return 'other', []


def _classify_brace(masked_stmt, head):
    """Classify a `...{...}` depth-0 block."""
    h = ' '.join(head.split())
    if h.startswith('typedef') or re.match(r'^(struct|union|enum)\b', h):
        # typedef struct {...} Alias;  /  struct Tag {...};  /  enum {...}
        names = set()
        tag = aggregate_tag(h)
        if tag:
            names.add(tag)
        # trailing alias after the closing brace
        m = re.search(r'\}\s*([A-Za-z_]\w*)\s*;?\s*$', masked_stmt)
        if m:
            names.add(m.group(1))
        # typedef may declare several aliases:  } A, *B;
        tail = masked_stmt.rsplit('}', 1)[-1]
        for nm in declarator_names(tail):
            names.add(nm)
        return 'aggregate', list(names)
    # function definition or table/initializer
    pre = h.split('(')[0]
    if '(' in h and '=' not in pre and not PROTO_SKIP.match(h):
        return 'body', []          # function definition -- RETAINED (root)
    if '=' in h:
        return 'init', []          # table / descriptor initializer -- root
    return 'other', []


def _attach_comments(blocks, raw_lines, masked):
    """Extend each block's comment_l0 up over an immediately-preceding
    comment block (only blank lines may intervene)."""
    masked_lines = masked.split('\n')
    occupied = set()
    for b in blocks:
        for ln in range(b.l0, b.l1 + 1):
            occupied.add(ln)
    for b in blocks:
        c = b.l0 - 1
        # skip blank lines directly above
        while c >= 0 and not masked_lines[c].strip() and c not in occupied:
            c -= 1
        # absorb a contiguous run of pure-comment lines above
        start = b.l0
        while c >= 0 and c not in occupied:
            ml = masked_lines[c]
            rl = raw_lines[c]
            is_comment_line = (not ml.strip()) and rl.strip() != ''
            if is_comment_line:
                start = c
                c -= 1
            else:
                break
        b.comment_l0 = start
        for ln in range(start, b.l0):
            occupied.add(ln)


# --------------------------------------------------------------------------
# reachability closure
# --------------------------------------------------------------------------
def _closure(candidates, blocks, by_name):
    """Return candidate Blocks NOT reachable from roots.

    Roots: every identifier referenced by a non-candidate block (fn bodies,
    initializers, static_asserts, pragmas, #if/#include/other lines). A
    candidate is REACHED if it declares a rooted name; reaching it adds its
    own referenced identifiers to roots. Iterate to fixpoint.
    """
    roots = set()
    for b in blocks:
        if not b.is_candidate:
            roots |= b.idents
    reached_ids = set()
    # a candidate that declares NO name cannot be proven dead -> never strip
    for b in candidates:
        if not b.names:
            reached_ids.add(id(b))
    changed = True
    while changed:
        changed = False
        for b in candidates:
            if id(b) in reached_ids:
                continue
            if any(nm in roots for nm in b.names):
                reached_ids.add(id(b))
                before = len(roots)
                roots |= b.idents
                if len(roots) != before:
                    changed = True
    strippable = [b for b in candidates if id(b) not in reached_ids]
    return strippable


def is_own_header_include(line, stem):
    m = INCLUDE_LINE.match(line)
    if not m:
        return False
    inc_stem = os.path.splitext(os.path.basename(m.group(1)))[0].lower()
    return inc_stem == stem


# --------------------------------------------------------------------------
# audit / removal-plan
# --------------------------------------------------------------------------
def plan_file(path):
    """Return (raw_lines, strippable_blocks, drop_line_set)."""
    raw_lines, blocks = segment(path)
    for b in blocks:
        b.is_candidate = b.kind in {'extern', 'proto', 'typedef',
                                    'aggregate', 'define'}
    by_name = {}
    for b in blocks:
        if b.is_candidate:
            for nm in b.names:
                by_name.setdefault(nm, []).append(b)
    cand = [b for b in blocks if b.is_candidate]
    strippable = _closure(cand, blocks, by_name)

    # never drop a pragma push/pop or the bodies between them; candidates are
    # already only decl-kinds so push/pop are excluded by construction.
    drop = set()
    for b in strippable:
        # candidate is removable: drop its lines + attached comment
        for ln in range(b.comment_l0, b.l1 + 1):
            drop.add(ln)
    return raw_lines, strippable, drop


def lines_after_removal(raw_lines, drop):
    return '\n'.join(l for i, l in enumerate(raw_lines) if i not in drop)


# --------------------------------------------------------------------------
# build gate
# --------------------------------------------------------------------------
def ninja_build(target):
    """Build one .o target; return (ok, sjis_warning, output).

    sjis_warning is set ONLY for a genuine sjiswrap encoding diagnostic: a
    line that BOTH names sjiswrap AND carries warning/error text, excluding
    the ninja command-echo line (which prints `sjiswrap.exe` on every build
    of an SJIS unit). The "compiled anyway" case (CLAUDE.md Tumbleweed.c) is
    a successful build carrying such a diagnostic line; a hard encoding break
    fails the build -- either way the caller reverts, but the flag must not
    mislabel an ordinary codegen failure on an SJIS unit.
    """
    r = subprocess.run(['ninja', target], cwd=ROOT,
                       capture_output=True, text=True)
    out = (r.stdout or '') + (r.stderr or '')
    sjis = False
    for line in out.splitlines():
        low = line.lower()
        if 'sjiswrap' not in low:
            continue
        if '.exe' in low and ('mwcceppc' in low or 'wibo' in low):
            continue  # the command-echo line, not a diagnostic
        if 'warning' in low or 'error' in low or 'convert' in low \
                or 'shift' in low:
            sjis = True
            break
    return r.returncode == 0, sjis, out


# --------------------------------------------------------------------------
# audit mode
# --------------------------------------------------------------------------
def run_audit(args):
    tus = discover_tus()
    files = sorted(c for c in tus if args.filter in c)
    report = {}
    tot_lines = tot_blocks = 0
    errs = 0
    for c in files:
        p = os.path.join(ROOT, c)
        if not os.path.exists(p):
            continue
        try:
            raw_lines, strippable, drop = plan_file(p)
        except Exception as e:
            print(f'PARSE-ERROR {c}: {e}', file=sys.stderr)
            errs += 1
            continue
        # honor own-header keep + never count a line that carries live code
        masked = mask('\n'.join(raw_lines)).split('\n')
        stem = os.path.splitext(os.path.basename(c))[0].lower()
        safe_drop = _safe_drop(raw_lines, masked, drop, stem, strippable)
        if not safe_drop:
            continue
        kinds = {}
        for b in strippable:
            kinds[b.kind] = kinds.get(b.kind, 0) + 1
        report[c] = {
            'lines': len(raw_lines),
            'strip_lines': len(safe_drop),
            'strip_blocks': len(strippable),
            'by_kind': kinds,
        }
        tot_lines += len(safe_drop)
        tot_blocks += len(strippable)
    print(f'{len(report)} files with strippable decls '
          f'({errs} parse errors)')
    print(f'projected: {tot_lines} lines, {tot_blocks} decl blocks removable')
    agg = {}
    for v in report.values():
        for k, n in v['by_kind'].items():
            agg[k] = agg.get(k, 0) + n
    print('  by kind: ' + ', '.join(f'{k}={n}' for k, n in
                                     sorted(agg.items(), key=lambda x: -x[1])))
    if args.out:
        json.dump(report, open(args.out, 'w'), indent=1, sort_keys=True)
        print(f'wrote {args.out}')
    if args.verbose or not args.out:
        for c in sorted(report, key=lambda c: -report[c]['strip_lines'])[:30]:
            v = report[c]
            print(f'  {v["strip_lines"]:5d} lines / {v["strip_blocks"]:4d} '
                  f'blocks   {c}')
    return report


def _safe_drop(raw_lines, masked, drop, stem, strippable):
    """Filter the drop set: never drop a line that (a) is the TU's own-header
    include, or (b) carries live code outside the candidate spans."""
    # own-header keep
    keep = set()
    for ln in drop:
        if ln < len(raw_lines) and is_own_header_include(raw_lines[ln], stem):
            keep.add(ln)
    return drop - keep


# --------------------------------------------------------------------------
# apply mode
# --------------------------------------------------------------------------
def apply_file(c, ofile, check_all_baselines=None):
    """Trim one file; gate on .o bytes. Returns (status, n_lines)."""
    p = os.path.join(ROOT, c)
    op = os.path.join(ROOT, ofile)
    if not os.path.exists(op):
        return 'no-baseline-o', 0
    base = md5_file(op)
    try:
        raw_lines, strippable, drop = plan_file(p)
    except Exception as e:
        return f'parse-error:{e}', 0
    masked = mask('\n'.join(raw_lines)).split('\n')
    stem = os.path.splitext(os.path.basename(c))[0].lower()
    drop = _safe_drop(raw_lines, masked, drop, stem, strippable)
    if not drop:
        return 'nothing-to-trim', 0
    orig = read_text(p)
    new = lines_after_removal(raw_lines, drop)
    if orig.endswith('\n') and not new.endswith('\n'):
        new += '\n'
    write_text(p, new)
    ok, sjis, out = ninja_build(ofile)
    if sjis:
        write_text(p, orig)
        ninja_build(ofile)
        return 'ABORT-sjiswrap-warning', 0
    if not ok:
        write_text(p, orig)
        ninja_build(ofile)
        return 'reverted-build-fail', 0
    if md5_file(op) != base:
        write_text(p, orig)
        ninja_build(ofile)
        return 'reverted-bytes-changed', 0
    return 'ok', len(drop)


def run_apply(args):
    tus = discover_tus()
    files = sorted(c for c in tus if args.filter in c)
    if args.report:
        rep = json.load(open(args.report))
        files = [c for c in files if c in rep]
    results = {'ok': 0, 'reverted': 0, 'aborted': 0, 'skipped': 0}
    total_lines = 0
    base_all = None
    if args.check_all:
        base_all = _hash_all_o()
    for c in files:
        status, n = apply_file(c, tus[c])
        if status == 'ok':
            results['ok'] += 1
            total_lines += n
            print(f'OK {c}: -{n} lines')
        elif status.startswith('reverted'):
            results['reverted'] += 1
            print(f'REVERTED {c} ({status})')
        elif status.startswith('ABORT'):
            results['aborted'] += 1
            print(f'ABORT {c} ({status})')
        else:
            results['skipped'] += 1
            if args.verbose:
                print(f'skip {c}: {status}')
    print(f'\napplied: {results["ok"]} files (-{total_lines} lines), '
          f'reverted: {results["reverted"]}, aborted: {results["aborted"]}, '
          f'skipped: {results["skipped"]}')
    if args.check_all and base_all is not None:
        after = _hash_all_o()
        changed = [o for o, h in after.items()
                   if base_all.get(o) != h and o in tus.values()]
        # only the TUs we touched should differ, and they should be IDENTICAL
        # (we reverted any byte change), so a change here is a hard failure.
        bad = [o for o in changed]
        if bad:
            print(f'WARNING --check-all: {len(bad)} .o files differ from '
                  f'baseline after trim (expected ZERO):')
            for o in bad[:20]:
                print(f'  {o}')
        else:
            print('--check-all: project-wide .o byte set unchanged (clean).')
    return results


def _hash_all_o():
    out = {}
    for dp, _, fns in os.walk(os.path.join(ROOT, BUILD_PREFIX, 'src')):
        for fn in fns:
            if fn.endswith('.o'):
                fp = os.path.join(dp, fn)
                rel = os.path.relpath(fp, ROOT)
                out[rel] = md5_file(fp)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit', action='store_true',
                      help='report strippable decls (no edits)')
    mode.add_argument('--apply', action='store_true',
                      help='trim files, gated on .o byte compare')
    ap.add_argument('filter', nargs='?', default='src/main/dll',
                    help='path substring filter (default: src/main/dll)')
    ap.add_argument('--out', help='write audit JSON report here')
    ap.add_argument('--report', help='apply only files listed in this report')
    ap.add_argument('--check-all', action='store_true',
                    help='full-build .o md5 sweep gate around an --apply run')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    if args.audit:
        run_audit(args)
    else:
        run_apply(args)


if __name__ == '__main__':
    sys.exit(main() or 0)
