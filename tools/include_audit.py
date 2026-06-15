#!/usr/bin/env python3
"""Empirically detect unused #include directives (task #168).

For each compiled TU, blank out one top-level #include at a time, rebuild
just that TU, and compare the .o bytes against the baseline build:

  build fails          -> include NEEDED (provides decls/typedefs)
  .o bytes change      -> include affects codegen (macros etc.) -> NEEDED
  .o bytes identical   -> include UNUSED (confirmed removable)

The .o byte hash is the gold standard: MWCC output is deterministic and
carries no line-number info, so identical bytes == identical codegen ==
matched_code conserved.

Candidates are batched across files (one include per file per round) so a
single parallel ninja invocation tests many files at once. Within a file,
includes are tested independently in reverse order; note that two includes
individually removable may not be jointly removable (one masking the other),
so --apply re-verifies the combined removal per file and falls back greedily.

Usage:
  python3 tools/include_audit.py --audit [--filter src/main] [--out FILE]
  python3 tools/include_audit.py --apply REPORT.json [--filter SUBSTR]
  python3 tools/include_audit.py --apply REPORT.json --dry-run
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
NINJA_CHUNK = 1500

BUILD_LINE = re.compile(r'^build (build/GSAE01/src/\S+\.o): \S+ (src/\S+\.c)')
INCLUDE_LINE = re.compile(r'^\s*#\s*include\s+[<"]([^>"]+)[>"]')
COND_PUSH = re.compile(r'^\s*#\s*(if|ifdef|ifndef)\b')
COND_POP = re.compile(r'^\s*#\s*endif\b')


def discover_tus():
    """Map src/.../*.c -> build/GSAE01/src/.../*.o from build.ninja."""
    tus = {}
    with open(BUILD_NINJA) as f:
        text = f.read()
    # unwrap ninja '$\n' line continuations (and their leading indent)
    text = re.sub(r'\$\n\s*', '', text)
    # build.ninja uses OS-native path separators (backslashes on Windows);
    # normalize to forward slashes so BUILD_LINE matches on every platform.
    text = text.replace('\\', '/')
    for line in text.splitlines():
        m = BUILD_LINE.match(line)
        if m:
            tus[m.group(2)] = m.group(1)
    return tus


def find_includes(path):
    """Return [(line_idx, include_text)] for top-level (depth-0) includes."""
    out = []
    depth = 0
    with open(path, errors='replace') as f:
        for i, line in enumerate(f):
            if COND_PUSH.match(line):
                depth += 1
            elif COND_POP.match(line):
                depth = max(0, depth - 1)
            elif depth == 0:
                m = INCLUDE_LINE.match(line)
                if m:
                    out.append((i, line.rstrip('\n')))
    return out


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read_lines(path):
    with open(path, errors='surrogateescape') as f:
        return f.readlines()


def write_lines(path, lines):
    with open(path, 'w', errors='surrogateescape') as f:
        f.writelines(lines)


def ninja_build(targets):
    """Build targets with -k 0 (keep going); per-target success judged by
    .o existence afterward, so failures here are expected and fine."""
    for i in range(0, len(targets), NINJA_CHUNK):
        subprocess.run(['ninja', '-k', '0'] + targets[i:i + NINJA_CHUNK],
                       cwd=ROOT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def audit(args):
    tus = discover_tus()
    files = sorted(p for p in tus if args.filter in p)
    work = []  # (cfile, ofile, baseline_hash, [(idx, text), ...])
    skipped = 0
    for c in files:
        o = os.path.join(ROOT, tus[c])
        if not os.path.exists(o) or not os.path.exists(os.path.join(ROOT, c)):
            skipped += 1
            continue
        incs = find_includes(os.path.join(ROOT, c))
        if incs:
            work.append((c, tus[c], sha1_file(o), incs))
    total_incs = sum(len(w[3]) for w in work)
    print(f'{len(work)} TUs with includes ({total_incs} include lines), '
          f'{skipped} skipped (no baseline .o)', flush=True)

    results = {}  # cfile -> {include_text: verdict}
    max_rounds = max((len(w[3]) for w in work), default=0)
    touched_targets = set()
    try:
        for rnd in range(max_rounds):
            batch = [(c, o, base, incs[-1 - rnd])
                     for (c, o, base, incs) in work if len(incs) > rnd]
            if not batch:
                break
            print(f'round {rnd}: testing {len(batch)} includes', flush=True)
            backups = {}
            for c, o, base, (idx, text) in batch:
                p = os.path.join(ROOT, c)
                lines = read_lines(p)
                backups[c] = list(lines)
                lines[idx] = '\n'
                write_lines(p, lines)
                op = os.path.join(ROOT, o)
                if os.path.exists(op):
                    os.unlink(op)
                touched_targets.add(o)
            try:
                ninja_build([o for _, o, _, _ in batch])
                for c, o, base, (idx, text) in batch:
                    op = os.path.join(ROOT, o)
                    if not os.path.exists(op):
                        verdict = 'NEEDED-compile'
                    elif sha1_file(op) == base:
                        verdict = 'REMOVABLE'
                    else:
                        verdict = 'NEEDED-codegen'
                    results.setdefault(c, {})[text] = verdict
            finally:
                for c, content in backups.items():
                    write_lines(os.path.join(ROOT, c), content)
    finally:
        if touched_targets:
            print('restoring baseline .o files...', flush=True)
            ninja_build(sorted(touched_targets))

    # verify baseline restored
    bad = [c for (c, o, base, _) in work
           if o in touched_targets and (
               not os.path.exists(os.path.join(ROOT, o))
               or sha1_file(os.path.join(ROOT, o)) != base)]
    if bad:
        print(f'WARNING: {len(bad)} TUs did not restore to baseline hash:')
        for c in bad[:20]:
            print(f'  {c}')

    removable = {c: [t for t, v in r.items() if v == 'REMOVABLE']
                 for c, r in results.items()}
    removable = {c: ts for c, ts in removable.items() if ts}
    out = {'results': results, 'removable': removable}
    with open(args.out, 'w') as f:
        json.dump(out, f, indent=1, sort_keys=True)
    n = sum(len(v) for v in removable.values())
    print(f'\n{n} removable includes across {len(removable)} files '
          f'-> {args.out}')
    for c in sorted(removable, key=lambda c: -len(removable[c]))[:30]:
        print(f'  {len(removable[c]):3d}  {c}')
    return 0


def apply_file(cfile, ofile, texts, dry_run):
    """Remove the given include lines from cfile; verify .o bytes unchanged.
    Returns (n_removed, status)."""
    p = os.path.join(ROOT, cfile)
    op = os.path.join(ROOT, ofile)
    if not os.path.exists(op):
        return 0, 'no baseline .o'
    base = sha1_file(op)
    incs = find_includes(p)
    by_text = {}
    for idx, text in incs:
        by_text.setdefault(text, []).append(idx)
    todo = []
    for t in texts:
        idxs = by_text.get(t)
        if idxs:
            todo.append((idxs[0], t))  # first occurrence only
    if not todo:
        return 0, 'includes not found (file changed since audit?)'

    def attempt(idx_set):
        lines = read_lines(p)
        backup = list(lines)
        kept = [l for i, l in enumerate(lines) if i not in idx_set]
        write_lines(p, kept)
        os.unlink(op)
        ninja_build([ofile])
        ok = os.path.exists(op) and sha1_file(op) == base
        if not ok:
            write_lines(p, backup)
            ninja_build([ofile])
        return ok

    if dry_run:
        return len(todo), 'dry-run'
    if attempt({i for i, _ in todo}):
        return len(todo), 'ok (combined)'
    # combined removal diverged -> greedy one-at-a-time
    removed = 0
    for _, t in sorted(todo, reverse=True):
        incs_now = find_includes(p)
        idx = next((i for i, txt in incs_now if txt == t), None)
        if idx is None:
            continue
        if attempt({idx}):
            removed += 1
    return removed, 'ok (greedy)' if removed else 'reverted (interacting includes)'


def is_own_header(cfile, inc_text):
    m = INCLUDE_LINE.match(inc_text)
    if not m:
        return False
    stem = os.path.splitext(os.path.basename(cfile))[0].lower()
    return os.path.splitext(os.path.basename(m.group(1)))[0].lower() == stem


def apply(args):
    with open(args.report) as f:
        rep = json.load(f)
    tus = discover_tus()
    total = 0
    for cfile in sorted(rep['removable']):
        if args.filter not in cfile:
            continue
        texts = rep['removable'][cfile]
        if not args.include_own_header:
            # keep a TU's own header by convention even when unused
            texts = [t for t in texts if not is_own_header(cfile, t)]
        if not texts:
            continue
        if cfile not in tus:
            print(f'{cfile}: not a build TU, skipped')
            continue
        n, status = apply_file(cfile, tus[cfile], texts, args.dry_run)
        total += n
        print(f'{cfile}: {n}/{len(texts)} removed — {status}', flush=True)
    print(f'\ntotal removed: {total}')
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit', action='store_true')
    mode.add_argument('--apply', metavar='REPORT', dest='report')
    ap.add_argument('--filter', default='src/',
                    help='only files whose path contains this substring')
    ap.add_argument('--out', default='/tmp/include_audit_report.json')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--include-own-header', action='store_true',
                    help='also remove a TU\'s own header when unused '
                         '(kept by default by convention)')
    args = ap.parse_args()
    if args.report:
        return apply(args)
    return audit(args)


if __name__ == '__main__':
    sys.exit(main())
