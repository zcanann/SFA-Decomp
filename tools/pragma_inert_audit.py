#!/usr/bin/env python3
"""Empirically detect INERT pragma wrappers (task #22).

Many `#pragma scheduling off` / `#pragma peephole off` / etc. wrappers in the
tree are LOAD-BEARING -- they were added to coax MWCC's codegen into matching
the target binary, so removing one regresses its function. But some are dead
weight: a wrapper whose effective on/off state equals the surrounding state
(e.g. `#pragma peephole on` inside a file that is already default-peephole-ON,
the recipe #173 class) produces BYTE-IDENTICAL .o output whether present or
absent. This tool finds those empirically.

Method (modeled on tools/include_audit.py):
  For each matched pragma REGION (a push pragma and its matching `reset`),
  blank BOTH lines, rebuild just that TU, and compare the .o bytes to baseline:

    .o bytes identical  -> INERT   (removable dead weight)
    .o bytes change     -> LOAD-BEARING (keep)
    build fails         -> LOAD-BEARING (keep)

  The .o byte hash is the gold standard: MWCC output is deterministic and
  carries no line-number info, so identical bytes == identical codegen ==
  matched_code conserved.

Pragma stack model (recipe #1): for each pragma KIND, `on`/`off`/`N` PUSH a
state and `reset` POPS the surrounding state (NOT reset-to-default). A region
is one matched push..reset pair per kind. Removing a region means deleting its
opening push line AND its matching reset line -- which leaves the lines between
them running under the SURROUNDING state. Nesting is handled per-kind with a
stack so testing one region never changes the effective state of siblings.

Regions are tested one-per-file-per-round (like include_audit) so blanked
regions never interfere within a round; the file is restored after each round.

Usage:
  python3 tools/pragma_inert_audit.py --census [--filter SUBSTR]
  python3 tools/pragma_inert_audit.py --audit [--kinds peephole,scheduling]
        [--states on,off] [--redundant-only] [--filter SUBSTR] [--out FILE]
  python3 tools/pragma_inert_audit.py --apply REPORT.json [--filter SUBSTR]
        [--dry-run]
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
PRAGMA_LINE = re.compile(r'^\s*#\s*pragma\s+(\w+)\s+(\w+)')

# Pragma kinds that use the push/reset stack model we can safely test.
STACK_KINDS = {
    'scheduling', 'peephole', 'optimization_level', 'dont_inline',
    'fp_contract', 'opt_common_subs', 'optimize_for_size',
    'opt_loop_invariants', 'opt_strength_reduction', 'exceptions',
    'ppc_unroll_speculative', 'force_active', 'warn_implicitconv',
    'internal', 'opt_propagation', 'opt_dead_assignments',
}
DEFAULT_STATE = 'DEFAULT'  # surrounding state at file scope (stack empty)


def discover_tus():
    """Map src/.../*.c -> build/GSAE01/src/.../*.o from build.ninja."""
    tus = {}
    with open(BUILD_NINJA) as f:
        text = f.read()
    text = re.sub(r'\$\n\s*', '', text)
    for line in text.splitlines():
        m = BUILD_LINE.match(line)
        if m:
            tus[m.group(2)] = m.group(1)
    return tus


def read_lines(path):
    with open(path, errors='surrogateescape') as f:
        return f.readlines()


def write_lines(path, lines):
    with open(path, 'w', errors='surrogateescape') as f:
        f.writelines(lines)


def find_regions(path):
    """Return matched pragma regions in `path`.

    Each region is a dict: {kind, state, surrounding, push_idx, reset_idx,
    redundant}. `redundant` is True when state == surrounding (the statically
    high-confidence inert class). Only balanced push..reset pairs are returned.
    """
    stacks = {}  # kind -> [(push_idx, state)]
    regions = []
    lines = read_lines(path)
    for i, line in enumerate(lines):
        m = PRAGMA_LINE.match(line)
        if not m:
            continue
        kind, arg = m.group(1), m.group(2)
        if kind not in STACK_KINDS:
            continue
        st = stacks.setdefault(kind, [])
        if arg == 'reset':
            if not st:
                continue  # unbalanced reset; ignore
            push_idx, state = st.pop()
            surrounding = st[-1][1] if st else DEFAULT_STATE
            regions.append({
                'kind': kind, 'state': state, 'surrounding': surrounding,
                'push_idx': push_idx, 'reset_idx': i,
                'redundant': state == surrounding,
            })
        else:
            st.append((i, arg))
    return regions


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def ninja_build(targets):
    for i in range(0, len(targets), NINJA_CHUNK):
        subprocess.run(['ninja', '-k', '0'] + targets[i:i + NINJA_CHUNK],
                       cwd=ROOT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def region_key(r):
    """Stable identity of a region within a file, robust to line shifts:
    (kind, state, push line text, reset line text are all implied) -- we use
    (kind, state, push_idx) at audit time and re-locate by ordinal at apply."""
    return (r['kind'], r['state'], r['push_idx'], r['reset_idx'])


def select(regions, args):
    out = []
    for r in regions:
        if args.kinds and r['kind'] not in args.kinds:
            continue
        if args.states and r['state'] not in args.states:
            continue
        if args.redundant_only and not r['redundant']:
            continue
        out.append(r)
    return out


def census(args):
    tus = discover_tus()
    files = sorted(p for p in tus if args.filter in p)
    bykind = {}
    redundant = {}
    perfile = {}
    for c in files:
        p = os.path.join(ROOT, c)
        if not os.path.exists(p):
            continue
        regs = find_regions(p)
        if not regs:
            continue
        perfile[c] = regs
        for r in regs:
            k = (r['kind'], r['state'])
            bykind[k] = bykind.get(k, 0) + 1
            if r['redundant']:
                redundant[k] = redundant.get(k, 0) + 1
    print('=== all matched regions (kind, state): count [redundant] ===')
    for k in sorted(bykind, key=lambda k: -bykind[k]):
        print(f'  {bykind[k]:5d} [{redundant.get(k,0):4d} redundant]  '
              f'{k[0]} {k[1]}')
    tot = sum(bykind.values())
    totred = sum(redundant.values())
    print(f'  total {tot} regions, {totred} statically redundant, '
          f'across {len(perfile)} files')
    return 0


def audit(args):
    tus = discover_tus()
    files = sorted(p for p in tus if args.filter in p)
    work = []  # (cfile, ofile, base_hash, [regions])
    skipped = 0
    for c in files:
        o = tus[c]
        op = os.path.join(ROOT, o)
        cp = os.path.join(ROOT, c)
        if not os.path.exists(op) or not os.path.exists(cp):
            skipped += 1
            continue
        regs = select(find_regions(cp), args)
        if regs:
            work.append((c, o, sha1_file(op), regs))
    total = sum(len(w[3]) for w in work)
    print(f'{len(work)} TUs, {total} candidate regions, {skipped} skipped',
          flush=True)

    results = {}  # cfile -> [ {region..., verdict} ]
    max_rounds = max((len(w[3]) for w in work), default=0)
    touched = set()
    try:
        for rnd in range(max_rounds):
            batch = [(c, o, base, regs[rnd])
                     for (c, o, base, regs) in work if len(regs) > rnd]
            if not batch:
                break
            print(f'round {rnd}: testing {len(batch)} regions', flush=True)
            backups = {}
            for c, o, base, r in batch:
                p = os.path.join(ROOT, c)
                lines = read_lines(p)
                backups[c] = list(lines)
                lines[r['push_idx']] = '\n'
                lines[r['reset_idx']] = '\n'
                write_lines(p, lines)
                op = os.path.join(ROOT, o)
                if os.path.exists(op):
                    os.unlink(op)
                touched.add(o)
            try:
                ninja_build([o for _, o, _, _ in batch])
                for c, o, base, r in batch:
                    op = os.path.join(ROOT, o)
                    if not os.path.exists(op):
                        verdict = 'LOAD-BEARING-compile'
                    elif sha1_file(op) == base:
                        verdict = 'INERT'
                    else:
                        verdict = 'LOAD-BEARING-codegen'
                    rr = dict(r)
                    rr['verdict'] = verdict
                    results.setdefault(c, []).append(rr)
            finally:
                for c, content in backups.items():
                    write_lines(os.path.join(ROOT, c), content)
    finally:
        if touched:
            print('restoring baseline .o files...', flush=True)
            ninja_build(sorted(touched))

    bad = [c for (c, o, base, _) in work
           if o in touched and (
               not os.path.exists(os.path.join(ROOT, o))
               or sha1_file(os.path.join(ROOT, o)) != base)]
    if bad:
        print(f'WARNING: {len(bad)} TUs did not restore to baseline:')
        for c in bad[:20]:
            print(f'  {c}')

    inert = {c: [r for r in rs if r['verdict'] == 'INERT']
             for c, rs in results.items()}
    inert = {c: rs for c, rs in inert.items() if rs}
    out = {'results': results, 'inert': inert}
    with open(args.out, 'w') as f:
        json.dump(out, f, indent=1, sort_keys=True)
    n = sum(len(v) for v in inert.values())
    print(f'\n{n} INERT regions across {len(inert)} files -> {args.out}')
    for c in sorted(inert, key=lambda c: -len(inert[c]))[:30]:
        kinds = {}
        for r in inert[c]:
            kk = f"{r['kind']} {r['state']}"
            kinds[kk] = kinds.get(kk, 0) + 1
        desc = ', '.join(f'{v}x {k}' for k, v in sorted(kinds.items()))
        print(f'  {len(inert[c]):3d}  {c}  ({desc})')
    return 0


def apply_file(cfile, ofile, regions, dry_run):
    """Remove the given inert regions from cfile by re-locating them via the
    current file's region list (ordinal match on kind+state+push/reset text),
    then verify .o bytes unchanged. Returns (n_removed, status)."""
    p = os.path.join(ROOT, cfile)
    op = os.path.join(ROOT, ofile)
    if not os.path.exists(op):
        return 0, 'no baseline .o'
    base = sha1_file(op)

    # Collect the line indices to blank, re-locating each region in the current
    # file by matching (kind, state, push_idx, reset_idx). The audit stored
    # indices from the same file state, so direct match works unless the file
    # changed since the audit; we verify by re-parsing and matching the tuple.
    cur = find_regions(p)
    cur_by_key = {region_key(r): r for r in cur}
    blank = set()
    matched = 0
    for r in regions:
        rr = cur_by_key.get((r['kind'], r['state'], r['push_idx'],
                             r['reset_idx']))
        if rr is None:
            continue
        blank.add(rr['push_idx'])
        blank.add(rr['reset_idx'])
        matched += 1
    if not blank:
        return 0, 'regions not found (file changed since audit?)'
    if dry_run:
        return matched, 'dry-run'

    def attempt(blank_set):
        lines = read_lines(p)
        backup = list(lines)
        kept = [l for i, l in enumerate(lines) if i not in blank_set]
        write_lines(p, kept)
        if os.path.exists(op):
            os.unlink(op)
        ninja_build([ofile])
        ok = os.path.exists(op) and sha1_file(op) == base
        if not ok:
            write_lines(p, backup)
            ninja_build([ofile])
        return ok

    if attempt(blank):
        return matched, 'ok (combined)'
    # Combined removal diverged -> greedy region-by-region from end of file.
    removed = 0
    for r in sorted(regions, key=lambda r: -r['push_idx']):
        cur = find_regions(p)
        cur_by_key = {region_key(x): x for x in cur}
        rr = cur_by_key.get((r['kind'], r['state'], r['push_idx'],
                             r['reset_idx']))
        if rr is None:
            continue
        if attempt({rr['push_idx'], rr['reset_idx']}):
            removed += 1
    return removed, ('ok (greedy)' if removed else
                     'reverted (regions interact)')


def apply(args):
    with open(args.report) as f:
        rep = json.load(f)
    inert = rep['inert']
    tus = discover_tus()
    files = sorted(c for c in inert if args.filter in c)
    total_removed = 0
    touched = []
    for c in files:
        if c not in tus:
            print(f'  SKIP {c} (no .o mapping)')
            continue
        n, status = apply_file(c, tus[c], inert[c], args.dry_run)
        total_removed += n
        if n:
            touched.append(c)
        print(f'  {n:3d}  {c}  [{status}]')
    print(f'\n{"(dry-run) " if args.dry_run else ""}'
          f'{total_removed} regions removed across {len(touched)} files')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--audit', action='store_true')
    ap.add_argument('--apply', dest='report')
    ap.add_argument('--filter', default='')
    ap.add_argument('--kinds', default='', help='comma-separated kinds')
    ap.add_argument('--states', default='', help='comma-separated states')
    ap.add_argument('--redundant-only', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--out', default='/tmp/pragma_inert.json')
    args = ap.parse_args()
    args.kinds = set(x for x in args.kinds.split(',') if x)
    args.states = set(x for x in args.states.split(',') if x)
    if args.census:
        return census(args)
    if args.audit:
        return audit(args)
    if args.report:
        return apply(args)
    ap.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
