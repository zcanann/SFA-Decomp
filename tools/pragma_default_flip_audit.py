#!/usr/bin/env python3
"""DRY-RUN census for the global scheduling/peephole default flip (task #22).

Hypothesis (team-lead, equivalence PROVEN): the project compiles with the
default `-O4,p` (peephole+schedule ON) and then fights that default with
~8700 per-function `#pragma scheduling off` / `#pragma peephole off` wrappers.
`-opt nopeephole,noschedule` added to the base cflags is BYTE-IDENTICAL to
those off pragmas. So the clean end-state is: flip the global default to OFF
(`-opt nopeephole,noschedule` in cflags_base), strip the now-redundant off
wrappers, and add explicit `#pragma ... on` wrappers ONLY to the functions
that genuinely need ON.

The make-or-break unknown is that last set: functions currently UNWRAPPED
(running at the default ON) whose codegen DEPENDS on ON -- they would silently
regress under a global off-flip unless given an explicit `on` wrapper. The big
block is the audio peephole-ON-target units (recipe #68).

This tool measures that set WITHOUT landing anything:
  1. Snapshot current src .o hashes (default ON -- the ground truth).
  2. Patch configure.py: insert `-opt nopeephole,noschedule` after `-O4,p`
     in cflags_base, regenerate build.ninja.
  3. Rebuild the src tree (default now OFF, pragmas still present).
  4. Diff each src .o vs the snapshot. A TU whose .o is UNCHANGED is flip-safe
     (every function either off-wrapped, on-wrapped, or insensitive). A TU
     whose .o CHANGES has unwrapped functions that need explicit `on` wrappers
     -- objdump pinpoints which functions.
  5. ALWAYS restore configure.py + regenerate + rebuild, leaving the tree
     exactly as found.

This NEVER commits. It only reports the census needed to plan the rollout.

Usage:
  python3 tools/pragma_default_flip_audit.py --census [--functions] [--out F]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGURE = os.path.join(ROOT, 'configure.py')
BUILD_NINJA = os.path.join(ROOT, 'build.ninja')
FLIP_FLAGS = '    "-opt",\n    "nopeephole,noschedule",\n'
ANCHOR = '    "-O4,p",\n'

BUILD_LINE = re.compile(r'^build (build/GSAE01/src/\S+\.o): \S+ (src/\S+\.c)')


def sh(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def discover_src_tus():
    tus = {}
    with open(BUILD_NINJA) as f:
        text = re.sub(r'\$\n\s*', '', f.read())
    for line in text.splitlines():
        m = BUILD_LINE.match(line)
        if m:
            tus[m.group(2)] = m.group(1)
    return tus


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


def regen():
    run([sys.executable, 'configure.py'])


def build_src(targets):
    # report.json depends on the whole src tree; build it to populate all.
    run(['ninja'] + targets)


def text_symbol_bytes(ofile_abs):
    """Return {symbol_name: raw .text bytes} via the ELF symbol table.

    Uses `objdump -h`/`-t` (ELF reading only -- no PPC disassembler needed) to
    locate each `.text` function symbol's offset+size, then slices the raw
    `.text` bytes out of the object file. Raw bytes are position-independent
    (relocated operands carry their pre-link addend, identical across two
    compiles of the same symbol), so a per-symbol byte difference == a real
    codegen difference, robust to earlier-function size shifts.
    """
    h = subprocess.run(['objdump', '-h', ofile_abs],
                       capture_output=True, text=True).stdout
    toff = tsize = None
    for line in h.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] == '.text':
            tsize = int(p[2], 16)
            toff = int(p[5], 16)
            break
    if toff is None:
        return {}
    with open(ofile_abs, 'rb') as f:
        f.seek(toff)
        text = f.read(tsize)
    t = subprocess.run(['objdump', '-t', ofile_abs],
                       capture_output=True, text=True).stdout
    syms = {}
    for line in t.splitlines():
        # function symbols look like: '<val> <flags> F .text\t<size> <name>'
        parts = line.split('\t')
        if len(parts) != 2 or ' F .text' not in parts[0]:
            continue
        val = int(parts[0].split()[0], 16)
        rt = parts[1].split()
        size = int(rt[0], 16)
        name = rt[1] if len(rt) > 1 else ''
        if name:
            syms[name] = text[val:val + size]
    return syms


def changed_symbols(on_abs, off_abs):
    """Names of .text symbols whose bytes differ between the two .o files."""
    a = text_symbol_bytes(on_abs)
    b = text_symbol_bytes(off_abs)
    return sorted(n for n in a if a.get(n) != b.get(n))


VARIANTS = {
    'both': '    "-opt",\n    "nopeephole,noschedule",\n',
    'sched': '    "-opt",\n    "noschedule",\n',
    'peep': '    "-opt",\n    "nopeephole",\n',
}


def matching_units():
    """Set of source paths that are MatchingFor (fuzzy==100) per report.json."""
    rp = os.path.join(ROOT, 'build/GSAE01/report.json')
    m = set()
    if not os.path.exists(rp):
        return m
    rep = json.load(open(rp))
    for u in rep.get('units', []):
        sp = (u.get('metadata') or {}).get('source_path') or u.get('name')
        if sp and (u.get('measures') or {}).get('fuzzy_match_percent', 0) >= 100:
            m.add(sp)
    return m


def run_variant(cfg, flip, src_objs, base, on_dir):
    """Patch with one flip flag, rebuild, return {ofile: [changed symbols]}."""
    open(CONFIGURE, 'w').write(cfg.replace(ANCHOR, ANCHOR + flip, 1))
    regen()
    build_src(['build/GSAE01/report.json'])
    changed = {}
    for o in src_objs:
        if sh(os.path.join(ROOT, o)) != base[o]:
            on_copy = os.path.join(on_dir, o.replace('/', '_'))
            syms = changed_symbols(on_copy, os.path.join(ROOT, o))
            changed[o] = syms
    open(CONFIGURE, 'w').write(cfg)
    regen()
    return changed


def census(args):
    import shutil
    tus = discover_src_tus()
    inv = {v: k for k, v in tus.items()}
    src_objs = sorted(set(tus.values()))
    print(f'building + snapshotting {len(src_objs)} src .o (default ON)...',
          flush=True)
    build_src(['build/GSAE01/report.json'])
    base = {o: sh(os.path.join(ROOT, o)) for o in src_objs}
    matching = matching_units()

    on_dir = '/tmp/flip_on_objs'
    shutil.rmtree(on_dir, ignore_errors=True)
    os.makedirs(on_dir)
    for o in src_objs:
        ap = os.path.join(ROOT, o)
        if os.path.exists(ap):
            shutil.copy(ap, os.path.join(on_dir, o.replace('/', '_')))

    cfg = open(CONFIGURE).read()
    if ANCHOR not in cfg or 'noschedule' in cfg:
        print('configure.py anchor missing or already patched -- abort')
        return 1

    results = {}
    try:
        for name, flip in VARIANTS.items():
            print(f'--- variant {name}: rebuilding src tree ---', flush=True)
            results[name] = run_variant(cfg, flip, src_objs, base, on_dir)
    finally:
        print('restoring configure.py + rebuilding...', flush=True)
        open(CONFIGURE, 'w').write(cfg)
        regen()
        build_src(['build/GSAE01/report.json'])
        bad = [o for o in src_objs if sh(os.path.join(ROOT, o)) != base[o]]
        print(f'restore check: {len(bad)} src .o off-baseline'
              + (' (OK)' if not bad else ' -- WARNING'))
        shutil.rmtree(on_dir, ignore_errors=True)

    # Aggregate: a changed symbol under a variant = an unwrapped function that
    # needs that pass's `on` wrapper (off/on-wrapped fns are flip-invariant).
    def fn_set(name):
        s = set()
        for o, syms in results[name].items():
            for sym in syms:
                s.add((o, sym))
        return s
    need_sched = fn_set('sched')
    need_peep = fn_set('peep')
    need_any = fn_set('both') | need_sched | need_peep

    # current pragma counts (post phase-1) via the inert tool's parser
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'pia', os.path.join(ROOT, 'tools', 'pragma_inert_audit.py'))
    pia = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pia)
    off_regions = on_regions = 0
    for c in tus:
        ap = os.path.join(ROOT, c)
        if not os.path.exists(ap):
            continue
        for r in pia.find_regions(ap):
            if r['kind'] in ('scheduling', 'peephole'):
                if r['state'] == 'off':
                    off_regions += 1
                elif r['state'] == 'on':
                    on_regions += 1

    def split(fnset):
        mu = sum(1 for o, _ in fnset if inv.get(o) in matching)
        return mu, len(fnset) - mu

    print('\n=== DEFAULT-FLIP FUNCTION-LEVEL CENSUS ===')
    print(f'src TUs: {len(src_objs)}  (Matching: {len(matching)})')
    print(f'\n(1) OFF-wrappers strippable under default-off: {off_regions} '
          f'scheduling/peephole off regions (ALL go off-in-off=redundant)')
    print(f'    existing ON-wrappers kept: {on_regions}')
    print(f'\n(2) UNWRAPPED functions that DIFFER under default-off '
          f'(= need an explicit `on` wrapper):')
    print(f'    need scheduling-on : {len(need_sched)}  '
          f'(Matching/NonMatching {split(need_sched)})')
    print(f'    need peephole-on   : {len(need_peep)}  '
          f'(Matching/NonMatching {split(need_peep)})')
    print(f'    need either(any)   : {len(need_any)}  '
          f'(Matching/NonMatching {split(need_any)})')
    new_on_regions = len(need_sched) + len(need_peep)
    print(f'\n(3) PROJECTED FINAL pragma count (scheduling/peephole only):')
    print(f'    strip {off_regions} off-regions, keep {on_regions} on-regions, '
          f'add {new_on_regions} new on-regions')
    proj = on_regions + new_on_regions
    print(f'    => {off_regions + on_regions} current -> {proj} after flip '
          f'({(off_regions+on_regions-proj)/(off_regions+on_regions)*100:.0f}% '
          f'reduction)')

    # by-area breakdown of need-any
    by_area = {}
    for o, _ in need_any:
        c = inv.get(o, o)
        a = c.split('/')[2] if c.startswith('src/main/') else c.split('/')[1]
        by_area[a] = by_area.get(a, 0) + 1
    print('\n(4) functions-needing-on by area:')
    for a in sorted(by_area, key=lambda a: -by_area[a])[:20]:
        print(f'    {by_area[a]:4d}  {a}')

    out = {
        'off_regions_strippable': off_regions,
        'on_regions_kept': on_regions,
        'need_sched': sorted(f'{inv.get(o,o)}::{s}' for o, s in need_sched),
        'need_peep': sorted(f'{inv.get(o,o)}::{s}' for o, s in need_peep),
        'need_any_count': len(need_any),
        'new_on_regions': new_on_regions,
        'projected_final': proj,
        'matching_units': len(matching),
    }
    with open(args.out, 'w') as f:
        json.dump(out, f, indent=1)
    print(f'\nfull census -> {args.out}')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--functions', action='store_true')
    ap.add_argument('--out', default='/tmp/pragma_flip_census.json')
    args = ap.parse_args()
    if args.census:
        return census(args)
    ap.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
