#!/usr/bin/env python3
"""Scoped scheduling/peephole default-off flip + off-pragma strip (task #22).

For each census-confirmed unit (units whose every scheduling/peephole-sensitive
function wants OFF -- see pragma_default_flip_audit.py): add `extra_cflags=
cflags_noopt` to its Object() in configure.py (default -> off for that TU) and
strip its now-redundant scheduling/peephole `off` push+reset pairs (stack-aware,
recipe #1; KEEP `on`-region pairs and all other pragmas). Then rebuild that
unit's src .o and confirm it is BYTE-IDENTICAL to before -- if any unit differs
it was secretly default-ON-dependent, so revert it and flag it.

Processes a slice [--start, --start+--count) of /tmp/scoped_units.json so the
caller can gate+commit+push in small batches. Leaves successful edits in the
working tree; reverts only the units that fail the per-unit .o gate.

Usage:
  python3 tools/pragma_scoped_flip.py --units /tmp/scoped_units.json \
      --start 0 --count 30
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
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import pragma_inert_audit as pia  # noqa: E402


def sh(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def regen():
    subprocess.run([sys.executable, 'configure.py'], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build(targets):
    subprocess.run(['ninja'] + targets, cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def conf_path(unit):
    return unit[len('src/'):] if unit.startswith('src/') else unit


def add_extra_cflags(cfg, path):
    pat = re.compile(r'(Object\([^\n]*?"' + re.escape(path) + r'")\)')
    new, n = pat.subn(r'\1, extra_cflags=cflags_noopt)', cfg, count=1)
    return new, n == 1


def strip_off_pragmas(cunit):
    p = os.path.join(ROOT, cunit)
    regs = pia.find_regions(p)
    drop = set()
    for r in regs:
        if r['kind'] in ('scheduling', 'peephole') and r['state'] == 'off':
            drop.add(r['push_idx'])
            drop.add(r['reset_idx'])
    if not drop:
        return 0
    lines = pia.read_lines(p)
    pia.write_lines(p, [l for i, l in enumerate(lines) if i not in drop])
    return len(drop) // 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--units', default='/tmp/scoped_units.json')
    ap.add_argument('--start', type=int, default=0)
    ap.add_argument('--count', type=int, default=30)
    args = ap.parse_args()

    all_units = json.load(open(args.units))
    tus = pia.discover_tus()
    sl = all_units[args.start:args.start + args.count]
    print(f'slice [{args.start}:{args.start+len(sl)}] of {len(all_units)}: '
          f'{len(sl)} units', flush=True)

    # ensure baseline .o present, snapshot
    objs = {u: tus[u] for u in sl if u in tus}
    build([objs[u] for u in objs])
    snap = {u: sh(os.path.join(ROOT, objs[u])) for u in objs}

    cfg_backup = open(CONFIGURE).read()
    c_backup = {u: open(os.path.join(ROOT, u)).read() for u in objs}

    # apply all edits in the slice
    cfg = cfg_backup
    stripped = {}
    for u in objs:
        cfg, ok = add_extra_cflags(cfg, conf_path(u))
        if not ok:
            print(f'  WARN: could not find Object for {u} -- skipping')
            continue
        stripped[u] = strip_off_pragmas(u)
    open(CONFIGURE, 'w').write(cfg)
    regen()
    build([objs[u] for u in stripped])

    failed = [u for u in stripped if sh(os.path.join(ROOT, objs[u])) != snap[u]]
    ok_units = [u for u in stripped if u not in failed]

    if failed:
        print(f'  {len(failed)} units FAILED .o gate -- reverting them:')
        for u in failed:
            print(f'    REVERT {u}')
        # rebuild configure with only the ok units' extra_cflags
        cfg = cfg_backup
        for u in ok_units:
            cfg, _ = add_extra_cflags(cfg, conf_path(u))
        open(CONFIGURE, 'w').write(cfg)
        for u in failed:
            open(os.path.join(ROOT, u), 'w').write(c_backup[u])
        regen()
        build([objs[u] for u in failed])
        bad = [u for u in failed
               if sh(os.path.join(ROOT, objs[u])) != snap[u]]
        if bad:
            print(f'  WARNING: {len(bad)} reverted units did NOT restore')

    # final per-unit verify of the kept ones
    regress = [u for u in ok_units if sh(os.path.join(ROOT, objs[u])) != snap[u]]
    print(f'\nSUCCEEDED: {len(ok_units)} units, '
          f'{sum(stripped[u] for u in ok_units)} off-regions stripped')
    print(f'FAILED/reverted: {len(failed)}')
    if regress:
        print(f'  ERROR: {len(regress)} kept units not byte-identical: {regress}')
        return 1
    json.dump({'succeeded': ok_units, 'failed': failed},
              open('/tmp/scoped_flip_last.json', 'w'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
