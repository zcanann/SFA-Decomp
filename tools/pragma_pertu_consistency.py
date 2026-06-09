#!/usr/bin/env python3
"""PART A: per-TU scheduling/peephole consistency classification (task #22).

The user's question: are the per-function `#pragma scheduling/peephole off`
wrappers genuinely needed, or a decomp artifact? A compiler sets scheduling/
peephole PER-TU (one flag per compilation), never per-function. So for each TU
carrying off-pragmas we classify every function's TRUE preference and ask
whether ONE unit flag could reproduce the whole TU:

  wants_off  = a currently OFF-wrapped function whose bytes CHANGE if forced on
               (strip its off-pragma, default stays on) -> it really needs off.
  wants_on   = a currently UNWRAPPED function whose bytes CHANGE if the default
               flips off -> it really needs on.
  insensitive= unchanged either way.

  CONSISTENT-OFF TU: wants_on == 0  -> matchable with ONE unit flag, zero
                     per-function pragmas (the 253 census-clean units).
  MIXED TU         : wants_off > 0 AND wants_on > 0 -> cannot be a single
                     original compilation (a real split or a C crutch).

Method (two whole-tree rebuilds, reverted after):
  1. snapshot baseline src .o (current matched mix).
  2. ALL-ON  : strip off-pragmas in every off-pragma TU (default-on), rebuild,
               per-symbol diff vs baseline -> wants_off per TU.
  3. ALL-OFF : strip + add the default-off cflag, rebuild, diff -> wants_on.
  4. restore everything; classify; report.

Usage: python3 tools/pragma_pertu_consistency.py [--out F]
"""
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGURE = os.path.join(ROOT, 'configure.py')
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import pragma_inert_audit as pia
import pragma_default_flip_audit as pf
import pragma_scoped_flip as psf


def sh(p):
    if not os.path.exists(p):
        return None
    h = hashlib.sha1()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


NOOPT_DEF = 'cflags_noopt = ["-opt", "nopeephole,noschedule"]\n\n'


def regen():
    r = subprocess.run([sys.executable, 'configure.py'], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print('  !! configure.py regen FAILED:\n' + r.stderr[-800:], flush=True)


def build(targets):
    for i in range(0, len(targets), 1500):
        subprocess.run(['ninja'] + targets[i:i + 1500], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def off_pragma_units(tus):
    out = []
    for c in tus:
        ap = os.path.join(ROOT, c)
        if not os.path.exists(ap):
            continue
        if any(r['kind'] in ('scheduling', 'peephole') and r['state'] == 'off'
               for r in pia.find_regions(ap)):
            out.append(c)
    return out


def diff_fns(units, objs, on_dir):
    """For each unit, symbols whose bytes differ from the saved baseline copy."""
    res = {}
    for u in units:
        cur = os.path.join(ROOT, objs[u])
        base = os.path.join(on_dir, objs[u].replace('/', '_'))
        if os.path.exists(cur) and os.path.exists(base):
            res[u] = pf.changed_symbols(base, cur)
        else:
            res[u] = []
    return res


def main():
    import argparse, shutil
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='/tmp/pragma_pertu.json')
    args = ap.parse_args()

    tus = pia.discover_tus()
    units = off_pragma_units(tus)
    objs = {u: tus[u] for u in units if u in tus}
    units = list(objs)
    print(f'{len(units)} TUs carry scheduling/peephole off pragmas', flush=True)
    build([objs[u] for u in units])

    bdir = '/tmp/pertu_baseline'
    shutil.rmtree(bdir, ignore_errors=True)
    os.makedirs(bdir)
    for u in units:
        ap_ = os.path.join(ROOT, objs[u])
        if os.path.exists(ap_):
            shutil.copy(ap_, os.path.join(bdir, objs[u].replace('/', '_')))

    cfg_backup = open(CONFIGURE).read()
    c_backup = {u: open(os.path.join(ROOT, u)).read() for u in units}
    wants_off = wants_on = {}
    try:
        # ALL-ON: strip off-pragmas, default stays on
        print('ALL-ON: stripping off-pragmas, rebuilding...', flush=True)
        for u in units:
            psf.strip_off_pragmas(u)
        build([objs[u] for u in units])
        wants_off = diff_fns(units, objs, bdir)
        # restore .c
        for u in units:
            open(os.path.join(ROOT, u), 'w').write(c_backup[u])

        # ALL-OFF: strip off-pragmas + default-off cflag
        print('ALL-OFF: strip + default-off cflag, rebuilding...', flush=True)
        cfg = cfg_backup.replace('cflags_runtime = [',
                                 NOOPT_DEF + 'cflags_runtime = [', 1)
        for u in units:
            cfg, ok = psf.add_extra_cflags(cfg, psf.conf_path(u))
            if not ok:
                print(f'  WARN add_extra_cflags miss: {u}')
            psf.strip_off_pragmas(u)
        open(CONFIGURE, 'w').write(cfg)
        regen()
        build([objs[u] for u in units])
        wants_on = diff_fns(units, objs, bdir)
    finally:
        print('restoring .c + configure.py + rebuilding...', flush=True)
        for u in units:
            open(os.path.join(ROOT, u), 'w').write(c_backup[u])
        open(CONFIGURE, 'w').write(cfg_backup)
        regen()
        build([objs[u] for u in units])
        bad = [u for u in units
               if sh(os.path.join(ROOT, objs[u]))
               != sh(os.path.join(bdir, objs[u].replace('/', '_')))]
        print(f'restore check: {len(bad)} off-baseline'
              + (' (OK)' if not bad else ' WARNING'))
        shutil.rmtree(bdir, ignore_errors=True)

    consistent = mixed = consistent_on_only = pure_insensitive = 0
    tot_off = tot_on = 0
    detail = {}
    for u in units:
        no = len(wants_off.get(u, []))
        non = len(wants_on.get(u, []))
        tot_off += no
        tot_on += non
        if non == 0 and no > 0:
            consistent += 1
            cls = 'consistent-off'
        elif non > 0 and no > 0:
            mixed += 1
            cls = 'mixed'
        elif non > 0 and no == 0:
            consistent_on_only += 1
            cls = 'consistent-on(off-pragmas inert?)'
        else:
            pure_insensitive += 1
            cls = 'all-insensitive(off-pragmas inert?)'
        detail[u] = {'wants_off': wants_off.get(u, []),
                     'wants_on': wants_on.get(u, []), 'class': cls}

    print('\n=== PART A: PER-TU CONSISTENCY (off-pragma TUs) ===')
    print(f'TUs with off-pragmas: {len(units)}')
    print(f'  CONSISTENT-OFF (one unit flag suffices, 0 per-fn pragmas): '
          f'{consistent}')
    print(f'  MIXED (both an off-needing and an on-needing fn): {mixed}')
    print(f'  consistent-on-only (off-pragmas look inert): {consistent_on_only}')
    print(f'  all-insensitive (off-pragmas look inert): {pure_insensitive}')
    print(f'function totals: wants_off {tot_off}, wants_on {tot_on}')
    json.dump(detail, open(args.out, 'w'), indent=1)
    print(f'per-TU detail -> {args.out}')
    print('\nMIXED TUs (for PART B address-cluster check):')
    for u in sorted(units):
        if detail[u]['class'] == 'mixed':
            print(f'  off={len(detail[u]["wants_off"]):2d} '
                  f'on={len(detail[u]["wants_on"]):2d}  {u}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
