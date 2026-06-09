#!/usr/bin/env python3
"""PART C: split the scheduling/peephole `off`-needing functions by which pass
they actually need, to estimate C-fixability (task #22).

scheduling on/off controls the instruction SCHEDULER (reorders loads/stores/FP
around calls). C cannot reproduce a specific schedule -- the matching playbook
only ever nudges it (statement splits), never disables it. So a function that
needs scheduling-off is GENUINELY per-TU-setting-dependent, not a C crutch.
peephole on/off controls dot-form fusion (extsb.+cmpwi etc.); SOME of those ARE
C-fixable. This tool quantifies the split among the off-needing functions.

Method (4 whole-tree rebuilds of the off-pragma TUs, reverted after):
  baseline  = current matched .o (sched-off + peep-off where wrapped).
  ALL-ON    : strip off-pragmas (default on). off-wrapped fns that change vs
              baseline = wants_off (the off-needing set).
  PEEP-ONLY : strip + `-opt nopeephole` (sched stays ON). Among wants_off, the
              ones that change = scheduling-sensitive (NOT C-replaceable).
  SCHED-ONLY: strip + `-opt noschedule` (peep stays ON). Among wants_off, the
              ones that change = peephole-sensitive (maybe C-fixable).

Usage: python3 tools/pragma_pass_split.py
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGURE = os.path.join(ROOT, 'configure.py')
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import pragma_inert_audit as pia
import pragma_default_flip_audit as pf
import pragma_scoped_flip as psf


def regen():
    r = subprocess.run([sys.executable, 'configure.py'], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode:
        print('  !! regen FAILED:', r.stderr[-400:], flush=True)


def build(targets):
    for i in range(0, len(targets), 1500):
        subprocess.run(['ninja'] + targets[i:i + 1500], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def off_pragma_units():
    tus = pia.discover_tus()
    units = []
    for c in tus:
        ap = os.path.join(ROOT, c)
        if os.path.exists(ap) and any(
                r['kind'] in ('scheduling', 'peephole') and r['state'] == 'off'
                for r in pia.find_regions(ap)):
            units.append(c)
    return tus, units


def main():
    tus, units = off_pragma_units()
    objs = {u: tus[u] for u in units}
    build(list(objs.values()))
    bdir = '/tmp/passsplit_base'
    shutil.rmtree(bdir, ignore_errors=True)
    os.makedirs(bdir)
    for u in units:
        shutil.copy(os.path.join(ROOT, objs[u]),
                    os.path.join(bdir, objs[u].replace('/', '_')))

    cfg_backup = open(CONFIGURE).read()
    c_backup = {u: open(os.path.join(ROOT, u)).read() for u in units}

    def changed(flagname=None, flagval=None):
        """strip off-pragmas (+optional default flag), rebuild, return
        {unit: set(changed symbols vs baseline)}; restore .c afterward."""
        cfg = cfg_backup
        if flagname:
            cfg = cfg.replace('cflags_runtime = [',
                              f'cflags_{flagname} = ["-opt", "{flagval}"]\n\n'
                              'cflags_runtime = [', 1)
        for u in units:
            if flagname:
                pat = re.compile(r'(Object\([^\n]*?"'
                                 + re.escape(psf.conf_path(u)) + r'")\)')
                cfg = pat.subn(rf'\1, extra_cflags=cflags_{flagname})',
                               cfg, count=1)[0]
            psf.strip_off_pragmas(u)
        open(CONFIGURE, 'w').write(cfg)
        regen()
        build(list(objs.values()))
        res = {u: set(pf.changed_symbols(
            os.path.join(bdir, objs[u].replace('/', '_')),
            os.path.join(ROOT, objs[u]))) for u in units}
        open(CONFIGURE, 'w').write(cfg_backup)
        for u in units:
            open(os.path.join(ROOT, u), 'w').write(c_backup[u])
        return res

    try:
        wants_off = changed()                       # default on
        sched_sens = changed('peeponly', 'nopeephole')   # sched on, peep off
        peep_sens = changed('schedonly', 'noschedule')   # sched off, peep on
    finally:
        open(CONFIGURE, 'w').write(cfg_backup)
        for u in units:
            open(os.path.join(ROOT, u), 'w').write(c_backup[u])
        regen()
        build(list(objs.values()))
        shutil.rmtree(bdir, ignore_errors=True)

    sched_only = peep_only = both = neither = 0
    for u in units:
        wo = wants_off[u]
        s = sched_sens[u] & wo
        p = peep_sens[u] & wo
        for fn in wo:
            a, b = fn in s, fn in p
            if a and b:
                both += 1
            elif a:
                sched_only += 1
            elif b:
                peep_only += 1
            else:
                neither += 1
    tot = sched_only + peep_only + both + neither
    print('\n=== PART C: off-needing functions by required pass ===')
    print(f'off-needing (wants_off) functions: {tot}')
    print(f'  scheduling-only : {sched_only}')
    print(f'  peephole-only   : {peep_only}  (potential C-fix candidates)')
    print(f'  need BOTH        : {both}')
    print(f'  combo/edge       : {neither}')
    print(f'  => scheduling-involved (NOT C-replaceable): {sched_only+both} '
          f'({(sched_only+both)/tot*100:.0f}%)')
    print(f'  => peephole-only (maybe C-fixable):         {peep_only} '
          f'({peep_only/tot*100:.0f}%)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
