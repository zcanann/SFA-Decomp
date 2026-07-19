#!/usr/bin/env python3
"""Compare ALLOC section SIZES in our objects against the retail objects.

The sharpest cheap predictor of a DOL-sha move on promotion, and invisible to
every score gate.

objdiff's fuzzy score compares .text CONTENT function-by-function, so a unit
whose .text is byte-identical reads 100.00000 even when the object carries an
extra constant pool. At link time that pool is real: an extra .sdata2 shifts
every following _SDA2_BASE_-relative displacement, corrupting unrelated
functions across the whole image. synth_jobs.c shipped a 16-byte .sdata2 where
retail's was 0 and skewed 920 functions at fuzzy 100.00000.

An INCOMPLETE unit links the retail object, so main.dol's sha1 is blind too --
the defect only appears the moment the unit is promoted. This screen predicts
that without paying for a link.

A retail object with NO .sdata2 at all, versus ours with one, means the retail
TU sourced those constants from a NEIGHBOURING TU's pool (an extern), i.e. a
mis-drawn TU boundary -- not something a literal rewrite inside this file fixes.

BENIGN CLASS -- do not chase: retail objects record alloc-section sizes already
PADDED UP to 8-byte alignment, ours record the exact size. So ours < retail with
round_up(ours, 8) == retail is inert; the linker re-aligns either way. This was
confirmed against 15 units promoted with the DOL sha holding, 6 of which show
only padding deltas. Applying the rule to 4 units that DID move the sha isolated
the extra .sdata2 pool as their sole real defect in every case.

usage: python3 tools/section_size_check.py [unit-substring ...]
       --all   also list the benign alignment-padding deltas
exit status 1 if any scanned unit has a REAL mismatch.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, 'build/binutils/powerpc-eabi-objdump')

ALLOC = ('.text', '.data', '.rodata', '.sdata', '.sdata2',
         '.sbss', '.sbss2', '.bss')
HDR_RE = re.compile(r'^\s*\d+\s+(\S+)\s+([0-9a-f]{8})\s')


def sections(path):
    r = subprocess.run([OBJDUMP, '-h', path], capture_output=True)
    if r.returncode != 0:
        return None
    out = {}
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        m = HDR_RE.match(line)
        if m and m.group(1) in ALLOC:
            out[m.group(1)] = int(m.group(2), 16)
    return out


def classify(sec, ours, retail):
    """Return (severity, note); severity 'real', 'pad', or None if equal."""
    if ours == retail:
        return None, ''
    if retail == 0 and ours:
        return 'real', 'EXTRA-POOL (retail TU sourced these from a sibling)'
    if ours < retail and (ours + 7) // 8 * 8 == retail:
        return 'pad', 'benign align-8 padding'
    if ours > retail:
        return 'real', 'ours LARGER by 0x%x' % (ours - retail)
    return 'real', 'ours SHORT by 0x%x beyond padding' % (retail - ours)


def main():
    argv = [a for a in sys.argv[1:] if a != '--all']
    show_pad = '--all' in sys.argv[1:]
    filters = argv
    units = json.load(open(os.path.join(ROOT, 'objdiff.json')))['units']
    scanned = bad = 0
    for u in units:
        name = u.get('name', '')
        if filters and not any(f in name for f in filters):
            continue
        ours_p, retail_p = u.get('base_path'), u.get('target_path')
        if not ours_p or not retail_p:
            continue
        ours_p = os.path.join(ROOT, ours_p)
        retail_p = os.path.join(ROOT, retail_p)
        if not (os.path.exists(ours_p) and os.path.exists(retail_p)):
            continue
        ours, retail = sections(ours_p), sections(retail_p)
        if ours is None or retail is None:
            continue
        scanned += 1
        diffs, real = [], False
        for sec in ALLOC:
            a, b = ours.get(sec, 0), retail.get(sec, 0)
            sev, note = classify(sec, a, b)
            if sev is None:
                continue
            if sev == 'real':
                real = True
            elif not show_pad:
                continue
            diffs.append('  [%s] %-8s ours=0x%-5x retail=0x%-5x %s'
                         % (sev, sec, a, b, note))
        if diffs:
            if real:
                bad += 1
            print('\n=== %s' % name)
            print('\n'.join(diffs))
    print('\nscanned=%d real-mismatch=%d' % (scanned, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
