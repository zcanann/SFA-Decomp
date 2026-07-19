"""Compare .text function ORDER in our objects against the retail objects.

Both standard gates are blind to function placement: objdiff pairs functions by
name, so a relocated function still scores 100, and an incomplete unit links the
retail object rather than ours, so main.dol's sha1 never moves either. This
screen compares the order of the commonly-named .text functions in
build/GSAE01/src/<unit>.o against build/GSAE01/obj/<unit>.o and reports any unit
whose order differs. Absolute offsets are ignored; only relative order matters.

usage: python3 tools/order_check.py [unit-substring ...]
exit status 1 if any unit is mis-ordered.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, 'build/binutils/powerpc-eabi-objdump')


def text_functions(obj_path):
    """Return .text function symbol names ordered by offset, or None."""
    r = subprocess.run([OBJDUMP, '-t', obj_path], capture_output=True)
    if r.returncode != 0:
        return None
    found = []
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        if '\t' not in line:
            continue
        left, right = line.split('\t', 1)
        m = re.match(r'^([0-9a-f]{8}) (.{7}) (\S+)$', left)
        if not m:
            continue
        offset, flags, section = m.groups()
        if section != '.text' or 'F' not in flags:
            continue
        fields = right.split()
        if len(fields) < 2:
            continue
        found.append((int(offset, 16), fields[-1]))
    found.sort()
    return [name for _, name in found]


def scan(filters=()):
    config = json.load(open(os.path.join(ROOT, 'objdiff.json')))
    hits = []
    scanned = 0
    for unit in config['units']:
        name = unit['name']
        if filters and not any(f in name for f in filters):
            continue
        target, base = unit.get('target_path'), unit.get('base_path')
        if not target or not base:
            continue
        target = os.path.join(ROOT, target)
        base = os.path.join(ROOT, base)
        if not (os.path.exists(target) and os.path.exists(base)):
            continue
        retail, ours = text_functions(target), text_functions(base)
        if retail is None or ours is None:
            continue
        scanned += 1
        shared = set(retail) & set(ours)
        if len(shared) < 2:
            continue
        retail_order = [n for n in retail if n in shared]
        our_order = [n for n in ours if n in shared]
        if retail_order != our_order:
            index = next(i for i, (a, b) in enumerate(zip(retail_order, our_order)) if a != b)
            hits.append({
                'unit': name,
                'retail': retail_order,
                'ours': our_order,
                'first_divergence': index,
                'extra_symbols': sorted(set(ours) - set(retail)),
                'missing_symbols': sorted(set(retail) - set(ours)),
            })
    return scanned, hits


def main():
    scanned, hits = scan(sys.argv[1:])
    print('scanned=%d misordered=%d' % (scanned, len(hits)))
    for hit in hits:
        i = hit['first_divergence']
        print('\n=== %s' % hit['unit'])
        print('  first divergence @%d: retail=%s ours=%s'
              % (i, hit['retail'][i], hit['ours'][i]))
        if hit['extra_symbols']:
            print('  extra in ours: %s' % ' '.join(hit['extra_symbols']))
        if hit['missing_symbols']:
            print('  missing from ours: %s' % ' '.join(hit['missing_symbols']))
    return 1 if hits else 0


if __name__ == '__main__':
    sys.exit(main())
