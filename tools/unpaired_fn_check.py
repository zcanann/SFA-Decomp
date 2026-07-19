#!/usr/bin/env python3
"""Find functions our objects emit out-of-line that retail INLINED away.

objdiff pairs functions by NAME and does not count UNPAIRED symbols, so a
function present in our .text but absent from retail's is invisible to the fuzzy
score. The unit reads 100.00000 while its .text is strictly larger than retail's.
Cause: a `static` helper that retail's compiler inlined at every call site.

SOUND TEST (both conditions must hold):
  (a) our .text exceeds retail's by EXACTLY the sum of the unpaired symbols, and
  (b) NO caller in EITHER object relocates against the symbol.
Condition (b) needs care: `objdump -r` FALSE-ZEROS for static intra-TU calls,
which are resolved at assembly time and leave no reloc. So a zero reloc count is
NOT evidence on its own -- this screen reports the reloc counts and the size
arithmetic, and the arithmetic is what carries the verdict.

FIX = mark the symbol `static inline`. NEVER DELETE IT: nm-extras are usually
retail-inlined static helpers that the file still genuinely calls, so deleting
breaks the build. Proven on snd3dgroup's clip127 (.text 0x1730 vs retail 0x171c,
exactly its 20 bytes); after `static inline` the .text matched exactly.

!! ONLY APPLY TO NonMatching UNITS -- ON A COMPLETE UNIT THE FIX BREAKS THE DOL.
A complete unit links OUR object, and mwld DEAD-STRIPS the unreferenced
out-of-line copy, so the duplicate never reaches the image and the DOL sha is
already correct: on a Matching unit this defect is COSMETIC. Adding `inline`
there instead perturbs the inlining heuristics in the CALLERS, drops the unit
off 100 and moves the sha. Six units (mikaladon, dll_0105_largecrate,
dll_011B_landedarwing, dll_01F6_flag, dll_0295_wcapertures, hoodedzyck) moved
the sha this way and had to be reverted. Check the Object() flag first, and
gate on the DOL sha regardless.

The fix is invisible to fuzzy in BOTH directions -- nine NonMatching units were
fixed here for a total fuzzy delta of 0.00000 -- so the DOL sha and the .text
size are the only instruments that see it.

usage: python3 tools/unpaired_fn_check.py [unit-substring ...]
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, 'build/binutils/powerpc-eabi-objdump')

SYM_RE = re.compile(r'^([0-9a-f]{8}) (.{7}) (\S+)\s+([0-9a-f]{8}) (.+)$')


def text_syms(path):
    """name -> size for .text function symbols; plus the .text section size."""
    r = subprocess.run([OBJDUMP, '-t', '-h', path], capture_output=True)
    if r.returncode != 0:
        return None, None
    syms, size = {}, None
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        m = re.match(r'^\s*\d+\s+\.text\s+([0-9a-f]{8})\s', line)
        if m:
            size = int(m.group(1), 16)
        if '\t' not in line:
            continue
        left, right = line.split('\t', 1)
        m = SYM_RE.match(left + '\t' + right) or SYM_RE.match(line)
        if not m:
            continue
        flags, sec, sz, nm = m.group(2), m.group(3), m.group(4), m.group(5)
        if sec != '.text' or 'F' not in flags:
            continue
        syms[nm.strip()] = int(sz, 16)
    return syms, size


def reloc_targets(path):
    r = subprocess.run([OBJDUMP, '-r', path], capture_output=True)
    if r.returncode != 0:
        return set()
    out = set()
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        f = line.split()
        if len(f) >= 3 and f[1].startswith('R_PPC'):
            out.add(f[2].split('+')[0].split('-')[0])
    return out


def main():
    filters = sys.argv[1:]
    units = json.load(open(os.path.join(ROOT, 'objdiff.json')))['units']
    hits = 0
    for u in units:
        name = u.get('name', '')
        if filters and not any(f in name for f in filters):
            continue
        op, rp = u.get('base_path'), u.get('target_path')
        if not op or not rp:
            continue
        op, rp = os.path.join(ROOT, op), os.path.join(ROOT, rp)
        if not (os.path.exists(op) and os.path.exists(rp)):
            continue
        osyms, osize = text_syms(op)
        rsyms, rsize = text_syms(rp)
        if osyms is None or rsyms is None or osize is None or rsize is None:
            continue
        if osize <= rsize:
            continue
        extra = {k: v for k, v in osyms.items() if k not in rsyms}
        if not extra:
            continue
        delta = osize - rsize
        total = sum(extra.values())
        orel, rrel = reloc_targets(op), reloc_targets(rp)
        verdict = 'EXACT' if total == delta else 'PARTIAL'
        hits += 1
        print('\n=== %s' % name)
        print('  .text ours=0x%x retail=0x%x delta=0x%x  unpaired-sum=0x%x  [%s]'
              % (osize, rsize, delta, total, verdict))
        for k, v in sorted(extra.items(), key=lambda x: -x[1]):
            print('    %-44s size=0x%-5x reloc ours=%s retail=%s'
                  % (k, v, 'Y' if k in orel else 'n',
                     'Y' if k in rrel else 'n'))
    print('\nunits with unpaired .text symbols: %d' % hits)


if __name__ == '__main__':
    main()
