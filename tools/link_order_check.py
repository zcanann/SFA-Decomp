#!/usr/bin/env python3
"""Link-order screen for a proposed TU boundary inside a retail object.

  python3 tools/link_order_check.py <retail.o> <cut_function_index>

Two TUs are emitted in link order, so for a cut to be REAL every data symbol
the HEAD side owns must sit at a LOWER address than every symbol the TAIL side
owns, in every section.  A head symbol above a tail symbol REFUTES the cut.

Only TU-PRIVATE symbols constrain anything.  A GLOBAL mutable symbol
(.data/.sdata/.bss/.sbss at global binding) may be DEFINED in either TU and
externed by the other, so its address proves nothing -- counting those produces
false REFUTED verdicts.  The constraining set is:
    .rodata/.sdata2 with a compiler-generated name (lbl_ADDR, @N, jumptable_)
    any section at LOCAL binding (a file-scope static)

POWER IS ONE-SIDED.  REFUTED is strong evidence against a cut; SEPARABLE is
weak (the screen over-accepts to the RIGHT of a true boundary, because the head
side accumulates every preceding symbol).  VACUOUS means no evidence either way.

Controls (w147):
  POSITIVE  ld -r of objprint.o + objprint_dolphin.o -- two genuinely adjacent
            TUs -- puts the true boundary at index 45, and index 45 is the
            FIRST cut the screen calls SEPARABLE; all 44 cuts interior to the
            real objprint TU are rejected.
  NEGATIVE  pathcamgroup (one genuine TU by the duplicate-value law) yields
            0/9 SEPARABLE; objprint yields 0/44.
"""
import collections, re, subprocess, sys

OBJDUMP = 'build/binutils/powerpc-eabi-objdump'
DATASEC = ('.rodata', '.data', '.sdata', '.sdata2', '.bss', '.sbss', '.sbss2')
LITSEC = ('.rodata', '.sdata2')
POOLNAME = re.compile(r'(lbl_[0-9A-Fa-f]{8}$|jumptable_|@\d)')

def private(sec, bind, name):
    if sec in LITSEC and POOLNAME.match(name): return True
    return bind == 'l'

def load(obj):
    syms = subprocess.run([OBJDUMP, '-t', obj], capture_output=True, text=True).stdout
    fns, data = [], {}
    for l in syms.splitlines():
        m = re.match(r'([0-9a-f]{8})\s.*\sF\s+\.text\s+([0-9a-f]{8})\s+(\S+)', l)
        if m:
            fns.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3))); continue
        m = re.match(r'([0-9a-f]{8})\s+(l|g)\s+\S*\s*O\s+(\S+)\s+[0-9a-f]{8}\s+(\S+)', l)
        if m and m.group(3) in DATASEC:
            data[m.group(4)] = (m.group(3), int(m.group(1), 16), m.group(2))
    fns.sort()
    rel = subprocess.run([OBJDUMP, '-r', obj], capture_output=True, text=True).stdout
    cur, recs = None, []
    for l in rel.splitlines():
        if l.startswith('RELOCATION RECORDS FOR'):
            cur = l.split('[')[1].split(']')[0]; continue
        m = re.match(r'([0-9a-f]{8})\s+(\S+)\s+(\S+)$', l)
        if m and cur == '.text': recs.append((int(m.group(1), 16), m.group(3).split('+')[0]))
    return fns, data, recs

def check(obj, cut, verbose=True):
    fns, data, recs = load(obj)
    idx = {n: i for i, (_, _, n) in enumerate(fns)}
    def owner(off):
        for a, s, n in fns:
            if a <= off < a + s: return n
    refs = collections.defaultdict(set)
    for off, tgt in recs:
        o = owner(off)
        if tgt in data and o is not None: refs[tgt].add(idx[o])
    verdict, evid = 'VACUOUS', 0
    bysec = collections.defaultdict(list)
    for name, (sec, addr, bind) in data.items():
        if private(sec, bind, name): bysec[sec].append((addr, name, bind))
    problems = []
    for sec in sorted(bysec):
        heads, tails = [], []
        for addr, name, bind in sorted(bysec[sec]):
            r = sorted(refs.get(name, ()))
            side = ('BOTH' if any(i < cut for i in r) and any(i >= cut for i in r)
                    else 'HEAD' if any(i < cut for i in r) else 'TAIL' if r else 'none')
            if verbose: print('  %-8s %08x %-4s %-28s %-5s refs=%s' % (sec, addr, bind, name, side, r[:8]))
            if side == 'HEAD': heads.append(addr); evid += 1
            elif side == 'TAIL': tails.append(addr); evid += 1
            elif side == 'BOTH':
                problems.append('%s %s referenced by BOTH sides (TU-private)' % (sec, name)); evid += 1
        if heads and tails:
            if max(heads) > min(tails):
                problems.append('%s: head %08x is ABOVE tail %08x' % (sec, max(heads), min(tails)))
            else:
                verdict = 'SEPARABLE'
    if problems: verdict = 'REFUTED'
    elif evid and verdict != 'SEPARABLE': verdict = 'VACUOUS (one side owns nothing)'
    return verdict, problems, fns[cut][2] if cut < len(fns) else '?'

if __name__ == '__main__':
    v, p, n = check(sys.argv[1], int(sys.argv[2]))
    for x in p: print('  !! ' + x)
    print('CUT idx %s (%s): %s' % (sys.argv[2], n, v))
