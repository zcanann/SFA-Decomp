#!/usr/bin/env python3
"""Per-function map of TU-PRIVATE pool references in a retail object, used to
corroborate a proposed TU boundary: the two sides must reference DISJOINT pool
blocks and BOTH sides must actually own one.

Each .text relocation target is resolved through the symbol table to its
defining section, so pool entries are found by what they ARE, not by how the
carve happened to name or bind them.

  python3 tools/pool_overlap_check.py <retail.o> [cut_function]

VACUOUS means the screen has no evidence to offer, NOT that the cut is bad --
a landed split (skeetla) reads vacuous on its tail side.
"""
import collections, re, subprocess, sys

OBJDUMP = 'build/binutils/powerpc-eabi-objdump'
# A TU-private pool entry is one of two things, and LINKAGE ALONE decides
# neither:
#   .sdata2/.rodata literal  -- compiler-interned, TU-private whatever its
#       carved linkage (88% of retail pool syms are carved GLOBAL, so an
#       `l`-only filter is blind for most objects)
#   .data/.sdata LOCAL       -- a file-scope static (jumptable, static array)
# A GLOBAL .data/.sdata symbol is a shared mutable global; cross-TU references
# to it are normal and prove nothing about a TU boundary.
LITSEC = ('.sdata2', '.rodata')
STATICSEC = ('.data', '.sdata')
POOLSEC = LITSEC + STATICSEC
POOLNAME = re.compile(r'(lbl_[0-9A-Fa-f]{8}$|jumptable_|@\d)')


def load(obj):
    syms = subprocess.run([OBJDUMP, '-t', obj], capture_output=True, text=True).stdout
    fns, pool = [], {}
    for l in syms.splitlines():
        m = re.match(r'([0-9a-f]{8})\s.*\sF\s+\.text\s+([0-9a-f]{8})\s+(\S+)', l)
        if m:
            fns.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
            continue
        # pool data symbol:  ADDR l|g   O .sdata2  SIZE  name
        m = re.match(r'([0-9a-f]{8})\s+(l|g)\s+\S*\s*O\s+(\S+)\s+[0-9a-f]{8}\s+(\S+)', l)
        if m and POOLNAME.match(m.group(4)):
            sec, bind = m.group(3), m.group(2)
            if sec in LITSEC or (sec in STATICSEC and bind == 'l'):
                pool[m.group(4)] = (sec, int(m.group(1), 16))
    fns.sort()

    rel = subprocess.run([OBJDUMP, '-r', obj], capture_output=True, text=True).stdout
    cur, recs = None, []
    for l in rel.splitlines():
        if l.startswith('RELOCATION RECORDS FOR'):
            cur = l.split('[')[1].split(']')[0]
            continue
        m = re.match(r'([0-9a-f]{8})\s+(\S+)\s+(\S+)$', l)
        if m and cur == '.text':
            recs.append((int(m.group(1), 16), m.group(3).split('+')[0]))
    return fns, pool, recs


def main():
    obj = sys.argv[1]
    cut = sys.argv[2] if len(sys.argv) > 2 else None
    fns, pool, recs = load(obj)
    if not pool:
        print("NO TU-PRIVATE POOL in %s -- screen is VACUOUS here." % obj)
    names = [n for _, _, n in fns]

    def owner(off):
        for a, s, n in fns:
            if a <= off < a + s:
                return n
        return '?'

    byfn = collections.defaultdict(set)
    for off, tgt in recs:
        if tgt in pool:
            byfn[owner(off)].add(tgt)

    print("%-46s %s" % ("FUNCTION", "TU-private pool refs"))
    for a, s, n in fns:
        mark = ">>" if (cut and names.index(n) >= names.index(cut)) else "  "
        d = sorted(byfn.get(n, ()))
        print("%s %-44s %s" % (mark, n, " ".join(d)))

    if cut:
        i = names.index(cut)
        head = set().union(*[byfn.get(n, set()) for n in names[:i]] or [set()])
        tail = set().union(*[byfn.get(n, set()) for n in names[i:]] or [set()])
        ov = head & tail
        print("\nHEAD pool: %d syms" % len(head))
        print("TAIL pool: %d syms" % len(tail))
        print("OVERLAP  : %s" % (" ".join(sorted(ov)) if ov else "NONE"))
        print("VERDICT  : %s" % ("VACUOUS (a side owns no pool)" if not head or not tail
                                 else "SEPARABLE" if not ov else "NOT SEPARABLE"))


if __name__ == '__main__':
    main()
