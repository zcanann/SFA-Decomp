#!/usr/bin/env python3
"""Physical .sdata2 address-ownership census (retail-DOL oracle).

Every `extern <T> lbl_803Exxxx;` in src/ names a word of the retail .sdata2 pool.
Some of those declarations are LEGITIMATE cross-TU imports; others are a unit
importing its OWN pool, which is a defect (the unit should emit the literal and
splits.txt should claim the range).  Spelling cannot tell them apart -- ADDRESS
OWNERSHIP can.

Oracle: decode every r2-relative (SDA2, base 0x803E6500) access in the RETAIL
main.dol .text, resolve it to an absolute .sdata2 address, and attribute it to
the owning unit via splits.txt .text ranges.  refset(A) = units whose retail code
physically touches A.  For a declaration of A inside unit U:

    SELF    refset(A) == {U}        -> U's own pool word
    SHARED  U in refset(A), |..|>1  -> merged TU or a real cross-TU import
    FOREIGN U not in refset(A)      -> declared in the wrong file / merged TU

Cross-checked against the splits.txt .sdata2 claims: SELF+unclaimed is the
directly-actionable population (claim the range, literalize the value).

Usage:  python3 tools/sdata2_ownership_census.py [--claims] [--runs]
"""
import os, re, struct, sys, json, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOL = os.path.join(ROOT, 'orig/GSAE01/sys/main.dol')
SPLITS = os.path.join(ROOT, 'config/GSAE01/splits.txt')
SDA2_BASE = 0x803E6500
SDATA2_LO, SDATA2_HI = 0x803DE500, 0x803E8440

d = open(DOL, 'rb').read()
off = struct.unpack_from('>18I', d, 0)
adr = struct.unpack_from('>18I', d, 0x48)
siz = struct.unpack_from('>18I', d, 0x90)

units = {}
cur = None
for line in open(SPLITS):
    if line.strip() and not line[0].isspace() and line.rstrip().endswith(':'):
        cur = line.strip()[:-1]
        units.setdefault(cur, collections.defaultdict(list))
        continue
    m = re.match(r'\s+(\.?\w+)\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)', line)
    if m and cur:
        units[cur][m.group(1)].append((int(m.group(2), 16), int(m.group(3), 16)))

text_iv = sorted((s, e, u) for u, x in units.items() for s, e in x.get('.text', []))
claims = sorted((s, e, u) for u, x in units.items() for s, e in x.get('.sdata2', []))


def owner_text(a):
    lo, hi = 0, len(text_iv)
    while lo < hi:
        m = (lo + hi) // 2
        if text_iv[m][0] <= a:
            lo = m + 1
        else:
            hi = m
    return text_iv[lo - 1][2] if lo and text_iv[lo - 1][1] > a else None


def claimer(a):
    lo, hi = 0, len(claims)
    while lo < hi:
        m = (lo + hi) // 2
        if claims[m][0] <= a:
            lo = m + 1
        else:
            hi = m
    return claims[lo - 1][2] if lo and claims[lo - 1][1] > a else None


DFORM = set(list(range(32, 56)) + [14])
refs = collections.defaultdict(set)
nrefs = 0
for i in (0, 1):
    if not siz[i]:
        continue
    for k in range(0, siz[i], 4):
        w = struct.unpack_from('>I', d, off[i] + k)[0]
        if (w >> 26) not in DFORM or ((w >> 16) & 31) != 2:
            continue
        disp = w & 0xFFFF
        disp -= 0x10000 if disp & 0x8000 else 0
        refs[SDA2_BASE + disp].add(owner_text(adr[i] + k))
        nrefs += 1
assert nrefs > 15000, 'SDA21 sweep found only %d refs' % nrefs

# --- src declarations, with included .c files folded into their host TU ---
decl_re = re.compile(rb'extern\s+(?:const\s+)?([A-Za-z_][A-Za-z_0-9]*)\s+(lbl_([0-9A-Fa-f]{8}))\s*(?:\[[^\]]*\])?\s*;')
inc_re = re.compile(rb'#include\s+"([^"]*\.c)"')
decls, hostmap = [], {}
for dp, dn, fns in os.walk(os.path.join(ROOT, 'src')):
    for fn in fns:
        if not fn.endswith(('.c', '.h', '.cpp')):
            continue
        p = os.path.join(dp, fn)
        rp = os.path.relpath(p, ROOT)
        b = open(p, 'rb').read()
        for m in decl_re.finditer(b):
            decls.append((rp, m.group(1).decode(), m.group(2).decode(), int(m.group(3), 16)))
        for m in inc_re.finditer(b):
            c = os.path.normpath(os.path.join(os.path.dirname(rp), m.group(1).decode()))
            if not os.path.exists(os.path.join(ROOT, c)):
                c = os.path.normpath(os.path.join('src', m.group(1).decode()))
            hostmap[c] = rp

file2unit = {'src/' + u: u for u in units}
for _ in range(5):
    for c, h in hostmap.items():
        if c not in file2unit and h in file2unit:
            file2unit[c] = file2unit[h]

out = collections.defaultdict(list)
for path, typ, name, addr in decls:
    u = file2unit.get(path)
    rs = refs.get(addr, set())
    if not (SDATA2_LO <= addr < SDATA2_HI):
        cls = 'NOT_SDATA2'
    elif u is None:
        cls = 'UNMAPPED'
    elif rs == {u}:
        cls = 'SELF'
    elif u in rs:
        cls = 'SHARED'
    elif not rs:
        cls = 'NOREF'
    else:
        cls = 'FOREIGN'
    out[cls].append(dict(file=path, unit=u, type=typ, sym=name, addr=addr,
                         refset=sorted(x for x in rs if x), claim=claimer(addr)))

print('declarations: %d' % sum(len(v) for v in out.values()))
for k in sorted(out, key=lambda k: -len(out[k])):
    print('  %-12s %5d' % (k, len(out[k])))
sub = collections.Counter('claim-' + ('self' if r['claim'] == r['unit'] else
                                      'none' if r['claim'] is None else 'other')
                          for r in out['SELF'])
print('  SELF split: %s' % dict(sub))

if '--claims' in sys.argv:
    print('\n=== SELF, unclaimed: splits.txt .sdata2 claim requests ===')
    per = collections.defaultdict(set)
    for r in out['SELF']:
        if r['claim'] is None:
            per[r['unit']].add(r['addr'])
    for u in sorted(per, key=lambda u: -len(per[u])):
        a = sorted(per[u])
        runs, s, p = [], a[0], a[0]
        for x in a[1:]:
            if x - p > 64:
                runs.append((s, p))
                s = x
            p = x
        runs.append((s, p))
        print('%-52s %3d  %s' % (u, len(a),
              ' '.join('0x%08X..0x%08X' % (x, y + 4) for x, y in runs)))
    print('\n=== SELF, claimed by ANOTHER unit: split-boundary corrections ===')
    per = collections.defaultdict(set)
    for r in out['SELF']:
        if r['claim'] not in (None, r['unit']):
            per[(r['unit'], r['claim'])].add(r['addr'])
    for (u, c), a in sorted(per.items(), key=lambda kv: -len(kv[1])):
        print('%-46s <- claimed by %-40s %2d 0x%08X..0x%08X' % (u, c, len(a), min(a), max(a) + 4))

json.dump({k: v for k, v in out.items()},
          open(os.path.join(ROOT, 'build/sdata2_census.json'), 'w'), indent=1)


# ---------------------------------------------------------------------------
# --graph: pool DEFINER / IMPORTER dependency graph, from OBJECT SYMBOL TABLES
#
# A unit that reads 100% on .text but carries an incomplete pool is usually
# BORROWING retail's pool: its source declares `extern const f32 lbl_803Exxxx`
# with no definer of its own, and the link resolves it out of the unit's own
# RETAIL object.  Literalizing those declarations mints ANONYMOUS `@N` words,
# which DESTROYS the named symbol -- so it only works when no OTHER unit
# imports that word.  Promoting a definer out from under an importer LINKFAILS.
#
#   PROVIDES(U)  lbl_ syms defined by U's retail object
#   CONSUMERS(s) units != U whose CURRENTLY-LINKED object has s undefined
#   LEAF         a unit with no consumed provides -- promotable today
#
# Work the leaves first, then inward: a definer becomes promotable once every
# consumer has been literalized off it (src-linked) or promoted (retail-linked).
#
# Usage:  python3 tools/sdata2_ownership_census.py --graph [--all]
# ---------------------------------------------------------------------------
if '--graph' in sys.argv:
    import subprocess

    NM = os.path.join(ROOT, 'build/binutils/powerpc-eabi-nm')
    status = {}
    for line in open(os.path.join(ROOT, 'configure.py')):
        m = re.search(r'Object\((MatchingFor\([^)]*\)|Matching|NonMatching|Equivalent)'
                      r'\s*,\s*"([^"]+)"', line)
        if m:
            status[m.group(2)] = m.group(1)

    def scan(root):
        """unit -> (defined lbl_ syms, undefined lbl_ syms) for every .o under root."""
        base = os.path.join(ROOT, root)
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(base)
                 for f in fs if f.endswith('.o')]
        d, u = collections.defaultdict(set), collections.defaultdict(set)
        for i in range(0, len(files), 400):
            chunk = files[i:i + 400]
            out_ = subprocess.run([NM, '-A', '-g'] + chunk, capture_output=True,
                                  text=True).stdout
            for line in out_.splitlines():
                if ':' not in line:
                    continue
                f, rest = line.split(':', 1)
                p = rest.split()
                if len(p) < 2:
                    continue
                unit = os.path.relpath(f, base)[:-2] + '.c'
                if p[0] == 'U':
                    if p[1].startswith('lbl_'):
                        u[unit].add(p[1])
                elif p[-1].startswith('lbl_'):
                    d[unit].add(p[-1])
        return d, u

    rdef, rund = scan('build/GSAE01/obj')
    sdef, sund = scan('build/GSAE01/src')

    # ORPHAN FILTER -- stale rename artifacts inflate an unfiltered sweep ~3x.
    allsrc = set(sdef) | set(sund)
    orphans = allsrc - set(units)
    kept = allsrc & set(units)
    assert kept, 'orphan filter removed every src unit'
    print('src objects with pool syms %d: %d in splits.txt, %d ORPHANED (filtered)'
          % (len(allsrc), len(kept), len(orphans)))

    def src_linked(u):
        return status.get(u, '').startswith(('Matching', 'Equivalent'))

    # CONSUMERS: only the object the linker ACTUALLY uses for each unit counts.
    consumers = collections.defaultdict(set)
    for u in units:
        for s in (sund if src_linked(u) else rund).get(u, ()):
            consumers[s].add(u)

    rows = []
    for u in units:
        provides = rdef.get(u, set())
        blocked = {s: sorted(consumers[s] - {u}) for s in provides
                   if consumers[s] - {u}}
        borrows = sorted(sund.get(u, set()) & provides)
        if provides or borrows:
            rows.append((u, sorted(provides), borrows, blocked))

    leaves = [r for r in rows if not r[3]]
    print('units defining pool syms: %d   LEAVES (no external consumer): %d'
          % (len(rows), len(leaves)))
    print('\n=== BLOCKED: promoting the definer would LINKFAIL its importers ===')
    for u, prov, bor, bl in sorted(rows, key=lambda r: -len(r[3])):
        if not bl:
            continue
        print('%-52s provides %3d  borrows %3d' % (u, len(prov), len(bor)))
        for s, cs in sorted(bl.items()):
            print('      %-16s -> %s' % (s, ', '.join(cs)))
    if '--all' in sys.argv:
        print('\n=== LEAVES: literalize + promote (topological front) ===')
        for u, prov, bor, bl in sorted(leaves, key=lambda r: -len(r[2])):
            if bor:
                print('%-52s borrows %3d of %3d provided' % (u, len(bor), len(prov)))

    json.dump({'provides': {u: p for u, p, b, x in rows},
               'borrows': {u: b for u, p, b, x in rows if b},
               'blocked': {u: x for u, p, b, x in rows if x},
               'orphans': sorted(orphans)},
              open(os.path.join(ROOT, 'build/sdata2_graph.json'), 'w'), indent=1)
