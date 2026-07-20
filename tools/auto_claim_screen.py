#!/usr/bin/env python3
"""Find `auto_*` data ranges that can be claimed into a real TU for a scored gain.

dtk emits an `auto_generated` object for every retail address range that
`splits.txt` assigns to no TU. Each such object reports `matched_data == 0`, so
the class is pure unmatched mass in the top-level `report.json` measures (it is
excluded from the `game`/`sdk` categories).

Claiming a range is score-NEUTRAL unless our source already emits the bytes:
moving a range from an auto object into unit X leaves top-level `total_data`
unchanged, so `matched_data` only rises if our `.o` reproduces the span exactly.
`matched_data` additionally scores a section 0 unless our size EQUALS the claim,
so a partial pool gains nothing and can cost unit X its complete status.

A range is therefore reported only when all four hold:
  1. OWNERSHIP  - retail code relocates against symbols in the range, and every
                  such symbol is referenced by exactly ONE unit (a symbol shared
                  by several units means retail merged those TUs; unassignable).
  2. EXCLUSIVE  - no other unit references anything inside the span.
  3. SIZE PARITY- the sole-owned run length equals our emitted section size.
  4. BYTE-EXACT - our section bytes equal the retail bytes at that address.

Ordering caveat: `.sdata2` claims in splits.txt are in file order == address
order. Verify a new claim preserves that before applying (the script prints the
bracketing claims), then gate on DOL sha AND DOL size, not on the score alone.

Usage: python3 tools/auto_claim_screen.py [--section .sdata2]
"""
import json, os, re, subprocess, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")
REPORT = os.path.join(ROOT, "build/GSAE01/report.json")


def symbols():
    out = {}
    txt = open(os.path.join(ROOT, "config/GSAE01/symbols.txt")).read()
    for m in re.finditer(r'^([A-Za-z_]\w*)\s*=\s*(\.\w+):0x([0-9A-Fa-f]+);(.*)$', txt, re.M):
        s = re.search(r'size:0x([0-9A-Fa-f]+)', m.group(4))
        out[m.group(1)] = (m.group(2), int(m.group(3), 16), int(s.group(1), 16) if s else 4)
    return out


def claims():
    by = defaultdict(list)
    cur = None
    for line in open(os.path.join(ROOT, "config/GSAE01/splits.txt")):
        if re.match(r'^\S.*:\s*$', line):
            cur = line.strip().rstrip(':')
            continue
        m = re.match(r'\s+(\.\w+)\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)', line)
        if m and cur:
            by[m.group(1)].append((int(m.group(2), 16), int(m.group(3), 16), cur))
    for k in by:
        by[k].sort()
    return by


def sec_bytes(path, sec):
    out = subprocess.run([OBJDUMP, '-s', '-j', sec, path],
                         capture_output=True, text=True).stdout
    d = bytearray()
    for line in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+)\s((?:[0-9a-f]{2,8}\s){1,4})', line)
        if m:
            try:
                d += bytes.fromhex(m.group(2).replace(' ', ''))
            except ValueError:
                pass
    return bytes(d)


def main():
    sec = '.sdata2'
    if '--section' in sys.argv:
        sec = sys.argv[sys.argv.index('--section') + 1]

    sym = symbols()
    cl = claims()
    unclaimed = lambda a: not any(s <= a < e for s, e, _ in cl[sec])
    rep = json.load(open(REPORT))
    live = set(re.findall(r'(build/GSAE01/src/\S+\.o)',
                          open(os.path.join(ROOT, 'build.ninja')).read()))

    image = {}
    for x in rep['units']:
        if not (x.get('metadata') or {}).get('auto_generated'):
            continue
        big = max(x['sections'], key=lambda s: int(s.get('size', 0) or 0))
        if big['name'] != sec:
            continue
        p = os.path.join(ROOT, 'build/GSAE01/obj', x['name'].split('/')[-1] + '.o')
        base = int(re.search(r'_([0-9A-Fa-f]{8})_', x['name']).group(1), 16)
        for i, b in enumerate(sec_bytes(p, sec)):
            image[base + i] = b

    refby = defaultdict(set)
    for x in rep['units']:
        if (x.get('metadata') or {}).get('auto_generated'):
            continue
        rel = x['name'].split('/', 1)[1]
        tgt = os.path.join(ROOT, 'build/GSAE01/obj', rel + '.o')
        if not os.path.exists(tgt):
            continue
        out = subprocess.run([OBJDUMP, '-r', tgt], capture_output=True, text=True).stdout
        for m in re.finditer(r'R_PPC\S+\s+(\S+)', out):
            n = m.group(1).split('+')[0]
            if n in sym and sym[n][0] == sec and unclaimed(sym[n][1]):
                refby[n].add(rel)

    sole = defaultdict(list)
    for n, us in refby.items():
        if len(us) == 1:
            sole[next(iter(us))].append((sym[n][1], sym[n][2]))

    shared = sum(sym[n][2] for n, us in refby.items() if len(us) > 1)
    print(f"unclaimed {sec} symbols referenced by retail: {len(refby)}")
    print(f"  shared by >1 unit (merged TU, unassignable): {shared} B")
    print()

    wins = []
    for u, lst in sorted(sole.items()):
        src = 'build/GSAE01/src/' + u + '.o'
        if src not in live:
            continue
        ours = sec_bytes(os.path.join(ROOT, src), sec)
        if not ours:
            continue
        lst.sort()
        lo, hi = lst[0][0], lst[-1][0] + lst[-1][1]
        if any(lo <= sym[n][1] < hi and u not in us for n, us in refby.items()):
            continue
        if hi - lo != len(ours):
            continue
        retail = bytes(image[lo + i] for i in range(len(ours))) \
            if all(lo + i in image for i in range(len(ours))) else None
        if retail == ours:
            wins.append((u, lo, hi))

    if not wins:
        print("No claimable range: every sole-owned run fails size parity or byte equality.")
        print("This is the expected steady state - our pools are short because the owning")
        print("unit's code is not fully decompiled. Re-run as functions land.")
        return
    print(f"CLAIMABLE ({len(wins)}):")
    for u, lo, hi in wins:
        print(f"  {u}")
        print(f"    add to splits.txt:  {sec:<11s} start:0x{lo:08X} end:0x{hi:08X}   ({hi-lo} B)")
        prev = [c for c in cl[sec] if c[1] <= lo]
        nxt = [c for c in cl[sec] if c[0] >= hi]
        if prev:
            print(f"    prev claim 0x{prev[-1][0]:08X}..0x{prev[-1][1]:08X} {prev[-1][2]}")
        if nxt:
            print(f"    next claim 0x{nxt[0][0]:08X}..0x{nxt[0][1]:08X} {nxt[0][2]}")


if __name__ == "__main__":
    main()
