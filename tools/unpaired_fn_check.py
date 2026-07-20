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

!! THE ONLY SOUND GATE IS THE DOL SHA. `build/GSAE01/main.dol` must equal
`orig/GSAE01/sys/main.dol` (e750e8e894707a52446118a4b84f1b58b677b269) -- the
gate value IS retail's DOL and a clean tree reproduces it byte-for-byte.

!! .text BYTE-IDENTITY AGAINST THE CARVED RETAIL .o IS *NOT* SUFFICIENT (w89).
For DLL units the carve UNDER-CLAIMS: `splits.txt` does not cover the
out-of-line copy, so the retail .o lacks it and our .text "matches" once the
copy is removed -- yet retail's main.dol DOES contain those bytes, and removing
them moves the DOL AWAY from retail. Eight units were taken to exact .text AND
.data AND .sdata2 parity with the carve this way and every one regressed the
DOL: hoodedzyck, dll_0105_largecrate, dll_011B_landedarwing, dll_01F6_flag,
dll_02A2_arwspeedstr, dll_0295_wcapertures, dll_01BE_dimlava,
dll_01F5_shipbattle (mikaladon is the same class). All reverted. For these the
unpaired symbol is a CARVE ARTIFACT, not a source defect -- leave them alone.

Where the fix IS correct: a unit linked into main.dol proper whose dead copy
mwld actually dead-strips, so removing it is DOL-neutral. Proven on hw_dspctrl
(complete=True, 4 helpers, .text 0x2fd0 -> exactly retail's 0x2e20, DOL
unmoved) and textrender. Note this REFUTES the older "NonMatching units only"
rule: hw_dspctrl is complete. Decide by measuring the DOL, not by the flag.

Necessary (not sufficient) precondition: ZERO `bl` to the symbol in our object,
i.e. every call site is already inlined, so caller codegen cannot move.

The fix is invisible to fuzzy in BOTH directions -- nine NonMatching units were
fixed here for a total fuzzy delta of 0.00000 -- so the DOL sha and the .text
size are the only instruments that see it.

!!!! .o BYTES ARE NOT DOL BYTES (w90). THIS IS THE LAW THIS TOOL EXISTS TO
ENFORCE. An unpaired symbol is nearly always an UNREFERENCED STATIC, and mwld
DEAD-STRIPS it: it never reaches main.elf and costs ZERO bytes in the shipped
binary. Ranking candidates by .o size -- as every earlier revision of this
screen did -- manufactures work that cannot pay. Measured tree-wide: of 35
ours-only symbols totalling 6,880 B, **34 (6,868 B) are deadstripped**. The one
apparent survivor was a NAME COLLISION (below). The real recoverable total is
ZERO. So this screen now classifies every candidate LIVE vs DEADSTRIPPED and
ranks by LIVE bytes only; deadstripped symbols are quarantined in a separate
zero-cost section and must never be read as recoverable.

!!!! LIVENESS MUST BE DECIDED BY ADDRESS, NOT BY NAME. A bare name lookup in
main.elf false-positives on generic static names. Concrete case: OSExec's local
`Callback` (0xc) "appeared" live, but the ELF's `Callback` at 0x80244594 is
OSReboot.o's own local of identical size, and 0x80244594 lies inside OSReboot's
split range, not OSExec's. A symbol counts as LIVE only when an ELF address
bearing that name falls INSIDE THE UNIT'S OWN .text split range.

!!!! .text BYTE-IDENTITY AGAINST THE CARVED RETAIL .o IS *NOT* SUFFICIENT --
a second, independent proof (w90). sal_volume's CalcBus/CalcBusDPL2 (836 B) were
`static inline`d: .text went 0xadc -> 0x798 BYTE-IDENTICAL to the carve, and
extab/extabindex went 0x18/0x24 -> exactly the claimed 0x8/0xC. Every structural
instrument read perfect -- and the DOL still MOVED (a9a6b41a). Cause: the
baseline .sdata2 was ALREADY byte-identical to retail (f0c07cc2) and inlining
perturbed the pool to ff838f. The 836 B had been deadstripped all along, so the
"fix" traded a correct pool for nothing. Reverted. Check EVERY section, and gate
on the DOL.

usage: python3 tools/unpaired_fn_check.py [unit-substring ...]
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, 'build/binutils/powerpc-eabi-objdump')
NM = os.path.join(ROOT, 'build/binutils/powerpc-eabi-nm')
ELF = os.path.join(ROOT, 'build/GSAE01/main.elf')
SPLITS = os.path.join(ROOT, 'config/GSAE01/splits.txt')

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


def elf_addrs():
    """name -> set of addresses defined in the linked ELF.

    A name may be defined more than once (distinct file-local statics), which is
    exactly why callers must disambiguate by address.
    """
    r = subprocess.run([NM, ELF], capture_output=True)
    if r.returncode != 0:
        sys.exit('FATAL: nm failed on %s -- cannot screen liveness.' % ELF)
    out = {}
    for line in r.stdout.decode('utf8', 'replace').splitlines():
        f = line.split()
        if len(f) != 3:
            continue
        try:
            addr = int(f[0], 16)
        except ValueError:
            continue
        out.setdefault(f[2], set()).add(addr)
    return out


def split_text_ranges():
    """source path (no extension) -> (start, end) of its .text claim."""
    out, cur = {}, None
    for line in open(SPLITS):
        m = re.match(r'^(\S+\.(?:c|cpp)):\s*$', line)
        if m:
            cur = os.path.splitext(m.group(1))[0]
            continue
        m = re.match(r'^\s*\.text\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)',
                     line)
        if m and cur:
            out[cur] = (int(m.group(1), 16), int(m.group(2), 16))
    return out


def unit_key(base_path):
    """objdiff base_path -> the splits.txt key, e.g. dolphin/os/OSExec."""
    p = base_path.replace('\\', '/')
    marker = 'build/GSAE01/src/'
    if marker in p:
        p = p.split(marker, 1)[1]
    return os.path.splitext(p)[0]


def is_live(name, rng, addrs):
    """LIVE iff an ELF address bearing this name lies in the unit's own range.

    Name-only matching is unsound -- see the OSExec/OSReboot `Callback`
    collision in the module docstring.
    """
    if rng is None:
        return False
    lo, hi = rng
    return any(lo <= a < hi for a in addrs.get(name, ()))


def positive_control(examined, addrs, ranges):
    """Fail loudly rather than reporting a vacuous zero.

    Several screens in this project have reported confident zeros through silent
    join bugs. These controls exercise the SAME lookup path the verdicts use, so
    a broken join cannot masquerade as 'nothing recoverable'.
    """
    errs = []
    if len(addrs) < 1000:
        errs.append('ELF symbol table looks empty (%d names) -- is main.elf '
                    'built?' % len(addrs))
    if len(ranges) < 100:
        errs.append('splits.txt .text ranges failed to parse (%d found).'
                    % len(ranges))

    # The load-bearing control: paired symbols of a unit that IS linked must
    # resolve LIVE inside that unit's own range. If none do, the
    # name->address->range join is broken and every DEADSTRIPPED verdict is junk.
    live_pairs = sum(1 for nm_, rng in examined if is_live(nm_, rng, addrs))
    if examined and live_pairs == 0:
        errs.append('join control FAILED: 0 of %d known-linked paired symbols '
                    'resolved LIVE in their own split range.' % len(examined))

    # Regression control for the collision bug: OSExec's `Callback` shares a
    # name with OSReboot's and must NOT be counted live.
    if 'dolphin/os/OSExec' in ranges and 'Callback' in addrs:
        if is_live('Callback', ranges['dolphin/os/OSExec'], addrs):
            errs.append('collision control FAILED: OSExec `Callback` counted '
                        'LIVE; address disambiguation is not working.')
    if errs:
        sys.exit('POSITIVE CONTROL FAILED -- results are NOT trustworthy:\n  '
                 + '\n  '.join(errs))
    return live_pairs


def main():
    filters = sys.argv[1:]
    units = json.load(open(os.path.join(ROOT, 'objdiff.json')))['units']
    addrs = elf_addrs()
    ranges = split_text_ranges()
    reports, control_syms, vacuous = [], [], []
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
        rng = ranges.get(unit_key(u['base_path']))
        extra = {k: v for k, v in osyms.items() if k not in rsyms}
        missing = {k: v for k, v in rsyms.items() if k not in osyms}
        # Paired symbols feed the join control: these ARE in retail, so for any
        # genuinely linked unit they must resolve LIVE in the unit's own range.
        control_syms.extend((k, rng) for k in osyms if k in rsyms)
        if not extra and not missing:
            continue
        delta = osize - rsize
        orel, rrel = reloc_targets(op), reloc_targets(rp)
        live = {k: v for k, v in extra.items() if is_live(k, rng, addrs)}
        dead = {k: v for k, v in extra.items() if k not in live}
        if rsize == 0:
            vacuous.append(name)
        reports.append(dict(
            name=name, osize=osize, rsize=rsize, delta=delta, rng=rng,
            live=live, dead=dead, missing=missing, orel=orel, rrel=rrel,
            live_bytes=sum(live.values()), dead_bytes=sum(dead.values())))

    positive_control(control_syms, addrs, ranges)

    def emit(r, show_live):
        pool = r['live'] if show_live else r['dead']
        verdict = 'ZERO-CLAIM' if r['rsize'] == 0 else (
            'EXACT' if sum(r['live'].values()) + sum(r['dead'].values())
            == r['delta'] else 'PARTIAL')
        print('\n=== %s' % r['name'])
        print('  .text ours=0x%x retail=0x%x delta=0x%x  live=0x%x dead=0x%x  [%s]'
              % (r['osize'], r['rsize'], r['delta'], r['live_bytes'],
                 r['dead_bytes'], verdict))
        if r['rsize'] == 0:
            print('    !! VACUOUS-100 LANDMINE: splits.txt claims a ZERO-LENGTH '
                  '.text range, so objdiff pairs nothing and the unit scores '
                  '100.0 having verified NOTHING. Not an inlining defect.')
        for k, v in sorted(pool.items(), key=lambda x: -x[1]):
            print('    OURS-ONLY   %-44s size=0x%-5x reloc ours=%s retail=%s'
                  % (k, v, 'Y' if k in r['orel'] else 'n',
                     'Y' if k in r['rrel'] else 'n'))
        for k, v in sorted(r['missing'].items(), key=lambda x: -x[1]):
            print('    RETAIL-ONLY %-44s size=0x%-5x  (we emit nothing for it)'
                  % (k, v))

    live_r = sorted([r for r in reports if r['live']],
                    key=lambda r: -r['live_bytes'])
    dead_r = sorted([r for r in reports if r['dead']],
                    key=lambda r: -r['dead_bytes'])

    print('#' * 72)
    print('# LIVE -- reach main.elf inside their own split range. REAL DOL bytes.')
    print('# These are the ONLY candidates that can pay. Gate on the DOL sha.')
    print('#' * 72)
    for r in live_r:
        emit(r, True)
    if not live_r:
        print('\n  (none -- no unpaired symbol reaches the linked binary)')

    print('\n\n' + '#' * 72)
    print('# DEADSTRIPPED -- ZERO DOL COST. NOT RECOVERABLE. DO NOT WORK THESE.')
    print('# mwld drops these unreferenced statics; they cost nothing shipped.')
    print('# Touching one can only LOSE (sal_volume traded a byte-correct')
    print('# .sdata2 pool for 836 B that were never in the binary).')
    print('#' * 72)
    for r in dead_r:
        emit(r, False)

    if vacuous:
        print('\n\n' + '#' * 72)
        print('# VACUOUS-100 LANDMINES: zero-length .text claim, objdiff pairs')
        print('# nothing, yet declared MatchingFor -- "100%" verifies NOTHING.')
        print('# Reporting defects, not byte defects: retail has no code at')
        print('# these addresses at all. A MatchingFor flip is NOT the fix --')
        print('# with no retail object to link instead it risks breaking the')
        print('# link for zero byte gain. Surfaced here deliberately.')
        print('#' * 72)
        for n in vacuous:
            print('  %s' % n)

    lb = sum(r['live_bytes'] for r in reports)
    db = sum(r['dead_bytes'] for r in reports)
    print('\n' + '-' * 72)
    print('units with unpaired .text symbols: %d' % len(reports))
    print('LIVE (real DOL bytes)   : %5d B in %d units' % (lb, len(live_r)))
    print('DEADSTRIPPED (zero cost): %5d B in %d units' % (db, len(dead_r)))
    print('.o BYTES ARE NOT DOL BYTES -- only the LIVE column can pay.')


if __name__ == '__main__':
    main()
