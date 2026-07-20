"""Register-blind + raw diff in one pass: separates a permutation cap from real structure.

ndiff matches instruction TEXT, so under a whole-function register rotation it aligns
unrelated instructions by coincidence and manufactures phantom structural regions. That
has produced a wrong verdict five times, including a false "14 structural lines"
correction to a correct "purely permutation-capped" call.

Running both diffs together makes the distinction immediate: dll_0B_func04 is 627/627
instructions with 17 register-blind divergences against 366 raw -- i.e. permutation, not
structure. A function with real structural work shows a REGBLIND count near its RAW count.

That heuristic is only valid because REGBLIND also canonicalizes POOL RELOCATION NAMES.
It did not, until it had already misdispatched a lane: Effect3_func04 read 188 RAW / 174
REGBLIND -- "real structural work", the highest-ranked open target -- when every one of
the 188 was an anonymous @N on our side against a compiler-named lbl_/jumptable_ on
retail's. Byte-level truth was 14 register-field bits in an otherwise byte-perfect stream.
With pool names folded it reads 188 / 4.

A RELOC line that still differs under REGBLIND is therefore a genuine symbol disagreement
and worth reading -- but note the converse is NOT a defect to fix: retail naming a .sdata2
float that we emit anonymously is the documented phantom (CLAUDE.md), and is almost always
already byte-identical. Confirm against the section bytes before believing it.

Usage:  python3 tools/sdiff.py <unit> <symbol>
        unit accepts either form: "main/shader.c" or "main/main/shader"
"""
import re
import subprocess
import sys
import difflib

BRANCH = re.compile(r'^(b|ba|bl|bla|bc|bca|bcl|bdnz|bdz|b[a-z]{1,3}[+-]?)\s')


def pool_float_syms(path='config/GSAE01/symbols.txt'):
    """Names of 4-byte .sdata2 floats -- i.e. pool constants that happen to carry a
    project-given name (gMoonRockPi) rather than a compiler-style one (lbl_803DF9D0).
    Folding only the compiler-style spellings still let 13 of 16 named-pool relocs read
    as structural work and re-promoted a capped function. Classify by SECTION AND TYPE,
    not by how the name looks."""
    out = set()
    try:
        with open(path) as f:
            for l in f:
                if '.sdata2:' not in l or 'data:float' not in l:
                    continue
                if not re.search(r'size:0x4\b', l):
                    continue
                out.add(l.split('=')[0].strip())
    except OSError:
        pass
    return out


POOL_FLOATS = pool_float_syms()
POOL_FOLDED = []


def norm_unit(u):
    """Accept the report.json name ("main/main/shader") or the source path
    ("main/shader.c"). function_objdump.py wants the source-path form."""
    if u.endswith('.c'):
        return u
    parts = u.split('/')
    if len(parts) > 1 and parts[0] == parts[1]:
        parts = parts[1:]
    return '/'.join(parts) + '.c'


def insns(s, blind):
    out = []
    for l in s.split('\n'):
        m = re.match(r'\s+[0-9a-f]+:\t(?:[0-9a-f]{2} ){4}\t(.*)', l)
        if m:
            t = re.sub(r'<.*', '', m.group(1)).strip()
            # A branch's target address is position-dependent noise: normalize the whole
            # operand regardless of digit count. Matching on digit width alone (the old
            # {4,}) left short targets like "bl f10" unnormalized while normalizing
            # retail's longer ones, inflating the divergence count with formatting noise.
            if BRANCH.match(t):
                op, _, _ = t.partition(' ')
                t = op + ' A'
            else:
                t = re.sub(r'\b(0x)?[0-9a-f]{4,}\b', 'A', t)
            if blind:
                t = re.sub(r'\br\d+\b', 'R', t)
                t = re.sub(r'\bf\d+\b', 'F', t)
            out.append(t)
        elif 'R_PPC' in l:
            sym = l.split()[-1]
            # A pool constant is an anonymous @N on our side and a compiler-named
            # lbl_/jumptable_ on retail's. That is a NAMING difference, not a
            # structural one, and it survived register-blindness -- making a
            # function whose 188 diffs were ALL pool names read as "real
            # structural work" and misdispatching a whole lane at it.
            if blind:
                if sym in POOL_FLOATS:
                    # Folding every named .sdata2 float would also HIDE a genuine
                    # wrong-constant reference (ours cites gFooScale, retail gBarScale).
                    # Fold, but count it so the caller is told to confirm against the
                    # section bytes rather than silently trusting a clean REGBLIND.
                    POOL_FOLDED.append(sym)
                    sym = 'POOL'
                else:
                    sym = re.sub(
                        r'^(@\d+|lbl_[0-9A-Fa-f]{6,}|jumptable_[0-9A-Fa-f]{6,})$',
                        'POOL', sym)
            out.append('RELOC ' + sym)
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    unit, sym = norm_unit(sys.argv[1]), sys.argv[2]
    r = subprocess.run(['python3', 'tools/function_objdump.py', unit, sym],
                       capture_output=True, text=True)
    if '===== current' not in r.stdout:
        print("function_objdump gave no paired output for %s :: %s" % (unit, sym))
        if r.stderr.strip():
            print(r.stderr.strip()[:400])
        return 1
    tgt, cur = r.stdout.split('===== current')

    for blind in (False, True):
        T, C = insns(tgt, blind), insns(cur, blind)
        sm = difflib.SequenceMatcher(a=T, b=C, autojunk=False)
        n = 0
        regions = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            n += max(i2 - i1, j2 - j1)
            regions.append((tag, T[i1:i2], C[j1:j2]))
        print(('REGBLIND' if blind else 'RAW'), 'target', len(T), 'cur', len(C), 'diff', n)
        if blind and POOL_FOLDED:
            u = sorted(set(POOL_FOLDED))
            print('  note: folded %d named .sdata2 float reloc(s) as pool naming (%s).'
                  % (len(u), ', '.join(u[:6]) + ('...' if len(u) > 6 else '')))
            print('  a clean REGBLIND here assumes the pool CONTENT matches -- confirm'
                  ' the .sdata2 section bytes before calling this function capped.')
        if blind:
            if not regions:
                print('  (pure register permutation -- no structural work available)')
            for tag, a, b in regions:
                print(' ', tag, 'T:', a, '\n      C:', b)
    return 0


if __name__ == '__main__':
    sys.exit(main())
