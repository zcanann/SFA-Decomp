"""Register-blind + raw diff in one pass: separates a permutation cap from real structure.

ndiff matches instruction TEXT, so under a whole-function register rotation it aligns
unrelated instructions by coincidence and manufactures phantom structural regions. That
has produced a wrong verdict five times, including a false "14 structural lines"
correction to a correct "purely permutation-capped" call.

Running both diffs together makes the distinction immediate: dll_0B_func04 is 627/627
instructions with 17 register-blind divergences against 366 raw -- i.e. permutation, not
structure. A function with real structural work shows a REGBLIND count near its RAW count.

Usage:  python3 tools/sdiff.py <unit> <symbol>
        unit accepts either form: "main/shader.c" or "main/main/shader"
"""
import re
import subprocess
import sys
import difflib

BRANCH = re.compile(r'^(b|ba|bl|bla|bc|bca|bcl|bdnz|bdz|b[a-z]{1,3}[+-]?)\s')


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
            out.append('RELOC ' + l.split()[-1])
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
        if blind:
            if not regions:
                print('  (pure register permutation -- no structural work available)')
            for tag, a, b in regions:
                print(' ', tag, 'T:', a, '\n      C:', b)
    return 0


if __name__ == '__main__':
    sys.exit(main())
