#!/usr/bin/env python3
"""Compare two .o files: PASS if link-equivalent.

Fast path: byte-identical everywhere except that local @NNN symbol name
strings in .strtab may differ in their digits (same-length renames).

Fallback (worker-engine): when @NNN renames change name LENGTH, .strtab
name offsets shift and .symtab bytes legitimately differ too. In that
case prove equivalence structurally via objdump: all other section
CONTENTS identical, symbol table identical modulo a consistent 1:1
@NNN rename (addresses/sizes/bindings/sections unchanged), relocations
identical with targets mapping through that rename.

Usage: deref_o_gate.py baseline.o new.o   -> exit 0 PASS / 1 FAIL"""
import sys, re, struct, subprocess, os

def _find_objdump():
    env = os.environ.get('SFA_OBJDUMP')
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, '..', 'build', 'binutils', 'powerpc-eabi-objdump'),
        os.path.join(here, '..', 'build', 'binutils', 'powerpc-eabi-objdump.exe'),
        '/home/jack/code/SFA-Decomp/build/binutils/powerpc-eabi-objdump',
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


OBJDUMP = _find_objdump()


def sections(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF'
    e_shoff, = struct.unpack('>I', d[0x20:0x24])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('>HHH', d[0x2e:0x34])
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack('>IIIIII', d[off:off+24])
        secs.append((name, typ, offset, size))
    shstr_off, shstr_size = secs[e_shstrndx][2], secs[e_shstrndx][3]
    shstr = d[shstr_off:shstr_off+shstr_size]
    out = {}
    for name, typ, offset, size in secs:
        nm = shstr[name:shstr.index(b'\0', name)].decode()
        out[nm] = d[offset:offset+size] if typ != 8 else b''  # SHT_NOBITS
    return out


def od(args):
    return subprocess.run([OBJDUMP] + args, capture_output=True, text=True).stdout


def dump_sections(p):
    out, cur, secs = od(['-s', p]), None, {}
    for line in out.splitlines():
        m = re.match(r'Contents of section (\S+):', line)
        if m:
            cur = m.group(1); secs[cur] = []
        elif cur:
            secs[cur].append(line)
    return secs


def dump_syms(p):
    rows = []
    for line in od(['-t', p]).splitlines():
        m = re.match(r'([0-9a-f]{8})\s+(\S+)\s+(\S*)\s*(\S+)\s+([0-9a-f]{8})\s+(\S+)', line)
        if m:
            rows.append(m.groups())
    return rows


def dump_relocs(p):
    rows = []
    for line in od(['-r', p]).splitlines():
        m = re.match(r'([0-9a-f]{8})\s+(\S+)\s+(\S+)', line)
        if m:
            rows.append(m.groups())
    return rows


def structural_check(old, new):
    """Full objdump-level equivalence modulo consistent @NNN renames."""
    problems = []
    a, b = dump_sections(old), dump_sections(new)
    if set(a) != set(b):
        problems.append('section set differs: %r' % (set(a) ^ set(b)))
    for s in a:
        if s in ('.symtab', '.strtab', '.shstrtab'):
            continue
        if a.get(s) != b.get(s):
            problems.append('section %s contents differ' % s)
    sa, sb = dump_syms(old), dump_syms(new)
    ren = {}
    if len(sa) != len(sb):
        problems.append('symbol count differs %d vs %d' % (len(sa), len(sb)))
    else:
        for ra, rb in zip(sa, sb):
            if ra[:5] != rb[:5]:
                problems.append('symbol meta differs: %r vs %r' % (ra, rb))
            na, nb = ra[5], rb[5]
            if na != nb:
                if na.startswith('@') and nb.startswith('@'):
                    if ren.setdefault(na, nb) != nb:
                        problems.append('inconsistent rename %s -> %s / %s' % (na, ren[na], nb))
                else:
                    problems.append('symbol name differs: %r vs %r' % (na, nb))
    ra_, rb_ = dump_relocs(old), dump_relocs(new)
    if len(ra_) != len(rb_):
        problems.append('reloc count differs %d vs %d' % (len(ra_), len(rb_)))
    else:
        for x, y in zip(ra_, rb_):
            if x[0] != y[0] or x[1] != y[1]:
                problems.append('reloc meta differs: %r vs %r' % (x, y))
            tx = ren.get(x[2].split('+')[0], x[2].split('+')[0])
            if tx != y[2].split('+')[0]:
                problems.append('reloc target differs: %r vs %r' % (x, y))
    return problems, len(ren)


def main():
    old, new = sys.argv[1], sys.argv[2]
    a, b = sections(old), sections(new)
    if set(a) != set(b):
        print('FAIL: section sets differ'); sys.exit(1)
    ok = True
    name_table_only = True
    for nm in a:
        if a[nm] == b[nm]:
            continue
        if nm == '.strtab':
            ta, tb = a[nm].split(b'\0'), b[nm].split(b'\0')
            if len(ta) != len(tb):
                ok = False; continue
            for x, y in zip(ta, tb):
                if x != y and not (re.fullmatch(rb'@\d+', x) and re.fullmatch(rb'@\d+', y)):
                    print('FAIL: .strtab non-@NNN diff: %r vs %r' % (x, y))
                    ok = False; name_table_only = False
        elif nm == '.symtab':
            ok = False  # may be a name-offset shift from @NNN length change
        else:
            n = min(len(a[nm]), len(b[nm]))
            first = next((i for i in range(n) if a[nm][i] != b[nm][i]), n)
            print('FAIL: section %s differs (len %d vs %d, first diff @0x%x)'
                  % (nm, len(a[nm]), len(b[nm]), first))
            ok = False; name_table_only = False
    if ok:
        print('PASS'); sys.exit(0)
    if name_table_only and os.path.isfile(OBJDUMP):
        problems, nren = structural_check(old, new)
        if not problems:
            print('PASS (structural: %d local @NNN renames, all sections/symbols/relocs equivalent)' % nren)
            sys.exit(0)
        for p in problems[:20]:
            print('FAIL:', p)
    print('FAIL')
    sys.exit(1)


main()
