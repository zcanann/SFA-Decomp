#!/usr/bin/env python3
"""Compare two .o files: PASS if byte-identical everywhere except that
local @NNN symbol name strings in .strtab may differ in their digits.
Usage: check_o.py baseline.o new.o   -> exit 0 PASS / 1 FAIL"""
import sys, re, struct

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

a, b = sections(sys.argv[1]), sections(sys.argv[2])
if set(a) != set(b):
    print('FAIL: section sets differ'); sys.exit(1)
ok = True
for nm in a:
    if a[nm] == b[nm]:
        continue
    if nm == '.strtab':
        # mask @NNN names: split on NUL, compare token-by-token
        ta, tb = a[nm].split(b'\0'), b[nm].split(b'\0')
        if len(ta) != len(tb):
            print('FAIL: .strtab token count differs'); ok = False; continue
        for x, y in zip(ta, tb):
            if x != y and not (re.fullmatch(rb'@\d+', x) and re.fullmatch(rb'@\d+', y)):
                print('FAIL: .strtab non-@NNN diff: %r vs %r' % (x, y)); ok = False
    else:
        n = min(len(a[nm]), len(b[nm]))
        first = next((i for i in range(n) if a[nm][i] != b[nm][i]), n)
        print('FAIL: section %s differs (len %d vs %d, first diff @0x%x)' % (nm, len(a[nm]), len(b[nm]), first))
        ok = False
print('PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
