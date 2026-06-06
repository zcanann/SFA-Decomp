#!/usr/bin/env python3
"""Compare two .o files: PASS if byte-identical everywhere except that
local @NNN symbol name strings in .strtab may differ in their digits.

Usage: check_o.py baseline.o current.o [--rebuild [ninja-root]]

--rebuild closes the stale-.o false-PASS hole (a failed compile leaves
the previous .o on disk, which then md5-matches the baseline): the tool
DELETES current.o, runs `ninja <current.o>` from ninja-root (default:
cwd), and FAILS LOUDLY if the build errors or the .o does not reappear -
only then does it compare. Always use --rebuild when gating a fresh
edit; the bare 2-arg form is for comparing already-verified artifacts.
exit 0 PASS / 1 FAIL"""
import sys, re, struct, os, subprocess

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
    raw = {}
    for name, typ, offset, size in secs:
        nm = shstr[name:shstr.index(b'\0', name)].decode()
        out[nm] = d[offset:offset+size] if typ != 8 else b''  # SHT_NOBITS
        raw[nm] = (typ, offset, size)
    # resolve symtab: list of (resolved-name, rest-of-entry-fields)
    if '.symtab' in out and '.strtab' in out:
        st, sb = out['.symtab'], out['.strtab']
        syms = []
        for i in range(0, len(st), 16):
            name_off, value, size_, info, other, shndx = struct.unpack('>IIIBBH', st[i:i+16])
            nm = sb[name_off:sb.index(b'\0', name_off)].decode('latin-1', 'replace')
            syms.append((nm, value, size_, info, other, shndx))
        out['__symbols__'] = syms
    return out

base_p, cur_p = sys.argv[1], sys.argv[2]
if '--rebuild' in sys.argv:
    i = sys.argv.index('--rebuild')
    root = sys.argv[i+1] if len(sys.argv) > i+1 else os.getcwd()
    rel = os.path.relpath(cur_p, root)
    if os.path.exists(cur_p):
        os.unlink(cur_p)
    r = subprocess.run(['ninja', rel], cwd=root, capture_output=True, text=True, timeout=600)
    out = r.stdout + r.stderr
    # \berror\b avoids false-positives on filenames like OSError.c in benign WARN lines
    err_re = re.compile(r'(?i)\berror\b')
    if r.returncode != 0 or 'FAILED' in out or err_re.search(out):
        print('FAIL: rebuild of %s errored (exit %d)' % (rel, r.returncode))
        for ln in out.splitlines():
            if 'FAILED' in ln or err_re.search(ln):
                print('  ' + ln.strip())
        sys.exit(1)
    if not os.path.exists(cur_p):
        print('FAIL: %s missing after rebuild - build did not produce it' % cur_p)
        sys.exit(1)
a, b = sections(base_p), sections(cur_p)
if set(a) != set(b):
    print('FAIL: section sets differ'); sys.exit(1)
ok = True
for nm in a:
    if a[nm] == b[nm]:
        continue
    if nm == '__symbols__':
        sa, sb_ = a[nm], b[nm]
        if len(sa) != len(sb_):
            print('FAIL: symbol count differs'); ok = False; continue
        for x, y in zip(sa, sb_):
            if x == y: continue
            # allow local @NNN name changes only; all other fields must match
            if x[1:] == y[1:] and re.fullmatch(r'@\d+', x[0]) and re.fullmatch(r'@\d+', y[0]):
                continue
            print('FAIL: symbol diff: %r vs %r' % (x, y)); ok = False
        continue
    if nm == '.symtab':
        # byte diffs here are acceptable IFF __symbols__ (resolved view) passes;
        # the st_name offsets legitimately shift when @NNN digit counts change
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
