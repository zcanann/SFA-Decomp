#!/usr/bin/env python3
"""Find Ghidra-style offset derefs that can be replaced with typed struct access.

Parses every `typedef struct` in include/ + src/main/ to compute field offsets
(sequential layout, natural alignment), drops any struct whose computed offsets
contradict a STATIC_ASSERT(offsetof(...)) anywhere in the tree, then scans each
.c function (scope-aware: variable types reset per function) for
`*(T *)((u8|char|int *)var + 0xNN)` derefs where `var` is declared with a parsed
struct type and 0xNN lands on a named (non-pad/unk) field.

Only hits where the deref width/signedness matches the field type are safe to
replace byte-exactly; TYPEDIFF hits need manual review (lha/lhz, cmpwi/cmplwi).

Usage: python3 tools/offset_deref_scan.py [path-substring-filter]
"""
import re, glob, sys

SIZES = {'u8':1,'s8':1,'char':1,'undefined':1,'bool':1,
         'u16':2,'s16':2,'short':2,'ushort':2,'undefined2':2,
         'u32':4,'s32':4,'int':4,'uint':4,'f32':4,'float':4,'long':4,'ulong':4,'undefined4':4,
         'f64':8,'double':8}
TYPEMAP = {'u8':('u8','char','undefined'),'s8':('s8','char'),'u16':('u16','ushort'),
           's16':('s16','short'),'u32':('u32','uint'),'s32':('s32','int'),
           'int':('int','s32'),'f32':('f32','float')}

struct_re = re.compile(r'typedef struct (\w+)\s*\{(.*?)\}\s*\w*\s*;', re.S)
field_re = re.compile(r'^\s*(?:struct\s+)?(\w+)\s*(\*?)\s*(\w+)\s*(?:\[([^\]]+)\])?\s*(?:\[([^\]]+)\])?\s*;')
assert_re = re.compile(r'STATIC_ASSERT\(offsetof\((\w+),\s*(\w+)\)\s*==\s*(0[xX][0-9a-fA-F]+|\d+)\)')
decl_re = re.compile(r'\b(\w+) \*\s*(\w+)\s*[=;,)]')
deref_re = re.compile(r'\*\((u8|s8|u16|s16|u32|s32|int|uint|f32|float|char) \*\)\s*'
                      r'\(\s*(?:\((?:u8|char|int) \*\)\s*)?(\w+) \+ (0[xX][0-9a-fA-F]+|\d+)\)')
fn_re = re.compile(r'^[a-zA-Z_][\w\* ]*[ \*](\w+)\(')


def parse_struct(body, structs):
    off = 0
    fields = []
    for line in body.split('\n'):
        line = line.split('//')[0].split('/*')[0].strip()
        if not line:
            continue
        if ':' in line and '[' not in line:
            return None  # bitfields unsupported
        m = field_re.match(line)
        if not m:
            if line and not line.startswith('}'):
                return None
            continue
        t, ptr, fname, a1, a2 = m.groups()
        if ptr:
            size, align = 4, 4
        elif t in SIZES:
            size = align = SIZES[t]
        elif t in structs and structs[t]:
            flds = structs[t]
            size = flds[-1][0] + flds[-1][3]
            align = 4
        else:
            return None
        count = 1
        for a in (a1, a2):
            if a:
                try:
                    count *= int(a, 0)
                except ValueError:
                    return None
        off = (off + align - 1) & ~(align - 1)
        fields.append((off, fname, t + ('*' if ptr else ''), size))
        off += size * count
    return fields


def main():
    filt = sys.argv[1] if len(sys.argv) > 1 else ''
    files = [f for f in glob.glob('include/**/*.h', recursive=True)
             + glob.glob('src/main/**/*.[ch]', recursive=True)
             if 'reference_projects' not in f]

    structs = {}
    for _ in range(2):  # two passes for nested structs
        for fn in files:
            txt = open(fn, errors='ignore').read()
            for m in struct_re.finditer(txt):
                if m.group(1) not in structs or structs[m.group(1)] is None:
                    structs[m.group(1)] = parse_struct(m.group(2), structs)
    structs = {k: v for k, v in structs.items() if v}

    for fn in files:
        txt = open(fn, errors='ignore').read()
        for m in assert_re.finditer(txt):
            s, f, o = m.group(1), m.group(2), int(m.group(3), 0)
            if s in structs:
                d = {fl[1]: fl[0] for fl in structs[s]}
                if f in d and d[f] != o:
                    del structs[s]  # computed layout contradicts ground truth

    total = 0
    for c in sorted(glob.glob('src/main/**/*.c', recursive=True)):
        if 'autos' in c or filt not in c:
            continue
        lines = open(c, errors='ignore').read().split('\n')
        vartype = {}
        curfn = '?'
        out = []
        for i, l in enumerate(lines):
            fm = fn_re.match(l)
            if fm and not l.rstrip().endswith(';'):
                curfn = fm.group(1)
                vartype = {}
            for m in decl_re.finditer(l):
                if m.group(1) in structs:
                    vartype[m.group(2)] = m.group(1)
            for m in deref_re.finditer(l):
                t, v, off = m.group(1), m.group(2), int(m.group(3), 0)
                if v not in vartype:
                    continue
                for fo, fname, ft, fsz in structs[vartype[v]]:
                    if fo == off and 'pad' not in fname.lower() and 'unk' not in fname.lower():
                        ok = ft in TYPEMAP.get(t, (t,))
                        out.append((i + 1, curfn, v, vartype[v], hex(off), fname, ft, t,
                                    'TYPEOK' if ok else 'TYPEDIFF'))
        if out:
            total += len(out)
            print('=====', c)
            for o in out:
                print('   ', o)
    print('TOTAL', total)


if __name__ == '__main__':
    main()
