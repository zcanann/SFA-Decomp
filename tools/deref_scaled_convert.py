#!/usr/bin/env python3
"""Element-scaled struct deref converter: handles `*(T*)(var + K)` and
`var[K]` where var is a non-byte pointer (int*/s16*), mapping byte offset
K*esize through a parsed struct.

Usage: scaled_convert.py <file.c> <header> <Struct> <esize> <var> [var...]
"""
import re, sys, collections

SIZES = {'u8':1,'s8':1,'char':1,'undefined':1,'byte':1,'bool':1,'undefined1':1,
         'u16':2,'s16':2,'short':2,'ushort':2,'undefined2':2,
         'u32':4,'s32':4,'int':4,'uint':4,'f32':4,'float':4,'long':4,'ulong':4,
         'undefined4':4,'f64':8,'double':8}
CLASS_OF = {'f32':'F32','float':'F32','int':'S32','s32':'S32','u32':'U32','uint':'U32',
            'undefined4':'S32','long':'S32','ulong':'U32',
            's16':'S16','short':'S16','u16':'U16','ushort':'U16','undefined2':'U16',
            's8':'S8','u8':'U8','char':'S8','byte':'U8','undefined':'U8','undefined1':'U8'}
SIZE = {'F32':4,'S32':4,'U32':4,'PTR':4,'S16':2,'U16':2,'S8':1,'U8':1}

path, header, sname, esize_s = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
varnames = sys.argv[5:]
esize = int(esize_s)

htxt = open(header, errors='ignore').read()
for dm in re.finditer(r'^#define\s+(\w+)\s+(0[xX][0-9a-fA-F]+|\d+)\s*$', htxt, re.M):
    htxt = re.sub(r'\b%s\b' % dm.group(1), dm.group(2), htxt)

field_re = re.compile(r'^\s*(?:struct\s+)?(\w+)\s*(\*?)\s*(\w+)\s*(?:\[([^\]]+)\])?\s*;')
struct_re = re.compile(r'typedef struct (\w+)\s*\{(.*?)\}\s*\w*\s*;', re.S)

def evaldim(a):
    toks = re.findall(r'0[xX][0-9a-fA-F]+|\d+', a)
    norm = a
    for t in toks:
        norm = norm.replace(t, str(int(t, 0)), 1)
    if not re.fullmatch(r'[0-9 +\-*()]+', norm.strip()):
        raise ValueError(a)
    return int(eval(norm))

def parse(body, structs):
    off, fields = 0, []
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    for line in body.split('\n'):
        line = line.split('//')[0].split('/*')[0].strip()
        if not line:
            continue
        m = field_re.match(line)
        if not m:
            if line and not line.startswith('}'):
                return None
            continue
        t, ptr, fname, a1 = m.groups()
        if ptr:
            size = align = 4
        elif t in SIZES:
            size = align = SIZES[t]
        elif t in structs and structs[t]:
            flds = structs[t]
            size = flds[-1][0] + flds[-1][3]
            align = 4
        else:
            return None
        try:
            count = evaldim(a1) if a1 else 1
        except ValueError:
            return None
        off = (off + align - 1) & ~(align - 1)
        cls = 'ARR' if count != 1 else ('PTR' if ptr else CLASS_OF.get(t))
        fields.append((off, fname, t + ('*' if ptr else ''), size, cls))
        off += size * count
    return fields

structs = {}
for _ in range(2):
    for m in struct_re.finditer(htxt):
        if m.group(1) not in structs or structs[m.group(1)] is None:
            structs[m.group(1)] = parse(m.group(2), structs)
if not structs.get(sname):
    sys.exit('ERROR: could not parse %s' % sname)

M = {}
def flatten(name, base, prefix):
    for off, fname, ty, size, cls in structs[name]:
        low = fname.lower()
        base_ty = ty.rstrip('*')
        if cls is None and not ty.endswith('*') and structs.get(base_ty):
            flatten(base_ty, base + off, prefix + fname + '.')
        elif 'pad' not in low and cls not in (None, 'ARR'):
            M[base + off] = (prefix + fname, cls, ty)
flatten(sname, 0, '')

src = open(path, encoding='latin-1').read()
stats = collections.Counter()
ECLS = {4: 'S32', 2: 'S16', 1: 'S8'}

for var in varnames:
    def drepl(m, var=var):
        ty = re.sub(r'\s+', ' ', m.group(1).strip())
        off = int(m.group(2), 0) * esize
        cls = 'PTR' if ty.endswith('*') else CLASS_OF.get(ty)
        if cls is None or off not in M:
            stats['skip'] += 1
            return m.group(0)
        name, fcls, fty = M[off]
        mem = '((%s *)%s)->%s' % (sname, var, name)
        if cls == 'PTR' and ty != fty and ty != 'void *':
            if fty != 'void *' or m.string[max(0, m.start()-1)] == '*':
                stats['launder'] += 1
                return '*(%s*)&%s' % (ty, mem)
        if cls == fcls:
            stats['member'] += 1
            return mem
        if SIZE.get(cls) == SIZE.get(fcls):
            stats['launder'] += 1
            return '*(%s *)&%s' % (ty, mem)
        stats['skip_size'] += 1
        return m.group(0)
    src = re.sub(r'\*\(\s*([A-Za-z0-9_]+(?:\s*\*+)?)\s*\*\)\s*\(\s*%s\s*\+\s*'
                 r'(0x[0-9a-fA-F]+|\d+)\s*\)' % re.escape(var), drepl, src)

    def irepl(m, var=var):
        off = int(m.group(1), 0) * esize
        ecls = ECLS[esize]
        if off not in M:
            stats['skip_idx'] += 1
            return m.group(0)
        name, fcls, fty = M[off]
        if SIZE.get(fcls) != esize:
            stats['skip_idx_size'] += 1
            return m.group(0)
        mem = '((%s *)%s)->%s' % (sname, var, name)
        if fcls == ecls:
            stats['member'] += 1
            return mem
        stats['launder'] += 1
        return '*(%s *)&%s' % ({4: 'int', 2: 's16', 1: 's8'}[esize], mem)
    src = re.sub(r'\b%s\[(0x[0-9a-fA-F]+|\d+)\]' % re.escape(var), irepl, src)

open(path, 'w', encoding='latin-1', newline='').write(src)
print(dict(stats))
