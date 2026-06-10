#!/usr/bin/env python3
"""Generate a <Name> typedef in a TU from observed bytecast deref offsets.

Usage: gen_struct.py <file.c> <StructName> <size-or-0> <var> [var...]

Collects *(T*)((char|u8|s8*)var + N) offsets/widths, emits
  typedef struct Name { u8 pad00[..]; f32 unk10; ... } Name;
inserted after the last #include. Size 0 = round up to last field +
width, 8-aligned. Field types from the deref casts (first-seen wins,
wider wins on conflict). Layout is pads + scalars only - byte-exact by
construction; gate the consuming conversion as usual.
"""
import re, sys, collections

SIZES = {'u8':1,'s8':1,'char':1,'u16':2,'s16':2,'u32':4,'s32':4,'int':4,
         'uint':4,'f32':4,'float':4,'f64':8}
esize = 1
args = sys.argv[1:]
if '--esize' in args:
    i = args.index('--esize')
    esize = int(args[i+1])
    args = args[:i] + args[i+2:]
path, sname, size_s = args[0], args[1], args[2]
varnames = args[3:]
size = int(size_s, 0)

src = open(path, encoding='latin-1').read()
if 'typedef struct %s' % sname in src:
    print('ALREADY-DEFINED')
    sys.exit(0)
inner = r'\(\s*(?:char|u8|s8)\s*\*\)\s*' if esize == 1 else ''
deref_re = re.compile(r'\*\(\s*(u8|s8|u16|s16|u32|s32|int|uint|f32|float|char)\s*(\*?)\s*\*\)\s*'
                      r'\(\s*%s(%s)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)'
                      % (inner, '|'.join(re.escape(v) for v in varnames)))
wants = {}
for m in deref_re.finditer(src):
    t, ptr, off = m.group(1), m.group(2), int(m.group(4), 0) * esize
    if ptr:
        t, w = 'void*', 4
    else:
        w = SIZES[t]
        t = {'float':'f32','char':'s8','uint':'u32','int':'s32'}.get(t, t)
    if off % w:
        continue
    if off not in wants or wants[off][1] < w:
        wants[off] = (t, w)
if esize > 1:
    idx_re = re.compile(r'\b(%s)\[(0x[0-9a-fA-F]+|\d+)\]' % '|'.join(re.escape(v) for v in varnames))
    et = {4: 's32', 2: 's16'}[esize]
    for m in idx_re.finditer(src):
        off = int(m.group(2), 0) * esize
        if off not in wants:
            wants[off] = (et, esize)

if not wants:
    print('NO-SITES')
    sys.exit(0)
# drop overlapping smaller fields
items = sorted(wants.items())
clean, cur = [], 0
for off, (t, w) in items:
    if off < cur:
        continue
    clean.append((off, t, w))
    cur = off + w
end = clean[-1][0] + clean[-1][2]
if size == 0:
    size = (end + 7) & ~7
elif end > size:
    print('SITES BEYOND SIZE (end 0x%X > 0x%X)' % (end, size))
    sys.exit(1)

out = ['typedef struct %s {' % sname]
cur = 0
for off, t, w in clean:
    if off > cur:
        out.append('    u8 pad%X[0x%X - 0x%X];' % (cur, off, cur))
    if t == 'void*':
        out.append('    void *unk%X;' % off)
    else:
        out.append('    %s unk%X;' % (t, off))
    cur = off + w
if cur < size:
    out.append('    u8 pad%X[0x%X - 0x%X];' % (cur, size, cur))
out.append('} %s;' % sname)
block = '\n'.join(out) + '\n\n'

m = None
for m in re.finditer(r'^#include "[^"]*"\n', src, re.M):
    pass
ins = m.end() if m else 0
src = src[:ins] + '\n' + block + src[ins:]
open(path, 'w', encoding='latin-1', newline='').write(src)
print('GENERATED %s: %d fields, size 0x%X' % (sname, len(clean), size))
