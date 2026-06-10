#!/usr/bin/env python3
"""Split state-struct pad arrays into named unkNNN fields for offsets that
a TU actually derefs, so deref_convert_struct can map them.

Usage: pad_extend.py [--deps h1,h2] <file.c> <header-with-struct> <StructName> <var> [var...]

--deps: extra headers parsed for nested struct SIZES only (not edited).

Only edits the struct definition inside <header-with-struct> (which may be
the .c itself). Layout is unchanged by construction (pad splits + same-width
fields); ALWAYS full-build gate afterwards.
Prints the edited header path on success.
"""
import re, sys, collections

SIZES = {'u8':1,'s8':1,'char':1,'u16':2,'s16':2,'u32':4,'s32':4,'int':4,
         'uint':4,'f32':4,'float':4,'f64':8}
FIELD_T = {1:'u8',2:'u16',4:'s32'}

argv = sys.argv[1:]
deps = []
if argv and argv[0] == '--deps':
    deps = argv[1].split(',')
    argv = argv[2:]
cfile, hfile, sname = argv[0], argv[1], argv[2]
varnames = argv[3:]

src = open(cfile, encoding='latin-1').read()
deref_re = re.compile(r'\*\(\s*(u8|s8|u16|s16|u32|s32|int|uint|f32|float|char)\s*\*\)\s*'
                      r'\(\s*(?:\(\s*(?:char|u8|s8|int)\s*\*\)\s*)?(%s)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)'
                      % '|'.join(re.escape(v) for v in varnames))
wants = {}  # off -> (width, type)
for m in deref_re.finditer(src):
    t, off = m.group(1), int(m.group(3), 0)
    w = SIZES[t]
    if off % w:
        continue
    if off not in wants or wants[off][0] < w:
        ftype = 'f32' if t in ('f32','float') else FIELD_T[w]
        wants[off] = (w, ftype)

hsrc = open(hfile, encoding='latin-1').read()
m = re.search(r'(typedef struct %s\s*\{)(.*?)(\}\s*\w*\s*;)' % re.escape(sname), hsrc, re.S)
if not m:
    sys.exit('struct %s not found in %s' % (sname, hfile))
body = m.group(2)

# walk fields computing offsets (same model as deref_convert_struct: natural alignment)
lines = body.split('\n')
out = []
off = 0
pad_re = re.compile(r'^(\s*)u8\s+(\w*pad\w*)\s*\[\s*([^\]]+)\s*\]\s*;(.*)$')
field_re = re.compile(r'^\s*(?:struct\s+)?(\w+)\s*(\*?)\s*(\w+)\s*(?:\[([^\]]+)\])?\s*;')

def evaldim(a):
    a = a.strip()
    toks = re.findall(r'0[xX][0-9a-fA-F]+|\d+', a)
    norm = a
    for t in toks:
        norm = norm.replace(t, str(int(t, 0)), 1)
    if not re.fullmatch(r'[0-9 +\-*()]+', norm):
        raise ValueError(a)
    return int(eval(norm))

# nested struct sizes from any header content already concatenated? handle only
# same-file structs defined earlier
known_structs = {}
dep_src = '\n'.join(open(d, errors='ignore').read() for d in deps) + '\n' + hsrc
for sm in re.finditer(r'typedef struct (\w+)\s*\{(.*?)\}\s*\w*\s*;', dep_src, re.S):
    if sm.group(1) == sname:
        continue
    sz = 0
    ok = True
    for line in re.sub(r'/\*.*?\*/', '', sm.group(2), flags=re.S).split('\n'):
        line = line.split('//')[0].strip()
        if not line:
            continue
        fm = field_re.match(line)
        if not fm:
            ok = False
            break
        t, ptr, fn_, a1 = fm.groups()
        unit = 4 if ptr else SIZES.get(t) or known_structs.get(t)
        if unit is None:
            ok = False
            break
        cnt = evaldim(a1) if a1 else 1
        al = min(unit, 4) if not ptr else 4
        sz = (sz + al - 1) & ~(al - 1)
        sz += unit * cnt
    if ok:
        known_structs[sm.group(1)] = sz

changed = False
for line in lines:
    stripped = line.split('//')[0].strip()
    pm = pad_re.match(line)
    if pm and stripped:
        indent, pname, dim, rest = pm.groups()
        try:
            n = evaldim(dim)
        except ValueError:
            out.append(line)
            continue
        lo, hi = off, off + n
        inside = sorted((o, w, t) for o, (w, t) in wants.items() if lo <= o and o + w <= hi)
        if not inside:
            out.append(line)
            off += n
            continue
        # split pad
        cur = lo
        segs = []
        for o, w, t in inside:
            if o < cur:
                continue  # overlap with previous new field
            if o % w:
                continue
            if o > cur:
                segs.append('%su8 pad%X[0x%X - 0x%X];' % (indent, cur, o, cur))
            segs.append('%s%s unk%X;' % (indent, t, o))
            cur = o + w
        if cur < hi:
            segs.append('%su8 pad%X[0x%X - 0x%X];' % (indent, cur, hi, cur))
        out.extend(segs)
        changed = True
        off += n
        continue
    fm = field_re.match(stripped) if stripped else None
    if fm:
        t, ptr, fname, a1 = fm.groups()
        unit = 4 if ptr else SIZES.get(t) or known_structs.get(t)
        if unit is None:
            sys.exit('unknown field type %r in %s at offset 0x%X' % (t, sname, off))
        cnt = evaldim(a1) if a1 else 1
        al = min(unit, 4) if not ptr else 4
        off = (off + al - 1) & ~(al - 1)
        off += unit * cnt
    out.append(line)

if not changed:
    print('NOCHANGE')
    sys.exit(0)
new = hsrc[:m.start(2)] + '\n'.join(out) + hsrc[m.end(2):]
open(hfile, 'w', encoding='latin-1', newline='').write(new)
print('EXTENDED %s (%d offsets wanted)' % (hfile, len(wants)))
