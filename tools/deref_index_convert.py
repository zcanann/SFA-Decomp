#!/usr/bin/env python3
"""Convert obj[K] element-indexed GameObject accesses to member access.

Usage: index_convert.py <file.c> <var> [var...]

Per-function: reads the var's decl (param or local) to get the element
size (int*/u32* = 4, s16*/u16* = 2, u8*/s8*/char* = 1); byte offset =
K * esize, mapped through the GameObject offset table. The emitted
member form is decl-type independent. Read-modify-write (obj[K] |= x)
and address-of (&obj[K]) sites convert too; unmapped offsets stay raw.
"""
import re, sys, collections

src_tool = open('tools/deref_convert_gameobject.py', encoding='latin-1').read()
GO = eval(re.search(r'GO = (\{.*?\n\})', src_tool, re.S).group(1))

W = {'F32': ('f32', 4), 'S32': ('s32', 4), 'U32': ('u32', 4), 'PTR': (None, 4),
     'S16': ('s16', 2), 'U16': ('u16', 2), 'S8': ('s8', 1), 'U8': ('u8', 1)}
ESIZE = {'int': 4, 'u32': 4, 's32': 4, 'uint': 4, 'f32': 4,
         's16': 2, 'u16': 2, 'short': 2, 'ushort': 2,
         'u8': 1, 's8': 1, 'char': 1, 'byte': 1}

path = sys.argv[1]
varnames = sys.argv[2:]
src = open(path, encoding='latin-1').read()
lines = src.split('\n')
stats = collections.Counter()

defre = re.compile(r'^[A-Za-z_][\w \t\*]*?\b\w+\s*\(')

def fn_blocks():
    i = 0
    while i < len(lines):
        if defre.match(lines[i]) and not lines[i].lstrip().startswith(('typedef', '#', 'extern')):
            j = i
            bad = False
            while j < len(lines) and '{' not in lines[j]:
                if ';' in lines[j]:
                    bad = True
                    break
                j += 1
            if bad or j >= len(lines) or ';' in lines[j].split('{')[0]:
                i += 1
                continue
            depth, k = 0, j
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0 and k >= j:
                    break
                k += 1
            yield (i, k)
            i = k + 1
        else:
            i += 1

for s, e in list(fn_blocks()):
    body = '\n'.join(lines[s:e+1])
    for var in varnames:
        decls = {d for d in re.findall(r'\b(\w+)\s*\*\s*%s\s*[,;=)]' % re.escape(var), body)
                 if d in ESIZE}
        if len(decls) != 1:
            continue
        dtype = decls.pop()
        esize = ESIZE[dtype]
        CLS = {'int': 'S32', 's32': 'S32', 'u32': 'U32', 'uint': 'U32', 'f32': 'F32',
               's16': 'S16', 'short': 'S16', 'u16': 'U16', 'ushort': 'U16',
               'u8': 'U8', 's8': 'S8', 'char': 'S8', 'byte': 'U8'}
        ecls = CLS[dtype]

        def repl(m, var=var, esize=esize, ecls=ecls, dtype=dtype):
            k = int(m.group(1), 0)
            off = k * esize
            if off not in GO:
                stats['skip'] += 1
                return m.group(0)
            name, fcls = GO[off]
            tyname, fw = W[fcls]
            if fw != esize:
                stats['skip_width'] += 1
                return m.group(0)
            mem = '((GameObject *)%s)->%s' % (var, name)
            if fcls == ecls:
                stats['member'] += 1
                return mem
            # width matches, class differs (PTR vs int, signedness):
            # launder through the decl's element type
            stats['launder'] += 1
            return '*(%s *)&%s' % (dtype, mem)

        new = re.sub(r'\b%s\[(0x[0-9a-fA-F]+|\d+)\]' % re.escape(var), repl, body)
        if new != body:
            body = new
    nb = body.split('\n')
    lines[s:e+1] = nb

open(path, 'w', encoding='latin-1', newline='').write('\n'.join(lines))
print(dict(stats))
