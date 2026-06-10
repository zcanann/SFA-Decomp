#!/usr/bin/env python3
"""Generic struct offset-deref -> member converter, gated by .o byte-identity.

Usage: deref_convert_struct.py <file.c> <header.h> <StructName> <var> [var...]

Parses StructName from <header.h> (sequential layout, natural alignment,
nested structs, bitfield-bearing structs skipped), builds an offset->(member,
type) map, then rewrites width-matched constant-offset derefs of the named
base variable(s) into ((StructName *)var)->member access. Width-matched-but-
type-differing sites are laundered (*(T *)&((StructName *)var)->member) to
preserve cmpwi/cmplwi/extsb behavior; pad/unk-covered or width-mismatched
sites stay raw. Pointer fields whose cast type differs, are chained-dereffed,
or are used in pointer arithmetic are laundered to keep the concrete type.

Same byte-neutral-by-construction contract as deref_convert_gameobject.py;
ALWAYS gate the result with tools/deref_o_gate.py against the baseline .o.
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

struct_re = re.compile(r'typedef struct (\w+)\s*\{(.*?)\}\s*\w*\s*;', re.S)
field_re = re.compile(r'^\s*(?:struct\s+)?(\w+)\s*(\*?)\s*(\w+)\s*(?:\[([^\]]+)\])?\s*(?:\[([^\]]+)\])?\s*;')


def _evaldim(a):
    """Evaluate a constant array-dimension expr (hex/dec, + - *)."""
    a = a.strip()
    if not re.fullmatch(r'[0-9a-fA-FxX +\-*]+', a):
        raise ValueError(a)
    toks = re.findall(r'0[xX][0-9a-fA-F]+|\d+', a)
    norm = a
    for t in toks:
        norm = norm.replace(t, str(int(t, 0)), 1)
    return int(eval(norm))


def parse_struct(body, structs):
    off, fields = 0, []
    bit_state = {'unit': 0, 'bits': 0}
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)  # strip block comments (multi-line)
    for line in body.split('\n'):
        line = line.split('//')[0].split('/*')[0].strip()
        if not line:
            continue
        bm = re.match(r'^\s*(\w+)\s+\w+\s*:\s*(\d+)\s*;', line)
        if bm and bm.group(1) in SIZES:
            # bitfield run: pack into units of the base type; fields stay
            # unmapped ('ARR') but offsets keep advancing for later fields
            unit = SIZES[bm.group(1)]
            if bit_state['unit'] != unit or bit_state['bits'] + int(bm.group(2)) > unit * 8:
                off = (off + unit - 1) & ~(unit - 1)
                fields.append((off, '__bits%X' % off, bm.group(1), unit, 'ARR'))
                off += unit
                bit_state['unit'], bit_state['bits'] = unit, 0
            bit_state['bits'] += int(bm.group(2))
            continue
        bit_state['unit'], bit_state['bits'] = 0, 0
        if ':' in line and '[' not in line:
            return None  # non-simple bitfield form
        m = field_re.match(line)
        if not m:
            if line and not line.startswith('}'):
                return None
            continue
        t, ptr, fname, a1, a2 = m.groups()
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
        count = 1
        for a in (a1, a2):
            if a:
                try:
                    count *= _evaldim(a)
                except Exception:
                    return None
        off = (off + align - 1) & ~(align - 1)
        # array fields can't be assigned/read as scalars - exclude from the
        # member map ('ARR' blocks both mapping and nested-struct recursion)
        cls = 'ARR' if count != 1 else ('PTR' if ptr else CLASS_OF.get(t))
        fields.append((off, fname, t + ('*' if ptr else ''), size, cls))
        off += size * count
    return fields


def main():
    # --include-unk: also map unkNNN-named fields (pads stay excluded), the
    # same policy deref_convert_gameobject.py uses for the GameObject tail.
    include_unk = '--include-unk' in sys.argv
    argv = [a for a in sys.argv if a != '--include-unk']
    path, header, sname = argv[1], argv[2], argv[3]
    varnames = argv[4:]
    htxt = open(header, errors='ignore').read()
    # substitute simple numeric #defines so macro array dims parse
    # (e.g. s16 randomHeadings[CHECKPOINT4_RANDOM_HEADING_COUNT])
    for dm in re.finditer(r'^#define\s+(\w+)\s+(0[xX][0-9a-fA-F]+|\d+)\s*$', htxt, re.M):
        htxt = re.sub(r'\b%s\b' % dm.group(1), dm.group(2), htxt)
    structs = {}
    for _ in range(2):
        for m in struct_re.finditer(htxt):
            if m.group(1) not in structs or structs[m.group(1)] is None:
                structs[m.group(1)] = parse_struct(m.group(2), structs)
    if sname not in structs or not structs[sname]:
        print('ERROR: could not parse', sname); sys.exit(2)
    # Flatten nested struct members into dotted paths so a deref landing inside
    # an embedded struct (e.g. GroundBaddieState.baddie.controlMode) maps to the
    # full member path. Recurses single (non-array, non-pointer) struct members.
    def flatten(name, base, prefix, out):
        for off, fname, ty, size, cls in structs.get(name) or []:
            low = fname.lower()
            base_ty = ty.rstrip('*')
            if cls is None and not ty.endswith('*') and base_ty in structs and structs[base_ty]:
                flatten(base_ty, base + off, prefix + fname + '.', out)
            else:
                if 'pad' in low or cls in (None, 'ARR') or ('unk' in low and not include_unk):
                    continue
                out[base + off] = (prefix + fname, cls, ty)
    M = {}
    flatten(sname, 0, '', M)

    src = open(path, encoding='latin-1').read()  # byte-preserving (SJIS-safe)
    stats = collections.Counter()
    for var in varnames:
        def drepl(m, var=var):
            ty = re.sub(r'\s+', ' ', m.group(1).strip())
            off = int(m.group(2), 0)
            cls = 'PTR' if ty.endswith('*') else CLASS_OF.get(ty)
            if cls is None or off not in M:
                stats['skip'] += 1
                return m.group(0)
            name, fcls, fty = M[off]
            mem = '((%s *)%s)->%s' % (sname, var, name)
            if cls == 'PTR' and ty != fty and ty != 'void *':
                after = m.string[m.end():m.end()+4].lstrip(') ')
                chained = after[:2] == '->' or after[:1] in ('[', '+', '-')
                # a concrete-typed field mismatching the deref's pointer type
                # is an illegal implicit conversion in EVERY context (MWCC
                # C89), not just chained ones - always launder; a void* field
                # only needs the launder when the result is chained/offset.
                if chained or fty != 'void *':
                    stats['launder'] += 1
                    return '*(%s*)&%s' % (ty, mem)
            if cls == fcls:
                stats['member'] += 1
                return mem
            if SIZE.get(cls) == SIZE.get(fcls):
                stats['launder'] += 1
                if ty.endswith('*'):
                    return '*(%s*)&%s' % (ty, mem)
                return '*(%s *)&%s' % (ty, mem)
            stats['skip_size'] += 1
            return m.group(0)
        src = re.sub(
            r'\*\(\s*([A-Za-z0-9_]+(?:\s*\*+)?)\s*\*\)\s*\(\s*'
            r'(?:\(\s*(?:char|u8|s8|byte|undefined)\s*\*\)\s*)?%s\s*\+\s*'
            r'(0x[0-9a-fA-F]+|\d+)\s*\)' % re.escape(var), drepl, src)
    open(path, 'w', encoding='latin-1', newline='').write(src)
    print(dict(stats))


if __name__ == '__main__':
    main()
