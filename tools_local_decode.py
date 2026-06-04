#!/usr/bin/env python3
"""Decode foodbag builder-fn target asm into FbBuf C statements."""
import re, sys

def field(off):
    if off < 8: return f'??{off:#x}'
    o = off - 8
    if o == 0: return 'buf.cmds'
    if o == 4: return 'buf.ctx'
    if 0x20 <= o < 0x2c: return f'buf.col[{(o-0x20)//4}]'
    if 0x2c <= o < 0x38: return f'buf.pos[{(o-0x2c)//4}]'
    if o == 0x38: return 'buf.scale'
    if o == 0x3c: return 'buf.v3c'
    if o == 0x40: return 'buf.v40'
    if o == 0x44: return 'buf.v44'
    if 0x46 <= o < 0x54: return f'buf.hw[{(o-0x46)//2}]'
    if o == 0x54: return 'buf.flags'
    if 0x58 <= o <= 0x5d: return ['buf.v58','buf.v59','buf.v5a','buf.v5b','buf.v5c','buf.count'][o-0x58]
    if o >= 0x60:
        k = (o-0x60)//0x18; r = (o-0x60)%0x18
        n = {0:'mode',4:'x',8:'y',0xc:'z',0x10:'tex',0x14:'flags',0x16:'layer'}.get(r, f'+{r:#x}')
        return f'e[{k}].{n}'
    return f'buf+{o:#x}'

def main(unit_s, fn):
    src = open(unit_s).read()
    m = re.search(r'\.fn '+fn+r', global(.*?)\.endfn '+fn, src, re.S)
    lines = m.group(1).strip().split('\n')
    reg = {}; freg = {}
    reg['r3']='param_1'; reg['r4']='param_2'; reg['r5']='param_3'; reg['r6']='param_4'
    freg['f1']='param_f1'; freg['f2']='param_f2'
    base_reg = None
    out = []
    for ln in lines:
        lm = re.match(r'.*\*/\s+(\S+)\s*(.*)', ln)
        if not lm:
            if '.L_' in ln: out.append(ln.strip())
            continue
        op, args = lm.group(1), lm.group(2).replace(', ',',').strip()
        a = args.split(',') if args else []
        def val(r): return reg.get(r, r)
        if op == 'li': reg[a[0]] = a[1] if not a[1].startswith('0x') or int(a[1],16)<10 else a[1]
        elif op == 'lis':
            mm = re.match(r'(\w+)@ha', a[1])
            reg[a[0]] = ('HA', mm.group(1)) if mm else a[1]
        elif op == 'addi':
            d, s, imm = a[0], a[1], a[2]
            sv = reg.get(s)
            if isinstance(sv, tuple) and sv[0]=='HA':
                reg[d] = sv[1]; base_reg = d
                out.append(f'  // base = {sv[1]} -> {d}')
            elif s == 'r1':
                off = int(imm, 16)
                reg[d] = f'&{field(off)}' if off >= 8 else f'sp+{imm}'
            elif isinstance(sv, str) and sv.startswith('lbl_'):
                reg[d] = f'{sv}+{imm}'
            elif sv and not isinstance(sv, tuple):
                reg[d] = f'({sv}+{imm})'
            else:
                reg[d] = f'{s}+{imm}'
        elif op == 'mr': reg[a[0]] = reg.get(a[1], a[1])
        elif op in ('lfs','lfd'):
            mm = re.match(r'(\w+)@sda21', a[1])
            if mm: freg[a[0]] = mm.group(1)
            else:
                mm2 = re.match(r'(-?0x[0-9a-f]+|\d+)\((\w+)\)', a[1])
                if mm2: freg[a[0]] = f'*(f32*)({val(mm2.group(2))}+{mm2.group(1)})'
        elif op in ('fadds','fsubs','fmuls'):
            o = {'fadds':'+','fsubs':'-','fmuls':'*'}[op]
            freg[a[0]] = f'({freg.get(a[1],a[1])} {o} {freg.get(a[2],a[2])})'
        elif op in ('stb','sth','stw'):
            mm = re.match(r'(-?0x[0-9a-f]+|\d+)\((\w+)\)', a[1])
            if mm and mm.group(2) == 'r1':
                off = int(mm.group(1), 16) if '0x' in mm.group(1) else int(mm.group(1))
                out.append(f'  {field(off)} = {val(a[0])};   // {op}')
            else:
                out.append(f'  *({op} {a[1]}) = {val(a[0])};')
        elif op == 'stfs':
            mm = re.match(r'(-?0x[0-9a-f]+|\d+)\((\w+)\)', a[1])
            if mm and mm.group(2) == 'r1':
                off = int(mm.group(1), 16) if '0x' in mm.group(1) else int(mm.group(1))
                out.append(f'  {field(off)} = {freg.get(a[0],a[0])};')
            else:
                out.append(f'  *(f32*)({val(mm.group(2))}+{mm.group(1)}) = {freg.get(a[0],a[0])};')
        elif op in ('lwz','lhz','lha','lbz'):
            mm = re.match(r'(\w+)@sda21', a[1])
            if mm: reg[a[0]] = mm.group(1)
            else:
                mm2 = re.match(r'(-?0x[0-9a-f]+|\d+)\((\w+)\)', a[1])
                if mm2:
                    cast = {'lwz':'u32','lhz':'u16','lha':'s16','lbz':'u8'}[op]
                    if mm2.group(2)=='r1':
                        off = int(mm2.group(1),16) if '0x' in mm2.group(1) else int(mm2.group(1))
                        reg[a[0]] = field(off)
                    else:
                        reg[a[0]] = f'*({cast}*)({val(mm2.group(2))}+{mm2.group(1)})'
        elif op in ('cmpwi','cmplwi'):
            out.append(f'  // {op} {val(a[-2]) if len(a)>2 else val(a[0])}, {a[-1]}')
        elif op in ('beq','bne','bge','ble','bgt','blt','b'):
            out.append(f'  // {op} {a[-1] if a else ""}')
        elif op == 'bl':
            out.append(f'  // CALL {args}  args: r3={val("r3")} r4={val("r4")} r5={val("r5")} r6={val("r6")} r7={val("r7")} r8={val("r8")} r9={val("r9")} r10={val("r10")} f1={freg.get("f1")}')
            reg['r3']='RET'
        elif op in ('bctrl',):
            out.append(f'  // BCTRL args: r3={val("r3")} r4={val("r4")} r5={val("r5")} r6={val("r6")} r7={val("r7")} r8={val("r8")} r9={val("r9")} r10={val("r10")}')
        elif op == 'mtctr':
            out.append(f'  // mtctr {val(a[0])}')
        elif op == 'extsh': reg[a[0]] = f'(s16){val(a[1])}'
        elif op == 'extsb': reg[a[0]] = f'(s8){val(a[1])}'
        elif op == 'oris': reg[a[0]] = f'({val(a[1])} | {hex(int(a[2],16)<<16)})'
        elif op == 'ori': reg[a[0]] = f'({val(a[1])} | {a[2]})'
        elif op == 'or': reg[a[0]] = f'({val(a[1])} | {val(a[2])})'
        elif op in ('mulhw','srawi','srwi','add','subf','clrlwi','rlwinm','neg','fctiwz','xoris'):
            out.append(f'  // {op} {args}   [{",".join(val(x) for x in a)}]')
        elif op in ('stwu','mflr','mtlr','blr','nop'): pass
        else:
            out.append(f'  // ?? {op} {args}')
    print('\n'.join(out))

if __name__ == '__main__':
    main('build/GSAE01/asm/main/dll/foodbag.s', sys.argv[1])
