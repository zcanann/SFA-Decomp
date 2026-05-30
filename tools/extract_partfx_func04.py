"""
Draft-extractor for the PartFxSpawn-style EffectNN_func04 family (modgfx / dim_partfx).

Usage: python3 tools/extract_partfx_func04.py <SymbolName> <cfg.f00 stack offset hex> [asm_unit]
  e.g. python3 tools/extract_partfx_func04.py Effect6_func04 0x08

Emits best-effort C for the regular per-case field assignments:
  - lbl * (f32)(s32)randomGetRange(lo,hi)        (fmuls)
  - (f32)(s32)randomGetRange(lo,hi) / lbl        (fdivs)
  - lbl_A * (f32)(s32)rand + lbl_B               (fmadds)
  - (f32)(s32)randomGetRange(lo,hi)              (bare convert)
  - cfg.fXX = randomGetRange(lo,hi)              (int store)
  - cfg.fXX = lbl / constant / (HI<<16)+LO
Control flow (labels, branches, cmp, vtable dispatch) is passed through as
  /*+off*/ comments so the switch + per-case param_3 guards can be assembled by
  hand against config/GSAE01/.../<unit>_data.s jumptable (recipe #13 case order).
Validated: reproduces the hand-matched Effect6_func04 (97.2%) field set exactly.
NOTE: per-case `if (param_3 != 0)` copy guards, sub-switches on param_3 fields,
  and mathFn_80021ac8 matrix calls are NOT auto-resolved — fill from raw asm.
"""
import re, sys

fn = sys.argv[1]
base_field = int(sys.argv[2], 16)  # stack offset of cfg.f00
unit = sys.argv[3] if len(sys.argv) > 3 else 'build/GSAE01/asm/main/dll/modgfx.s'

# slurp function asm
lines = []
cap = False
for ln in open(unit):
    if ln.startswith(f'.fn {fn},'):
        cap = True
    if cap:
        lines.append(ln.rstrip('\n'))
    if cap and ln.startswith(f'.endfn {fn}'):
        break

# parse instruction lines: addr -> (mnem, rest)
insns = []  # (addr, text)
for ln in lines:
    m = re.search(r'/\* ([0-9A-F]{8}) [0-9A-F]{8}  [0-9A-F ]+\*/\t(.*)', ln)
    if m:
        insns.append((int(m.group(1),16), m.group(2).strip()))
    else:
        lm = re.match(r'\.L_([0-9A-F]+):', ln)
        if lm:
            insns.append((int(lm.group(1),16), '__label__'))

FNBASE = insns[0][0]
def field(off):
    d = off - base_field
    return f'f{d:02x}'

# emit C for a linear run of insns (best-effort, regular patterns only)
def emit(seq):
    out = []
    i = 0
    pend_rand = None  # (lo,hi)
    while i < len(seq):
        addr, t = seq[i]
        # randomGetRange call sequence
        m = re.match(r'li r3, (-?0x[0-9a-f]+|-?\d+)', t)
        if m and i+2 < len(seq) and 'li r4,' in seq[i+1][1] and 'bl randomGetRange' in seq[i+2][1]:
            lo = m.group(1)
            hi = re.match(r'li r4, (-?0x[0-9a-f]+|-?\d+)', seq[i+1][1]).group(1)
            # look ahead: is it stored as int (stw OFF) or converted to float?
            j = i+3
            # skip to next meaningful
            if j < len(seq) and re.match(r'stw r3, 0x([0-9a-f]+)\(r1\)', seq[j][1]):
                off = int(re.match(r'stw r3, 0x([0-9a-f]+)\(r1\)', seq[j][1]).group(1),16)
                out.append(f'cfg.{field(off)} = randomGetRange({lo}, {hi});')
                i = j+1; continue
            # float conversion: find the lfd bias ... fsubs, then optional lfs+fmuls/fdivs, then stfs
            # gather window until stfs
            k = j
            lblmul = None; op = None; off=None; fmadd=None
            while k < len(seq) and k < j+14:
                tk = seq[k][1]
                mm = re.match(r'lfs f\d+, (lbl_[0-9A-F]+)@sda21', tk)
                if 'fmuls' in tk: op='mul'
                if 'fdivs' in tk: op='div'
                if 'fmadds' in tk: op='madd'
                if mm:
                    if lblmul is None: lblmul = mm.group(1)
                    else: fmadd = mm.group(1)
                sm = re.match(r'stfs f\d+, 0x([0-9a-f]+)\(r1\)', tk)
                if sm:
                    off = int(sm.group(1),16); k+=1; break
                k+=1
            rng = f'(f32)(s32)randomGetRange({lo}, {hi})'
            if off is None:
                out.append(f'/* TODO rand {lo},{hi} */'); i=j; continue
            if op=='mul' and fmadd is None:
                out.append(f'cfg.{field(off)} = {lblmul} * {rng};')
            elif op=='div':
                out.append(f'cfg.{field(off)} = {rng} / {lblmul};')
            elif op=='madd':
                out.append(f'cfg.{field(off)} = {lblmul} * {rng} + {fmadd};')
            elif op is None and lblmul is None:
                out.append(f'cfg.{field(off)} = {rng};')
            else:
                out.append(f'/* TODO rand {lo},{hi} op={op} */ cfg.{field(off)} = {rng};')
            i = k; continue
        # lfs lbl ... stfs OFF  (direct constant)
        m = re.match(r'lfs f\d+, (lbl_[0-9A-F]+)@sda21', t)
        if m and i+1 < len(seq):
            sm = re.match(r'stfs f\d+, 0x([0-9a-f]+)\(r1\)', seq[i+1][1])
            if sm:
                off=int(sm.group(1),16)
                out.append(f'cfg.{field(off)} = {m.group(1)};')
                i+=2; continue
        # li r0,K ; stw/sth/stb OFF
        m = re.match(r'li r0, (-?0x[0-9a-f]+|-?\d+)', t)
        if m and i+1 < len(seq):
            sm = re.match(r'st[whb] r0, 0x([0-9a-f]+)\(r1\)', seq[i+1][1])
            if sm:
                off=int(sm.group(1),16)
                out.append(f'cfg.{field(off)} = {m.group(1)};')
                i+=2; continue
        # lis r3,HI ; addi r0,r3,LO ; stw OFF
        m = re.match(r'lis r3, 0x([0-9a-f]+)', t)
        if m and i+2 < len(seq):
            am = re.match(r'(addi|subi) r0, r3, (0x[0-9a-f]+|\d+)', seq[i+1][1])
            sm = re.match(r'st[whb] r0, 0x([0-9a-f]+)\(r1\)', seq[i+2][1])
            if am and sm:
                hi=int(m.group(1),16); lo=int(am.group(2),16)
                val = (hi<<16)+lo if am.group(1)=='addi' else (hi<<16)-lo
                off=int(sm.group(1),16)
                out.append(f'cfg.{field(off)} = 0x{val:x};')
                i+=3; continue
        if t=='__label__':
            out.append(f'  L_{addr:x}:')
        elif re.match(r'(b |beq|bne|bgt|blt|bge|ble|cmp|bctr|or |xor|ori|rlwinm|lhz|lha|lwz|stw r3|bl )', t):
            out.append(f'    /*+{addr-FNBASE:#x}*/ {t}')
        i+=1
    return out

for c in emit(insns):
    print(c)
