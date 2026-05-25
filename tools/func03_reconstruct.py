#!/usr/bin/env python3
"""Reconstruct an unrolled "func03" render-command-builder from its target asm.

Many DLL objects have a func03 that builds an on-stack array of 0x18-byte
gfx-command entries ({u32 mode; f32 x,y,z; void* tex; u16 flags; u8 layer;})
plus a 0x60-byte header, then calls (*gModgfxInterface->vtbl[2])(&buf, ...).
Ghidra leaves these as ~10% partials (or empty stubs) because the buffer is
reached through a pointer-to-pointer, so MWCC dead-store-eliminates every
field write. Recipe #8 (CLAUDE.md): wrap header+entries in ONE struct passed
by address so the stores survive.

This tool parses the TARGET disassembly (via tools/function_objdump.py),
tracks register/freg values (li, lis/addi base+offset, mr param, lfs label,
lha base+off, or-const) and the stores to r1, then emits the matching C
struct reconstruction. Use a single `extern u8 lbl_xxxxx[]` base for
tex/hw/call-args (matches the target's reused base register).

SCOPE / LIMITATIONS:
  * Handles the UNROLLED 0x18-entry GfxCmd buffer form (pickup/savegame
    dll_XX_func03). Tune the local `GfxCmd entries[N]` array size so entries
    land at r1+104 AND the frame matches the target (try [32] first).
  * Does NOT handle: looped entry builders (1 unrolled entry + loop), 4-byte
    or 1-byte stride command variants (call arg5 != 0x18), or entries built
    from computed CONCAT44 int->double values. Those need manual work.
  * The float-CSE cap: funcs with many distinct float labels cap ~42-50%
    (MWCC preloads them into fregs vs target's inline loads); few-distinct
    -float funcs reach 78-87%.

Usage: python3 tools/func03_reconstruct.py <unit.c> <dll_XX_func03>
       (prints the reconstructed C function to stdout)
Author: bravoop. Verified on pickup dll_9D (87%), savegame dll_93-99.
"""
import re, sys, subprocess
unit, fn = sys.argv[1], sys.argv[2]
out = subprocess.run(['python3','tools/function_objdump.py',unit,fn],capture_output=True,text=True).stdout
lines = out.split('\n')
s=next((i for i,l in enumerate(lines) if 'target build' in l),0)
e=next((i for i,l in enumerate(lines) if 'current build' in l),len(lines))
seg=lines[s:e]
items=[]; i=0
while i < len(seg):
    m=re.match(r'\s*([0-9a-f]+):\s+[0-9a-f ]{11,}\t(\S+)\s*(.*)', seg[i])
    if m:
        reloc=None
        if i+1<len(seg):
            rm=re.match(r'\s*[0-9a-f]+:\s+(R_PPC\S+)\s+(\S+)', seg[i+1])
            if rm: reloc=(rm.group(1),rm.group(2))
        items.append((int(m.group(1),16),m.group(2),m.group(3).strip(),reloc))
    i+=1
reg={}; freg={}; store={}
params={'r3':'param_1','r4':'param_2','r5':'param_3','r6':'param_4'}
has_fun=False; fun_name=None; trail=None
globalcallargs=[None]*7
for off,mnem,ops,reloc in items:
    o=[x.strip() for x in ops.split(',')]
    if mnem=='li': reg[o[0]]=('imm', int(o[1],0))
    elif mnem=='lis':
        reg[o[0]]=('base',reloc[1]) if (reloc and 'HA' in reloc[0]) else ('imm',(int(o[1],0)<<16))
    elif mnem=='addi':
        if reloc and 'LO' in reloc[0]: reg[o[0]]=('base',reloc[1])
        elif o[1]=='r1': reg[o[0]]=('stack',int(o[2],0))
        else:
            b=reg.get(o[1])
            if b and b[0]=='base': reg[o[0]]=('off',b[1],int(o[2],0))
            elif b and b[0]=='off': reg[o[0]]=('off',b[1],b[2]+int(o[2],0))
            elif b and b[0]=='imm': reg[o[0]]=('imm',b[1]+int(o[2],0))
            else: reg[o[0]]=('imm',int(o[2],0) if o[2].lstrip('-').isdigit() else 0)
    elif mnem=='mr': reg[o[0]]=('param',params[o[1]]) if o[1] in params else reg.get(o[1])
    elif mnem=='or':
        a=reg.get(o[1]); b=reg.get(o[2])
        reg[o[0]]=('or',a,b)
    elif mnem=='lfs' and reloc: freg[o[0]]=('lbl',reloc[1])
    elif mnem=='lha':
        mm=re.match(r'(-?\d+)\((r\w+)\)',o[1]); 
        if mm:
            b=reg.get(mm.group(2))
            reg[o[0]]=('s16', b[1] if b and b[0]=='base' else '?', int(mm.group(1)))
    elif mnem in ('stb','sth','stw','stfs') and o[1].endswith('(r1)'):
        fo=int(re.match(r'(-?\d+)\(r1\)',o[1]).group(1))
        store[fo]=(mnem, (freg if mnem=='stfs' else reg).get(o[0]))
    elif mnem=='bctrl':
        globalcallargs[:]=[reg.get('r%d'%n) for n in range(4,11)]
    elif mnem=='bl' and reloc and reloc[1].startswith('FUN'):
        if fun_name is None: fun_name=reloc[1]
        else: trail=reloc[1]
        has_fun=True
def V(v):
    if v is None: return '0'
    t=v[0]
    if t=='imm': 
        x=v[1]; return hex(x) if x>=10 else str(x)
    if t=='lbl' or t=='base': return v[1] if t=='lbl' else ('&'+v[1]+'[0]')
    if t=='off': return '&%s[%d]'%(v[1],v[2])
    if t=='param': return v[1]
    if t=='s16': return '*(s16 *)&%s[%d]'%(v[1],v[2])
    if t=='or':
        return '%s | %s'%(V(v[1]),V(v[2]))
    return '0'
# entries from 0x68
base=8
es=0x68
bases=[]; b=es
while (b in store) or (b+4 in store): bases.append(b); b+=0x18
N=len(bases)
def hh(d): return store.get(base+d)
ctxexpr = fun_name+'()' if (has_fun and fun_name) else 'param_1'
# but ctx store at base+4:
ctxstore=store.get(base+4)
if ctxstore and ctxstore[1] and ctxstore[1][0]=='param': ctxexpr=ctxstore[1][1]
elif has_fun and fun_name: ctxexpr=fun_name+'()'
L=[]
L.append("void %s(int param_1, int param_2, int param_3, uint param_4)"%fn)
L.append("{")
L.append("  struct { GfxCmd *cmds; int ctx; u8 pad0[0x18]; f32 col[3]; f32 pos[3]; f32 scale;")
L.append("    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;")
L.append("    u8 v58, v59, v5a, v5b, v5c, count; u8 pad1[2]; GfxCmd entries[32]; } buf;")
L.append("  GfxCmd *e = buf.entries;")
L.append("  int ctx;")
for i,b in enumerate(bases):
    g=lambda d: V(store.get(b+d,(None,None))[1]) if store.get(b+d) else '0'
    tex=g(0x10); tex='(void *)0' if tex=='0' else tex
    L.append("  e[%d].layer = %s; e[%d].flags = %s; e[%d].tex = %s; e[%d].mode = %s;"%(i,g(0x16),i,g(0x14),i,tex,i,g(0)))
    L.append("  e[%d].x = %s; e[%d].y = %s; e[%d].z = %s;"%(i,g(4),i,g(8),i,g(0xc)))
def hv(d):
    st=hh(d); return V(st[1]) if st else '0'
L.append("  buf.v58 = %s;"%hv(0x58))
L.append("  ctx = %s;"%ctxexpr)
L.append("  buf.ctx = ctx;")
L.append("  buf.v44 = %s;"%hv(0x44))
L.append("  buf.pos[0] = %s; buf.pos[1] = %s; buf.pos[2] = %s;"%(hv(0x2c),hv(0x30),hv(0x34)))
L.append("  buf.col[0] = %s; buf.col[1] = %s; buf.col[2] = %s;"%(hv(0x20),hv(0x24),hv(0x28)))
L.append("  buf.scale = %s;"%hv(0x38))
L.append("  buf.v40 = %s;"%hv(0x40))
L.append("  buf.v3c = %s;"%hv(0x3c))
L.append("  buf.v59 = %s;"%hv(0x59))
L.append("  buf.v5a = %s;"%hv(0x5a))
L.append("  buf.v5b = %s;"%hv(0x5b))
L.append("  buf.count = %d;"%N)
L.append("  buf.hw[0] = %s; buf.hw[1] = %s; buf.hw[2] = %s; buf.hw[3] = %s;"%(hv(0x46),hv(0x48),hv(0x4a),hv(0x4c)))
L.append("  buf.hw[4] = %s; buf.hw[5] = %s; buf.hw[6] = %s;"%(hv(0x4e),hv(0x50),hv(0x52)))
L.append("  buf.cmds = buf.entries;")
L.append("  buf.flags = %s;"%hv(0x54))
posb=hv(0x2c)
L.append("  if ((param_4 & 1) != 0) {")
L.append("    if (ctx == 0) {")
for j,fo in enumerate((0xc,0x10,0x14)):
    L.append("      buf.pos[%d] = %s + *(f32 *)(param_3 + %#x);"%(j,posb,fo))
L.append("    } else {")
for j,fo in enumerate((0x18,0x1c,0x20)):
    L.append("      buf.pos[%d] = %s + *(f32 *)(ctx + %#x);"%(j,posb,fo))
L.append("    }")
L.append("  }")
L.append("  (**(code **)(*gModgfxInterface + 8))(&buf, %s);"%(", ".join(V(a) for a in globalcallargs)))
if trail: L.append("  %s();"%trail)
L.append("}")
sys.stderr.write("N=%d base=%#x has_fun=%s fun=%s trail=%s\n"%(N,base,has_fun,fun_name,trail))
print('\n'.join(L))
