#!/usr/bin/env python3
"""GameObject offset-deref converter (engine partition tooling).

Usage: deref_convert_gameobject.py <file.c> <basevar> [basevar ...]

Rewrites width-matched constant-offset derefs of the named base variables
into ((GameObject *)var)->member access (inline-cast form, no decl
changes). Width-mismatched 4/2/1-byte sites are laundered
(*(T *)&((GameObject *)var)->member) to preserve cmpwi/cmplwi and
extension behavior; anything else is left raw.

PRECONDITIONS (caller must verify per function, see CLAUDE.md #77):
- every named base var is a BYTE pointer (u8*/char*) or integer address -
  typed pointers (int*/float*) scale arithmetic and will miscompile;
- the var actually points at the engine GameObject record (head =
  ObjAnimComponent; see include/main/game_object.h);
- WATCH for Ghidra PRE-SCALED offsets: when the import declared the base
  as int*/short* (e.g. `int *inner = *(int **)(obj + 0xb8);` ... `inner +
  0x25c`), the written offset is in ELEMENTS in some fns and BYTES in
  others depending on that fn's decl. Derive the REAL byte offset per
  function from the decl type before mapping; converting through this
  tool assumes byte offsets and will silently shift the field otherwise
  (the .o gate catches it, but only after a wasted round).
Always gate the result with tools/deref_o_gate.py against the baseline .o.

The map only covers offsets named in game_object.h; pad-region offsets
(0x35-0x37 etc.) are skipped automatically.
"""
import re, collections, sys
GO = {
0x00:('anim.rotX','S16'),0x02:('anim.rotY','S16'),0x04:('anim.rotZ','S16'),
0x06:('anim.flags','S16'),0x08:('anim.rootMotionScale','F32'),
0x0c:('anim.localPosX','F32'),0x10:('anim.localPosY','F32'),0x14:('anim.localPosZ','F32'),
0x18:('anim.worldPosX','F32'),0x1c:('anim.worldPosY','F32'),0x20:('anim.worldPosZ','F32'),
0x24:('anim.velocityX','F32'),0x28:('anim.velocityY','F32'),0x2c:('anim.velocityZ','F32'),
0x30:('anim.parent','PTR'),0x44:('anim.classId','S16'),0x46:('anim.seqId','S16'),
0x48:('anim.defId','S16'),0x4c:('anim.placementData','PTR'),0x50:('anim.modelInstance','PTR'),
0x54:('anim.hitReactState','PTR'),0x60:('anim.eventTable','PTR'),0x68:('anim.dll','PTR'),
0x6c:('anim.jointPoseData','PTR'),0x7c:('anim.banks','PTR'),
0x80:('anim.previousLocalPosX','F32'),0x84:('anim.previousLocalPosY','F32'),
0x88:('anim.previousLocalPosZ','F32'),0x8c:('anim.previousWorldPosX','F32'),
0x90:('anim.previousWorldPosY','F32'),0x94:('anim.previousWorldPosZ','F32'),
0x98:('anim.currentMoveProgress','F32'),0x9c:('anim.activeMoveProgress','F32'),
0xa0:('anim.currentMove','S16'),0xa2:('anim.activeMove','S16'),
0xa4:('anim.targetObj','PTR'),
0xa8:('anim.hitboxScale','F32'),0xad:('anim.bankIndex','S8'),
0xae:('anim.activeHitboxMode','S8'),0xaf:('anim.resetHitboxMode','S8'),
0xb0:('objectFlags','U16'),0xb4:('unkB4','S16'),0xb8:('extra','PTR'),
0xbc:('animEventCallback','PTR'),0xc0:('unkC0','PTR'),0xc4:('unkC4','PTR'),0xc8:('unkC8','PTR'),
0xdc:('unkDC','PTR'),0xe4:('unkE4','U8'),0xe5:('unkE5','U8'),0xe6:('unkE6','S16'),
0xe8:('unkE8','U8'),0xe9:('unkE9','S8'),0xea:('unkEA','U8'),0xeb:('unkEB','U8'),
0xef:('unkEF','S8'),0xf0:('unkF0','U8'),0xf4:('unkF4','S32'),0xf8:('unkF8','S32'),
0xfc:('unkFC','F32'),0x100:('unk100','F32'),0x104:('unk104','F32'),
}

CLASS_OF = {'f32':'F32','float':'F32','int':'S32','s32':'S32','u32':'U32','uint':'U32',
 's16':'S16','short':'S16','u16':'U16','ushort':'U16','s8':'S8','u8':'U8','char':'S8','byte':'U8'}
SIZE = {'F32':4,'S32':4,'U32':4,'PTR':4,'S16':2,'U16':2,'S8':1,'U8':1}

path = sys.argv[1]
args = sys.argv[2:]
# --bytecast-only: only convert ((char*)obj + N) byte-cast sites, NEVER the
# plain (obj + N) form. Required for files where obj is declared `int *obj`
# (or other non-byte pointer) so plain `obj + N` is element-scaled and would
# be mis-mapped to a byte offset.
bytecast_only = '--bytecast-only' in args
varnames = [a for a in args if not a.startswith('--')]
src = open(path, encoding='latin-1').read()  # byte-preserving (SJIS-safe)
stats = collections.Counter()

for var in varnames:
    def drepl(m, var=var):
        ty = re.sub(r'\s+',' ',m.group(1).strip())
        off = int(m.group(2),0)
        cls = 'PTR' if ty.endswith('*') else CLASS_OF.get(ty)
        if cls is None or off not in GO:
            stats['skip'] += 1
            return m.group(0)
        name,fcls = GO[off]
        mem = '((GameObject *)%s)->%s' % (var,name)
        # Pointer-typed sites need care: the anim.* fields (off < 0xb0) are
        # declared with concrete pointer types in objanim_internal.h, so a bare
        # member assigned to / from a differently-typed local is an illegal
        # implicit conversion. The GameObject tail fields (>=0xb0) are void* and
        # accept any pointer assignment. Also, a result immediately dereferenced
        # (->) or indexed ([) must keep its type regardless of offset. In all
        # these cases launder to the original cast type (byte-identical load).
        if cls=='PTR' and ty != 'void *':
            after = m.string[m.end():m.end()+4].lstrip(') ')
            # chained deref/index OR pointer arithmetic on the result both need
            # the concrete type (void* can't be dereffed or offset in MWCC).
            chained = after[:2] in ('->',) or after[:1] in ('[', '+', '-')
            # also: outer deref `**(T***)(obj+N)` or `*( *(T**)(obj+N) )` —
            # nearest non-space/non-paren char before the match is `*`
            # (unary deref of the loaded pointer).
            i = m.start()
            while i > 0 and m.string[i-1] in ' \t(':
                i -= 1
            before_star = i > 0 and m.string[i-1] == '*'
            if off < 0xb0 or chained or before_star:
                stats['launder'] += 1
                return '*(%s*)&%s' % (ty,mem)
        if cls==fcls:
            stats['member'] += 1
            return mem
        if SIZE.get(cls)==SIZE.get(fcls):
            stats['launder'] += 1
            if ty.endswith('*'):
                return '*(%s*)&%s' % (ty,mem)
            return '*(%s *)&%s' % (ty,mem)
        stats['skip_size'] += 1
        return m.group(0)
    # Optional inner byte-cast: *(T *)((char *)obj + 0xNN) / ((u8 *)obj + 0xNN).
    # Byte offset is identical whether obj is an int address or a byte pointer.
    # In --bytecast-only mode the inner byte-cast is REQUIRED (plain obj+N on a
    # non-byte pointer is element-scaled and must not be mapped to a byte field).
    bc = r'\(\s*(?:char|u8|s8|byte|undefined)\s*\*\)\s*'
    inner = bc if bytecast_only else (r'(?:%s)?' % bc)
    src = re.sub(r'\*\(\s*([A-Za-z0-9_]+(?:\s*\*+)?)\s*\*\)\s*\(\s*%s%s\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)' % (inner, re.escape(var)), drepl, src)
    def irepl(m, var=var):
        off = int(m.group(1),0)
        if off in GO and GO[off][1]=='U8':
            stats['idx'] += 1
            return '((GameObject *)%s)->%s' % (var,GO[off][0])
        stats['skip_idx'] += 1
        return m.group(0)
    # obj[K] is a byte index only when obj is a byte pointer; skip in
    # bytecast-only mode (there obj is element-scaled).
    if not bytecast_only:
        src = re.sub(r'\b%s\[(0x[0-9a-fA-F]+|\d+)\]' % re.escape(var), irepl, src)

open(path,'w',encoding='latin-1',newline='').write(src)
print(dict(stats))
