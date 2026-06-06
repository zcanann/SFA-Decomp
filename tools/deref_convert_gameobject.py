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
  ObjAnimComponent; see include/main/game_object.h).
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
0xa8:('anim.hitboxScale','F32'),0xad:('anim.bankIndex','S8'),
0xae:('anim.activeHitboxMode','S8'),0xaf:('anim.resetHitboxMode','S8'),
0xb0:('unkB0','U16'),0xb4:('unkB4','S16'),0xb8:('extra','PTR'),
0xbc:('unkBC','PTR'),0xc0:('unkC0','PTR'),0xc4:('unkC4','PTR'),0xc8:('unkC8','PTR'),
0xdc:('unkDC','PTR'),0xe4:('unkE4','U8'),0xe5:('unkE5','U8'),0xe6:('unkE6','S16'),
0xe8:('unkE8','U8'),0xe9:('unkE9','S8'),0xea:('unkEA','U8'),0xeb:('unkEB','U8'),
0xef:('unkEF','S8'),0xf0:('unkF0','U8'),0xf4:('unkF4','S32'),0xf8:('unkF8','S32'),
0xfc:('unkFC','F32'),0x100:('unk100','F32'),0x104:('unk104','F32'),
}

CLASS_OF = {'f32':'F32','float':'F32','int':'S32','s32':'S32','u32':'U32','uint':'U32',
 's16':'S16','short':'S16','u16':'U16','ushort':'U16','s8':'S8','u8':'U8','char':'S8','byte':'U8'}
SIZE = {'F32':4,'S32':4,'U32':4,'PTR':4,'S16':2,'U16':2,'S8':1,'U8':1}

path = sys.argv[1]
varnames = sys.argv[2:]
src = open(path).read()
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
    src = re.sub(r'\*\(\s*([A-Za-z0-9_]+(?:\s*\*+)?)\s*\*\)\s*\(\s*%s\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)' % re.escape(var), drepl, src)
    def irepl(m, var=var):
        off = int(m.group(1),0)
        if off in GO and GO[off][1]=='U8':
            stats['idx'] += 1
            return '((GameObject *)%s)->%s' % (var,GO[off][0])
        stats['skip_idx'] += 1
        return m.group(0)
    src = re.sub(r'\b%s\[(0x[0-9a-fA-F]+|\d+)\]' % re.escape(var), irepl, src)

open(path,'w').write(src)
print(dict(stats))
