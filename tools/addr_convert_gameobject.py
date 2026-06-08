#!/usr/bin/env python3
"""GameObject address-of (pointer-arg) converter — companion to
deref_convert_gameobject.py.

That tool rewrites the *scalar deref* form `*(T *)(obj + 0xNN)`. This tool
rewrites the *address-of / pointer-arg* form `(T *)(obj + 0xNN)` (no leading
`*`) — the worldPos/velocity/localPos triples passed by address into
PSVECSubtract/getXZDistance/objBboxFn/etc. — into
`(T *)&((GameObject *)obj)->member`. When the cast type's pointee exactly
matches the field's C type (e.g. (f32 *) on an F32 field) the now-redundant
cast is dropped: `&((GameObject *)obj)->member`.

Byte-identical: &struct->field at a known offset is the same address
computation as (obj + offset). Always gate with tools/deref_o_gate.py.

Usage: addr_convert_gameobject.py <file.c> <basevar> [basevar ...] [--bytecast-only]

PRECONDITIONS (same as the deref converter, see CLAUDE.md #77):
- each base var is a byte pointer or integer address (NOT int*/float* — that
  scales the arithmetic);
- the var points at the engine GameObject record (head = ObjAnimComponent).
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
# C pointee type that exactly represents a field of the given class (so the
# cast is redundant and can be dropped to &...->field).
EXACT = {'F32':'f32','S32':'int','S16':'s16','U16':'u16','S8':'s8','U8':'u8'}

path = sys.argv[1]
args = sys.argv[2:]
bytecast_only = '--bytecast-only' in args
varnames = [a for a in args if not a.startswith('--')]
src = open(path, encoding='latin-1').read()
stats = collections.Counter()

for var in varnames:
    def arepl(m, var=var):
        ty = re.sub(r'\s+', ' ', m.group(1).strip())   # e.g. "f32 *", "Vec *"
        off = int(m.group(2), 0)
        if off not in GO:
            stats['skip'] += 1
            return m.group(0)
        name, fcls = GO[off]
        mem = '&((GameObject *)%s)->%s' % (var, name)
        pointee = ty[:-1].strip()  # drop trailing '*'
        if EXACT.get(fcls) == pointee:
            stats['member'] += 1
            return mem
        stats['cast'] += 1
        return '(%s)%s' % (ty, mem)
    # (T *)(obj + 0xNN) NOT preceded by '*' (that is the scalar-deref form,
    # owned by deref_convert_gameobject.py). Optional inner (char *)/(u8 *).
    bc = r'\(\s*(?:char|u8|s8|byte|undefined)\s*\*\)\s*'
    inner = bc if bytecast_only else (r'(?:%s)?' % bc)
    pat = r'(?<![\*A-Za-z0-9_])\(\s*([A-Za-z_][A-Za-z0-9_]*\s*\*)\s*\)\s*\(\s*%s%s\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)' % (
        inner, re.escape(var))
    src = re.sub(pat, arepl, src)

open(path, 'w', encoding='latin-1', newline='').write(src)
print(dict(stats))
