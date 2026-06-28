/*
 * shemptytumblew (DLL 0x1B4) - the empty (non-rolling) tumbleweed bush.
 *
 * init orients the bush from its placement bytes and sizes a capsule hit
 * volume scaled by the model's root-motion scale; update just polls the
 * shared priority hit-effect handler each frame.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objhits.h"

extern f32 lbl_803DDC00;
extern void ObjHitbox_SetCapsuleBounds();
extern f32 lbl_803E5540;
extern f32 lbl_803E5544;
extern f32 lbl_803E5548;

typedef struct ShEmptyTumblewPlacement
{
    ObjPlacement head;
    u8 rotZByte;
    u8 rotYByte;
    u8 rotXByte;
    u8 pad1b;
    f32 scale;
} ShEmptyTumblewPlacement;

STATIC_ASSERT(offsetof(ShEmptyTumblewPlacement, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(ShEmptyTumblewPlacement, scale) == 0x1c);

void sh_emptytumblew_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x280,
                                              &lbl_803DDC00);
}

void sh_emptytumblew_init(s16* obj, ShEmptyTumblewPlacement* def)
{
    f32 scale;

    ((GameObject*)obj)->anim.rotZ = (def->rotZByte - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotY = (def->rotYByte - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotX = def->rotXByte << 8;
    ((GameObject*)obj)->anim.rootMotionScale = def->scale;
    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(obj, (int)(lbl_803E5540 * scale), (int)(lbl_803E5544 * scale), (int)(lbl_803E5548 * scale));
    ((GameObject*)obj)->objectFlags |= 0x4000;
}
