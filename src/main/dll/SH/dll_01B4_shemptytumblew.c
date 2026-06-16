/*
 * shemptytumblew (DLL 0x1B4) - the empty (non-rolling) tumbleweed bush.
 *
 * init orients the bush from its placement bytes and sizes a capsule hit
 * volume scaled by the model's root-motion scale; update just polls the
 * shared priority hit-effect handler each frame.
 */
#include "main/game_object.h"
#include "main/objhits.h"

extern f32 lbl_803DDC00;
extern void ObjHitbox_SetCapsuleBounds();
extern f32 lbl_803E5540;
extern f32 lbl_803E5544;
extern f32 lbl_803E5548;

void sh_emptytumblew_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x280,
                                              &lbl_803DDC00);
}

void sh_emptytumblew_init(s16* obj, int def)
{
    f32 scale;

    ((GameObject*)obj)->anim.rotZ = (*(u8*)(def + 0x18) - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotY = (*(u8*)(def + 0x19) - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotX = *(u8*)(def + 0x1a) << 8;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(def + 0x1c);
    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(obj, (int)(lbl_803E5540 * scale), (int)(lbl_803E5544 * scale), (int)(lbl_803E5548 * scale));
    ((GameObject*)obj)->objectFlags |= 0x4000;
}
