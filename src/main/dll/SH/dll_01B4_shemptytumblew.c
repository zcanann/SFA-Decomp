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
#include "main/dll/SH/dll_01B4_shemptytumblew.h"

#define SHEMPTYTUMBLEW_OBJFLAG_HIDDEN 0x4000

f32 lbl_803DDC00;
extern f32 lbl_803E5540;
extern f32 lbl_803E5544;
extern f32 lbl_803E5548;


void SH_EmptyTumbleW_update(GameObject* obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x280, &lbl_803DDC00);
}

void SH_EmptyTumbleW_init(s16* obj, ShEmptyTumblewPlacement* def)
{
    f32 scale;

    ((GameObject*)obj)->anim.rotZ = (def->rotZByte - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotY = (def->rotYByte - 0x7f) * 0x80;
    ((GameObject*)obj)->anim.rotX = def->rotXByte << 8;
    ((GameObject*)obj)->anim.rootMotionScale = def->scale;
    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, (int)(lbl_803E5540 * scale), (int)(lbl_803E5544 * scale),
                               (int)(lbl_803E5548 * scale));
    ((GameObject*)obj)->objectFlags |= SHEMPTYTUMBLEW_OBJFLAG_HIDDEN;
}

__declspec(section ".sdata2") f32 lbl_803E5540 = 15.0f;
__declspec(section ".sdata2") f32 lbl_803E5544 = -5.0f;
__declspec(section ".sdata2") f32 lbl_803E5548 = 100.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E554C = 0.0f;
#pragma explicit_zero_data reset
