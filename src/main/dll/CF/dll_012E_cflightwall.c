/*
 * cflightwall (DLL 0x12E) - static light-wall prop at CF (CloudRunner
 * Fortress). init seeds the three rotation bytes and optional uniform
 * scale from the placement; render just draws the model.
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E3EE8;
extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;

#define CFLIGHTWALL_OBJFLAG_UPDATE_DISABLED 0x8000
#define CFLIGHTWALL_OBJFLAG_HITDETECT_DISABLED 0x2000

int cflightwall_getExtraSize(void) { return 0x0; }

int cflightwall_getObjectTypeId(void) { return 0x0; }

void cflightwall_free(void)
{
}

void cflightwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3EE8); }

void cflightwall_hitDetect(void)
{
}

void cflightwall_update(void)
{
}

void cflightwall_init(s16* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)def[0x1b] / lbl_803E3EEC;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3EF0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3EE8;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    ((GameObject*)obj)->objectFlags |= CFLIGHTWALL_OBJFLAG_UPDATE_DISABLED | CFLIGHTWALL_OBJFLAG_HITDETECT_DISABLED;
}

void cflightwall_release(void)
{
}

void cflightwall_initialise(void)
{
}
