/*
 * cflightwall (DLL 0x12E) - static light-wall prop at CF (CloudRunner
 * Fortress). init seeds the three rotation bytes and optional uniform
 * scale from the placement; render just draws the model.
 */
#include "main/game_object.h"

extern f32 lbl_803E3EE8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;

void cflightwall_free(void)
{
}

void cflightwall_hitDetect(void)
{
}

void cflightwall_update(void)
{
}

void cflightwall_release(void)
{
}

void cflightwall_initialise(void)
{
}

int cflightwall_getExtraSize(void) { return 0x0; }
int cflightwall_getObjectTypeId(void) { return 0x0; }

void cflightwall_render(void) { objRenderFn_8003b8f4(lbl_803E3EE8); }

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
            ((GameObject*)obj)->anim.rootMotionScale * *(f32*)((char*)*(int**)&((GameObject*)obj)->anim.modelInstance + 4);
    }
    ((GameObject*)obj)->objectFlags |= 0xA000;
}
