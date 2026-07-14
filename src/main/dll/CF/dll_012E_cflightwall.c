/*
 * cflightwall (DLL 0x12E) - static light-wall prop at CF (CloudRunner
 * Fortress). init seeds the three rotation bytes and optional uniform
 * scale from the placement; render just draws the model.
 */
#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

#define CFLIGHTWALL_OBJFLAG_UPDATE_DISABLED    0x8000
#define CFLIGHTWALL_OBJFLAG_HITDETECT_DISABLED 0x2000

#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E3EE8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E3EEC = 255.0f;
__declspec(section ".sdata2") f32 lbl_803E3EF0 = 0.0f;
#pragma explicit_zero_data off

int CFLightWall_getExtraSize(void)
{
    return 0x0;
}

int CFLightWall_getObjectTypeId(void)
{
    return 0x0;
}

void CFLightWall_free(void)
{
}

void CFLightWall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3EE8);
}

void CFLightWall_hitDetect(void)
{
}

void CFLightWall_update(void)
{
}

void CFLightWall_init(s16* obj, u8* def)
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

void CFLightWall_release(void)
{
}

void CFLightWall_initialise(void)
{
}

ObjectDescriptor gCflightwallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFLightWall_initialise,
    (ObjectDescriptorCallback)CFLightWall_release,
    0,
    (ObjectDescriptorCallback)CFLightWall_init,
    (ObjectDescriptorCallback)CFLightWall_update,
    (ObjectDescriptorCallback)CFLightWall_hitDetect,
    (ObjectDescriptorCallback)CFLightWall_render,
    (ObjectDescriptorCallback)CFLightWall_free,
    (ObjectDescriptorCallback)CFLightWall_getObjectTypeId,
    CFLightWall_getExtraSize,
};
