/*
 * cflightwall (DLL 0x12E) - static light-wall prop at CF (CloudRunner
 * Fortress). init seeds the three rotation bytes and optional uniform
 * scale from the placement; render just draws the model.
 */
#include "main/object_render.h"
#include "main/dll/CF/dll_012E_cflightwall.h"

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

void CFLightWall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void CFLightWall_hitDetect(void)
{
}

void CFLightWall_update(void)
{
}

void CFLightWall_init(GameObject* obj, CFLightWallSetup* setup)
{
    obj->anim.rotZ = (s16)((s32)setup->rotZ << 8);
    obj->anim.rotY = (s16)((s32)setup->rotY << 8);
    obj->anim.rotX = (s16)((s32)setup->rotX << 8);
    if (setup->scale != 0)
    {
        obj->anim.rootMotionScale = (f32)(u32)setup->scale / 255.0f;
        if (!obj->anim.rootMotionScale)
        {
            obj->anim.rootMotionScale = 1.0f;
        }
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HITDETECT_DISABLED;
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
