/*
 * barrelpad (DLL 0x12F) - the barrel-launcher pad object. Spawns
 * arced-burst particle effects when the barrel's seqId indicates an
 * active launch (0x79) or a secondary launch state (0x748). init reads
 * rotation and rootMotionScale from the placement record and enables the
 * object in the engine with hit detection disabled.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/dll/dll_012F_barrelpad.h"
#include "main/object_descriptor.h"

/* anim.seqId variants driving the launch particle burst */
#define BARRELPAD_SEQ_LAUNCH_ACTIVE    0x79  /* active launch burst */
#define BARRELPAD_SEQ_LAUNCH_SECONDARY 0x748 /* secondary launch state */

int BarrelPad_getExtraSize(void)
{
    return 0x0;
}
int BarrelPad_getObjectTypeId(void)
{
    return 0x0;
}

void BarrelPad_free(void)
{
}

void BarrelPad_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void BarrelPad_hitDetect(void)
{
}

void BarrelPad_update(GameObject* obj)
{
    BarrelPadParticleArgs particleArgs;

    if (obj->anim.seqId == BARRELPAD_SEQ_LAUNCH_ACTIVE)
    {
        particleArgs.offset[0] = 0.0f;
        particleArgs.offset[1] = 8.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 12.0f, 12.0f, 2.0f, &particleArgs, 0);
    }
    else if (obj->anim.seqId == BARRELPAD_SEQ_LAUNCH_SECONDARY)
    {
        particleArgs.offset[0] = 0.0f;
        particleArgs.offset[1] = 6.0f;
        particleArgs.offset[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.25f, 5, 2, 5, 7.0f, 7.0f, 2.0f, &particleArgs, 0);
    }
}

void BarrelPad_init(GameObject* obj, BarrelPadSetup* setup)
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
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void BarrelPad_release(void)
{
}

void BarrelPad_initialise(void)
{
}

ObjectDescriptor gBarrelPadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)BarrelPad_initialise,
    (ObjectDescriptorCallback)BarrelPad_release,
    0,
    (ObjectDescriptorCallback)BarrelPad_init,
    (ObjectDescriptorCallback)BarrelPad_update,
    (ObjectDescriptorCallback)BarrelPad_hitDetect,
    (ObjectDescriptorCallback)BarrelPad_render,
    (ObjectDescriptorCallback)BarrelPad_free,
    (ObjectDescriptorCallback)BarrelPad_getObjectTypeId,
    BarrelPad_getExtraSize,
};
