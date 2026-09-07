/*
 * Barrel-launcher pad family. Its launch sequences spawn arced particle
 * bursts; placement data supplies the initial rotation and optional scale.
 */
#include "dlls/objects/303_BarrelPad.h"

#include "main/dll/partfx_interface.h"
#include "main/objfx.h"
#include "main/object_render.h"

#define BARRELPAD_SEQ_LAUNCH_ACTIVE    0x79
#define BARRELPAD_SEQ_LAUNCH_SECONDARY 0x748

#define BARRELPAD_ROTATION_SHIFT 8
#define BARRELPAD_SCALE_DIVISOR  255.0f
#define BARRELPAD_DEFAULT_SCALE  1.0f

int BarrelPad_getExtraSize(void) {
    return 0;
}

int BarrelPad_getObjectTypeId(void) {
    return 0;
}

void BarrelPad_free(void) {
}

void BarrelPad_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, BARRELPAD_DEFAULT_SCALE);
}

void BarrelPad_hitDetect(void) {
}

void BarrelPad_update(GameObject* obj) {
    PartFxSpawnParams particleArgs;

    if (obj->anim.romDefNo == BARRELPAD_SEQ_LAUNCH_ACTIVE) {
        particleArgs.posX = 0.0f;
        particleArgs.posY = 8.0f;
        particleArgs.posZ = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 5, 2, 0x19, 12.0f, 12.0f, 2.0f, &particleArgs, 0);
    } else if (obj->anim.romDefNo == BARRELPAD_SEQ_LAUNCH_SECONDARY) {
        particleArgs.posX = 0.0f;
        particleArgs.posY = 6.0f;
        particleArgs.posZ = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.25f, 5, 2, 5, 7.0f, 7.0f, 2.0f, &particleArgs, 0);
    }
}

void BarrelPad_init(GameObject* obj, BarrelPadPlacement* placement) {
    obj->anim.rotZ = (s16)((s32)placement->initialRotZ << BARRELPAD_ROTATION_SHIFT);
    obj->anim.rotY = (s16)((s32)placement->initialRotY << BARRELPAD_ROTATION_SHIFT);
    obj->anim.rotX = (s16)((s32)placement->initialRotX << BARRELPAD_ROTATION_SHIFT);
    if (placement->scale != 0) {
        obj->anim.rootMotionScale = (f32)(u32)placement->scale / BARRELPAD_SCALE_DIVISOR;
        if (!obj->anim.rootMotionScale) {
            obj->anim.rootMotionScale = BARRELPAD_DEFAULT_SCALE;
        }
        obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void BarrelPad_release(void) {
}

void BarrelPad_initialise(void) {
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
