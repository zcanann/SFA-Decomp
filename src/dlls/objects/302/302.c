/*
 * Static rendered-model family with placement rotation, optional uniform
 * scale, and disabled update/hit-detection callbacks.
 */
#include "dlls/objects/302.h"

#include "main/object_render.h"

#define CFLIGHTWALL_ROTATION_SHIFT 8
#define CFLIGHTWALL_SCALE_DIVISOR  255.0f
#define CFLIGHTWALL_DEFAULT_SCALE  1.0f

int CFLightWall_getExtraSize(void) {
    return 0;
}

int CFLightWall_getObjectTypeId(void) {
    return 0;
}

void CFLightWall_free(void) {
}

void CFLightWall_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void CFLightWall_hitDetect(void) {
}

void CFLightWall_update(void) {
}

void CFLightWall_init(GameObject* obj, CFLightWallPlacement* placement) {
    obj->anim.rotZ = (s16)((s32)placement->initialRotZ << CFLIGHTWALL_ROTATION_SHIFT);
    obj->anim.rotY = (s16)((s32)placement->initialRotY << CFLIGHTWALL_ROTATION_SHIFT);
    obj->anim.rotX = (s16)((s32)placement->initialRotX << CFLIGHTWALL_ROTATION_SHIFT);
    if (placement->scale != 0) {
        obj->anim.rootMotionScale = (f32)(u32)placement->scale / CFLIGHTWALL_SCALE_DIVISOR;
        if (!obj->anim.rootMotionScale) {
            obj->anim.rootMotionScale = CFLIGHTWALL_DEFAULT_SCALE;
        }
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void CFLightWall_release(void) {
}

void CFLightWall_initialise(void) {
}

ObjectDescriptor gCFLightWallObjDescriptor = {
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
