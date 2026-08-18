/*
 * GPSH_Scene (DLL 0x194) - Test of Knowledge scene geometry.
 */
#include "dlls/objects/404_GPSH_Scene.h"
#include "main/object_render.h"

int gpshScene_getExtraSize(void) {
    return 0;
}

int gpshScene_getObjectTypeId(void) {
    return 0;
}

void gpshScene_free(void) {
}

void gpshScene_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void gpshScene_hitDetect(void) {
}

void gpshScene_update(void) {
}

void gpshScene_init(GameObject* obj, const GPSHScenePlacement* placement) {
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
}

void gpshScene_release(void) {
}

void gpshScene_initialise(void) {
}

ObjectDescriptor gGPSHSceneObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gpshScene_initialise,
    (ObjectDescriptorCallback)gpshScene_release,
    0,
    (ObjectDescriptorCallback)gpshScene_init,
    (ObjectDescriptorCallback)gpshScene_update,
    (ObjectDescriptorCallback)gpshScene_hitDetect,
    (ObjectDescriptorCallback)gpshScene_render,
    (ObjectDescriptorCallback)gpshScene_free,
    (ObjectDescriptorCallback)gpshScene_getObjectTypeId,
    gpshScene_getExtraSize,
};
