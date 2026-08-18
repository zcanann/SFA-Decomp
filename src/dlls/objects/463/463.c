/*
 * DLL 0x1CF has no active-target object definition. Its init callback reads a
 * placement prefix, applies two encoded rotations, and disables visibility,
 * updates, and hit detection.
 */
#include "dlls/objects/463.h"

#include "main/object_render.h"
#include "main/gamebits_api.h"

int dll_1CF_getExtraSize(void) {
    return 0;
}

int dll_1CF_getObjectTypeId(void) {
    return 0;
}

void dll_1CF_free(void) {
}

void dll_1CF_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void dll_1CF_hitDetect(void) {
}

void dll_1CF_update(void) {
}

void dll_1CF_init(GameObject* obj, const Dll1CFPlacementView* placement) {
    if (mainGetBit(placement->gateGameBit) != 0u) {
        obj->anim.rotY = (s16)(((s32)placement->rotationYDegrees << 13) / 45);
    }
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN |
                                                 OBJECT_OBJFLAG_UPDATE_DISABLED));
}

void dll_1CF_release(void) {
}

void dll_1CF_initialise(void) {
}

ObjectDescriptor gDll1CFObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1CF_initialise,
    (ObjectDescriptorCallback)dll_1CF_release,
    0,
    (ObjectDescriptorCallback)dll_1CF_init,
    (ObjectDescriptorCallback)dll_1CF_update,
    (ObjectDescriptorCallback)dll_1CF_hitDetect,
    (ObjectDescriptorCallback)dll_1CF_render,
    (ObjectDescriptorCallback)dll_1CF_free,
    (ObjectDescriptorCallback)dll_1CF_getObjectTypeId,
    dll_1CF_getExtraSize,
};
