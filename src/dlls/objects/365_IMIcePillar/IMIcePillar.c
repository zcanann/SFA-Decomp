#include "dlls/objects/365_IMIcePillar.h"

#include "main/object_render.h"

int imIcePillar_getExtraSize(void) {
    return 4;
}

int imIcePillar_getObjectTypeId(void) {
    return 0;
}

void imIcePillar_free(void) {
}

void imIcePillar_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void imIcePillar_hitDetect(void) {
}

void imIcePillar_update(void) {
}

void imIcePillar_init(void) {
}

void imIcePillar_release(void) {
}

void imIcePillar_initialise(void) {
}

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imIcePillar_initialise,
    (ObjectDescriptorCallback)imIcePillar_release,
    0,
    (ObjectDescriptorCallback)imIcePillar_init,
    (ObjectDescriptorCallback)imIcePillar_update,
    (ObjectDescriptorCallback)imIcePillar_hitDetect,
    (ObjectDescriptorCallback)imIcePillar_render,
    (ObjectDescriptorCallback)imIcePillar_free,
    (ObjectDescriptorCallback)imIcePillar_getObjectTypeId,
    imIcePillar_getExtraSize,
};
