/* Clears sequence-event state and supplies otherwise minimal callbacks. */
#include "dlls/objects/324.h"
#include "main/object_render.h"
#include "main/objseq.h"

int dll_144_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    animUpdate->movementState = 0;
    return 0;
}

int dll_144_getExtraSize(void) {
    return 0;
}

int dll_144_getObjectTypeId(void) {
    return 0;
}

void dll_144_free(void) {
}

void dll_144_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void dll_144_hitDetect(void) {
}

void dll_144_update(void) {
}

void dll_144_init(GameObject* obj) {
    obj->anim.rotX = 0;
    obj->animEventCallback = dll_144_SeqFn;
}

void dll_144_release(void) {
}

void dll_144_initialise(void) {
}

ObjectDescriptor gDll144ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_144_initialise,
    (ObjectDescriptorCallback)dll_144_release,
    0,
    (ObjectDescriptorCallback)dll_144_init,
    (ObjectDescriptorCallback)dll_144_update,
    (ObjectDescriptorCallback)dll_144_hitDetect,
    (ObjectDescriptorCallback)dll_144_render,
    (ObjectDescriptorCallback)dll_144_free,
    (ObjectDescriptorCallback)dll_144_getObjectTypeId,
    dll_144_getExtraSize,
};
