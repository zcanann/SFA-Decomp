/* Supplies the render and message-queue callbacks for FElevControl. */
#include "dlls/objects/322_FElevContro.h"

#include "main/obj_message.h"
#include "main/object_render.h"

/* 1.0f model render scale from the shared scalar pool. */
enum {
    FELEV_CONTROL_MESSAGE_QUEUE_CAPACITY = 2,
};

int FElevControl_getExtraSize(void) {
    return 0;
}

int FElevControl_getObjectTypeId(void) {
    return 0;
}

void FElevControl_free(void) {
}

void FElevControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void FElevControl_hitDetect(void) {
}

void FElevControl_update(void) {
}

void FElevControl_init(GameObject* obj) {
    ObjMsg_AllocQueue(obj, 2);
}

void FElevControl_release(void) {
}

void FElevControl_initialise(void) {
}

ObjectDescriptor gFElevControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
