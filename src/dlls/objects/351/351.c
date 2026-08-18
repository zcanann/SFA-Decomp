/* Target marker used by CFAttractor and DBAttractor. */

#include "dlls/objects/351.h"

#include "main/object_render.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/vecmath.h"

#define ATTRACTOR_OBJECT_GROUP 0x1E

void attractor_getTarget(GameObject* obj, GameObject** outTarget) {
    GameObject* target = NULL;
    AttractorPlacement* placement = (AttractorPlacement*)obj->anim.placementData;

    switch (placement->mode) {
    case ATTRACTOR_MODE_NONE:
        break;
    case ATTRACTOR_MODE_RETURN_SELF:
        target = obj;
        break;
    case ATTRACTOR_MODE_FACE_PLAYER: {
        GameObject* player = Obj_GetPlayerObject();
        int angle = atan2i(player->anim.localPosX - obj->anim.localPosX, player->anim.localPosZ - obj->anim.localPosZ);
        obj->anim.rotX = angle + 0x8000;
        target = obj;
        break;
    }
    }
    *outTarget = target;
}

int attractor_getScale(GameObject* obj) {
    AttractorPlacement* placement = (AttractorPlacement*)obj->anim.placementData;
    if (placement->mode != ATTRACTOR_MODE_NONE) {
        return placement->unknown1A;
    }
    return 0;
}

int attractor_getExtraSize(void) {
    return 0;
}

int attractor_getObjectTypeId(void) {
    return 0;
}

void attractor_free(GameObject* obj) {
    objFreeObjectType(obj, ATTRACTOR_OBJECT_GROUP);
}

void attractor_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void attractor_hitDetect(void) {
}

void attractor_update(void) {
}

void attractor_init(GameObject* obj, AttractorPlacement* placement) {
    objAddObjectType(obj, ATTRACTOR_OBJECT_GROUP);
    {
        s8 rotation = placement->rotXByte;
        s16 rotX = rotation << 8;
        obj->anim.rotX = rotX;
    }
}

void attractor_release(void) {
}

void attractor_initialise(void) {
}

ObjectDescriptor12 gAttractorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)attractor_initialise,
    (ObjectDescriptorCallback)attractor_release,
    0,
    (ObjectDescriptorCallback)attractor_init,
    (ObjectDescriptorCallback)attractor_update,
    (ObjectDescriptorCallback)attractor_hitDetect,
    (ObjectDescriptorCallback)attractor_render,
    (ObjectDescriptorCallback)attractor_free,
    (ObjectDescriptorCallback)attractor_getObjectTypeId,
    attractor_getExtraSize,
    (ObjectDescriptorCallback)attractor_getScale,
    (ObjectDescriptorCallback)attractor_getTarget,
};
