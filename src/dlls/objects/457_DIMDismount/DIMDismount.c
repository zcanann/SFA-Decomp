/*
 * DIMDismount (DLL 0x1C9) - dismount-point object for Dinosaur Island
 * Mission 2. Tracks the nearest mount and exposes a signed-distance plane test
 * so the mount can determine which side of the dismount point the player is on.
 */
#include "dlls/objects/457_DIMDismount.h"
#include "dlls/objects/common/vehicle.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objprint_render_api.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/object_render.h"
#include "sys/objects.h"

typedef struct DimDismountNeighborVTable {
    void* unknown00[8];
    int (*canUseDismountPoint)(GameObject* neighbor, GameObject* dismountPoint);
} DimDismountNeighborVTable;

STATIC_ASSERT(offsetof(DimDismountNeighborVTable, canUseDismountPoint) == 0x20);

void DIMDismountPoint_func0B(GameObject* obj, int side) {
    (*gObjectTriggerInterface)->runSequence((side ^ 1) + 2, (void*)obj, -1);
}

int DIMDismountPoint_func0A(GameObject* obj) {
    GameObject* player = Obj_GetPlayerObject();
    DimDismountState* state = obj->extra;
    f32 signedDistance;
    int playerSide;

    signedDistance = state->planeConstant +
                     (state->planeNormalZ * player->anim.localPosZ +
                      (state->planeNormalX * player->anim.localPosX + state->planeNormalY * player->anim.localPosY));

    if (signedDistance >= 0.0f) {
        playerSide = 0;
    } else {
        playerSide = 1;
    }
    (*gObjectTriggerInterface)->runSequence(playerSide, (void*)obj, -1);
    return playerSide;
}

int DIMDismountPoint_getExtraSize(void) {
    return sizeof(DimDismountState);
}

int DIMDismountPoint_getObjectTypeId(void) {
    return 0;
}

void DIMDismountPoint_free(GameObject* obj) {
    objFreeObjectType(obj, DIM_DISMOUNT_POINT_OBJECT_GROUP);
}

void DIMDismountPoint_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible) {
    if (visible == 0 || obj->userData2 != 0) {
        if (obj->userData2 != 0) {
            objUpdateHitVolumeTransforms(obj);
        }
    } else {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void DIMDismountPoint_hitDetect(void) {
}

void DIMDismountPoint_update(GameObject* obj) {
    GameObject* nearestNeighbor;
    f32 searchRadius;

    searchRadius = 500.0f;
    nearestNeighbor = objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, obj, &searchRadius);
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (mainGetBit(GAMEBIT_NW_SnowHorn03E3) != 0) {
        obj->hitVolumeIndex = 1;
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->hitVolumeIndex = 0;
        if (nearestNeighbor != NULL &&
            (*(DimDismountNeighborVTable**)nearestNeighbor->anim.dll)->canUseDismountPoint(nearestNeighbor, obj) != 0) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        } else {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if ((obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0 && obj->anim.hitVolumeTransforms != NULL) {
        objUpdateHitVolumeTransforms(obj);
    }
}

void DIMDismountPoint_init(GameObject* obj, DimDismountPlacement* placement) {
    DimDismountState* state;

    objAddObjectType(obj, DIM_DISMOUNT_POINT_OBJECT_GROUP);
    obj->anim.rotX = (s16)(placement->rotationXByte << 8);
    state = obj->extra;
    state->planeNormalX = mathSinf(3.1415927f * (f32)(s32)obj->anim.rotX / 32768.0f);
    state->planeNormalY = 0.0f;
    state->planeNormalZ = mathCosf(3.1415927f * (f32)(s32)obj->anim.rotX / 32768.0f);
    state->planeConstant = -(state->planeNormalX * obj->anim.localPosX + state->planeNormalY * obj->anim.localPosY +
                             state->planeNormalZ * obj->anim.localPosZ);
    obj->userData2 = 1;
}

void DIMDismountPoint_release(void) {
}

void DIMDismountPoint_initialise(void) {
}

ObjectDescriptor12 gDIMDismountPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)DIMDismountPoint_initialise,
    (ObjectDescriptorCallback)DIMDismountPoint_release,
    0,
    (ObjectDescriptorCallback)DIMDismountPoint_init,
    (ObjectDescriptorCallback)DIMDismountPoint_update,
    (ObjectDescriptorCallback)DIMDismountPoint_hitDetect,
    (ObjectDescriptorCallback)DIMDismountPoint_render,
    (ObjectDescriptorCallback)DIMDismountPoint_free,
    (ObjectDescriptorCallback)DIMDismountPoint_getObjectTypeId,
    DIMDismountPoint_getExtraSize,
    (ObjectDescriptorCallback)DIMDismountPoint_func0A,
    (ObjectDescriptorCallback)DIMDismountPoint_func0B,
};
