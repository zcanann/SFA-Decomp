/*
 * DLL 0x1A4 (slot 420) - paired SnowHorn Wastes ice objects.
 *
 * Retail objects NW_ice1, NW_ice2, and NW_ice3 use this DLL. Each instance
 * finds the slot-419 object with the same placement pair ID, follows its
 * transform, and disables collision as that paired object fades out.
 */
#include "dlls/objects/420.h"

#include "dlls/objects/419.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/objhits.h"
#include "main/objtype.h"

#define NW_ICE_COLLISION_ALPHA_THRESHOLD 0xC0
#define NW_ICE_NEAR_DISTANCE             120.0f

int NW_ice_getExtraSize(void) {
    return sizeof(NwIceState);
}

void NW_ice_free(GameObject* obj) {
    objFreeObjectType(obj, NW_ICE_OBJECT_GROUP_ID);
}

void NW_ice_render(void) {
}

void NW_ice_update(GameObject* obj) {
    GameObject** candidatePtr;
    int objectIndex;
    NwIcePlacement* placement;
    NwIceState* state;
    GameObject** pairedObjects;
    GameObject* candidateObject;
    int objectCount;
    f32 nearestDistance;

    nearestDistance = 3.4028235e38f;
    state = (NwIceState*)obj->extra;
    if (state->pairedIceObject != NULL) {
        obj->anim.localPosX = state->pairedIceObject->anim.localPosX;
        obj->anim.localPosY = state->pairedIceObject->anim.localPosY;
        obj->anim.localPosZ = state->pairedIceObject->anim.localPosZ;
        obj->anim.rotX = state->pairedIceObject->anim.rotX;
        objGetNearestTypeToExcludingSelf(NW_ICE_OBJECT_GROUP_ID, obj, &nearestDistance);

        if (state->pairedIceObject->anim.alpha < NW_ICE_COLLISION_ALPHA_THRESHOLD) {
            ObjHits_DisableObject(obj);
            playerReleaseLedgeGrabOn(Obj_GetPlayerObject(), obj);
        } else {
            ObjHits_EnableObject(obj);
        }

        if ((state->pairedIceObject->anim.alpha < NW_ICE_COLLISION_ALPHA_THRESHOLD) ||
            (nearestDistance < NW_ICE_NEAR_DISTANCE)) {
            obj->objectFlags = (u16)(obj->objectFlags | 0x100);
        } else {
            obj->objectFlags = (u16)(obj->objectFlags & ~0x100);
        }
    } else {
        pairedObjects = (GameObject**)objGetAllOfType(DLL1A3_OBJECT_GROUP_ID, &objectCount);
        placement = (NwIcePlacement*)obj->anim.placementData;
        for (objectIndex = 0, candidatePtr = pairedObjects; objectIndex < objectCount; candidatePtr++, objectIndex++) {
            candidateObject = *candidatePtr;
            if (obj != candidateObject &&
                placement->pairId == ((NwIcePlacement*)candidateObject->anim.placementData)->pairId) {
                state->pairedIceObject = pairedObjects[objectIndex];
                break;
            }
        }
    }
}

void NW_ice_init(GameObject* obj) {
    objAddObjectType(obj, NW_ICE_OBJECT_GROUP_ID);
}

ObjectDescriptor gNW_iceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)NW_ice_init,
    (ObjectDescriptorCallback)NW_ice_update,
    0,
    (ObjectDescriptorCallback)NW_ice_render,
    (ObjectDescriptorCallback)NW_ice_free,
    0,
    NW_ice_getExtraSize,
};
