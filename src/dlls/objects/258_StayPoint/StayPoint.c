/*
 * DLL 0x102 - StayPoint.
 *
 * Offers a conditional stay command and tracks whether Tricky is holding
 * position within this object's engagement radius.
 */
#include "dlls/objects/258_StayPoint.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/gamebits.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/objprint_render_api.h"

#define STAYPOINT_ENGAGE_RADIUS_SQ 1e+02f

#define STAYPOINT_GAMEBIT_NONE   -1
#define STAYPOINT_MENU_ITEM_NONE -1

#define STAYPOINT_PRIORITY_DEFAULT 0
#define STAYPOINT_PRIORITY_MENU    0x10

#define STAYPOINT_MODEL_VISIBLE_FLAG 0x01

#define STAYPOINT_COMMAND_TYPE 3

void StayPoint_update(GameObject* obj) {
    StayPointPlacement* placement;
    GameObject* tricky;
    int isCurrentStayPoint;

    placement = (StayPointPlacement*)obj->anim.placementData;
    tricky = getTrickyObject();
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (tricky != NULL) {
        isCurrentStayPoint = ((int)obj - (int)trickyGetStayPoint(tricky) == 0);
        if (isCurrentStayPoint == 0 && placement->activeGameBit != STAYPOINT_GAMEBIT_NONE) {
            mainSetBits(placement->activeGameBit, 0);
        }
        if (placement->requiredGameBit == STAYPOINT_GAMEBIT_NONE || mainGetBit(placement->requiredGameBit) != 0) {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared(&obj->anim.worldPosX, &tricky->anim.worldPosX) < STAYPOINT_ENGAGE_RADIUS_SQ) {
                if (placement->activeGameBit != STAYPOINT_GAMEBIT_NONE) {
                    mainSetBits(placement->activeGameBit, 1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == STAYPOINT_MENU_ITEM_NONE) {
                obj->anim.modelInstance->hitVolumes[0].priority = STAYPOINT_PRIORITY_DEFAULT;
            } else {
                obj->anim.modelInstance->hitVolumes[0].priority = STAYPOINT_PRIORITY_MENU;
            }
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if (((obj->anim.modelInstance->flags & STAYPOINT_MODEL_VISIBLE_FLAG) != 0) &&
                obj->anim.hitVolumeTransforms != NULL) {
                objUpdateHitVolumeTransforms(obj);
            }
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                           STAYPOINT_COMMAND_TYPE);
            }
        }
    }
}

void StayPoint_init(GameObject* obj) {
    u32 flags;

    flags = obj->objectFlags;
    flags |= OBJECT_OBJFLAG_HIDDEN;
    obj->objectFlags = flags;
}

ObjectDescriptor gStayPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};
