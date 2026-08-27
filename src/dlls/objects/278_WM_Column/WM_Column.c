#include "dlls/objects/278_WM_Column.h"

#include "main/carryable_interface.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/object_render.h"
#include "main/obj_list.h"
#include "main/objtype.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/gamebits_api.h"

#define WM_COLUMN_GROUP                        4
#define WM_COLUMN_TARGET_GROUP                 0x10
#define WM_COLUMN_TYPE_ID                      0
#define WM_COLUMN_SCENE_MARKER_OBJECT_ID       499
#define WM_COLUMN_OBJECT_ID_BASE               500
#define WM_COLUMN_GAME_BIT_NONE                -1
#define WM_COLUMN_GAME_BIT_CLEAR               0
#define WM_COLUMN_GAME_BIT_SET                 1
#define WM_COLUMN_USER_FLAG_SNAP_ON_DROP       0x01
#define WM_COLUMN_USER_FLAG_CLEAR_SPOT_ON_GRAB 0x02
#define WM_COLUMN_INITIAL_SEARCH_DISTANCE      10000.0f
#define WM_COLUMN_SCENE_MARKER_DISTANCE        35.0f
#define WM_COLUMN_DROP_TARGET_MIN_DISTANCE     60.0f
#define WM_COLUMN_DROP_ENABLED                 0
#define WM_COLUMN_DROP_DISABLED                1
#define WM_COLUMN_ROTATION_SHIFT               8
#define WM_COLUMN_DEFAULT_MODEL_BANK           0
#define WM_COLUMN_CARRYABLE_INIT_ARG           0x32
#define WM_COLUMN_MODEL_SCALE                  1.0f

int WM_Column_getExtraSize(void) {
    return sizeof(CarryableState);
}

int WM_Column_getObjectTypeId(void) {
    return WM_COLUMN_TYPE_ID;
}

void WM_Column_free(GameObject* obj) {
    objFreeObjectType(obj, WM_COLUMN_GROUP);
    (*gCarryableInterface)->free(obj);
}

void WM_Column_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if ((*gCarryableInterface)->updateRenderState(obj, visible) != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, WM_COLUMN_MODEL_SCALE);
    }
}

void WM_Column_hitDetect(void) {
}

void WM_Column_update(GameObject* obj) {
    GameObject** objects;
    u32 playerStateFlags;
    f32 nearestDistance;
    int objectIndex;
    int objectCount;
    GameObject* candidate;
    CarryableState* state;
    GameObject* player;

    state = obj->extra;
    nearestDistance = WM_COLUMN_INITIAL_SEARCH_DISTANCE;
    if ((*gCarryableInterface)->updateHeld(obj, (CarryableState*)obj->extra) != 0) {
        if ((obj->userData1 & WM_COLUMN_USER_FLAG_CLEAR_SPOT_ON_GRAB) != 0) {
            objects = ObjList_GetObjects(&objectIndex, &objectCount);
            for (; objectIndex < objectCount; objectIndex++) {
                candidate = objects[objectIndex];
                if (candidate != obj && candidate->anim.romDefNo == WM_COLUMN_SCENE_MARKER_OBJECT_ID &&
                    Vec_distance(&obj->anim.worldPosX, &candidate->anim.worldPosX) < WM_COLUMN_SCENE_MARKER_DISTANCE) {
                    WMColumnPlacement* placement = (WMColumnPlacement*)objects[objectIndex]->anim.placementData;

                    if (placement->occupiedGameBit != WM_COLUMN_GAME_BIT_NONE) {
                        mainSetBits(placement->occupiedGameBit, WM_COLUMN_GAME_BIT_CLEAR);
                    }
                }
            }
        }

        player = Obj_GetPlayerObject();
        objGetNearestTypeTo(WM_COLUMN_TARGET_GROUP, obj, &nearestDistance);
        playerStateFlags = playerGetStateFlag310(player);
        if ((playerStateFlags & PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE) != 0 &&
            nearestDistance > WM_COLUMN_DROP_TARGET_MIN_DISTANCE) {
            (*gCarryableInterface)->setDropDisabled(state, WM_COLUMN_DROP_ENABLED);
            setAButtonIcon(A_BUTTON_ICON_PLACE_CARRYABLE);
            obj->userData1 |= WM_COLUMN_USER_FLAG_SNAP_ON_DROP;
        } else {
            (*gCarryableInterface)->setDropDisabled(state, WM_COLUMN_DROP_DISABLED);
        }
        obj->userData1 &= ~WM_COLUMN_USER_FLAG_CLEAR_SPOT_ON_GRAB;
    } else {
        if ((obj->userData1 & WM_COLUMN_USER_FLAG_SNAP_ON_DROP) != 0) {
            objects = ObjList_GetObjects(&objectIndex, &objectCount);
            for (; objectIndex < objectCount; objectIndex++) {
                candidate = objects[objectIndex];
                if (candidate != obj && candidate->anim.romDefNo == WM_COLUMN_SCENE_MARKER_OBJECT_ID &&
                    Vec_distance(&obj->anim.worldPosX, &candidate->anim.worldPosX) < WM_COLUMN_SCENE_MARKER_DISTANCE) {
                    WMColumnPlacement* placement = (WMColumnPlacement*)objects[objectIndex]->anim.placementData;

                    if (obj->anim.romDefNo == (s8)placement->modelBankIndex + WM_COLUMN_OBJECT_ID_BASE) {
                        if (placement->occupiedGameBit != WM_COLUMN_GAME_BIT_NONE) {
                            mainSetBits(placement->occupiedGameBit, WM_COLUMN_GAME_BIT_SET);
                        }
                    } else if (placement->occupiedGameBit != WM_COLUMN_GAME_BIT_NONE) {
                        mainSetBits(placement->occupiedGameBit, WM_COLUMN_GAME_BIT_CLEAR);
                    }
                    obj->anim.localPosX = objects[objectIndex]->anim.localPosX;
                    obj->anim.localPosY = objects[objectIndex]->anim.localPosY;
                    obj->anim.localPosZ = objects[objectIndex]->anim.localPosZ;
                }
            }
        }

        playerStateFlags = playerGetStateFlag310(Obj_GetPlayerObject());
        if ((playerStateFlags & PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE) != 0) {
            (*gCarryableInterface)->setDropDisabled(state, WM_COLUMN_DROP_ENABLED);
            obj->userData1 |= WM_COLUMN_USER_FLAG_CLEAR_SPOT_ON_GRAB;
        } else {
            (*gCarryableInterface)->setDropDisabled(state, WM_COLUMN_DROP_DISABLED);
            obj->userData1 &= ~WM_COLUMN_USER_FLAG_CLEAR_SPOT_ON_GRAB;
        }
        obj->userData1 &= ~WM_COLUMN_USER_FLAG_SNAP_ON_DROP;
    }
}

void WM_Column_init(GameObject* obj, WMColumnPlacement* placement) {
    CarryableState* state = obj->extra;

    obj->anim.rotX = (s16)(placement->initialYaw << WM_COLUMN_ROTATION_SHIFT);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->userData1 = 0;
    obj->anim.bankIndex = placement->modelBankIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount) {
        obj->anim.bankIndex = WM_COLUMN_DEFAULT_MODEL_BANK;
    }
    (*gCarryableInterface)->init(obj, state, WM_COLUMN_CARRYABLE_INIT_ARG);
    objAddObjectType(obj, WM_COLUMN_GROUP);
}

void WM_Column_release(void) {
}

void WM_Column_initialise(void) {
}

ObjectDescriptor gWM_ColumnObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_Column_initialise,
    (ObjectDescriptorCallback)WM_Column_release,
    0,
    (ObjectDescriptorCallback)WM_Column_init,
    (ObjectDescriptorCallback)WM_Column_update,
    (ObjectDescriptorCallback)WM_Column_hitDetect,
    (ObjectDescriptorCallback)WM_Column_render,
    (ObjectDescriptorCallback)WM_Column_free,
    (ObjectDescriptorCallback)WM_Column_getObjectTypeId,
    WM_Column_getExtraSize,
};
