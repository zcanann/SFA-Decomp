/*
 * SH_swaplift / warpstonelift (DLL 0x1AF) - the WarpStone lift platform.
 *
 * The platform tracks whether the player is standing in range by scanning its
 * contact-object list. It offers Rock Candy through the Y-button menu, records
 * when the candy has been given to the WarpStone, and disables its interaction
 * hit volume while the player is out of range.
 */
#include "dlls/objects/431_SH_swaplift.h"

#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/tricky_api.h"
#include "main/gamebits.h"
#include "main/obj_trigger.h"
#include "main/object_render.h"
#include "sys/objects.h"

#define WARP_STONE_LIFT_PLAYER_CLASS_ID 1

s32 gWarpStoneLiftStateGameBits[WARP_STONE_LIFT_STATE_GAMEBIT_COUNT] = {
    GAMEBIT_ITEM_RockCandy_Got,
    GAMEBIT_ITEM_RockCandy_Used,
};

int warpstonelift_getExtraSize(void) {
    return sizeof(WarpStoneLiftState);
}

int warpstonelift_getObjectTypeId(void) {
    return 0;
}

void warpstonelift_free(void) {
}

void warpstonelift_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void warpstonelift_hitDetect(void) {
}

void warpstonelift_update(GameObject* obj) {
    WarpStoneLiftState* state = obj->extra;
    int objectOffset;
    u8* contactState;
    int foundPlayer = 0;
    int count;
    int i;
    s16 item;

    contactState = (u8*)obj->anim.hitboxTransformState;
    count = ((ObjHitboxTransformState*)contactState)->contactObjectCount;
    if (count > 0) {
        objectOffset = 0;
        for (i = 0; i < count; i++) {
            GameObject* other =
                *(GameObject**)(contactState + objectOffset + offsetof(ObjHitboxTransformState, contactObjects));
            if (other->anim.classId == WARP_STONE_LIFT_PLAYER_CLASS_ID) {
                foundPlayer = 1;
            }
            objectOffset += sizeof(GameObject*);
        }
    }
    if (foundPlayer != 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        switch (state->stateId) {
        case WARP_STONE_LIFT_STATE_WAITING_FOR_ROCK_CANDY:
        case WARP_STONE_LIFT_STATE_ROCK_CANDY_AVAILABLE:
            getYButtonItem(&item);
            if ((mainGetBit(GAMEBIT_ITEM_RockCandy_Got) != 0 && cMenuGetSelectedItem() != -1) ||
                item == GAMEBIT_ITEM_RockCandy_Got) {
                Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
            } else {
                Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
            }
            if (ObjTrigger_IsSetById(obj, GAMEBIT_ITEM_RockCandy_Got) != 0) {
                mainSetBits(GAMEBIT_ITEM_RockCandyRelated0886, 1);
                mainSetBits(GAMEBIT_ITEM_RockCandy_Used, 1);
                state->stateId = WARP_STONE_LIFT_STATE_ROCK_CANDY_USED;
                Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 3);
            } else if (ObjTrigger_IsSet(obj) != 0) {
                mainSetBits(GAMEBIT_SH_WarpStoneComplainingAboutGifts, 1);
            }
            break;
        case WARP_STONE_LIFT_STATE_ROCK_CANDY_USED:
            if (ObjTrigger_IsSet(obj) != 0) {
                mainSetBits(GAMEBIT_ITEM_RockCandyRelated0886, 1);
            }
            break;
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
}

void warpstonelift_init(GameObject* obj, const WarpStoneLiftPlacement* placement) {
    WarpStoneLiftState* stateStorage = obj->extra;
    int i;

    obj->anim.rotX = placement->rotXByte << 8;
    obj->userData1 = 0;
    for (i = 0; i < WARP_STONE_LIFT_STATE_GAMEBIT_COUNT; i++) {
        if (mainGetBit(gWarpStoneLiftStateGameBits[i]) != 0) {
            stateStorage->stateId = i + 1;
        }
    }
    switch (stateStorage->stateId) {
    case WARP_STONE_LIFT_STATE_WAITING_FOR_ROCK_CANDY:
    case WARP_STONE_LIFT_STATE_ROCK_CANDY_USED:
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 3);
        break;
    case WARP_STONE_LIFT_STATE_ROCK_CANDY_AVAILABLE:
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        break;
    }
}

void warpstonelift_release(void) {
}

void warpstonelift_initialise(void) {
}

ObjectDescriptor gWarpStoneLiftObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)warpstonelift_initialise,
    (ObjectDescriptorCallback)warpstonelift_release,
    0,
    (ObjectDescriptorCallback)warpstonelift_init,
    (ObjectDescriptorCallback)warpstonelift_update,
    (ObjectDescriptorCallback)warpstonelift_hitDetect,
    (ObjectDescriptorCallback)warpstonelift_render,
    (ObjectDescriptorCallback)warpstonelift_free,
    (ObjectDescriptorCallback)warpstonelift_getObjectTypeId,
    warpstonelift_getExtraSize,
};
