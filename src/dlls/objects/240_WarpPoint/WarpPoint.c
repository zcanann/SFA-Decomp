/*
 * WarpPoint (DLL 0x00F0) - placed map-transition / save-point markers.
 *
 * Each instance carries a placement-defined mode byte
 * (WarpPointPlacement.mode at 0x1D) that selects how the marker behaves in
 * WarpPoint_update:
 *   mode 0: proximity warp / trigger-sequence near the player;
 *   mode 1: trigger sequences while a hint flag is set and on a timer;
 *   mode 2/4: gated warp when its game bit is set and the player is in
 *             range (modes 2/4 use the world-space distance variant);
 *   mode 3: one-shot trigger-sequence gated on its game bit.
 * mode 2 also doubles as a no-op marker at init (clears the timer).
 *
 * Most behavior keys off the player object's position/parent, the WARPTAB
 * index the player arrived through (gArrivedWarpIndex), and per-marker game
 * bits. Markers placed on the WARPPOINT_MAP_SAVE_* maps additionally record a
 * save point the first time their own arrivalWarpId matches that index.
 */
#include "dlls/objects/240_WarpPoint.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/rcp_dolphin_api.h"
#include "main/shader_api.h"

/* placement idents that arm the one-shot save-point recording at init */
#define WARPPOINT_MAP_SAVE_A 0x4B675
#define WARPPOINT_MAP_SAVE_B 0x46882

/* romDefNo variant that records a save point (sets GAMEBIT_WarpPointRelatedD53
   and calls the map-event savePoint) before running its sequence. */
#define WARPPOINT_SEQ_ID_SAVEPOINT 0x27E

#define WARPPOINT_OBJECT_TYPE_ID       1
#define WARPPOINT_INITIAL_WARP_DELAY   0x1E
#define WARPPOINT_RADIUS_SHIFT         2
#define WARPPOINT_HINT_TRIGGER_RADIUS  100.0f
#define WARPPOINT_ZERO                 0.0f
#define WARPPOINT_HINT_TIMER_FRAMES    2
#define WARPPOINT_NO_ARRIVAL_WARP      -1
#define WARPPOINT_NO_WARP              -1
#define WARPPOINT_ANIM_TRIGGER_WARP    1
#define WARPPOINT_ANIM_TRIGGER_NONE    0
#define WARPPOINT_SEQUENCE_HINT_ACTIVE 1
#define WARPPOINT_SEQUENCE_HINT_DONE   0

int WarpPoint_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    WarpPointPlacement* placement = (WarpPointPlacement*)obj->anim.placementData;

    (void)unused;

    if (placement->mode != WARPPOINT_MODE_GATED_WARP) {
        if (animUpdate->curEventId == WARPPOINT_ANIM_TRIGGER_WARP) {
            int warpId = (s8) * (u8*)&placement->warpId;
            if (warpId > WARPPOINT_NO_WARP) {
                warpToMap(warpId, 1);
                animUpdate->curEventId = WARPPOINT_ANIM_TRIGGER_NONE;
            }
        }
    }
    return 0;
}

int WarpPoint_getExtraSize(void) {
    return sizeof(WarpPointState);
}

int WarpPoint_getObjectTypeId(void) {
    return WARPPOINT_OBJECT_TYPE_ID;
}

void WarpPoint_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    WarpPointPlacement* placement = (WarpPointPlacement*)obj->anim.placementData;

    (void)fwdArg2;
    (void)fwdArg3;
    (void)fwdArg4;
    (void)fwdArg5;

    if (visible == 0) {
        return;
    }
    if (placement->mode == WARPPOINT_MODE_HINT_TIMER) {
        return;
    }
}

void WarpPoint_update(GameObject* obj) {
    WarpPointPlacement* placement;
    WarpPointState* state;
    GameObject* player;
    f32 distance;

    placement = (WarpPointPlacement*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    state->warpDelay -= framesThisStep;
    if (state->warpDelay < 0) {
        state->warpDelay = 0;
    }
    if (placement->savePointArmed != 0 && state->savePointRecorded == 0 && gArrivedWarpIndex > WARPPOINT_NO_ARRIVAL_WARP &&
        gArrivedWarpIndex == placement->arrivalWarpId) {
        (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 0, getCurMapLayer());
        state->savePointRecorded = 1;
    }
    switch (placement->mode) {
    case WARPPOINT_MODE_PROXIMITY:
        if (gArrivedWarpIndex > WARPPOINT_NO_ARRIVAL_WARP || mainGetBit(GAMEBIT_WarpPointRelatedD53) != 0) {
            f32 deltaX = player->anim.localPosX - obj->anim.localPosX;
            f32 deltaY = player->anim.localPosY - obj->anim.localPosY;
            f32 deltaZ = player->anim.localPosZ - obj->anim.localPosZ;
            distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
            if (state->sequenceTriggered == 0 && placement->enabled != 0 && distance < state->triggerRadius &&
                player->anim.parent == obj->anim.parent) {
                if (obj->anim.romDefNo == WARPPOINT_SEQ_ID_SAVEPOINT) {
                    mainSetBits(GAMEBIT_WarpPointRelatedD53, 1);
                    (*gMapEventInterface)
                        ->savePoint(&player->anim.localPosX, player->anim.rotX, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state->sequenceId, obj, -1);
                mainSetBits(GAMEBIT_WarpPointRelatedD53, 0);
                gWarpArrivalTimer = WARPPOINT_HINT_TIMER_FRAMES;
                state->sequenceTriggered = 1;
            }
        }
        if (placement->warpId > WARPPOINT_NO_WARP) {
            f32 playerDistance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
            if (playerDistance < state->triggerRadius) {
                warpToMap(placement->warpId, 1);
            }
        }
        break;
    case WARPPOINT_MODE_HINT_TIMER: {
        f32 deltaX = player->anim.localPosX - obj->anim.localPosX;
        f32 deltaY = player->anim.localPosY - obj->anim.localPosY;
        f32 deltaZ = player->anim.localPosZ - obj->anim.localPosZ;
        distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
        if (gArrivedWarpIndex > WARPPOINT_NO_ARRIVAL_WARP && placement->enabled != 0 && distance < WARPPOINT_HINT_TRIGGER_RADIUS &&
            player->anim.parent == obj->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(WARPPOINT_SEQUENCE_HINT_ACTIVE, obj, -1);
            gWarpArrivalTimer = WARPPOINT_HINT_TIMER_FRAMES;
        }
        if (state->warpDelay == 0 && distance < (f32)placement->radius &&
            placement->warpId > WARPPOINT_NO_WARP && placement->warpId > WARPPOINT_NO_WARP) {
            (*gObjectTriggerInterface)->runSequence(WARPPOINT_SEQUENCE_HINT_DONE, obj, -1);
        }
        break;
    }
    case WARPPOINT_MODE_GATED_WARP:
        if (WARPPOINT_ZERO != (distance = state->triggerRadius)) {
            f32 deltaX = player->anim.worldPosX - obj->anim.worldPosX;
            f32 deltaY = player->anim.worldPosY - obj->anim.worldPosY;
            f32 deltaZ = player->anim.worldPosZ - obj->anim.worldPosZ;
            distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
        }
        if (mainGetBit(state->gameBit) != 0 && state->sequenceTriggered == 0 && placement->enabled != 0 &&
            distance <= state->triggerRadius && player->anim.parent == obj->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, obj, -1);
            state->sequenceTriggered = 1;
        } else {
            if (state->sequenceTriggered == 1 && mainGetBit(state->gameBit) != 0 && state->warpDelay == 0 &&
                distance <= state->triggerRadius && placement->warpId > WARPPOINT_NO_WARP) {
                mainSetBits(state->gameBit, 0);
                warpToMap(placement->warpId, 0);
            }
        }
        break;
    case WARPPOINT_MODE_ONESHOT_SEQ: {
        f32 deltaX = player->anim.localPosX - obj->anim.localPosX;
        f32 deltaY = player->anim.localPosY - obj->anim.localPosY;
        f32 deltaZ = player->anim.localPosZ - obj->anim.localPosZ;
        distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
        if (mainGetBit(state->gameBit) != 0 && state->sequenceTriggered == 0 && placement->enabled != 0 &&
            distance < state->triggerRadius && player->anim.parent == obj->anim.parent) {
            mainSetBits(state->gameBit, 0);
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, obj, -1);
            state->sequenceTriggered = 1;
        }
        break;
    }
    case WARPPOINT_MODE_GATED_WARP2:
        if (WARPPOINT_ZERO != (distance = state->triggerRadius)) {
            f32 deltaX = player->anim.worldPosX - obj->anim.worldPosX;
            f32 deltaY = player->anim.worldPosY - obj->anim.worldPosY;
            f32 deltaZ = player->anim.worldPosZ - obj->anim.worldPosZ;
            distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
        }
        if (gArrivedWarpIndex > WARPPOINT_NO_ARRIVAL_WARP && state->sequenceTriggered == 0 && placement->enabled != 0 &&
            distance < state->triggerRadius && player->anim.parent == obj->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, obj, -1);
            gWarpArrivalTimer = WARPPOINT_HINT_TIMER_FRAMES;
            state->sequenceTriggered = 1;
        }
        if (mainGetBit(state->gameBit) != 0 && state->warpDelay == 0 && distance <= state->triggerRadius &&
            placement->warpId > WARPPOINT_NO_WARP) {
            mainSetBits(state->gameBit, 0);
            warpToMap(placement->warpId, 1);
        }
        break;
    }
}

void WarpPoint_init(GameObject* obj, WarpPointPlacement* placement) {
    WarpPointState* state = obj->extra;
    obj->animEventCallback = WarpPoint_animEventCallback;
    obj->anim.rotX = (s16)((u32)placement->yawByte << 8);
    state->warpDelay = WARPPOINT_INITIAL_WARP_DELAY;
    state->triggerRadius = (f32)((s32)placement->radius << WARPPOINT_RADIUS_SHIFT);
    state->gameBit = placement->gameBit;
    state->sequenceId = (s16)(s32)placement->sequenceId;
    if (placement->enabled != 0) {
        state->sequenceTriggered = 0;
    } else {
        state->sequenceTriggered = 1;
    }
    if (placement->mode == WARPPOINT_MODE_GATED_WARP) {
        state->warpDelay = 0;
    }
    if (placement->base.ident == WARPPOINT_MAP_SAVE_A || placement->base.ident == WARPPOINT_MAP_SAVE_B) {
        placement->savePointArmed = 1;
    } else {
        placement->savePointArmed = 0;
    }
}

ObjectDescriptor gWarpPointObjDescriptor = {
    0,                                                   /* reserved0 */
    0,                                                   /* reserved1 */
    0,                                                   /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                    /* slotCountAndFlags */
    0,                                                   /* initialise */
    0,                                                   /* release */
    0,                                                   /* slot02 */
    (ObjectDescriptorCallback)WarpPoint_init,            /* init */
    (ObjectDescriptorCallback)WarpPoint_update,          /* update */
    0,                                                   /* hitDetect */
    (ObjectDescriptorCallback)WarpPoint_render,          /* render */
    0,                                                   /* free */
    (ObjectDescriptorCallback)WarpPoint_getObjectTypeId, /* getObjectTypeId */
    WarpPoint_getExtraSize,                              /* getExtraSize */
};
