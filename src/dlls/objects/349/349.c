/* Proximity-triggered sliding door. */

#include "dlls/objects/349.h"

#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define SLIDING_DOOR_PROXIMITY_RADIUS       130.0f
#define SLIDING_DOOR_GATE_GAMEBIT_NONE      -1
#define SLIDING_DOOR_PREEMPT_TRIGGER_NONE   0
#define SLIDING_DOOR_STARTUP_SEQUENCE_NONE  -1
#define SLIDING_DOOR_SEQUENCE_FLAGS_DEFAULT -1
#define SLIDING_DOOR_TRIGGER_CLOSE_COMPLETE 1
#define SLIDING_DOOR_TRIGGER_OPEN_COMPLETE  2
#define SLIDING_DOOR_SCALE_DIVISOR          64.0f
#define SLIDING_DOOR_UPDATE_LATCHED         1

int slidingDoor_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    register int playerNear;
    register int trickyNear;
    register SlidingDoorState* state;
    SlidingDoorPlacement* placement;
    u32 mode;
    int result;
    GameObject* player;
    GameObject* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL) {
        playerNear = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX) < SLIDING_DOOR_PROXIMITY_RADIUS;
    } else {
        playerNear = 0;
    }

    if (tricky != NULL) {
        trickyNear = Vec_xzDistance(&obj->anim.worldPosX, &tricky->anim.worldPosX) < SLIDING_DOOR_PROXIMITY_RADIUS;
    } else {
        trickyNear = 0;
    }

    state = obj->extra;
    placement = (SlidingDoorPlacement*)obj->anim.placementData;
    mode = state->mode;

    if (mode == SLIDING_DOOR_MODE_CLOSED) {
        if (mainGetBit(placement->openGameBit) != 0 &&
            (placement->gateGameBit == SLIDING_DOOR_GATE_GAMEBIT_NONE || mainGetBit(placement->gateGameBit) != 0)) {
            mainSetBits(placement->openedGameBit, TRUE);
            if (playerNear != 0 || trickyNear != 0) {
                state->mode = SLIDING_DOOR_MODE_OPENING;
            }
        }
    } else if (mode == SLIDING_DOOR_MODE_OPEN) {
        if ((mainGetBit(placement->openGameBit) != 0 ||
             (placement->gateGameBit != SLIDING_DOOR_GATE_GAMEBIT_NONE && mainGetBit(placement->gateGameBit) != 0)) &&
            playerNear == 0 && trickyNear == 0) {
            state->mode = SLIDING_DOOR_MODE_CLOSING;
        }
    }

    {
        register SlidingDoorState* transitionState = state;
        if (transitionState->mode == SLIDING_DOOR_MODE_OPENING) {
            if (animUpdate->curEventId == SLIDING_DOOR_TRIGGER_OPEN_COMPLETE) {
                transitionState->mode = SLIDING_DOOR_MODE_OPEN;
            }
        } else if (transitionState->mode == SLIDING_DOOR_MODE_CLOSING) {
            if (animUpdate->curEventId == SLIDING_DOOR_TRIGGER_CLOSE_COMPLETE) {
                transitionState->mode = SLIDING_DOOR_MODE_CLOSED;
            }
        }
    }

    result = 0;
    {
        u32 modeAfter = state->mode;
        if (modeAfter != SLIDING_DOOR_MODE_OPENING) {
            if (modeAfter != SLIDING_DOOR_MODE_CLOSING) {
                result = 1;
            }
        }
    }
    return result;
}

int slidingDoor_getExtraSize(void) {
    return sizeof(SlidingDoorState);
}

int slidingDoor_getObjectTypeId(void) {
    return 0;
}

void slidingDoor_free(void) {
}

void slidingDoor_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void slidingDoor_hitDetect(void) {
}

void slidingDoor_update(GameObject* obj) {
    SlidingDoorState* state;
    SlidingDoorPlacement* placement;
    if (obj->userData1 != 0) {
        return;
    }
    state = obj->extra;
    placement = (SlidingDoorPlacement*)obj->anim.placementData;
    if (placement->preemptTriggerId != SLIDING_DOOR_PREEMPT_TRIGGER_NONE) {
        u32 mode = state->mode;
        if (mode != SLIDING_DOOR_MODE_CLOSED) {
            (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptTriggerId);
        }
    }
    {
        s8 startupSequenceId = placement->startupSequenceId;
        if (startupSequenceId != SLIDING_DOOR_STARTUP_SEQUENCE_NONE) {
            (*gObjectTriggerInterface)->runSequence(startupSequenceId, obj, SLIDING_DOOR_SEQUENCE_FLAGS_DEFAULT);
        }
    }
    obj->userData1 = SLIDING_DOOR_UPDATE_LATCHED;
}

void slidingDoor_init(GameObject* obj, SlidingDoorPlacement* placement) {
    SlidingDoorState* state;
    f32 scale;
    u32 doorState = SLIDING_DOOR_MODE_CLOSED;
    obj->userData1 = doorState;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = slidingDoor_sequenceCallback;
    scale = (f32)(u32)placement->scaleByte / SLIDING_DOOR_SCALE_DIVISOR;
    obj->anim.rootMotionScale = scale;
    obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    state = obj->extra;
    state->mode = doorState;
}

void slidingDoor_release(void) {
}

void slidingDoor_initialise(void) {
}

ObjectDescriptor gSlidingDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)slidingDoor_initialise,
    (ObjectDescriptorCallback)slidingDoor_release,
    0,
    (ObjectDescriptorCallback)slidingDoor_init,
    (ObjectDescriptorCallback)slidingDoor_update,
    (ObjectDescriptorCallback)slidingDoor_hitDetect,
    (ObjectDescriptorCallback)slidingDoor_render,
    (ObjectDescriptorCallback)slidingDoor_free,
    (ObjectDescriptorCallback)slidingDoor_getObjectTypeId,
    slidingDoor_getExtraSize,
};
