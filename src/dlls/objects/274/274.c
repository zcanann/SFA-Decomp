#include "dlls/objects/274.h"

#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/rcp_dolphin_api.h"

#define SEQ_OBJECT_GROUP                           0xF
#define SEQ_OBJECT_SEQUENCE_INDEX_NONE             -1
#define SEQ_OBJECT_GAME_BIT_NONE                   -1
#define SEQ_OBJECT_SEQUENCE_ID_NONE                -1
#define SEQ_OBJECT_PREEMPT_SEQUENCE_ID_NONE        0
#define SEQ_OBJECT_WARP_MAP_ID_NONE                0
#define SEQ_OBJECT_WARP_TRANSITION_TYPE            0
#define SEQ_OBJECT_SEQUENCE_ARG_NONE               -1
#define SEQ_OBJECT_SEQUENCE_FLAGS_DEFAULT          1
#define SEQ_OBJECT_SEQUENCE_WORLD_SPACE_MODE       0
#define SEQ_OBJECT_INIT_FLAGS_DEFAULT              0
#define SEQ_OBJECT_TYPE_ID                         0
#define SEQ_OBJECT_DEFAULT_MODEL_BANK              0
#define SEQ_OBJECT_MODEL_SCALE                     1.0f
#define SEQ_OBJECT_GAME_BIT_CLEAR                  0
#define SEQ_OBJECT_GAME_BIT_SET                    1
#define SEQ_OBJECT_TRIGGER_BIT_CLEAR               0
#define SEQ_OBJECT_FLAG_REARM_WHEN_OPEN_BIT_CLEARS 0x01
#define SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_EVENT      0x02
#define SEQ_OBJECT_FLAG_KEEP_TRIGGER_BIT_ON_DONE   0x04
#define SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_DONE       0x08
#define SEQ_OBJECT_FLAG_USE_SEQUENCE_PARAM         0x10
#define SEQ_OBJECT_STATE_OPEN                      0x01
#define SEQ_OBJECT_STATE_RUN_OPEN_SEQUENCE         0x02
#define SEQ_OBJECT_STATE_SEQUENCE_DONE             0x04
#define SEQ_OBJECT_ROTATION_SHIFT                  8
#define SEQ_OBJECT_CAMERA_ID                       86
#define SEQ_OBJECT_CAMERA_MODE                     1
#define SEQ_OBJECT_CAMERA_ARG_DEFAULT              0

typedef void (*ObjectInitCallback)(GameObject* obj, ObjPlacement* placement, int flags);

/* Only the init slot used here is recovered. */
typedef struct ObjectInitInterface {
    void* slot0;
    ObjectInitCallback init;
} ObjectInitInterface;

STATIC_ASSERT(offsetof(ObjectInitInterface, init) == 0x4);

typedef enum SeqObjectAnimEvent {
    SEQ_OBJECT_ANIM_EVENT_SET_OPEN_BIT = 1,
    SEQ_OBJECT_ANIM_EVENT_WARP = 2,
    SEQ_OBJECT_ANIM_EVENT_SET_CAMERA = 3
} SeqObjectAnimEvent;

void objCallOnLoadCallback(GameObject* obj) {
    if (obj != NULL) {
        ((ObjectInitInterface*)*obj->anim.dll)->init(obj, obj->anim.placement, SEQ_OBJECT_INIT_FLAGS_DEFAULT);
    }
}

static int SeqObject_animEventCallback(GameObject* obj, int* unused, ObjSeqState* animUpdate) {
    SeqObjectPlacement* placement;
    SeqObjectState* state;
    int eventIndex;

    (void)unused;

    if (obj->seqIndex == SEQ_OBJECT_SEQUENCE_INDEX_NONE) {
        return 0;
    }
    placement = (SeqObjectPlacement*)obj->anim.placementData;
    state = obj->extra;
    animUpdate->movementState = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        int eventId = animUpdate->eventIds[eventIndex];

        switch (eventId) {
        case SEQ_OBJECT_ANIM_EVENT_SET_OPEN_BIT: {
            u8 flags = placement->flags;

            if ((flags & SEQ_OBJECT_FLAG_REARM_WHEN_OPEN_BIT_CLEARS) == 0 &&
                (flags & SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_EVENT) != 0) {
                mainSetBits(placement->openGameBit, SEQ_OBJECT_GAME_BIT_SET);
            }
            break;
        }
        case SEQ_OBJECT_ANIM_EVENT_WARP: {
            u8 mapId = placement->warpMapId;

            if (mapId != SEQ_OBJECT_WARP_MAP_ID_NONE) {
                warpToMap(mapId, SEQ_OBJECT_WARP_TRANSITION_TYPE);
            }
            break;
        }
        case SEQ_OBJECT_ANIM_EVENT_SET_CAMERA:
            (*gObjectTriggerInterface)
                ->setCamVars(SEQ_OBJECT_CAMERA_ID, SEQ_OBJECT_CAMERA_MODE, SEQ_OBJECT_CAMERA_ARG_DEFAULT,
                             SEQ_OBJECT_CAMERA_ARG_DEFAULT);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQ_OBJECT_STATE_SEQUENCE_DONE);
    return 0;
}

int SeqObject_getExtraSize(void) {
    return SEQ_OBJECT_STATE_SIZE;
}

int SeqObject_getObjectTypeId(void) {
    return SEQ_OBJECT_TYPE_ID;
}

void SeqObject_free(GameObject* obj) {
    objFreeObjectType(obj, SEQ_OBJECT_GROUP);
}

void SeqObject_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, SEQ_OBJECT_MODEL_SCALE);
    }
}

void SeqObject_update(GameObject* obj) {
    SeqObjectState* state;
    SeqObjectPlacement* placement;
    s32 triggerBitValue;

    state = obj->extra;
    placement = (SeqObjectPlacement*)obj->anim.placementData;

    if ((state->flags & SEQ_OBJECT_STATE_SEQUENCE_DONE) != 0) {
        u8 flags = placement->flags;

        if ((flags & SEQ_OBJECT_FLAG_REARM_WHEN_OPEN_BIT_CLEARS) != 0) {
            if ((flags & SEQ_OBJECT_FLAG_KEEP_TRIGGER_BIT_ON_DONE) == 0) {
                mainSetBits(placement->triggerGameBit, SEQ_OBJECT_GAME_BIT_CLEAR);
            }
        } else {
            if ((flags & SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_DONE) != 0) {
                mainSetBits(placement->openGameBit, SEQ_OBJECT_GAME_BIT_SET);
            }
            state->flags = (u8)(state->flags | SEQ_OBJECT_STATE_OPEN);
        }
        state->flags = (u8)(state->flags & ~SEQ_OBJECT_STATE_SEQUENCE_DONE);
    }

    if ((state->flags & SEQ_OBJECT_STATE_OPEN) == 0) {
        if (mainGetBit(placement->openGameBit) != 0) {
            state->flags = (u8)(state->flags | SEQ_OBJECT_STATE_OPEN);
        }

        triggerBitValue = mainGetBit(placement->triggerGameBit);
        triggerBitValue = (s8)triggerBitValue;
        if (triggerBitValue != state->triggerBitState) {
            state->triggerBitState = triggerBitValue;
            if (triggerBitValue != SEQ_OBJECT_TRIGGER_BIT_CLEAR) {
                if (placement->sequenceId != SEQ_OBJECT_SEQUENCE_ID_NONE) {
                    (*gObjectTriggerInterface)
                        ->setRunSequenceWorldSpace((int)obj, SEQ_OBJECT_SEQUENCE_WORLD_SPACE_MODE);
                    (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, SEQ_OBJECT_SEQUENCE_ARG_NONE);
                }
                if ((placement->flags & SEQ_OBJECT_FLAG_REARM_WHEN_OPEN_BIT_CLEARS) == 0 &&
                    (placement->flags &
                     (SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_EVENT | SEQ_OBJECT_FLAG_SET_OPEN_BIT_ON_DONE)) == 0) {
                    mainSetBits(placement->openGameBit, SEQ_OBJECT_GAME_BIT_SET);
                }
            }
        }
    } else if ((state->flags & SEQ_OBJECT_STATE_RUN_OPEN_SEQUENCE) != 0) {
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptSequenceId);
        if ((placement->flags & SEQ_OBJECT_FLAG_USE_SEQUENCE_PARAM) != 0) {
            (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, placement->sequenceParam);
        } else {
            (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, SEQ_OBJECT_SEQUENCE_FLAGS_DEFAULT);
        }
        state->flags = (u8)(state->flags & ~SEQ_OBJECT_STATE_RUN_OPEN_SEQUENCE);
    } else if ((placement->flags & SEQ_OBJECT_FLAG_REARM_WHEN_OPEN_BIT_CLEARS) != 0 &&
               mainGetBit(placement->openGameBit) == 0) {
        state->flags = (u8)(state->flags & ~SEQ_OBJECT_STATE_OPEN);
    }
}

void SeqObject_init(GameObject* obj, SeqObjectPlacement* placement) {
    ObjAnimComponent* objAnim;
    SeqObjectState* state;

    objAnim = &obj->anim;
    state = obj->extra;
    objAnim->rotX = (s16)(placement->initialYaw << SEQ_OBJECT_ROTATION_SHIFT);
    obj->animEventCallback = SeqObject_animEventCallback;
    *(u8*)&objAnim->bankIndex = placement->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = SEQ_OBJECT_DEFAULT_MODEL_BANK;
    }
    objAddObjectType(obj, SEQ_OBJECT_GROUP);
    state->flags = 0;
    if (placement->openGameBit != SEQ_OBJECT_GAME_BIT_NONE &&
        mainGetBit(placement->openGameBit) != SEQ_OBJECT_GAME_BIT_CLEAR) {
        state->flags = (u8)(state->flags | SEQ_OBJECT_STATE_OPEN);
        if (placement->preemptSequenceId != SEQ_OBJECT_PREEMPT_SEQUENCE_ID_NONE) {
            state->flags = (u8)(state->flags | SEQ_OBJECT_STATE_RUN_OPEN_SEQUENCE);
        }
    }
    state->triggerBitState = SEQ_OBJECT_TRIGGER_BIT_CLEAR;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

ObjectDescriptor gSeqObjectObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SeqObject_init,
    (ObjectDescriptorCallback)SeqObject_update,
    0,
    (ObjectDescriptorCallback)SeqObject_render,
    (ObjectDescriptorCallback)SeqObject_free,
    (ObjectDescriptorCallback)SeqObject_getObjectTypeId,
    SeqObject_getExtraSize,
};
