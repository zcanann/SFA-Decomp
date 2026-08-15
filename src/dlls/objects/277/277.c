#include "dlls/objects/277.h"

#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"

#define DLL_115_GROUP                              0xF
#define DLL_115_TYPE_ID                            0
#define DLL_115_SEQUENCE_INDEX_NONE                -1
#define DLL_115_GAME_BIT_NONE                      -1
#define DLL_115_SEQUENCE_ID_NONE                   -1
#define DLL_115_SEQUENCE_ARG_NONE                  -1
#define DLL_115_GAME_BIT_SET                       1
#define DLL_115_ROTATION_SHIFT                     8
#define DLL_115_MODEL_SCALE                        1.0f
#define DLL_115_STATE_ADVANCE_PENDING              0x01
#define DLL_115_PLACEMENT_FINISH_FLAG              0x10
#define DLL_115_COMPLETION_GAME_BIT_HALFWORD_INDEX 12

STATIC_ASSERT(DLL_115_COMPLETION_GAME_BIT_HALFWORD_INDEX ==
              offsetof(Dll115Placement, completionGameBits) / sizeof(s16));

int dll_115_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int step;
    Dll115State* state = obj->extra;
    Dll115Placement* placement = (Dll115Placement*)obj->anim.placementData;
    animUpdate->flags = animUpdate->savedFlags;
    animUpdate->movementState = 0;
    if (obj->seqIndex == DLL_115_SEQUENCE_INDEX_NONE) {
        return 0;
    }
    step = state->step;
    if (step >= DLL_115_STEP_DONE || step < DLL_115_STEP_IDLE) {
        int nextStep = step + 1;

        if (nextStep < DLL_115_STEP_COUNT) {
            s16 nextGameBit = placement->activeGameBits[nextStep];

            if (nextGameBit != DLL_115_GAME_BIT_NONE && nextGameBit != placement->activeGameBits[step]) {
                if (mainGetBit(nextGameBit) != 0) {
                    (*gObjectTriggerInterface)->endSequence(obj->seqIndex);
                }
            }
        }
    }
    state->flags = (u8)(state->flags | DLL_115_STATE_ADVANCE_PENDING);
    return 0;
}

int dll_115_getExtraSize(void) {
    return DLL_115_STATE_SIZE;
}

int dll_115_getObjectTypeId(void) {
    return DLL_115_TYPE_ID;
}

void dll_115_free(GameObject* obj) {
    objFreeObjectType(obj, DLL_115_GROUP);
}

void dll_115_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL_115_MODEL_SCALE);
    }
}

void dll_115_hitDetect(void) {
}

void dll_115_update(GameObject* obj) {
    Dll115State* state;
    Dll115Placement* placement;
    s16* placementCursor;
    int previousStep;
    int gameBit;

    state = obj->extra;
    placement = (Dll115Placement*)obj->anim.placementData;
    if ((state->flags & DLL_115_STATE_ADVANCE_PENDING) != 0) {
        gameBit = placement->completionGameBits[state->step];
        if (gameBit != DLL_115_GAME_BIT_NONE) {
            mainSetBits(gameBit, DLL_115_GAME_BIT_SET);
        }
        state->flags = (u8)(state->flags & ~DLL_115_STATE_ADVANCE_PENDING);
        state->step++;
    }

    switch (state->step) {
    case DLL_115_STEP_FINISH:
        (*gObjectTriggerInterface)->preempt((int)obj, placement->finishPreemptId);
        (*gObjectTriggerInterface)->runSequence(placement->finishSequenceId, obj, placement->finishSequenceParam);
        break;
    case DLL_115_STEP_IDLE:
    case DLL_115_STEP_DONE:
        break;
    default:
        gameBit = placement->activeGameBits[state->step];
        if (gameBit == DLL_115_GAME_BIT_NONE) {
            state->step = DLL_115_STEP_IDLE;
        } else if (mainGetBit(gameBit) != 0) {
            s8 sequenceId = placement->sequenceIds[state->step];

            if (sequenceId != DLL_115_SEQUENCE_ID_NONE) {
                (*gObjectTriggerInterface)->runSequence(sequenceId, obj, DLL_115_SEQUENCE_ARG_NONE);
            }
        }
        break;
    }

    previousStep = state->step - 1;
    placementCursor = (s16*)placement + previousStep;
    while (previousStep >= 0) {
        gameBit = placementCursor[DLL_115_COMPLETION_GAME_BIT_HALFWORD_INDEX];
        if (gameBit == DLL_115_GAME_BIT_NONE) {
            break;
        }
        if (mainGetBit(gameBit) != 0) {
            break;
        }
        state->step--;
        placementCursor--;
        previousStep--;
    }
}

void dll_115_init(GameObject* obj, Dll115Placement* placement) {
    s16* placementCursor;
    Dll115State* state;
    int step;

    state = obj->extra;
    obj->anim.rotX = (s16)(placement->initialYaw << DLL_115_ROTATION_SHIFT);
    obj->animEventCallback = dll_115_animEventCallback;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    objAddObjectType(obj, DLL_115_GROUP);

    step = 0;
    placementCursor = (s16*)placement;
    do {
        if (placementCursor[DLL_115_COMPLETION_GAME_BIT_HALFWORD_INDEX] == DLL_115_GAME_BIT_NONE) {
            break;
        }
        if (mainGetBit(placementCursor[DLL_115_COMPLETION_GAME_BIT_HALFWORD_INDEX]) == 0) {
            break;
        }
        placementCursor++;
        step++;
    } while (step < DLL_115_STEP_COUNT);

    if (step < DLL_115_STEP_COUNT && placement->completionGameBits[step] == DLL_115_GAME_BIT_NONE) {
        state->step = DLL_115_STEP_IDLE;
    } else {
        state->step = step;
    }
    if (state->step == DLL_115_STEP_IDLE && (placement->flags & DLL_115_PLACEMENT_FINISH_FLAG) != 0) {
        state->step = DLL_115_STEP_FINISH;
    }
}

void dll_115_release(void) {
}

void dll_115_initialise(void) {
}

ObjectDescriptor gDll115ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_115_initialise,
    (ObjectDescriptorCallback)dll_115_release,
    0,
    (ObjectDescriptorCallback)dll_115_init,
    (ObjectDescriptorCallback)dll_115_update,
    (ObjectDescriptorCallback)dll_115_hitDetect,
    (ObjectDescriptorCallback)dll_115_render,
    (ObjectDescriptorCallback)dll_115_free,
    (ObjectDescriptorCallback)dll_115_getObjectTypeId,
    dll_115_getExtraSize,
};
