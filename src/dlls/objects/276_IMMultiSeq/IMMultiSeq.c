#include "dlls/objects/276_IMMultiSeq.h"

#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"

#define IM_MULTI_SEQ_GROUP                     0xF
#define IM_MULTI_SEQ_TYPE_ID                   0
#define IM_MULTI_SEQ_SEQUENCE_INDEX_NONE       -1
#define IM_MULTI_SEQ_GAME_BIT_NONE             -1
#define IM_MULTI_SEQ_SEQUENCE_ID_NONE          -1
#define IM_MULTI_SEQ_SEQUENCE_ARG_NONE         -1
#define IM_MULTI_SEQ_COMPLETION_POLARITY_SHIFT 4
#define IM_MULTI_SEQ_ROTATION_SHIFT            8
#define IM_MULTI_SEQ_DEFAULT_MODEL_BANK        0
#define IM_MULTI_SEQ_MODEL_SCALE               1.0f
#define IM_MULTI_SEQ_STATE_ADVANCE_PENDING     0x01

int IMMultiSeq_animEventCallback(GameObject* obj, int* unused, ObjSeqState* animUpdate) {
    IMMultiSeqState* state;
    IMMultiSeqPlacement* placement;
    int step;

    (void)unused;

    state = obj->extra;
    placement = (IMMultiSeqPlacement*)obj->anim.placementData;
    animUpdate->flags = animUpdate->savedFlags;
    animUpdate->movementState = 0;
    if (obj->seqIndex == IM_MULTI_SEQ_SEQUENCE_INDEX_NONE) {
        return 0;
    }
    step = state->step;
    if (step != IM_MULTI_SEQ_STEP_COUNT) {
        int nextStep = step + 1;

        if ((s32)nextStep < IM_MULTI_SEQ_STEP_COUNT) {
            s16 gameBit = placement->activeGameBits[nextStep];

            if (gameBit != IM_MULTI_SEQ_GAME_BIT_NONE) {
                int bitValue = mainGetBit(gameBit);
                int expectedValue = !((placement->polarityMask >> nextStep) & 1);

                if ((u32)expectedValue == bitValue) {
                    (*gObjectTriggerInterface)->endSequence(obj->seqIndex);
                }
            }
        }
    }
    state->flags = (u8)(state->flags | IM_MULTI_SEQ_STATE_ADVANCE_PENDING);
    return 0;
}

int IMMultiSeq_getExtraSize(void) {
    return IM_MULTI_SEQ_STATE_SIZE;
}

int IMMultiSeq_getObjectTypeId(void) {
    return IM_MULTI_SEQ_TYPE_ID;
}

void IMMultiSeq_free(GameObject* obj) {
    objFreeObjectType(obj, IM_MULTI_SEQ_GROUP);
}

void IMMultiSeq_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, IM_MULTI_SEQ_MODEL_SCALE);
    }
}

void IMMultiSeq_hitDetect(void) {
}

void IMMultiSeq_update(GameObject* obj) {
    IMMultiSeqState* state;
    IMMultiSeqPlacement* placement;
    u8 step;
    int previousStep;
    s16 gameBit;

    state = obj->extra;
    placement = (IMMultiSeqPlacement*)obj->anim.placementData;

    if ((state->flags & IM_MULTI_SEQ_STATE_ADVANCE_PENDING) != 0) {
        step = state->step;
        gameBit = placement->completionGameBits[step];
        mainSetBits(gameBit, !((placement->polarityMask >> (step + IM_MULTI_SEQ_COMPLETION_POLARITY_SHIFT)) & 1));
        state->flags = (u8)(state->flags & ~IM_MULTI_SEQ_STATE_ADVANCE_PENDING);
        state->step++;
    }

    if ((int)state->step != IM_MULTI_SEQ_STEP_COUNT) {
        u8 activeStep = state->step;

        gameBit = placement->activeGameBits[activeStep];
        if (gameBit == IM_MULTI_SEQ_GAME_BIT_NONE) {
            state->step = IM_MULTI_SEQ_STEP_COUNT;
        } else if ((u32)(!((placement->polarityMask >> state->step) & 1)) == mainGetBit(gameBit)) {
            s8 sequenceId = placement->sequenceIds[state->step];

            if (sequenceId != IM_MULTI_SEQ_SEQUENCE_ID_NONE) {
                (*gObjectTriggerInterface)->runSequence(sequenceId, obj, IM_MULTI_SEQ_SEQUENCE_ARG_NONE);
            }
        }
    }

    previousStep = state->step - 1;
    while (previousStep >= 0) {
        gameBit = placement->completionGameBits[previousStep];
        if (gameBit == IM_MULTI_SEQ_GAME_BIT_NONE) {
            break;
        }
        if (((placement->polarityMask >> (previousStep + IM_MULTI_SEQ_COMPLETION_POLARITY_SHIFT)) & 1) !=
            mainGetBit(gameBit)) {
            break;
        }
        state->step--;
        previousStep--;
    }
}

void IMMultiSeq_init(GameObject* obj, IMMultiSeqPlacement* placement) {
    ObjAnimComponent* objAnim;
    IMMultiSeqState* state;
    int step;

    objAnim = &obj->anim;
    state = obj->extra;
    objAnim->rotX = (s16)(placement->initialYaw << IM_MULTI_SEQ_ROTATION_SHIFT);
    obj->animEventCallback = IMMultiSeq_animEventCallback;
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    objAnim->bankIndex = placement->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = IM_MULTI_SEQ_DEFAULT_MODEL_BANK;
    }
    objAddObjectType(obj, IM_MULTI_SEQ_GROUP);
    step = 0;
    while (step < IM_MULTI_SEQ_STEP_COUNT) {
        if ((u32)((placement->polarityMask >> (step + IM_MULTI_SEQ_COMPLETION_POLARITY_SHIFT)) & 1) ==
            mainGetBit(placement->completionGameBits[step])) {
            break;
        }
        step++;
    }
    state->step = step;
}

void IMMultiSeq_release(void) {
}

void IMMultiSeq_initialise(void) {
}

ObjectDescriptor gIMMultiSeqObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IMMultiSeq_initialise,
    (ObjectDescriptorCallback)IMMultiSeq_release,
    0,
    (ObjectDescriptorCallback)IMMultiSeq_init,
    (ObjectDescriptorCallback)IMMultiSeq_update,
    (ObjectDescriptorCallback)IMMultiSeq_hitDetect,
    (ObjectDescriptorCallback)IMMultiSeq_render,
    (ObjectDescriptorCallback)IMMultiSeq_free,
    (ObjectDescriptorCallback)IMMultiSeq_getObjectTypeId,
    IMMultiSeq_getExtraSize,
};
