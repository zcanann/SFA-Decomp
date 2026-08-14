/* CloudRunner Fortress prisoner behavior. */

#include "dlls/objects/335_CFPrisonUnc.h"

#include "main/audio/sfx_ids.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/object_render.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define CFPRISONUNCLE_OBJECT_TYPE_ID         9
#define CFPRISONUNCLE_MESSAGE_QUEUE_CAPACITY 1
#define CFPRISONUNCLE_COMPANION_CLASS_ID     0x3D
#define CFPRISONUNCLE_HEAD_AIM_LIMIT         0x41
#define CFPRISONUNCLE_MUTTER_RANDOM_RANGE    0x1E
#define CFPRISONUNCLE_HEAD_VECTOR_INDEX      1
#define CFPRISONUNCLE_HEAD_VECTOR_ANGLE      -0xAAA

#define CFPRISONUNCLE_SEQUENCE_RELEASE  0
#define CFPRISONUNCLE_SEQUENCE_DIALOGUE 1
#define CFPRISONUNCLE_TRIGGER_MAGIC     2
#define CFPRISONUNCLE_MAGIC_REWARD      2

#define CFPRISONUNCLE_ANIM_STEP 0.005f

int cfPrisonUncle_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    CfPrisonUncleState* state = obj->extra;
    if (state->magicGranted != 0) {
        return 0;
    }
    if (animUpdate->curEventId == CFPRISONUNCLE_TRIGGER_MAGIC) {
        state->magicGranted = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), CFPRISONUNCLE_MAGIC_REWARD);
    }
    return 0;
}

int cfPrisonUncle_getExtraSize(void) {
    return sizeof(CfPrisonUncleState);
}

int cfPrisonUncle_getObjectTypeId(void) {
    return CFPRISONUNCLE_OBJECT_TYPE_ID;
}

void cfPrisonUncle_free(void) {
}

void cfPrisonUncle_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    CfPrisonUncleState* state = obj->extra;
    if (mainGetBit(GAMEBIT_CF_UncleFlewOff) != 0) {
        if (state->companion != NULL && objUpdateOpacity(state->companion) != 0) {
            objRenderModelAndHitVolumes(state->companion, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        }
    } else if (mainGetBit(GAMEBIT_CF_PrisonCageOpened) != 0 && visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        if (state->companion != NULL && objUpdateOpacity(state->companion) != 0) {
            objRenderModelAndHitVolumes(state->companion, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        }
    } else if (state != NULL && state->companion != NULL) {
        if (state->cageOpen == 0) {
            if (visible != 0) {
                if (objUpdateOpacity(state->companion) != 0) {
                    objRenderModelAndHitVolumes(state->companion, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
                    ObjPath_GetPointWorldPosition(state->companion, 0, &obj->anim.localPosX, &obj->anim.localPosY,
                                                  &obj->anim.localPosZ, 0);
                }
                objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            }
        } else {
            if (objUpdateOpacity(state->companion) != 0) {
                objRenderModelAndHitVolumes(state->companion, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            }
            if (visible != 0) {
                objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            }
        }
    }
}

void cfPrisonUncle_hitDetect(void) {
}

void cfPrisonUncle_update(GameObject* obj) {
    CfPrisonUncleState* state = obj->extra;
    GameObject* player;
    u32 messageSender;
    int objectIndex;
    int objectCount;
    u32 message;
    u32 messageArgument;
    GameObject** objects;
    int index;
    if (state == NULL) {
        return;
    }
    if (mainGetBit(GAMEBIT_CF_UncleFlewOff) != 0) {
        return;
    }
    if (ObjMsg_Pop(obj, &message, &messageSender, &messageArgument) != 0) {
        state->companion = NULL;
    }
    if (state->companion == NULL) {
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        for (index = objectIndex; index < objectCount; index++) {
            if (objects[index]->anim.classId == CFPRISONUNCLE_COMPANION_CLASS_ID) {
                state->companion = objects[index];
                index = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag(obj);
    state->cageOpen = mainGetBit(GAMEBIT_CF_PrisonCageOpened);
    if (state->cageOpen == 0) {
        player = Obj_GetPlayerObject();
        characterAimHeadAtTarget(obj, player, &((CfPrisonUncleState*)obj->extra)->eyeAnimState,
                                 CFPRISONUNCLE_HEAD_AIM_LIMIT, 0, 3);
        if (randomGetRange(0, CFPRISONUNCLE_MUTTER_RANDOM_RANGE) == 0) {
            objSoundStart(obj, &state->soundState, SFXbaddie_kooshy_call);
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            s16* modelVector;
            characterAimHeadAtTarget(obj, player, &((CfPrisonUncleState*)obj->extra)->eyeAnimState,
                                     CFPRISONUNCLE_HEAD_AIM_LIMIT, 0, 3);
            modelVector = objFindJointPoseVector(obj, CFPRISONUNCLE_HEAD_VECTOR_INDEX);
            *modelVector = CFPRISONUNCLE_HEAD_VECTOR_ANGLE;
            (*gObjectTriggerInterface)->runSequence(CFPRISONUNCLE_SEQUENCE_DIALOGUE, obj, -1);
        } else {
            objSoundUpdateMouth(obj, &state->soundState);
            ObjAnim_AdvanceCurrentMove(obj, CFPRISONUNCLE_ANIM_STEP, (f32)(u32)framesThisStep, 0);
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (obj->seqIndex == -1) {
            (*gObjectTriggerInterface)->runSequence(CFPRISONUNCLE_SEQUENCE_RELEASE, obj, -1);
        }
    }
}

void cfPrisonUncle_init(GameObject* obj) {
    CfPrisonUncleState* state;
    ObjMsg_AllocQueue(obj, CFPRISONUNCLE_MESSAGE_QUEUE_CAPACITY);
    obj->animEventCallback = cfPrisonUncle_sequenceCallback;
    state = obj->extra;
    state->unknown64 = 464;
    state->unknown68 = 465;
    state->unknown70 = 0;
    state->magicGranted = 0;
    if (mainGetBit(GAMEBIT_CF_PrisonCageOpened) != 0) {
        mainSetBits(GAMEBIT_CF_UncleFlewOff, 1);
    }
}

void cfPrisonUncle_release(void) {
}

void cfPrisonUncle_initialise(void) {
}

ObjectDescriptor gCFPrisonUncleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfPrisonUncle_initialise,
    (ObjectDescriptorCallback)cfPrisonUncle_release,
    0,
    (ObjectDescriptorCallback)cfPrisonUncle_init,
    (ObjectDescriptorCallback)cfPrisonUncle_update,
    (ObjectDescriptorCallback)cfPrisonUncle_hitDetect,
    (ObjectDescriptorCallback)cfPrisonUncle_render,
    (ObjectDescriptorCallback)cfPrisonUncle_free,
    (ObjectDescriptorCallback)cfPrisonUncle_getObjectTypeId,
    cfPrisonUncle_getExtraSize,
};
