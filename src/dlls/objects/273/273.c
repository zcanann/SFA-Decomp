#include "dlls/objects/273.h"

#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/obj_trigger.h"
#include "main/objprint_render_api.h"
#include "main/objtype.h"
#include "main/pad_api.h"

#define DOOR_LOCK_OBJECT_GROUP                       0xF
#define DOOR_LOCK_INPUT_PORT                         0
#define DOOR_LOCK_CMENU_EXPLANATION_SEQUENCE         1
#define DOOR_LOCK_SEQUENCE_WORLD_SPACE_MODE          0
#define DOOR_LOCK_GAME_BIT_NONE                      -1
#define DOOR_LOCK_SEQUENCE_ID_NONE                   -1
#define DOOR_LOCK_QUEUED_SEQUENCE_ID_NONE            0
#define DOOR_LOCK_SEQUENCE_ARG_NONE                  -1
#define DOOR_LOCK_TRIGGER_COMMAND_NONE               0
#define DOOR_LOCK_TRIGGER_COMMAND_SET_UNLOCKED       1
#define DOOR_LOCK_TRIGGER_COMMAND_YIELD_QUEUED       2
#define DOOR_LOCK_FLAG_HIDE_WHEN_UNLOCKED            0x01
#define DOOR_LOCK_FLAG_CALLBACK_SETS_UNLOCKED        0x04
#define DOOR_LOCK_FLAG_CLEAR_REQUIRED_GAME_BIT       0x08
#define DOOR_LOCK_FLAG_DISABLE_IF_REQUIRED_BIT_CLEAR 0x10
#define DOOR_LOCK_FLAG_SEQUENCE_OPTION_2             0x20
#define DOOR_LOCK_FLAG_SEQUENCE_OPTION_4             0x40
#define DOOR_LOCK_FLAG_SEQUENCE_OPTION_8             0x80
#define DOOR_LOCK_MODE_CUSTOM_RENDER_WHEN_LOCKED     0x01
#define DOOR_LOCK_SEQUENCE_FLAGS_BASE                1
#define DOOR_LOCK_SEQUENCE_FLAG_2                    2
#define DOOR_LOCK_SEQUENCE_FLAG_4                    4
#define DOOR_LOCK_SEQUENCE_FLAG_8                    8
#define DOOR_LOCK_ROTATION_SHIFT                     8
#define DOOR_LOCK_DEFAULT_MODEL_BANK                 0
#define DOOR_LOCK_MODEL_SCALE                        1.0f
#define DOOR_LOCK_LOCKED                             0
#define DOOR_LOCK_UNLOCKED                           1
#define DOOR_LOCK_SEQUENCE_NOT_STARTED               0
#define DOOR_LOCK_SEQUENCE_STARTED                   1
#define DOOR_LOCK_CUSTOM_RENDER_DISABLED             0
#define DOOR_LOCK_CUSTOM_RENDER_ENABLED              1
#define DOOR_LOCK_HIDDEN_ALPHA                       0

static int DoorLock_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DoorLockPlacement* placement;

    (void)unused;

    placement = (DoorLockPlacement*)obj->anim.placementData;
    if (animUpdate->curEventId != DOOR_LOCK_TRIGGER_COMMAND_NONE) {
        if ((placement->flags & DOOR_LOCK_FLAG_CALLBACK_SETS_UNLOCKED) != 0 &&
            animUpdate->curEventId == DOOR_LOCK_TRIGGER_COMMAND_SET_UNLOCKED) {
            mainSetBits(placement->unlockedGameBit, DOOR_LOCK_UNLOCKED);
        }
        if (animUpdate->curEventId == DOOR_LOCK_TRIGGER_COMMAND_YIELD_QUEUED &&
            placement->queuedSequenceId != DOOR_LOCK_QUEUED_SEQUENCE_ID_NONE) {
            (*gObjectTriggerInterface)->yield(animUpdate, placement->queuedSequenceId);
        }
        animUpdate->curEventId = DOOR_LOCK_TRIGGER_COMMAND_NONE;
    }
    obj->userData2 = DOOR_LOCK_CUSTOM_RENDER_DISABLED;
    return 0;
}

int DoorLock_getExtraSize(void) {
    return DOOR_LOCK_STATE_SIZE;
}

void DoorLock_free(GameObject* obj) {
    objFreeObjectType(obj, DOOR_LOCK_OBJECT_GROUP);
}

void DoorLock_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0 || obj->userData2 != DOOR_LOCK_CUSTOM_RENDER_DISABLED) {
        if (obj->userData2 == DOOR_LOCK_CUSTOM_RENDER_DISABLED) {
            return;
        }
        objUpdateHitVolumeTransforms(obj);
        return;
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DOOR_LOCK_MODEL_SCALE);
}

void DoorLock_update(GameObject* obj) {
    DoorLockState* state;
    DoorLockPlacement* placement;
    int sequenceFlags;
    u8 placementFlags;

    state = obj->extra;
    placement = (DoorLockPlacement*)obj->anim.placementData;
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0 && mainGetBit(GAMEBIT_SawCMenuExplanation) == 0) {
        buttonDisable(DOOR_LOCK_INPUT_PORT, PAD_BUTTON_A);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace((int)obj, DOOR_LOCK_SEQUENCE_WORLD_SPACE_MODE);
        (*gObjectTriggerInterface)->runSequence(DOOR_LOCK_CMENU_EXPLANATION_SEQUENCE, obj, DOOR_LOCK_SEQUENCE_ARG_NONE);
        mainSetBits(GAMEBIT_SawCMenuExplanation, 1);
    } else {
        state->unlocked = mainGetBit(placement->unlockedGameBit);
        if ((placement->flags & DOOR_LOCK_FLAG_HIDE_WHEN_UNLOCKED) != 0) {
            if (state->unlocked != DOOR_LOCK_LOCKED) {
                obj->anim.alpha = DOOR_LOCK_HIDDEN_ALPHA;
            }
        } else if ((placement->modeFlags & DOOR_LOCK_MODE_CUSTOM_RENDER_WHEN_LOCKED) != 0) {
            if (state->unlocked != DOOR_LOCK_LOCKED) {
                obj->userData2 = DOOR_LOCK_CUSTOM_RENDER_DISABLED;
            } else {
                obj->userData2 = DOOR_LOCK_CUSTOM_RENDER_ENABLED;
            }
        }
        if (state->unlocked == DOOR_LOCK_LOCKED) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if (placement->requiredGameBit != DOOR_LOCK_GAME_BIT_NONE && mainGetBit(placement->requiredGameBit) == 0) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                if ((placement->flags & DOOR_LOCK_FLAG_DISABLE_IF_REQUIRED_BIT_CLEAR) != 0) {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
            }
            if (placement->triggerGameBit != DOOR_LOCK_GAME_BIT_NONE && mainGetBit(placement->triggerGameBit) == 0) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
            if ((placement->triggerGameBit != DOOR_LOCK_GAME_BIT_NONE &&
                 ObjTrigger_IsSetById(obj, placement->triggerGameBit) != 0) ||
                (placement->triggerGameBit == DOOR_LOCK_GAME_BIT_NONE && ObjTrigger_IsSet(obj) != 0)) {
                if (placement->unlockSequenceId != DOOR_LOCK_SEQUENCE_ID_NONE) {
                    (*gObjectTriggerInterface)
                        ->runSequence((int)placement->unlockSequenceId, obj, DOOR_LOCK_SEQUENCE_ARG_NONE);
                }
                if ((placement->flags & DOOR_LOCK_FLAG_CALLBACK_SETS_UNLOCKED) == 0) {
                    mainSetBits(placement->unlockedGameBit, DOOR_LOCK_UNLOCKED);
                }
                if ((placement->flags & DOOR_LOCK_FLAG_CLEAR_REQUIRED_GAME_BIT) != 0) {
                    mainSetBits(placement->requiredGameBit, 0);
                } else {
                    state->unlocked = DOOR_LOCK_UNLOCKED;
                    obj->userData1 = DOOR_LOCK_SEQUENCE_STARTED;
                }
                buttonDisable(DOOR_LOCK_INPUT_PORT, PAD_BUTTON_A);
            }
        } else {
            if (obj->userData1 == DOOR_LOCK_SEQUENCE_NOT_STARTED) {
                if (placement->unlockSequenceId != DOOR_LOCK_SEQUENCE_ID_NONE &&
                    placement->queuedSequenceId != DOOR_LOCK_QUEUED_SEQUENCE_ID_NONE) {
                    (*gObjectTriggerInterface)->preempt((int)obj, placement->queuedSequenceId);
                    sequenceFlags = DOOR_LOCK_SEQUENCE_FLAGS_BASE;
                    placementFlags = placement->flags;
                    if ((placementFlags & DOOR_LOCK_FLAG_SEQUENCE_OPTION_2) != 0) {
                        sequenceFlags |= DOOR_LOCK_SEQUENCE_FLAG_2;
                    }
                    if ((placementFlags & DOOR_LOCK_FLAG_SEQUENCE_OPTION_4) != 0) {
                        sequenceFlags |= DOOR_LOCK_SEQUENCE_FLAG_4;
                    }
                    if ((placementFlags & DOOR_LOCK_FLAG_SEQUENCE_OPTION_8) != 0) {
                        sequenceFlags |= DOOR_LOCK_SEQUENCE_FLAG_8;
                    }
                    (*gObjectTriggerInterface)->runSequence((int)placement->unlockSequenceId, obj, sequenceFlags);
                }
                obj->userData1 = DOOR_LOCK_SEQUENCE_STARTED;
            }
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        if ((obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0 && obj->anim.hitVolumeTransforms != NULL) {
            objUpdateHitVolumeTransforms(obj);
        }
    }
}

void DoorLock_init(GameObject* obj, DoorLockPlacement* placement) {
    ObjAnimComponent* objAnim;
    DoorLockState* state;

    objAnim = &obj->anim;
    objAnim->rotX = (s16)(placement->rotXByte << DOOR_LOCK_ROTATION_SHIFT);
    objAnim->rotY = (s16)(placement->rotYByte << DOOR_LOCK_ROTATION_SHIFT);
    objAnim->rotZ = (s16)(placement->rotZByte << DOOR_LOCK_ROTATION_SHIFT);
    obj->animEventCallback = DoorLock_animEventCallback;
    *(u8*)&objAnim->bankIndex = placement->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = DOOR_LOCK_DEFAULT_MODEL_BANK;
    }
    state = obj->extra;
    state->unlocked = mainGetBit(placement->unlockedGameBit);
    objAddObjectType(obj, DOOR_LOCK_OBJECT_GROUP);
    if ((placement->flags & DOOR_LOCK_FLAG_HIDE_WHEN_UNLOCKED) != 0) {
        if (state->unlocked != DOOR_LOCK_LOCKED) {
            objAnim->alpha = DOOR_LOCK_HIDDEN_ALPHA;
        }
    } else if ((placement->modeFlags & DOOR_LOCK_MODE_CUSTOM_RENDER_WHEN_LOCKED) != 0) {
        if (state->unlocked != DOOR_LOCK_LOCKED) {
            obj->userData2 = DOOR_LOCK_CUSTOM_RENDER_DISABLED;
        } else {
            obj->userData2 = DOOR_LOCK_CUSTOM_RENDER_ENABLED;
        }
    }
}

ObjectDescriptor gDoorLockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DoorLock_init,
    (ObjectDescriptorCallback)DoorLock_update,
    0,
    (ObjectDescriptorCallback)DoorLock_render,
    (ObjectDescriptorCallback)DoorLock_free,
    0,
    DoorLock_getExtraSize,
};
