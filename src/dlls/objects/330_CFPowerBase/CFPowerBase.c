/* CloudRunner Fortress power-base controller. */

#include "dlls/objects/330_CFPowerBase.h"

#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "sys/objects.h"

/* Pylon messages are answered once the base's sequence reaches this frame. */
#define CFPOWERBASE_MESSAGE_POWERED      0xA0005
#define CFPOWERBASE_SEQUENCE_READY_FRAME 175

#define CFPOWERBASE_OBJECT_TYPE_ID         1
#define CFPOWERBASE_MESSAGE_QUEUE_CAPACITY 2
#define CFPOWERBASE_PREEMPT_SEQUENCE_ID    0xFA
#define CFPOWERBASE_RESTORE_SEQUENCE_FLAGS 3
#define CFPOWERBASE_ANIM_EVENT_ALL_POWERED 1
#define CFPOWERBASE_GREEN_MODEL_INDEX      2
#define CFPOWERBASE_BLUE_MODEL_INDEX       1

typedef enum CfPowerBaseIndex {
    CFPOWERBASE_INDEX_RED = 0,
    CFPOWERBASE_INDEX_GREEN = 1,
    CFPOWERBASE_INDEX_BLUE = 2,
} CfPowerBaseIndex;

int cfPowerBase_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    CfPowerBaseState* state = obj->extra;
    GameObject* messageSender;
    u32 message;
    void* unusedMessageArgument = 0;
    int eventIndex;

    while (ObjMsg_Pop(obj, &message, &messageSender, &unusedMessageArgument) != 0) {
        switch (message) {
        case CFPOWERBASE_PYLON_MESSAGE_1:
            if (state->poweredGameBit == GAMEBIT_CF_RedPowerBasePowered &&
                animUpdate->curFrame > CFPOWERBASE_SEQUENCE_READY_FRAME) {
                ObjMsg_SendToObject((GameObject*)messageSender, CFPOWERBASE_PYLON_MESSAGE_1, obj, 0);
            }
            break;
        case CFPOWERBASE_PYLON_MESSAGE_2:
            if (state->poweredGameBit == GAMEBIT_CF_GreenPowerBasePowered &&
                animUpdate->curFrame > CFPOWERBASE_SEQUENCE_READY_FRAME) {
                ObjMsg_SendToObject((GameObject*)messageSender, CFPOWERBASE_PYLON_MESSAGE_2, obj, 0);
            }
            break;
        case CFPOWERBASE_PYLON_MESSAGE_3:
            if (state->poweredGameBit == GAMEBIT_CF_BluePowerBasePowered &&
                animUpdate->curFrame > CFPOWERBASE_SEQUENCE_READY_FRAME) {
                ObjMsg_SendToObject((GameObject*)messageSender, CFPOWERBASE_PYLON_MESSAGE_3, obj, 0);
            }
            break;
        case CFPOWERBASE_MESSAGE_POWERED:
            mainSetBits(state->poweredGameBit, 1);
            break;
        }
    }

    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        switch (animUpdate->eventIds[eventIndex]) {
        case CFPOWERBASE_ANIM_EVENT_ALL_POWERED:
            if (mainGetBit(GAMEBIT_CF_RedPowerBasePowered) != 0 && mainGetBit(GAMEBIT_CF_GreenPowerBasePowered) != 0 &&
                mainGetBit(GAMEBIT_CF_BluePowerBasePowered) != 0) {
                mainSetBits(GAMEBIT_CF_AllPowerBasesPowered, 1);
            }
            break;
        }
    }
    return 0;
}

int cfPowerBase_getExtraSize(void) {
    return sizeof(CfPowerBaseState);
}

int cfPowerBase_getObjectTypeId(void) {
    return CFPOWERBASE_OBJECT_TYPE_ID;
}

void cfPowerBase_free(void) {
}

void cfPowerBase_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void cfPowerBase_hitDetect(void) {
}

/* Update interaction and activation state. */
void cfPowerBase_update(GameObject* obj) {
    CfPowerBaseState* state = obj->extra;
    if (mainGetBit(state->heldCrystalGameBit) != 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if (obj->userData1 != 0) {
        (*gObjectTriggerInterface)->preempt((int)obj, CFPOWERBASE_PREEMPT_SEQUENCE_ID);
        (*gObjectTriggerInterface)->runSequence(state->baseIndex, obj, CFPOWERBASE_RESTORE_SEQUENCE_FLAGS);
        obj->userData1 = 0;
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        if ((*gGameUIInterface)->isItemBeingUsed(state->heldCrystalGameBit) != 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            mainSetBits(state->heldCrystalGameBit, 0);
            mainSetBits(GAMEBIT_CFPowerBaseRelated0973, 0);
            (*gObjectTriggerInterface)->runSequence(state->baseIndex, obj, -1);
        }
    }
}

/* Initialise this base from its powered game bit. */
void cfPowerBase_init(GameObject* obj, CfPowerBasePlacement* placement) {
    CfPowerBaseState* state = obj->extra;
    s16 poweredGameBit;
    obj->anim.rotX = (s16)(placement->initialYaw << 8);
    state->poweredGameBit = placement->poweredGameBit;
    poweredGameBit = state->poweredGameBit;
    switch (poweredGameBit) {
    case GAMEBIT_CF_RedPowerBasePowered:
        state->heldCrystalGameBit = GAMEBIT_ITEM_CFRedCrystal_Got;
        state->baseIndex = CFPOWERBASE_INDEX_RED;
        break;
    case GAMEBIT_CF_GreenPowerBasePowered:
        state->heldCrystalGameBit = GAMEBIT_ITEM_CFGreenCrystal_Got;
        state->baseIndex = CFPOWERBASE_INDEX_GREEN;
        Obj_SetActiveModelIndex(obj, CFPOWERBASE_GREEN_MODEL_INDEX);
        break;
    case GAMEBIT_CF_BluePowerBasePowered:
        state->heldCrystalGameBit = GAMEBIT_ITEM_CFBlueCrystal_Got;
        state->baseIndex = CFPOWERBASE_INDEX_BLUE;
        Obj_SetActiveModelIndex(obj, CFPOWERBASE_BLUE_MODEL_INDEX);
        break;
    }
    obj->animEventCallback = cfPowerBase_sequenceCallback;
    ObjMsg_AllocQueue(obj, CFPOWERBASE_MESSAGE_QUEUE_CAPACITY);
    if (mainGetBit(state->heldCrystalGameBit) != 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if (mainGetBit(state->poweredGameBit) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        obj->userData1 = 1;
    }
}

void cfPowerBase_release(void) {
}

void cfPowerBase_initialise(void) {
}

ObjectDescriptor gCFPowerBaseObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfPowerBase_initialise,
    (ObjectDescriptorCallback)cfPowerBase_release,
    0,
    (ObjectDescriptorCallback)cfPowerBase_init,
    (ObjectDescriptorCallback)cfPowerBase_update,
    (ObjectDescriptorCallback)cfPowerBase_hitDetect,
    (ObjectDescriptorCallback)cfPowerBase_render,
    (ObjectDescriptorCallback)cfPowerBase_free,
    (ObjectDescriptorCallback)cfPowerBase_getObjectTypeId,
    cfPowerBase_getExtraSize,
};
