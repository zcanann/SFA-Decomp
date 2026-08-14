/* CloudRunner Fortress prison-cage and cage-switch behavior. */

#include "dlls/objects/340.h"

#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/game_ui_interface.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/obj_message.h"
#include "main/objfx_hit_emitter_api.h"
#include "main/objhits.h"

typedef enum CfPrisonCageObjectSequenceId {
    CFPRISONCAGE_SEQUENCE_ID_CAGE = 0x127,
    CFPRISONCAGE_SEQUENCE_ID_SWITCH = 0x128,
} CfPrisonCageObjectSequenceId;

#define CFPRISONCAGE_MESSAGE_OPEN                0xA0005
#define CFPRISONCAGE_MESSAGE_QUEUE_CAPACITY      1
#define CFPRISONCAGE_SWITCH_OBJECT_TYPE_ID       8
#define CFPRISONCAGE_CAGE_SEQUENCE_ID            0
#define CFPRISONCAGE_SWITCH_SEQUENCE_ID          1
#define CFPRISONCAGE_SWITCH_OPEN_SEQUENCE_ID     0
#define CFPRISONCAGE_SWITCH_CLOSED_MOVE          0
#define CFPRISONCAGE_SWITCH_OPEN_MOVE            1
#define CFPRISONCAGE_OPEN_SEQUENCE_PREEMPT_FRAME 60
#define CFPRISONCAGE_HIT_EFFECT_ID               8
#define CFPRISONCAGE_HIT_EFFECT_RED              200
#define CFPRISONCAGE_HIT_EFFECT_GREEN            128
#define CFPRISONCAGE_HIT_EFFECT_BLUE             0

int cfPrisonCage_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    u32 message;
    u32 unusedMessageSender;
    u32 unusedMessageArgument = 0;
    CfPrisonCagePlacement* placement = (CfPrisonCagePlacement*)obj->anim.placement;

    if (mainGetBit(placement->openedGameBit) != 0) {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        return 0;
    }
    if (obj->anim.romDefNo == CFPRISONCAGE_SEQUENCE_ID_CAGE) {
        return 0;
    }
    while (ObjMsg_Pop(obj, &message, &unusedMessageSender, &unusedMessageArgument) != 0) {
        switch (message) {
        case CFPRISONCAGE_MESSAGE_OPEN:
            mainSetBits(placement->openedGameBit, TRUE);
            break;
        }
    }
    if (mainGetBit(GAMEBIT_ITEM_PrisonKey_Got) != 0) {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_PrisonKey_Got) != 0) {
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            (*gObjectTriggerInterface)->runSequence(CFPRISONCAGE_SWITCH_OPEN_SEQUENCE_ID, obj, -1);
        }
    }
    return 0;
}

int cfPrisonCage_getExtraSize(void) {
    return 0;
}

int cfPrisonCage_getObjectTypeId(GameObject* obj) {
    if (obj->anim.romDefNo == CFPRISONCAGE_SEQUENCE_ID_SWITCH) {
        return CFPRISONCAGE_SWITCH_OBJECT_TYPE_ID;
    }
    return 0;
}

void cfPrisonCage_free(void) {
}

void cfPrisonCage_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void cfPrisonCage_hitDetect(GameObject* obj) {
    f32 hitZ;
    f32 hitY;
    f32 hitX;

    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &hitX, &hitY, &hitZ) != 0) {
        objfx_spawnHitEmitterAtPos(&hitX, CFPRISONCAGE_HIT_EFFECT_ID, CFPRISONCAGE_HIT_EFFECT_RED,
                                   CFPRISONCAGE_HIT_EFFECT_GREEN, CFPRISONCAGE_HIT_EFFECT_BLUE);
    }
}

void cfPrisonCage_update(GameObject* obj) {
    int sequenceId;

    if (obj->userData1 != 0) {
        switch (obj->anim.romDefNo) {
        case CFPRISONCAGE_SEQUENCE_ID_CAGE:
            sequenceId = CFPRISONCAGE_CAGE_SEQUENCE_ID;
            break;
        case CFPRISONCAGE_SEQUENCE_ID_SWITCH:
        default:
            sequenceId = CFPRISONCAGE_SWITCH_SEQUENCE_ID;
            break;
        }
        (*gObjectTriggerInterface)->runSequence(sequenceId, obj, -1);
        obj->userData1 = FALSE;
    }
}

void cfPrisonCage_init(GameObject* obj, CfPrisonCagePlacement* placement) {
    ObjMsg_AllocQueue(obj, CFPRISONCAGE_MESSAGE_QUEUE_CAPACITY);
    obj->anim.rotX = (s16)((s32)placement->initialRotX << 8);
    obj->userData1 = TRUE;
    obj->animEventCallback = cfPrisonCage_sequenceCallback;
    if (obj->anim.romDefNo == CFPRISONCAGE_SEQUENCE_ID_SWITCH) {
        if (mainGetBit(placement->openedGameBit) != 0) {
            ObjAnim_SetCurrentMove(obj, CFPRISONCAGE_SWITCH_OPEN_MOVE, 0.0f, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, CFPRISONCAGE_SWITCH_CLOSED_MOVE, 0.0f, 0);
        }
    } else {
        if (mainGetBit(placement->openedGameBit) != 0) {
            (*gObjectTriggerInterface)->preempt((int)obj, CFPRISONCAGE_OPEN_SEQUENCE_PREEMPT_FRAME);
        }
    }
}

void cfPrisonCage_release(void) {
}

void cfPrisonCage_initialise(void) {
}

ObjectDescriptor gCFPrisonCageObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfPrisonCage_initialise,
    (ObjectDescriptorCallback)cfPrisonCage_release,
    0,
    (ObjectDescriptorCallback)cfPrisonCage_init,
    (ObjectDescriptorCallback)cfPrisonCage_update,
    (ObjectDescriptorCallback)cfPrisonCage_hitDetect,
    (ObjectDescriptorCallback)cfPrisonCage_render,
    (ObjectDescriptorCallback)cfPrisonCage_free,
    (ObjectDescriptorCallback)cfPrisonCage_getObjectTypeId,
    cfPrisonCage_getExtraSize,
};
