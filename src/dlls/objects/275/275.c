#include "dlls/objects/275.h"

#include "dolphin/os.h"
#include "game/objects/object.h"
#include "main/objseq.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"

#define SEQ_OBJ2_GROUP                               0xF
#define SEQ_OBJ2_TYPE_ID                             0
#define SEQ_OBJ2_GAME_BIT_NONE                       -1
#define SEQ_OBJ2_PREEMPT_SEQUENCE_ID_NONE            -1
#define SEQ_OBJ2_SEQUENCE_ARG_NONE                   -1
#define SEQ_OBJ2_GAME_BIT_CLEAR                      0
#define SEQ_OBJ2_GAME_BIT_CLEAR_UNSIGNED             0u
#define SEQ_OBJ2_GAME_BIT_SET                        1
#define SEQ_OBJ2_ROTATION_SHIFT                      8
#define SEQ_OBJ2_STATE_PREEMPT_SEQUENCE              0x01
#define SEQ_OBJ2_STATE_SEQUENCE_FINISHED             0x02
#define SEQ_OBJ2_FLAG_CLEAR_REQUIRED_BEFORE_PREEMPT  0x01
#define SEQ_OBJ2_FLAG_CLEAR_REQUIRED_AFTER_SEQUENCE  0x02
#define SEQ_OBJ2_FLAG_CLEAR_REQUIRED_BEFORE_SEQUENCE 0x04
#define SEQ_OBJ2_FLAG_SET_USED_BEFORE_PREEMPT        0x08
#define SEQ_OBJ2_FLAG_SET_USED_AFTER_SEQUENCE        0x10
#define SEQ_OBJ2_FLAG_SET_USED_BEFORE_SEQUENCE       0x20
#define SEQ_OBJ2_CLEAR_DURING_SEQUENCE_STORAGE_SIZE  0x30
#define SEQ_OBJ2_USED_DURING_SEQUENCE_STORAGE_SIZE   0x2C
#define SEQ_OBJ2_CLEAR_BEFORE_PREEMPT_STORAGE_SIZE   0x3C
#define SEQ_OBJ2_USED_BEFORE_PREEMPT_STORAGE_SIZE    0x38
#define SEQ_OBJ2_ABOUT_TO_PREEMPT_STORAGE_SIZE       0x38
#define SEQ_OBJ2_CLEAR_AFTER_SEQUENCE_STORAGE_SIZE   0x30
#define SEQ_OBJ2_USED_AFTER_SEQUENCE_STORAGE_SIZE    0x2C
#define SEQ_OBJ2_CLEAR_BEFORE_SEQUENCE_STORAGE_SIZE  0x30
#define SEQ_OBJ2_USED_BEFORE_SEQUENCE_STORAGE_SIZE   0x2C
#define SEQ_OBJ2_ABOUT_TO_START_STORAGE_SIZE         0x2C
#define SEQ_OBJ2_NEED_AND_USED_BIT_STORAGE_SIZE      0x28
#define SEQ_OBJ2_DIAGNOSTIC_FORMATS_SIZE             0x1BC
#define SEQ_OBJ2_DATA_SIZE                           0x24C

typedef enum SeqObj2AnimEvent {
    SEQ_OBJ2_ANIM_EVENT_CLEAR_REQUIRED_BIT = 0,
    SEQ_OBJ2_ANIM_EVENT_SET_USED_BIT = 1
} SeqObj2AnimEvent;

/* Complete data layout recovered from the TU's descriptor and diagnostic strings. */
typedef struct SeqObj2DataLayout {
    ObjectDescriptor descriptor;                                                  /* 0x000 */
    char needBitClearDuringSequence[SEQ_OBJ2_CLEAR_DURING_SEQUENCE_STORAGE_SIZE]; /* 0x038 */
    char usedBitSetDuringSequence[SEQ_OBJ2_USED_DURING_SEQUENCE_STORAGE_SIZE];    /* 0x068 */
    char needBitClearBeforePreempt[SEQ_OBJ2_CLEAR_BEFORE_PREEMPT_STORAGE_SIZE];   /* 0x094 */
    char usedBitSetBeforePreempt[SEQ_OBJ2_USED_BEFORE_PREEMPT_STORAGE_SIZE];      /* 0x0D0 */
    char aboutToPreemptSequence[SEQ_OBJ2_ABOUT_TO_PREEMPT_STORAGE_SIZE];          /* 0x108 */
    char needBitClearAfterSequence[SEQ_OBJ2_CLEAR_AFTER_SEQUENCE_STORAGE_SIZE];   /* 0x140 */
    char usedBitSetAfterSequence[SEQ_OBJ2_USED_AFTER_SEQUENCE_STORAGE_SIZE];      /* 0x170 */
    char needBitClearBeforeSequence[SEQ_OBJ2_CLEAR_BEFORE_SEQUENCE_STORAGE_SIZE]; /* 0x19C */
    char usedBitSetBeforeSequence[SEQ_OBJ2_USED_BEFORE_SEQUENCE_STORAGE_SIZE];    /* 0x1CC */
    char aboutToStartSequence[SEQ_OBJ2_ABOUT_TO_START_STORAGE_SIZE];              /* 0x1F8 */
    char needAndUsedBit[SEQ_OBJ2_NEED_AND_USED_BIT_STORAGE_SIZE];                 /* 0x224 */
} SeqObj2DataLayout;

STATIC_ASSERT(offsetof(SeqObj2DataLayout, descriptor) == 0x0);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, needBitClearDuringSequence) == 0x38);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, usedBitSetDuringSequence) == 0x68);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, needBitClearBeforePreempt) == 0x94);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, usedBitSetBeforePreempt) == 0xD0);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, aboutToPreemptSequence) == 0x108);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, needBitClearAfterSequence) == 0x140);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, usedBitSetAfterSequence) == 0x170);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, needBitClearBeforeSequence) == 0x19C);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, usedBitSetBeforeSequence) == 0x1CC);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, aboutToStartSequence) == 0x1F8);
STATIC_ASSERT(offsetof(SeqObj2DataLayout, needAndUsedBit) == 0x224);
STATIC_ASSERT(sizeof(SeqObj2DataLayout) == SEQ_OBJ2_DATA_SIZE);

extern const char sSeqObjNeedBitClearDuringSequenceFormat[];
extern const char sSeqObjDiagnosticFormats[];
extern const char sSeqObjNeedAndUsedBitFormat[];

static int SeqObj2_animEventCallback(GameObject* obj, int* unused, ObjSeqState* animUpdate) {
    SeqObjectPlacement* placement;
    SeqObj2State* state;
    int eventIndex;

    (void)unused;

    placement = (SeqObjectPlacement*)obj->anim.placementData;
    state = obj->extra;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        int eventId = animUpdate->eventIds[eventIndex];

        switch (eventId) {
        case SEQ_OBJ2_ANIM_EVENT_CLEAR_REQUIRED_BIT:
            mainSetBits(placement->requiredGameBit, SEQ_OBJ2_GAME_BIT_CLEAR);
            OSReport(sSeqObjNeedBitClearDuringSequenceFormat, placement->base.ident);
            break;
        case SEQ_OBJ2_ANIM_EVENT_SET_USED_BIT:
            mainSetBits(placement->usedGameBit, SEQ_OBJ2_GAME_BIT_SET);
            OSReport(sSeqObjDiagnosticFormats, placement->base.ident);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQ_OBJ2_STATE_SEQUENCE_FINISHED);
    return 0;
}

int SeqObj2_getExtraSize(void) {
    return SEQ_OBJ2_STATE_SIZE;
}

int SeqObj2_getObjectTypeId(void) {
    return SEQ_OBJ2_TYPE_ID;
}

void SeqObj2_free(GameObject* obj) {
    objFreeObjectType(obj, SEQ_OBJ2_GROUP);
}

void SeqObj2_render(void) {
}

void SeqObj2_hitDetect(void) {
}

void SeqObj2_update(GameObject* obj) {
    SeqObj2State* state;
    SeqObjectPlacement* placement;
    SeqObj2DataLayout* data;
    u32 sequenceParam;

    data = (SeqObj2DataLayout*)&gSeqObj2ObjDescriptor;
    state = obj->extra;
    placement = (SeqObjectPlacement*)obj->anim.placementData;

    if ((state->flags & SEQ_OBJ2_STATE_PREEMPT_SEQUENCE) != 0) {
        if ((placement->flags & SEQ_OBJ2_FLAG_CLEAR_REQUIRED_BEFORE_PREEMPT) != 0) {
            mainSetBits(placement->requiredGameBit, SEQ_OBJ2_GAME_BIT_CLEAR);
            OSReport(data->needBitClearBeforePreempt, placement->base.ident);
        }
        if ((placement->flags & SEQ_OBJ2_FLAG_SET_USED_BEFORE_PREEMPT) != 0) {
            mainSetBits(placement->usedGameBit, SEQ_OBJ2_GAME_BIT_SET);
            OSReport(data->usedBitSetBeforePreempt, placement->base.ident);
        }
        OSReport(data->aboutToPreemptSequence, placement->base.ident, placement->sequenceParam);
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptSequenceId);
        sequenceParam = placement->sequenceParam;
        (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, sequenceParam);
        state->flags = (u8)(state->flags & ~SEQ_OBJ2_STATE_PREEMPT_SEQUENCE);
    } else if ((state->flags & SEQ_OBJ2_STATE_SEQUENCE_FINISHED) != 0) {
        if ((placement->flags & SEQ_OBJ2_FLAG_CLEAR_REQUIRED_AFTER_SEQUENCE) != 0) {
            mainSetBits(placement->requiredGameBit, SEQ_OBJ2_GAME_BIT_CLEAR);
            OSReport(data->needBitClearAfterSequence, placement->base.ident);
        }
        if ((placement->flags & SEQ_OBJ2_FLAG_SET_USED_AFTER_SEQUENCE) != 0) {
            mainSetBits(placement->usedGameBit, SEQ_OBJ2_GAME_BIT_SET);
            OSReport(data->usedBitSetAfterSequence, placement->base.ident);
        }
        state->flags = (u8)(state->flags & ~SEQ_OBJ2_STATE_SEQUENCE_FINISHED);
    } else {
        if ((placement->requiredGameBit == SEQ_OBJ2_GAME_BIT_NONE ||
             mainGetBit(placement->requiredGameBit) != SEQ_OBJ2_GAME_BIT_CLEAR_UNSIGNED) &&
            (placement->usedGameBit == SEQ_OBJ2_GAME_BIT_NONE ||
             mainGetBit(placement->usedGameBit) == SEQ_OBJ2_GAME_BIT_CLEAR_UNSIGNED)) {
            if ((placement->flags & SEQ_OBJ2_FLAG_CLEAR_REQUIRED_BEFORE_SEQUENCE) != 0) {
                mainSetBits(placement->requiredGameBit, SEQ_OBJ2_GAME_BIT_CLEAR);
                OSReport(data->needBitClearBeforeSequence, placement->base.ident);
            }
            if ((placement->flags & SEQ_OBJ2_FLAG_SET_USED_BEFORE_SEQUENCE) != 0) {
                mainSetBits(placement->usedGameBit, SEQ_OBJ2_GAME_BIT_SET);
                OSReport(data->usedBitSetBeforeSequence, placement->base.ident);
            }
            OSReport(data->aboutToStartSequence, placement->base.ident);
            (*gObjectTriggerInterface)->runSequence(placement->sequenceId, obj, SEQ_OBJ2_SEQUENCE_ARG_NONE);
        }
    }
}

void SeqObj2_init(GameObject* obj, SeqObjectPlacement* placement) {
    SeqObj2State* state;

    state = obj->extra;
    OSReport(sSeqObjNeedAndUsedBitFormat, placement->base.ident, placement->requiredGameBit, placement->usedGameBit);
    obj->anim.rotX = (s16)((u32)placement->initialYaw << SEQ_OBJ2_ROTATION_SHIFT);
    obj->animEventCallback = SeqObj2_animEventCallback;
    if (placement->preemptSequenceId > SEQ_OBJ2_PREEMPT_SEQUENCE_ID_NONE) {
        s16 usedGameBit = placement->usedGameBit;

        if (usedGameBit != SEQ_OBJ2_GAME_BIT_NONE && mainGetBit(usedGameBit) != SEQ_OBJ2_GAME_BIT_CLEAR_UNSIGNED) {
            state->flags = (u8)(state->flags | SEQ_OBJ2_STATE_PREEMPT_SEQUENCE);
        }
    }
    objAddObjectType(obj, SEQ_OBJ2_GROUP);
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
}

void SeqObj2_release(void) {
}

void SeqObj2_initialise(void) {
}

ObjectDescriptor gSeqObj2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SeqObj2_initialise,
    SeqObj2_release,
    0,
    (ObjectDescriptorCallback)SeqObj2_init,
    (ObjectDescriptorCallback)SeqObj2_update,
    SeqObj2_hitDetect,
    SeqObj2_render,
    (ObjectDescriptorCallback)SeqObj2_free,
    (ObjectDescriptorCallback)SeqObj2_getObjectTypeId,
    SeqObj2_getExtraSize,
};

const char sSeqObjNeedBitClearDuringSequenceFormat[] = "newseqobj %d: need bit clear during sequence\n";
const char sSeqObjDiagnosticFormats[SEQ_OBJ2_DIAGNOSTIC_FORMATS_SIZE] =
    "newseqobj %d: used bit set during sequence\n\000newseqobj %d: need bit clear before preempting "
    "sequence\n\000\000\000\000newseqobj %d: used bit set before preempting sequence\n\000\000newseqobj %d: about to "
    "prempt the sequence - objs %d\n\000\000\000newseqobj %d: need bit clear after sequence\n\000\000\000\000newseqobj "
    "%d: used bit set after sequence\n\000\000newseqobj %d: need bit clear before sequence\n\000\000\000newseqobj %d: "
    "used bit set before sequence\n\000newseqobj %d: about to start the sequence\n\000\000";
const char sSeqObjNeedAndUsedBitFormat[SEQ_OBJ2_NEED_AND_USED_BIT_STORAGE_SIZE] =
    "newseqobj %d: Need Bit %d, Used Bit %d\n";
