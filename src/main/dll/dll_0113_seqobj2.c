/*
 * seqobj2 (DLL 0x113) - sequence-triggered placed objects.
 *
 * Hosts three closely-related object behaviours that all drive scripted
 * trigger sequences off game bits:
 *   - seqObject_*  : a generic open/trigger object. Watches openGameBit and
 *     triggerGameBit; on a rising trigger edge it runs the placement's
 *     trigger sequence, then optionally sets/clears bits per the placement
 *     flag byte. State is the SeqObjectState bitfield (SEQOBJECT_STATE_*).
 *   - seqObj2_*    : the SeqObj2 variant (single-byte SeqObj2State), gated on
 *     trigger/open game bits with the same SEQOBJECT_FLAG_* placement flags.
 *   - seqobj2_*    : the SeqObj2 object exported via gSeqObj2ObjDescriptor;
 *     seqobj2_SeqFn handles in-sequence events (op 0 clears the trigger bit,
 *     op 1 sets the open bit) and OSReports the bit usage for debugging.
 *
 * Game bits used here are per-placement (openGameBit/triggerGameBit), not
 * hardcoded; -1 is the "no bit" sentinel.
 */
#include "main/dll/alphaanim.h"
#include "main/dll/seqobjectstate_struct.h"
#include "main/dll/seqobj2state_struct.h"
#include "main/dll/immultiseqstate_struct.h"
#include "main/dll/doorlockstate_struct.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/objprint.h"
#include "main/gamebits.h"
#include "main/object_descriptor.h"
#include "dolphin/os.h"

extern u32 FUN_80017690();
extern void FUN_80017698(u32 gameBit, u32 value);
extern void FUN_800723a0(void);
extern const char sSeqObjNeedBitUsedBitFormat[];
extern const char sSeqObjNeedBitClearDuringSequenceFormat[];
extern const char lbl_80321208[];


STATIC_ASSERT(sizeof(DoorLockPlacement) == 0x28);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotYByte) == 0x19);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotZByte) == 0x1A);
STATIC_ASSERT(offsetof(DoorLockPlacement, flags) == 0x1B);
STATIC_ASSERT(offsetof(DoorLockPlacement, lockGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DoorLockPlacement, modelBankIndex) == 0x21);
STATIC_ASSERT(offsetof(DoorLockPlacement, modeFlags) == 0x26);
STATIC_ASSERT(sizeof(DoorLockState) == 0x1);
STATIC_ASSERT(sizeof(SeqObjectPlacement) == 0x28);
STATIC_ASSERT(offsetof(SeqObjectPlacement, openGameBit) == 0x18);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerGameBit) == 0x1A);
STATIC_ASSERT(offsetof(SeqObjectPlacement, initialYaw) == 0x1C);
STATIC_ASSERT(offsetof(SeqObjectPlacement, flags) == 0x1D);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerId) == 0x1E);
STATIC_ASSERT(offsetof(SeqObjectPlacement, modelBankIndex) == 0x1F);
STATIC_ASSERT(offsetof(SeqObjectPlacement, preemptSequenceId) == 0x20);
STATIC_ASSERT(offsetof(SeqObjectPlacement, sequenceParam) == 0x22);
STATIC_ASSERT(offsetof(SeqObjectPlacement, warpMapId) == 0x24);
STATIC_ASSERT(sizeof(IMMultiSeqPlacement) == 0x34);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, completionGameBits) == 0x18);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, activeGameBits) == 0x20);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, initialYaw) == 0x28);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, modelBankIndex) == 0x2A);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, triggerIds) == 0x2C);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, polarityMask) == 0x30);
STATIC_ASSERT(sizeof(SeqObjectState) == 0x3);
STATIC_ASSERT(offsetof(SeqObjectState, triggerBitState) == 0x1);
STATIC_ASSERT(sizeof(SeqObj2State) == 0x1);
STATIC_ASSERT(sizeof(IMMultiSeqState) == 0x2);

#define SEQOBJECT_STATE_OPEN 0x01
#define SEQOBJECT_STATE_TRIGGER_SEQUENCE 0x02
#define SEQOBJECT_STATE_SEQUENCE_DONE 0x04

#define SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR 0x01
#define SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE 0x02
#define SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE 0x04
#define SEQOBJECT_FLAG_SET_SOURCE_ON_DONE 0x08
#define SEQOBJECT_FLAG_USE_TRIGGER_PARAM 0x10
#define SEQOBJECT_FLAG_UNUSED_20 0x20

#define SEQOBJECT_OBJFLAG_HIDDEN 0x4000
#define SEQOBJECT_OBJFLAG_HITDETECT_DISABLED 0x2000

void seqObject_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xf);
}

void seqObject_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
}

void seqObject_update(int obj)
{
    u32 bitValue;
    u8 flagBits;
    SeqObjectPlacement * def;
    SeqObjectState* state;

    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    if ((state->flags & SEQOBJECT_STATE_SEQUENCE_DONE) != 0)
    {
        flagBits = def->flags;
        if ((flagBits & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) == 0)
        {
            if ((flagBits & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
            {
                FUN_80017698(def->openGameBit, 1);
            }
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        else if ((flagBits & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) == 0)
        {
            FUN_80017698(def->triggerGameBit, 0);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_SEQUENCE_DONE);
    }
    if ((state->flags & SEQOBJECT_STATE_OPEN) == 0)
    {
        bitValue = FUN_80017690(def->openGameBit);
        if (bitValue != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        bitValue = FUN_80017690(def->triggerGameBit);
        flagBits = bitValue;
        if ((flagBits != state->triggerBitState) && (state->triggerBitState = flagBits, flagBits != 0))
        {
            if (def->triggerId != -1)
            {
                (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
                (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj, -1);
            }
            if (((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) == 0) &&
                ((def->flags & (SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE | SEQOBJECT_FLAG_SET_SOURCE_ON_DONE)) == 0))
            {
                FUN_80017698(def->openGameBit, 1);
            }
        }
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) == 0)
    {
        if (((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0) &&
            (bitValue = FUN_80017690(def->openGameBit), bitValue == 0))
        {
            state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
        }
    }
    else
    {
        (*gObjectTriggerInterface)->preempt(obj, def->preemptSequenceId);
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj, 1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj,
                                                    def->sequenceParam);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
}

void seqObject_init(short* obj, int placement)
{
}

void seqObj2_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xf);
}

void seqObj2_update(int obj)
{
    u32 bitValue;
    SeqObjectPlacement * def;
    SeqObj2State* state;

    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    if ((state->flags & SEQOBJECT_STATE_OPEN) == 0)
    {
        if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) == 0)
        {
            if (((def->triggerGameBit == -1) ||
                    (bitValue = FUN_80017690(def->triggerGameBit), bitValue != 0)) &&
                ((def->openGameBit == -1 ||
                    (bitValue = FUN_80017690(def->openGameBit), bitValue == 0))))
            {
                if ((def->flags & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) != 0)
                {
                    FUN_80017698(def->triggerGameBit, 0);
                    FUN_800723a0();
                }
                if ((def->flags & SEQOBJECT_FLAG_UNUSED_20) != 0)
                {
                    FUN_80017698(def->openGameBit, 1);
                    FUN_800723a0();
                }
                FUN_800723a0();
                (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj, -1);
            }
        }
        else
        {
            if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE) != 0)
            {
                FUN_80017698(def->triggerGameBit, 0);
                FUN_800723a0();
            }
            if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
            {
                FUN_80017698(def->openGameBit, 1);
                FUN_800723a0();
            }
            state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
        }
    }
    else
    {
        if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            FUN_80017698(def->triggerGameBit, 0);
            FUN_800723a0();
        }
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
        {
            FUN_80017698(def->openGameBit, 1);
            FUN_800723a0();
        }
        FUN_800723a0();
        (*gObjectTriggerInterface)->preempt(obj, def->preemptSequenceId);
        (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj, def->sequenceParam);
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
}

void seqObj2_init(short* obj, int placement)
{
}

void seqobj2_render(void)
{
}

void seqobj2_hitDetect(void)
{
}

void SeqObj2_release(void)
{
}

void SeqObj2_initialise(void)
{
}

int seqobj2_getExtraSize(void) { return 0x1; }
int seqobj2_getObjectTypeId(void) { return 0x0; }

void seqobj2_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

void seqobj2_init(int* obj, SeqObjectPlacement* def)
{
    SeqObj2State* state = ((GameObject*)obj)->extra;
    OSReport(sSeqObjNeedBitUsedBitFormat, def->base.mapId, def->triggerGameBit, def->openGameBit);
    ((GameObject*)obj)->anim.rotX = (s16)((u32)def->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = seqobj2_SeqFn;
    if (def->preemptSequenceId > -1)
    {
        s16 slot = def->openGameBit;
        if (slot != -1 && GameBit_Get(slot) != 0u)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
    }
    ObjGroup_AddObject((u32)obj, 15);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (SEQOBJECT_OBJFLAG_HIDDEN | SEQOBJECT_OBJFLAG_HITDETECT_DISABLED));
}

int seqobj2_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    SeqObjectPlacement * def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    SeqObj2State* state = ((GameObject*)obj)->extra;
    int i;
    enum { SEQOBJ2_SEQEV_CLEAR_TRIGGER = 0, SEQOBJ2_SEQEV_SET_OPEN = 1 };
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int op = animUpdate->eventIds[i];
        switch (op)
        {
        case SEQOBJ2_SEQEV_CLEAR_TRIGGER:
            GameBit_Set(def->triggerGameBit, 0);
            OSReport(sSeqObjNeedBitClearDuringSequenceFormat, def->base.mapId);
            break;
        case SEQOBJ2_SEQEV_SET_OPEN:
            GameBit_Set(def->openGameBit, 1);
            OSReport(lbl_80321208, def->base.mapId);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    return 0;
}

void seqobj2_update(int* obj)
{
    SeqObj2State* state;
    SeqObjectPlacement * def;
    char* strBase;
    u32 bitValue;

    strBase = (char*)&gSeqObj2ObjDescriptor;
    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;

    if ((state->flags & SEQOBJECT_STATE_OPEN) != 0)
    {
        if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            GameBit_Set(def->triggerGameBit, 0);
            OSReport(strBase + 0x94, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
        {
            GameBit_Set(def->openGameBit, 1);
            OSReport(strBase + 0xd0, def->base.mapId);
        }
        OSReport(strBase + 0x108, def->base.mapId, def->sequenceParam);
        (*gObjectTriggerInterface)->preempt((int)obj, def->preemptSequenceId);
        bitValue = def->sequenceParam;
        (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, bitValue);
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) != 0)
    {
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE) != 0)
        {
            GameBit_Set(def->triggerGameBit, 0);
            OSReport(strBase + 0x140, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
        {
            GameBit_Set(def->openGameBit, 1);
            OSReport(strBase + 0x170, def->base.mapId);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
    else
    {
        if ((def->triggerGameBit == -1 || GameBit_Get(def->triggerGameBit) != 0) &&
            (def->openGameBit == -1 || GameBit_Get(def->openGameBit) == 0))
        {
            if ((def->flags & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) != 0)
            {
                GameBit_Set(def->triggerGameBit, 0);
                OSReport(strBase + 0x19c, def->base.mapId);
            }
            if ((def->flags & SEQOBJECT_FLAG_UNUSED_20) != 0)
            {
                GameBit_Set(def->openGameBit, 1);
                OSReport(strBase + 0x1cc, def->base.mapId);
            }
            OSReport(strBase + 0x1f8, def->base.mapId);
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, -1);
        }
    }
}


ObjectDescriptor gSeqObj2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SeqObj2_initialise,
    SeqObj2_release,
    0,
    (ObjectDescriptorCallback)seqobj2_init,
    (ObjectDescriptorCallback)seqobj2_update,
    seqobj2_hitDetect,
    seqobj2_render,
    (ObjectDescriptorCallback)seqobj2_free,
    (ObjectDescriptorCallback)seqobj2_getObjectTypeId,
    seqobj2_getExtraSize,
};
