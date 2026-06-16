#include "main/dll/alphaanim.h"
#include "main/dll/seqobjectstate_struct.h"
#include "main/dll/seqobj2state_struct.h"
#include "main/dll/immultiseqstate_struct.h"
#include "main/dll/doorlockstate_struct.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800723a0();

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

extern void OSReport(const char* fmt, ...);
extern const char sSeqObjNeedBitUsedBitFormat[];
extern const char sSeqObjNeedBitClearDuringSequenceFormat[];
extern const char lbl_80321208[];
extern int GameBit_Set(int eventId, int value);

void FUN_8017c5c4(int param_1)
{
    if (param_1 != 0)
    {
        (**(code**)(**(int**)&((GameObject*)param_1)->anim.dll + 4))(
            param_1, *(undefined4*)&((GameObject*)param_1)->anim.placementData, 0);
    }
    return;
}

undefined4
FUN_8017c608(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, int param_13, undefined4 param_14,
             undefined4 param_15,
             undefined4 param_16)
{
    byte eventId;
    int animState;
    int i;
    byte* flags;
    int placement;

    if (((GameObject*)param_9)->seqIndex != -1)
    {
        placement = *(int*)&((GameObject*)param_9)->anim.placementData;
        flags = ((GameObject*)param_9)->extra;
        animUpdate->sequenceEventActive = 0;
        animState = (int)animUpdate;
        for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
        {
            eventId = animUpdate->eventIds[i];
            if (eventId == 2)
            {
                if (*(byte*)(placement + 0x24) != 0)
                {
                    param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                           (uint) * (byte*)(placement + 0x24), '\0', animState, param_12, param_13, param_14
                                           , param_15, param_16);
                }
            }
            else if (eventId < 2)
            {
                if (((eventId != 0) && ((*(byte*)(placement + 0x1d) & 1) == 0)) &&
                    ((*(byte*)(placement + 0x1d) & 2) != 0))
                {
                    param_1 = FUN_80017698((int)*(short*)(placement + 0x18), 1);
                }
            }
            else if (eventId < 4)
            {
                animState = 0;
                param_12 = 0;
                (*gObjectTriggerInterface)->setCamVars(0x56, 1, 0, 0);
            }
        }
        *flags = *flags | 4;
    }
    return 0;
}

void seqObject_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xf);
    return;
}

void seqObject_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
    return;
}

void seqObject_update(int obj)
{
    uint bitValue;
    byte flagBits;
    SeqObjectPlacement * def;
    SeqObjectState* state;

    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    if ((state->flags & SEQOBJECT_STATE_SEQUENCE_DONE) != 0)
    {
        flagBits = def->flags;
        if ((flagBits & 1) == 0)
        {
            if ((flagBits & 8) != 0)
            {
                FUN_80017698(def->openGameBit, 1);
            }
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        else if ((flagBits & 4) == 0)
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
        flagBits = (byte)bitValue;
        if ((flagBits != state->triggerBitState) && (state->triggerBitState = flagBits, flagBits != 0))
        {
            if (def->triggerId != -1)
            {
                (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
                (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)obj, -1);
            }
            if (((def->flags & 1) == 0) && ((def->flags & 10) == 0))
            {
                FUN_80017698(def->openGameBit, 1);
            }
        }
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) == 0)
    {
        if (((def->flags & 1) != 0) &&
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
    return;
}

void seqObject_init(short* param_1, int param_2)
{
}

void seqObj2_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xf);
    return;
}

void seqObj2_update(int obj)
{
    uint bitValue;
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
    return;
}

void seqObj2_init(short* param_1, int param_2)
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

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */

void seqobj2_init(int* obj, SeqObjectPlacement* def)
{
    SeqObj2State* state = ((GameObject*)obj)->extra;
    OSReport(sSeqObjNeedBitUsedBitFormat, def->base.mapId, def->triggerGameBit, def->openGameBit);
    ((GameObject*)obj)->anim.rotX = (s16)((u32)def->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = (void*)seqobj2_SeqFn;
    if (def->preemptSequenceId > -1)
    {
        s16 slot = def->openGameBit;
        if (slot != -1 && (u32)GameBit_Get(slot) != 0u)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
    }
    ObjGroup_AddObject(obj, 15);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

int seqobj2_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    SeqObjectPlacement * def = *(SeqObjectPlacement**)&((GameObject*)obj)->anim.placementData;
    SeqObj2State* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int op = animUpdate->eventIds[i];
        switch (op)
        {
        case 0:
            GameBit_Set(def->triggerGameBit, 0);
            OSReport(sSeqObjNeedBitClearDuringSequenceFormat, def->base.mapId);
            break;
        case 1:
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
    char* descriptor;
    u32 bitValue;

    descriptor = (char*)&gSeqObj2ObjDescriptor;
    state = ((GameObject*)obj)->extra;
    def = *(SeqObjectPlacement**)&((GameObject*)obj)->anim.placementData;

    if ((state->flags & SEQOBJECT_STATE_OPEN) != 0)
    {
        if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            GameBit_Set(def->triggerGameBit, 0);
            OSReport(descriptor + 0x94, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
        {
            GameBit_Set(def->openGameBit, 1);
            OSReport(descriptor + 0xd0, def->base.mapId);
        }
        OSReport(descriptor + 0x108, def->base.mapId, def->sequenceParam);
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
            OSReport(descriptor + 0x140, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
        {
            GameBit_Set(def->openGameBit, 1);
            OSReport(descriptor + 0x170, def->base.mapId);
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
                OSReport(descriptor + 0x19c, def->base.mapId);
            }
            if ((def->flags & SEQOBJECT_FLAG_UNUSED_20) != 0)
            {
                GameBit_Set(def->openGameBit, 1);
                OSReport(descriptor + 0x1cc, def->base.mapId);
            }
            OSReport(descriptor + 0x1f8, def->base.mapId);
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, -1);
        }
    }
}

