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

extern ObjectTriggerInterface** gObjectTriggerInterface;

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

#define IMMULTISEQ_LATCH_ADVANCE_BIT 0x01

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E37A8;
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
    byte bVar1;
    int iVar2;
    int iVar3;
    byte* pbVar4;
    int iVar5;

    if (((GameObject*)param_9)->seqIndex != -1)
    {
        iVar5 = *(int*)&((GameObject*)param_9)->anim.placementData;
        pbVar4 = ((GameObject*)param_9)->extra;
        animUpdate->sequenceEventActive = 0;
        iVar2 = (int)animUpdate;
        for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
        {
            bVar1 = animUpdate->eventIds[iVar3];
            if (bVar1 == 2)
            {
                if (*(byte*)(iVar5 + 0x24) != 0)
                {
                    param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                           (uint) * (byte*)(iVar5 + 0x24), '\0', iVar2, param_12, param_13, param_14
                                           , param_15, param_16);
                }
            }
            else if (bVar1 < 2)
            {
                if (((bVar1 != 0) && ((*(byte*)(iVar5 + 0x1d) & 1) == 0)) &&
                    ((*(byte*)(iVar5 + 0x1d) & 2) != 0))
                {
                    param_1 = FUN_80017698((int)*(short*)(iVar5 + 0x18), 1);
                }
            }
            else if (bVar1 < 4)
            {
                iVar2 = 0;
                param_12 = 0;
                (*gObjectTriggerInterface)->setCamVars(0x56, 1, 0, 0);
            }
        }
        *pbVar4 = *pbVar4 | 4;
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
    byte bVar2;
    SeqObjectPlacement * def;
    SeqObjectState* state;

    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    if ((state->flags & SEQOBJECT_STATE_SEQUENCE_DONE) != 0)
    {
        bVar2 = def->flags;
        if ((bVar2 & 1) == 0)
        {
            if ((bVar2 & 8) != 0)
            {
                FUN_80017698(def->openGameBit, 1);
            }
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        else if ((bVar2 & 4) == 0)
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
        bVar2 = (byte)bitValue;
        if ((bVar2 != state->triggerBitState) && (state->triggerBitState = bVar2, bVar2 != 0))
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

void seqobj2_render(void);

void immultiseq_hitDetect(void)
{
}

void immultiseq_release(void)
{
}

void immultiseq_initialise(void)
{
}

void seqobject_init(int* obj, SeqObjectPlacement* params);

void immultiseq_init(int* obj, IMMultiSeqPlacement* params)
{
    ObjAnimComponent* objAnim;
    IMMultiSeqState* state;
    int i;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(params->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = (void*)immultiseq_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    objAnim->bankIndex = (s8)params->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjGroup_AddObject(obj, 0xf);
    i = 0;
    while (i < 4)
    {
        if ((uint)((params->polarityMask >> (i + 4)) & 1) == GameBit_Get(params->completionGameBits[i]))
        {
            break;
        }
        i++;
    }
    state->step = (u8)i;
}

void dll_115_hitDetect_nop(void);

int immultiseq_getExtraSize(void) { return 0x2; }
int immultiseq_getObjectTypeId(void) { return 0x0; }
int dll_115_getExtraSize_ret_2(void);

void immultiseq_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E37A8);
}

void dll_115_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void immultiseq_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void dll_115_free(int x);

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
int immultiseq_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    IMMultiSeqState* state = ((GameObject*)obj)->extra;
    IMMultiSeqPlacement * def = *(IMMultiSeqPlacement**)&((GameObject*)obj)->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    {
        int v = state->step;
        if (v != 4)
        {
            int next = v + 1;
            if ((s32)next < 4)
            {
                s16 gbit = def->activeGameBits[next];
                if (gbit != -1)
                {
                    int bv = GameBit_Get(gbit);
                    int nb = !((def->polarityMask >> next) & 1);
                    if ((u32)nb == (u32)bv)
                    {
                        (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
                    }
                }
            }
        }
    }
    state->flags = (u8)(state->flags | IMMULTISEQ_LATCH_ADVANCE_BIT);
    return 0;
}

void fn_8017C294(int* obj);

void immultiseq_update(int* obj)
{
    IMMultiSeqState* state;
    IMMultiSeqPlacement * def;
    u8 step;
    int prevStep;
    s16 bitId;

    state = ((GameObject*)obj)->extra;
    def = *(IMMultiSeqPlacement**)&((GameObject*)obj)->anim.placementData;

    if ((state->flags & IMMULTISEQ_LATCH_ADVANCE_BIT) != 0)
    {
        step = state->step;
        bitId = def->completionGameBits[step];
        GameBit_Set(bitId, (u32)!((def->polarityMask >> (step + 4)) & 1));
        state->flags = (u8)(state->flags & ~IMMULTISEQ_LATCH_ADVANCE_BIT);
        state->step++;
    }

    if ((int)state->step != 4)
    {
        u8 st = state->step;
        bitId = def->activeGameBits[st];
        if (bitId == -1)
        {
            state->step = 4;
        }
        else if ((u32)!((def->polarityMask >> state->step) & 1) == GameBit_Get(bitId))
        {
            s8 triggerId = def->triggerIds[state->step];
            if (triggerId != -1)
            {
                (*gObjectTriggerInterface)->runSequence(triggerId, obj, -1);
            }
        }
    }

    prevStep = state->step - 1;
    while (prevStep >= 0)
    {
        bitId = def->completionGameBits[prevStep];
        if (bitId == -1)
        {
            break;
        }
        if (((def->polarityMask >> (prevStep + 4)) & 1) != GameBit_Get(bitId))
        {
            break;
        }
        state->step--;
        prevStep--;
    }
}

int dll_115_seqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate);
