#include "main/dll/alphaanim.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"


extern undefined4 FUN_80006ba8();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800723a0();

extern ObjectTriggerInterface** gObjectTriggerInterface;

typedef struct DoorLockState
{
    u8 unlocked;
} DoorLockState;

typedef struct SeqObjectState
{
    u8 flags;
    s8 triggerBitState;
    u8 pad02;
} SeqObjectState;

typedef struct SeqObj2State
{
    u8 flags;
} SeqObj2State;

typedef struct IMMultiSeqState
{
    u8 step;
    u8 flags;
} IMMultiSeqState;

STATIC_ASSERT (
sizeof
(DoorLockPlacement)
==
0x28
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
rotXByte
)
==
0x18
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
rotYByte
)
==
0x19
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
rotZByte
)
==
0x1A
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
flags
)
==
0x1B
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
lockGameBit
)
==
0x1C
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
modelBankIndex
)
==
0x21
);
STATIC_ASSERT (offsetof
(DoorLockPlacement
,
modeFlags
)
==
0x26
);
STATIC_ASSERT (
sizeof
(DoorLockState)
==
0x1
);
STATIC_ASSERT (
sizeof
(SeqObjectPlacement)
==
0x28
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
openGameBit
)
==
0x18
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
triggerGameBit
)
==
0x1A
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
initialYaw
)
==
0x1C
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
flags
)
==
0x1D
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
triggerId
)
==
0x1E
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
modelBankIndex
)
==
0x1F
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
preemptSequenceId
)
==
0x20
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
sequenceParam
)
==
0x22
);
STATIC_ASSERT (offsetof
(SeqObjectPlacement
,
warpMapId
)
==
0x24
);
STATIC_ASSERT (
sizeof
(IMMultiSeqPlacement)
==
0x34
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
completionGameBits
)
==
0x18
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
activeGameBits
)
==
0x20
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
initialYaw
)
==
0x28
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
modelBankIndex
)
==
0x2A
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
triggerIds
)
==
0x2C
);
STATIC_ASSERT (offsetof
(IMMultiSeqPlacement
,
polarityMask
)
==
0x30
);
STATIC_ASSERT (
sizeof
(SeqObjectState)
==
0x3
);
STATIC_ASSERT (offsetof
(SeqObjectState
,
triggerBitState
)
==
0x1
);
STATIC_ASSERT (
sizeof
(SeqObj2State)
==
0x1
);
STATIC_ASSERT (
sizeof
(IMMultiSeqState)
==
0x2
);

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

/*
 * --INFO--
 *
 * Function: doorlock_init
 * EN v1.0 Address: 0x8017C178
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8017C250
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void doorlock_init(short* obj, DoorLockPlacement* config)
{
    ObjAnimComponent* objAnim;
    DoorLockState* state;

    objAnim = (ObjAnimComponent*)obj;
    *obj = (short)((byte)config->rotXByte << 8);
    ((GameObject*)obj)->anim.rotY = (short)((byte)config->rotYByte << 8);
    ((GameObject*)obj)->anim.rotZ = (short)((byte)config->rotZByte << 8);
    ((GameObject*)obj)->animEventCallback = (void*)Lock_DoorLock_SeqFn;
    *(u8*)&objAnim->bankIndex = config->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    state = ((GameObject*)obj)->extra;
    state->unlocked = (byte)GameBit_Get(config->lockGameBit);
    ObjGroup_AddObject(obj, 0xf);
    if ((config->flags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            objAnim->alpha = 0;
        }
    }
    else if ((config->modeFlags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
        }
        else
        {
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8017c5c4
 * EN v1.0 Address: 0x8017C5C4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8017C7EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c5c4(int param_1)
{
    if (param_1 != 0)
    {
        (**(code**)(**(int**)&((GameObject*)param_1)->anim.dll + 4))(
            param_1, *(undefined4*)&((GameObject*)param_1)->anim.placementData, 0);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c608
 * EN v1.0 Address: 0x8017C608
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8017C82C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: seqObject_free
 * EN v1.0 Address: 0x8017C7D0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C960
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_free(int param_1)
{
    ObjGroup_RemoveObject(param_1, 0xf);
    return;
}

/*
 * --INFO--
 *
 * Function: seqObject_render
 * EN v1.0 Address: 0x8017C7F4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017C984
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_render(int param_1, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: seqObject_update
 * EN v1.0 Address: 0x8017C81C
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017C9B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_update(int param_1)
{
    uint uVar1;
    byte bVar2;
    SeqObjectPlacement * def;
    SeqObjectState* state;

    state = ((GameObject*)param_1)->extra;
    def = (SeqObjectPlacement*)((GameObject*)param_1)->anim.placementData;
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
        uVar1 = FUN_80017690(def->openGameBit);
        if (uVar1 != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        uVar1 = FUN_80017690(def->triggerGameBit);
        bVar2 = (byte)uVar1;
        if ((bVar2 != state->triggerBitState) && (state->triggerBitState = bVar2, bVar2 != 0))
        {
            if (def->triggerId != -1)
            {
                (*gObjectTriggerInterface)->setRunSequenceWorldSpace(param_1, 0);
                (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)param_1, -1);
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
            (uVar1 = FUN_80017690(def->openGameBit), uVar1 == 0))
        {
            state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
        }
    }
    else
    {
        (*gObjectTriggerInterface)->preempt(param_1, def->preemptSequenceId);
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)param_1, 1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)param_1,
                                                    def->sequenceParam);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: seqObject_init
 * EN v1.0 Address: 0x8017CA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017CC04
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_init(short* param_1, int param_2)
{
}


/*
 * --INFO--
 *
 * Function: seqObj2_free
 * EN v1.0 Address: 0x8017CAF4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017CDE4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_free(int param_1)
{
    ObjGroup_RemoveObject(param_1, 0xf);
    return;
}

/*
 * --INFO--
 *
 * Function: seqObj2_update
 * EN v1.0 Address: 0x8017CB18
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8017CE10
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_update(int param_1)
{
    uint uVar1;
    SeqObjectPlacement * def;
    SeqObj2State* state;

    state = ((GameObject*)param_1)->extra;
    def = (SeqObjectPlacement*)((GameObject*)param_1)->anim.placementData;
    if ((state->flags & SEQOBJECT_STATE_OPEN) == 0)
    {
        if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) == 0)
        {
            if (((def->triggerGameBit == -1) ||
                    (uVar1 = FUN_80017690(def->triggerGameBit), uVar1 != 0)) &&
                ((def->openGameBit == -1 ||
                    (uVar1 = FUN_80017690(def->openGameBit), uVar1 == 0))))
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
                (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)param_1, -1);
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
        (*gObjectTriggerInterface)->preempt(param_1, def->preemptSequenceId);
        (*gObjectTriggerInterface)->runSequence(def->triggerId, (void*)param_1, def->sequenceParam);
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: seqObj2_init
 * EN v1.0 Address: 0x8017CCE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D064
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_init(short* param_1, int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
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

void immultiseq_hitDetect(void)
{
}

void immultiseq_release(void)
{
}

void immultiseq_initialise(void)
{
}

void seqobject_init(int* obj, SeqObjectPlacement* params)
{
    ObjAnimComponent* objAnim;
    SeqObjectState* state;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(params->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = (void*)seqobject_SeqFn;
    *(u8*)&objAnim->bankIndex = params->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjGroup_AddObject(obj, 0xf);
    state->flags = 0;
    if (params->openGameBit != -1 && GameBit_Get(params->openGameBit) != 0)
    {
        state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        if (params->preemptSequenceId != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_TRIGGER_SEQUENCE);
        }
    }
    state->triggerBitState = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

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

void dll_115_hitDetect_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int seqobject_getExtraSize(void) { return 0x3; }
int seqobject_getObjectTypeId(void) { return 0x0; }
int seqobj2_getExtraSize(void) { return 0x1; }
int seqobj2_getObjectTypeId(void) { return 0x0; }
int immultiseq_getExtraSize(void) { return 0x2; }
int immultiseq_getObjectTypeId(void) { return 0x0; }
int dll_115_getExtraSize_ret_2(void) { return 0x2; }
int dll_115_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E37A0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E37A8;
extern f32 lbl_803E37B0;

void seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E37A0);
}

void immultiseq_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E37A8);
}

void dll_115_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E37B0);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void seqobject_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void seqobj2_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void immultiseq_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void dll_115_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

/* Drift-recovery: add new fns with v1.0 names. */

extern void OSReport(const char* fmt, ...);
extern const char sSeqObjNeedBitUsedBitFormat[];
extern const char sSeqObjNeedBitClearDuringSequenceFormat[];
extern const char lbl_80321208[];
extern int GameBit_Set(int eventId, int value);
extern int warpToMap(int id, int flags);

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

void fn_8017C294(int* obj)
{
    if (obj != NULL)
    {
        ((void(*)(int*, int*, int))((void**)*(*(int***)&((GameObject*)obj)->anim.dll))[1])(
            obj, *(int**)&((GameObject*)obj)->anim.placementData, 0);
    }
}

void seqobj2_init(int* obj, SeqObjectPlacement* def)
{
    SeqObj2State* state = ((GameObject*)obj)->extra;
    OSReport(sSeqObjNeedBitUsedBitFormat, def->base.mapId, def->triggerGameBit, def->openGameBit);
    *(s16*)obj = (s16)((u32)def->initialYaw << 8);
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

int seqobject_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    SeqObjectPlacement * def;
    SeqObjectState* state;
    int i;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    def = *(SeqObjectPlacement**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int op = animUpdate->eventIds[i];
        switch (op)
        {
        case 1:
            {
                u8 flags = def->flags;
                if ((flags & 1) == 0 && (flags & 2) != 0)
                {
                    GameBit_Set(def->openGameBit, 1);
                }
                break;
            }
        case 2:
            {
                u8 v = def->warpMapId;
                if (v != 0)
                {
                    warpToMap(v, 0);
                }
                break;
            }
        case 3:
            (*gObjectTriggerInterface)->setCamVars(86, 1, 0, 0);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQOBJECT_STATE_SEQUENCE_DONE);
    return 0;
}

void seqobject_update(int* obj)
{
    SeqObjectState* state;
    SeqObjectPlacement * def;
    s32 bitValue;

    state = ((GameObject*)obj)->extra;
    def = *(SeqObjectPlacement**)&((GameObject*)obj)->anim.placementData;

    if ((state->flags & SEQOBJECT_STATE_SEQUENCE_DONE) != 0)
    {
        u8 flags = def->flags;

        if ((flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            if ((flags & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) == 0)
            {
                GameBit_Set(def->triggerGameBit, 0);
            }
        }
        else
        {
            if ((flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
            {
                GameBit_Set(def->openGameBit, 1);
            }
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_SEQUENCE_DONE);
    }

    if ((state->flags & SEQOBJECT_STATE_OPEN) == 0)
    {
        if (GameBit_Get(def->openGameBit) != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }

        bitValue = GameBit_Get(def->triggerGameBit);
        bitValue = (s8)bitValue;
        if (bitValue != state->triggerBitState)
        {
            state->triggerBitState = bitValue;
            if (bitValue != 0)
            {
                if (def->triggerId != -1)
                {
                    (*gObjectTriggerInterface)->setRunSequenceWorldSpace((int)obj, 0);
                    (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, -1);
                }
                if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) == 0 &&
                    (def->flags & (SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE |
                        SEQOBJECT_FLAG_SET_SOURCE_ON_DONE)) == 0)
                {
                    GameBit_Set(def->openGameBit, 1);
                }
            }
        }
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) != 0)
    {
        (*gObjectTriggerInterface)->preempt((int)obj, def->preemptSequenceId);
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj,
                                                    def->sequenceParam);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, 1);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
    else if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0 &&
        GameBit_Get(def->openGameBit) == 0)
    {
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
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

int dll_115_seqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    int v;
    u8* state = ((GameObject*)obj)->extra;
    s16* def = *(s16**)&((GameObject*)obj)->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    {
        v = state[0];
        if (v >= 10 || v < 8)
        {
            int n = v + 1;
            if (n < 8)
            {
                s16 newId = (def + n)[0x14];
                if (newId != -1 && newId != (def + v)[0x14])
                {
                    if (GameBit_Get(newId) != 0)
                    {
                        (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
                    }
                }
            }
        }
    }
    state[1] = (u8)(state[1] | 1);
    return 0;
}

