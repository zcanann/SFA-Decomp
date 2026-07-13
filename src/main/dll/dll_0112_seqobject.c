/*
 * seqobject (DLL 0x112): a generic gamebit-driven sequence/latch trigger.
 *
 * SeqObjectPlacement carries openGameBit (+0x18) and triggerGameBit (+0x1A).
 * When triggerGameBit transitions to set, the object runs sequence triggerId
 * (SeqFn dispatches the sequence-event opcodes 1-3: set openGameBit, warp to
 * warpMapId, set cam vars) and -- subject to the placement flag bits -- latches
 * openGameBit. The flag bits gate which gamebits are set/cleared as the object
 * opens and completes; used to chain world progression.
 *
 * objCallOnloadCallback is a small helper exported for other DLLs (cflevelcontrol)
 * to invoke an object's vtable slot 1 on its placement data.
 */
#include "main/dll/dll_0112_seqobject.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/rcp_dolphin.h"

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
STATIC_ASSERT(sizeof(SeqObjectState) == 0x3);
STATIC_ASSERT(offsetof(SeqObjectState, triggerBitState) == 0x1);

#define SEQOBJECT_OBJFLAG_HITDETECT_DISABLED 0x2000

#define SEQOBJECT_STATE_OPEN             0x01
#define SEQOBJECT_STATE_TRIGGER_SEQUENCE 0x02
#define SEQOBJECT_STATE_SEQUENCE_DONE    0x04

#define SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR     0x01
#define SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE 0x02
#define SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE   0x04
#define SEQOBJECT_FLAG_SET_SOURCE_ON_DONE     0x08
#define SEQOBJECT_FLAG_USE_TRIGGER_PARAM      0x10

/* sequence-event opcodes consumed by SeqObject_SeqFn */
enum
{
    SEQOBJECT_SEQEV_SET_OPEN_BIT = 1,
    SEQOBJECT_SEQEV_WARP = 2,
    SEQOBJECT_SEQEV_SET_CAM = 3
};

enum
{
    SEQOBJECT_OBJGROUP = 0xf
};

extern f32 lbl_803E37A0;

void objCallOnloadCallback(GameObject* obj)
{
    if (obj != NULL)
    {
        ((void (*)(GameObject*, int*, int))((void**)*(*(int***)&obj->anim.dll))[1])(
            obj, *(int**)&obj->anim.placementData, 0);
    }
}

int SeqObject_SeqFn(GameObject* obj, int* unused, ObjAnimUpdateState* animUpdate)
{
    SeqObjectPlacement* def;
    SeqObjectState* state;
    int i;
    if (obj->seqIndex == -1)
    {
        return 0;
    }
    def = *(SeqObjectPlacement**)&obj->anim.placementData;
    state = obj->extra;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int op = animUpdate->eventIds[i];
        switch (op)
        {
        case SEQOBJECT_SEQEV_SET_OPEN_BIT:
        {
            u8 flags = def->flags;
            if ((flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) == 0 &&
                (flags & SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE) != 0)
            {
                mainSetBits(def->openGameBit, 1);
            }
            break;
        }
        case SEQOBJECT_SEQEV_WARP:
        {
            u8 mapId = def->warpMapId;
            if (mapId != 0)
            {
                warpToMap(mapId, 0);
            }
            break;
        }
        case SEQOBJECT_SEQEV_SET_CAM:
            (*gObjectTriggerInterface)->setCamVars(86, 1, 0, 0);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQOBJECT_STATE_SEQUENCE_DONE);
    return 0;
}

int SeqObject_getExtraSize(void)
{
    return sizeof(SeqObjectState);
}
int SeqObject_getObjectTypeId(void)
{
    return 0;
}

void SeqObject_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, SEQOBJECT_OBJGROUP);
}

void SeqObject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes((GameObject*)p1, lbl_803E37A0);
}

void SeqObject_update(GameObject* obj)
{
    SeqObjectState* state;
    SeqObjectPlacement* def;
    s32 bitValue;

    state = obj->extra;
    def = *(SeqObjectPlacement**)&obj->anim.placementData;

    if ((state->flags & SEQOBJECT_STATE_SEQUENCE_DONE) != 0)
    {
        u8 flags = def->flags;

        if ((flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            if ((flags & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) == 0)
            {
                mainSetBits(def->triggerGameBit, 0);
            }
        }
        else
        {
            if ((flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
            {
                mainSetBits(def->openGameBit, 1);
            }
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_SEQUENCE_DONE);
    }

    if ((state->flags & SEQOBJECT_STATE_OPEN) == 0)
    {
        if (mainGetBit(def->openGameBit) != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }

        bitValue = mainGetBit(def->triggerGameBit);
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
                    (def->flags & (SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE | SEQOBJECT_FLAG_SET_SOURCE_ON_DONE)) == 0)
                {
                    mainSetBits(def->openGameBit, 1);
                }
            }
        }
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) != 0)
    {
        (*gObjectTriggerInterface)->preempt((int)obj, def->preemptSequenceId);
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, def->sequenceParam);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, 1);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
    else if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0 && mainGetBit(def->openGameBit) == 0)
    {
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
}

void SeqObject_init(GameObject* obj, SeqObjectPlacement* params)
{
    ObjAnimComponent* objAnim;
    SeqObjectState* state;

    objAnim = (ObjAnimComponent*)obj;
    state = obj->extra;
    obj->anim.rotX = (s16)(params->initialYaw << 8);
    obj->animEventCallback = SeqObject_SeqFn;
    *(u8*)&objAnim->bankIndex = params->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjGroup_AddObject((int)obj, SEQOBJECT_OBJGROUP);
    state->flags = 0;
    if (params->openGameBit != -1 && mainGetBit(params->openGameBit) != 0)
    {
        state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        if (params->preemptSequenceId != 0)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_TRIGGER_SEQUENCE);
        }
    }
    state->triggerBitState = 0;
    obj->objectFlags = (u16)(obj->objectFlags | SEQOBJECT_OBJFLAG_HITDETECT_DISABLED);
}
