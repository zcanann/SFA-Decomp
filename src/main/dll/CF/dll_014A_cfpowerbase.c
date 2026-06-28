/*
 * cfpowerbase (DLL 0x14A) - the three CloudRunner Fortress power bases
 * (type game bits 0x54/0x55/0x56, lit game bits 0x51/0x52/0x53). Each
 * base tracks its lit bit into the hitbox-mode prompt bits, relays
 * 0x11000x object messages to the requesting object once its trigger
 * sequence has progressed past 175, and grants game bit 0x4E0 when all
 * three bases are powered. update fires the queued state-change
 * trigger and, when the base is powered and its UI event clears, marks
 * it done and notifies via its type-index sequence.
 */
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/gamebits.h"

typedef struct CfPowerBaseMapData
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 typeBit; /* 0x1E: type game bit (0x54..0x56) */
} CfPowerBaseMapData;

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, typeBit) == 0x1E);

/* pylon beam-report protocol shared with cfmaincrystal (dll_014B): the
   crystal probes each pylon with the matching message; the powered base
   bounces it back at the requester once its trigger sequence has played
   far enough. CFPOWERBASE_MSG_POWERED marks this base lit. */
enum
{
    CFPOWERBASE_MSG_POWERED = 0xA0005,
    CFPOWERBASE_MSG_PYLON_1 = 0x110001,
    CFPOWERBASE_MSG_PYLON_2 = 0x110002,
    CFPOWERBASE_MSG_PYLON_3 = 0x110003
};

/* game bits: one type bit per base (0x54..0x56, also used as the
   placement type id); 0x4E0 is granted once all three are powered. */
enum
{
    GAMEBIT_CFBASE_1 = 0x54,
    GAMEBIT_CFBASE_2 = 0x55,
    GAMEBIT_CFBASE_3 = 0x56,
    GAMEBIT_CF_ALL_BASES = 0x4E0
};

/* trigger-sequence progress past which pylon messages are answered */
#define CFPOWERBASE_SEQ_READY 175

extern int ObjMsg_Pop();
extern int ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_SetActiveModelIndex(int* obj, int idx);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E41D0;

int cfpowerbase_SeqFn(int p1, int unused, ObjAnimUpdateState* animUpdate);
void cfpowerbase_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

int cfpowerbase_SeqFn(int p1, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int ObjMsg_Pop(int, int*, int*, int*);
    CfPowerBaseState* sub = ((GameObject*)p1)->extra;
    u8* animUpdateBytes = (u8*)animUpdate;
    int msgArg;
    int msgType;
    int msgFlag = 0;
    int i;

    while (ObjMsg_Pop(p1, &msgType, &msgArg, &msgFlag) != 0)
    {
        switch (msgType)
        {
        case CFPOWERBASE_MSG_PYLON_1:
            if (sub->typeBit == GAMEBIT_CFBASE_1 && *(s16*)(animUpdateBytes + 0x58) > CFPOWERBASE_SEQ_READY)
            {
                ObjMsg_SendToObject((void*)msgArg, CFPOWERBASE_MSG_PYLON_1, p1, 0);
            }
            break;
        case CFPOWERBASE_MSG_PYLON_2:
            if (sub->typeBit == GAMEBIT_CFBASE_2 && *(s16*)(animUpdateBytes + 0x58) > CFPOWERBASE_SEQ_READY)
            {
                ObjMsg_SendToObject((void*)msgArg, CFPOWERBASE_MSG_PYLON_2, p1, 0);
            }
            break;
        case CFPOWERBASE_MSG_PYLON_3:
            if (sub->typeBit == GAMEBIT_CFBASE_3 && *(s16*)(animUpdateBytes + 0x58) > CFPOWERBASE_SEQ_READY)
            {
                ObjMsg_SendToObject((void*)msgArg, CFPOWERBASE_MSG_PYLON_3, p1, 0);
            }
            break;
        case CFPOWERBASE_MSG_POWERED:
            GameBit_Set(sub->typeBit, 1);
            break;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (GameBit_Get(GAMEBIT_CFBASE_1) != 0 && GameBit_Get(GAMEBIT_CFBASE_2) != 0 && GameBit_Get(GAMEBIT_CFBASE_3) != 0)
            {
                GameBit_Set(GAMEBIT_CF_ALL_BASES, 1);
            }
            break;
        }
    }
    return 0;
}

int cfpowerbase_getExtraSize(void) { return sizeof(CfPowerBaseState); }

int cfpowerbase_getObjectTypeId(void) { return 0x1; }

void cfpowerbase_free(void)
{
}

void cfpowerbase_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E41D0);
}

void cfpowerbase_hitDetect(void)
{
}

/* cfpowerbase_update: track its gamebit's lit state, fire the queued
 * state-change trigger, and when the base is powered and its UI
 * condition clears, mark it done and notify. */
void cfpowerbase_update(int* obj)
{
    CfPowerBaseState* sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(sub->litBit) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        (*gObjectTriggerInterface)->preempt((int)obj, 0xfa);
        (*gObjectTriggerInterface)->runSequence(sub->typeIndex, obj, 3);
        ((GameObject*)obj)->unkF4 = 0;
    }
    if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isEventReady(sub->litBit) != 0)
        {
            ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(
                ((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
            GameBit_Set(sub->litBit, 0);
            GameBit_Set(0x973, 0);
            (*gObjectTriggerInterface)->runSequence(sub->typeIndex, obj, -1);
        }
    }
}

/* cfpowerbase_init: seed header and the sub's type from spawn params,
 * map the type id (0x54..0x56) to a model and gamebit, then gate the
 * active/lit state bits on those gamebits. */
void cfpowerbase_init(int* obj, u8* params)
{
    CfPowerBaseState* sub = ((GameObject*)obj)->extra;
    CfPowerBaseMapData* mapData = (CfPowerBaseMapData*)params;
    s16 type;
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    sub->typeBit = mapData->typeBit;
    type = sub->typeBit;
    switch (type)
    {
    case GAMEBIT_CFBASE_1:
        sub->litBit = 0x51;
        sub->typeIndex = 0;
        break;
    case GAMEBIT_CFBASE_2:
        sub->litBit = 0x52;
        sub->typeIndex = 1;
        Obj_SetActiveModelIndex(obj, 2);
        break;
    case GAMEBIT_CFBASE_3:
        sub->litBit = 0x53;
        sub->typeIndex = 2;
        Obj_SetActiveModelIndex(obj, 1);
        break;
    }
    ((GameObject*)obj)->animEventCallback = cfpowerbase_SeqFn;
    ObjMsg_AllocQueue(obj, 2);
    if (GameBit_Get(sub->litBit) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    if (GameBit_Get(sub->typeBit) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        ((GameObject*)obj)->unkF4 = 1;
    }
}

void cfpowerbase_release(void)
{
}

void cfpowerbase_initialise(void)
{
}
