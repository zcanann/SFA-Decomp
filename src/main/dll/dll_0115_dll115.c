/*
 * dll115 - a game-bit driven multi-stage sequence object.
 *
 * Each instance walks a step counter (state[0], 0..10) over three parallel
 * arrays in its placement data, all indexed by the current step:
 *   placement+0x18 : s16 game bits to SET when a step's sequence latches
 *   placement+0x28 : s16 gate game bits that must be set to advance a step
 *   placement+0x40 : s8  trigger-sequence ids to run for a step (-1 = none)
 * Step 8 is the idle/parked state, 9 runs the finishing preempt+sequence
 * (placement->finishSeqId/finishSeqParam/preemptArg), 10 is terminal. init
 * seeks the step to the first ungated entry, optionally jumping to step 9
 * when the placement's finish flag (0x39 & 0x10) is set. update advances on
 * the seqFn latch (state[1] bit 0) and rewinds while earlier set bits
 * (placement+0x18) go false.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objanim_update.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"

/* object group this object joins while active */
#define DLL115_OBJGROUP 0xf
extern f32 lbl_803E37B0;

enum
{
    DLL115_STEP_COUNT = 8,    /* number of indexed step slots */
    DLL115_STEP_IDLE = 8,     /* parked, awaiting nothing */
    DLL115_STEP_FINISH = 9,   /* run the preempt + finishing sequence */
    DLL115_STEP_DONE = 10     /* terminal */
};

/* placement+0x39 flag: start parked instances at the finishing step */
#define DLL115_PLACEMENT_FINISH_FLAG 0x10

#define DLL115_OBJFLAG_HIDDEN 0x4000
#define DLL115_OBJFLAG_HITDETECT_DISABLED 0x2000

void dll_115_hitDetect_nop(void)
{
}

int dll_115_getExtraSize_ret_2(void) { return 0x2; }
int dll_115_getObjectTypeId(void) { return 0x0; }

void dll_115_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E37B0);
}

void dll_115_free(int x) { ObjGroup_RemoveObject(x, DLL115_OBJGROUP); }

/* Sequence-event callback: while a trigger sequence is running on an
 * indexed step, end it once the NEXT step's gate bit (placement+0x28) has
 * gone set and differs from this step's gate bit. Always latches state[1]
 * bit 0 so update advances the step next frame. */
int dll_115_seqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    int step;
    u8* state = ((GameObject*)obj)->extra;
    s16* gateBits = (s16*)((GameObject*)obj)->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    step = state[0];
    if (step >= DLL115_STEP_DONE || step < DLL115_STEP_IDLE)
    {
        int next = step + 1;
        if (next < DLL115_STEP_COUNT)
        {
            s16 nextGate = (gateBits + next)[0x14];
            if (nextGate != -1 && nextGate != (gateBits + step)[0x14])
            {
                if (GameBit_Get(nextGate) != 0)
                {
                    (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
                }
            }
        }
    }
    state[1] = (u8)(state[1] | 1);
    return 0;
}

typedef struct Dll115Placement
{
    u8 pad0[0x38 - 0x0];
    u8 rotByte;        /* 0x38: rotX in 1/256 turns */
    u8 flags;          /* 0x39: DLL115_PLACEMENT_FINISH_FLAG */
    u8 finishSeqId;    /* 0x3A: step-9 trigger sequence id */
    u8 finishSeqParam; /* 0x3B */
    s16 preemptArg;    /* 0x3C */
    u8 pad3E[0x40 - 0x3E];
} Dll115Placement;

void dll_115_update(int obj)
{
    u8* state;
    u8* mapData;
    s16* p;
    int step;
    int eventId;

    state = ((GameObject*)obj)->extra;
    mapData = (u8*)((GameObject*)obj)->anim.placementData;
    if ((state[1] & 1) != 0)
    {
        eventId = ((s16*)(mapData + 0x18))[state[0]];
        if (eventId != -1)
        {
            GameBit_Set(eventId, 1);
        }
        state[1] = (u8)(state[1] & ~1);
        state[0]++;
    }
    switch (state[0])
    {
    case DLL115_STEP_FINISH:
        (*gObjectTriggerInterface)->preempt(obj, ((Dll115Placement*)mapData)->preemptArg);
        (*gObjectTriggerInterface)->runSequence(((Dll115Placement*)mapData)->finishSeqId, (void*)obj,
                                                ((Dll115Placement*)mapData)->finishSeqParam);
        break;
    case DLL115_STEP_IDLE:
    case DLL115_STEP_DONE:
        break;
    default:
        eventId = ((s16*)(mapData + 0x28))[state[0]];
        if (eventId == -1)
        {
            state[0] = DLL115_STEP_IDLE;
        }
        else if ((u32)GameBit_Get(eventId) != 0)
        {
            s8 id = (s8)((u8*)(mapData + 0x40))[state[0]];
            if (id != -1)
            {
                (*gObjectTriggerInterface)->runSequence(id, (void*)obj, -1);
            }
        }
        break;
    }
    step = state[0] - 1;
    p = (s16*)mapData + step;
    while (step >= 0)
    {
        eventId = p[12];
        if (eventId == -1) break;
        if ((u32)GameBit_Get(eventId) != 0) break;
        state[0]--;
        p--;
        step--;
    }
}

void dll_115_init(s16* obj, int mapData)
{
    s16* p;
    u8* state;
    int step;

    state = ((GameObject*)obj)->extra;
    *obj = (s16)(((Dll115Placement*)mapData)->rotByte << 8);
    ((GameObject*)obj)->animEventCallback = dll_115_seqFn;
    ((GameObject*)obj)->objectFlags |= (DLL115_OBJFLAG_HIDDEN | DLL115_OBJFLAG_HITDETECT_DISABLED);
    ObjGroup_AddObject((int)obj, DLL115_OBJGROUP);
    step = 0;
    p = (s16*)mapData;
    do
    {
        if (p[12] == -1) break;
        if ((u32)GameBit_Get(p[12]) == 0) break;
        p++;
        step++;
    }
    while (step < DLL115_STEP_COUNT);
    if ((step < DLL115_STEP_COUNT) && (*(s16*)(mapData + 0x18 + step * 2) == -1))
    {
        state[0] = DLL115_STEP_IDLE;
    }
    else
    {
        state[0] = step;
    }
    if ((state[0] == DLL115_STEP_IDLE) &&
        ((((Dll115Placement*)mapData)->flags & DLL115_PLACEMENT_FINISH_FLAG) != 0))
    {
        state[0] = DLL115_STEP_FINISH;
    }
}

void dll_115_release_nop(void)
{
}

void dll_115_initialise_nop(void)
{
}
