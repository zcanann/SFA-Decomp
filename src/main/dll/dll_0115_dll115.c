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
#include "main/obj_group.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/dll/dll_0115_dll115.h"


/* object group this object joins while active */
#define DLL115_OBJGROUP 0xf

enum
{
    DLL115_STEP_COUNT = 8,  /* number of indexed step slots */
    DLL115_STEP_IDLE = 8,   /* parked, awaiting nothing */
    DLL115_STEP_FINISH = 9, /* run the preempt + finishing sequence */
    DLL115_STEP_DONE = 10   /* terminal */
};

/* placement+0x39 flag: start parked instances at the finishing step */
#define DLL115_PLACEMENT_FINISH_FLAG 0x10

#define DLL115_OBJFLAG_HIDDEN             0x4000
#define DLL115_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(offsetof(Dll115Placement, setGameBits) == 0x18);
STATIC_ASSERT(offsetof(Dll115Placement, gateGameBits) == 0x28);
STATIC_ASSERT(offsetof(Dll115Placement, rotByte) == 0x38);
STATIC_ASSERT(offsetof(Dll115Placement, preemptArg) == 0x3C);
STATIC_ASSERT(offsetof(Dll115Placement, triggerSeqIds) == 0x40);
STATIC_ASSERT(sizeof(Dll115Placement) == 0x48);
STATIC_ASSERT(sizeof(Dll115State) == 0x2);


/* Sequence-event callback: while a trigger sequence is running on an
 * indexed step, end it once the NEXT step's gate bit (placement+0x28) has
 * gone set and differs from this step's gate bit. Always latches state[1]
 * bit 0 so update advances the step next frame. */
int dll_115_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int step;
    Dll115State* state = obj->extra;
    Dll115Placement* placement = (Dll115Placement*)obj->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (obj->seqIndex == -1)
    {
        return 0;
    }
    step = state->step;
    if (step >= DLL115_STEP_DONE || step < DLL115_STEP_IDLE)
    {
        int next = step + 1;
        if (next < DLL115_STEP_COUNT)
        {
            s16 nextGate = placement->gateGameBits[next];
            if (nextGate != -1 && nextGate != placement->gateGameBits[step])
            {
                if (mainGetBit(nextGate) != 0)
                {
                    (*gObjectTriggerInterface)->endSequence(obj->seqIndex);
                }
            }
        }
    }
    state->flags = (u8)(state->flags | 1);
    return 0;
}

int dll_115_getExtraSize_ret_2(void)
{
    return 0x2;
}
int dll_115_getObjectTypeId(void)
{
    return 0x0;
}

void dll_115_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, DLL115_OBJGROUP);
}

void dll_115_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_115_hitDetect_nop(void)
{
}

void dll_115_update(GameObject* obj)
{
    Dll115State* state;
    Dll115Placement* placement;
    s16* p;
    int step;
    int eventId;

    state = obj->extra;
    placement = (Dll115Placement*)obj->anim.placementData;
    if ((state->flags & 1) != 0)
    {
        eventId = placement->setGameBits[state->step];
        if (eventId != -1)
        {
            mainSetBits(eventId, 1);
        }
        state->flags = (u8)(state->flags & ~1);
        state->step++;
    }
    switch (state->step)
    {
    case DLL115_STEP_FINISH:
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptArg);
        (*gObjectTriggerInterface)
            ->runSequence(placement->finishSeqId, (void*)obj, placement->finishSeqParam);
        break;
    case DLL115_STEP_IDLE:
    case DLL115_STEP_DONE:
        break;
    default:
        eventId = placement->gateGameBits[state->step];
        if (eventId == -1)
        {
            state->step = DLL115_STEP_IDLE;
        }
        else if ((u32)mainGetBit(eventId) != 0)
        {
            s8 id = placement->triggerSeqIds[state->step];
            if (id != -1)
            {
                (*gObjectTriggerInterface)->runSequence(id, (void*)obj, -1);
            }
        }
        break;
    }
    step = state->step - 1;
    p = (s16*)placement + step;
    while (step >= 0)
    {
        eventId = p[12];
        if (eventId == -1)
            break;
        if ((u32)mainGetBit(eventId) != 0)
            break;
        state->step--;
        p--;
        step--;
    }
}

void dll_115_init(GameObject* obj, Dll115Placement* placement)
{
    s16* p;
    Dll115State* state;
    int step;

    state = obj->extra;
    obj->anim.rotX = (s16)(placement->rotByte << 8);
    obj->animEventCallback = dll_115_seqFn;
    obj->objectFlags |= (DLL115_OBJFLAG_HIDDEN | DLL115_OBJFLAG_HITDETECT_DISABLED);
    ObjGroup_AddObject((int)obj, DLL115_OBJGROUP);
    step = 0;
    p = (s16*)placement;
    do
    {
        if (p[12] == -1)
            break;
        if ((u32)mainGetBit(p[12]) == 0)
            break;
        p++;
        step++;
    } while (step < DLL115_STEP_COUNT);
    if ((step < DLL115_STEP_COUNT) && (placement->setGameBits[step] == -1))
    {
        state->step = DLL115_STEP_IDLE;
    }
    else
    {
        state->step = step;
    }
    if ((state->step == DLL115_STEP_IDLE) && ((placement->flags & DLL115_PLACEMENT_FINISH_FLAG) != 0))
    {
        state->step = DLL115_STEP_FINISH;
    }
}

void dll_115_release_nop(void)
{
}

void dll_115_initialise_nop(void)
{
}
