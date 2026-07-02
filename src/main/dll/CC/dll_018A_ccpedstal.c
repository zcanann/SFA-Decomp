/*
 * ccpedstal - Crystal Caves pedestal gate (DLL 0x018A). A pedestal whose
 * placement def-id selects one of two think routines, stored as a function
 * pointer in the extra block and dispatched each update. Both routines drive
 * the object's model index and active-hitbox bit from a gameBit and an
 * ObjTrigger, latching a one-shot "mark" that ccpedstal_update commits back
 * to the gameBit on the following frame.
 */
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/DR/dll_80209FE0_shared.h"

#define CCPEDSTAL_OBJFLAG_HIDDEN 0x4000
void ccpedstal_updateGameBitGate(int obj, u8* state2);
void ccpedstal_updateAltVariant(int obj, u8* state2);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int gameBitDecrement(int bit);
extern int gameBitIncrement(int bit);

/* placement def-ids that pick the pedestal's think routine */
enum
{
    PEDSTAL_DEF_ALT = 0x45f1a,
    PEDSTAL_DEF_GATE_A = 0x45f1b,
    PEDSTAL_DEF_GATE_B = 0x45f1c
};

/* ccpedstal extra block (extraSize 0x8): a think fn-pointer at +0, an
 * s16 GameBit id at +4, and a one-shot flag byte at +6 toggled by the
 * think routines and consumed by ccpedstal_update. */
typedef struct CcpedstalState
{
    void* think;
    s16 gameBit;
    u8 markFlags;
    u8 unk7;
} CcpedstalState;

STATIC_ASSERT(offsetof(CcpedstalState, gameBit) == 0x4);
STATIC_ASSERT(offsetof(CcpedstalState, markFlags) == 0x6);
STATIC_ASSERT(sizeof(CcpedstalState) == 0x8);

#pragma scheduling on
#pragma peephole on
int ccpedstal_getExtraSize(void) { return sizeof(CcpedstalState); }

#pragma scheduling off
#pragma peephole off
void ccpedstal_init(int* obj, u8* params)
{
    CcpedstalState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((u32)params[0x1a] << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | CCPEDSTAL_OBJFLAG_HIDDEN);
    switch (*(int*)(params + 0x14))
    {
    case PEDSTAL_DEF_ALT:
        state->think = ccpedstal_updateAltVariant;
        state->gameBit = 0xaa;
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
        break;
    case PEDSTAL_DEF_GATE_A:
        state->think = ccpedstal_updateGameBitGate;
        state->gameBit = 0xf1;
        break;
    case PEDSTAL_DEF_GATE_B:
        state->think = ccpedstal_updateGameBitGate;
        state->gameBit = 0xfe;
        break;
    }
}

/* If the pedestal's gameBit is set, lights the model (index 1, hitbox bit 8).
 * Otherwise shows model 0 and, while gameBit 0xA9 is set and the object's
 * 0xA9 trigger fires, runs sequence 0, decrements 0xA9 and marks the one-shot;
 * with 0xA9 clear it instead raises the obj's 0x10 hitbox bit. */
void ccpedstal_updateGameBitGate(int obj, u8* state2)
{
    CcpedstalState* state = (CcpedstalState*)state2;
    if (GameBit_Get(state->gameBit) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        Obj_SetActiveModelIndex(obj, 1);
    }
    else
    {
        int doMark;
        Obj_SetActiveModelIndex(obj, 0);
        if (GameBit_Get(0xa9) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
            if (ObjTrigger_IsSetById(obj, 0xa9) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                gameBitDecrement(0xa9);
                doMark = 1;
                goto check;
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED);
        }
        doMark = 0;
    check:
        if (doMark != 0)
        {
            state->markFlags = (u8)(state->markFlags | 1);
        }
    }
}

/* Alt-variant think routine. Mirrors the gate bit (8) from gameBit 0xDC5,
 * then on the pedestal's own gameBit: set -> model 0; clear -> model 1 and,
 * when the pending trigger asserts, runs sequence 1, increments 0xA9 and
 * marks the one-shot. */
void ccpedstal_updateAltVariant(int obj, u8* state2)
{
    CcpedstalState* state = (CcpedstalState*)state2;
    if (GameBit_Get(0xdc5) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
    }
    if (GameBit_Get(state->gameBit) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        Obj_SetActiveModelIndex(obj, 0);
    }
    else
    {
        int doMark;
        Obj_SetActiveModelIndex(obj, 1);
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            gameBitIncrement(0xa9);
            doMark = 1;
            goto check;
        }
        doMark = 0;
    check:
        if (doMark != 0)
        {
            state->markFlags = (u8)(state->markFlags | 1);
        }
    }
}

void ccpedstal_update(int obj)
{
    CcpedstalState* state = ((GameObject*)obj)->extra;
    if (state->markFlags != 0)
    {
        if (state->markFlags & 1)
        {
            GameBit_Set(state->gameBit, 1);
        }
        else
        {
            GameBit_Set(state->gameBit, 0);
        }
        state->markFlags = 0;
        if (GameBit_Get(0xdf0) == 0 && GameBit_Get(0xaa) != 0)
        {
            GameBit_Set(0xdf0, 1);
        }
    }
    (*(void (*)(int, int))state->think)(obj, (int)state);
}
