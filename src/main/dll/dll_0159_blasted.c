/*
 * Blasted (DLL 0x159) - CFBlastedRock/Wall/Tunnel + DRBlastedWall targets.
 * TU = 0x801A27B8..0x801A2BDC (helper fn_801A27B8 + blasted_*).
 */
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/map_block.h"
extern f32 lbl_803E4348;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int i);
extern u8* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern u8* fn_8006070C(void* block, int idx);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int lbl_803DDB18;
extern void objSetSlot(int* obj, int slot);

#define BLASTED_GAMEBIT_DAMAGE_BASE 0x2de /* base of per-damage-step progress GameBit array */

int blasted_getExtraSize(void)
{
    return 0x14;
}

int blasted_getObjectTypeId(void)
{
    return 0;
}

void blasted_free(void)
{
}

void blasted_hitDetect(void)
{
}

void blasted_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = ((GameObject*)obj)->extra;
    if (visible != 0 && state[3] == 0)
    {
        objRenderFn_8003b8f4((int)obj, p2, p3, p4, p5, lbl_803E4348);
    }
}

/* EN v1.0 0x801A27B8  size: 280b  Flags every trigger/volume in the map
 * block under the object that carries the given event id: sets bits 0..1
 * on matching block entries and bit 1 on matching group records. Returns 0
 * when the block is missing or not trigger-enabled. */
#pragma dont_inline on
int fn_801A27B8(int obj, int id)
{
    MapBlockData* block;

    block = mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                            ((GameObject*)obj)->anim.localPosZ));
    if (block == NULL || (block->unk4 & 0x8) == 0)
    {
        return 0;
    }
    {
        int j;
        int i;
        for (i = 0; i < block->unk9A; i++)
        {
            u8* e = mapBlockFn_800606ec(block, i);
            if (id == mapBlockFn_80060678(e))
            {
                *(int*)(e + 0x10) |= 3;
            }
        }
        for (j = 0; j < block->unkA2; j++)
        {
            u8* g = fn_8006070C(block, j);
            u8* p;
            int k;
            k = 0;
            p = g;
            for (; k < *(u8*)(g + 0x41); k++)
            {
                if (*(u8*)(p + 0x29) == id)
                {
                    *(int*)(g + 0x3c) |= 2;
                }
                p += 8;
            }
        }
    }
    return 1;
}
#pragma dont_inline reset

typedef struct BlastedTargetSetup
{
    u8 pad00[0x1A];
    s16 pieceCount;
    s16 triggerId;
    s16 completedGameBit;
    s16 progressGameBit;
} BlastedTargetSetup;

typedef struct BlastedTargetState
{
    u32 destroyedHitObjects[3];
    int triggerFired;
    u8 pad10;
    u8 damageStep;
    u8 pad12[2];
} BlastedTargetState;

STATIC_ASSERT(offsetof(BlastedTargetSetup, pieceCount) == 0x1A);
STATIC_ASSERT(offsetof(BlastedTargetSetup, triggerId) == 0x1C);
STATIC_ASSERT(offsetof(BlastedTargetSetup, completedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BlastedTargetSetup, progressGameBit) == 0x20);
STATIC_ASSERT(offsetof(BlastedTargetState, triggerFired) == 0x0C);
STATIC_ASSERT(offsetof(BlastedTargetState, damageStep) == 0x11);
STATIC_ASSERT(sizeof(BlastedTargetState) == 0x14);

/* EN v1.0 0x801A2928  size: 464b  Blasted-target update: once the target's
 * GameBit is latched, fires the map trigger; otherwise scans the model's
 * hit nodes for newly-destroyed (state 5) pieces, records each unique piece,
 * advances the damage model index, and on the final piece latches the
 * GameBit, fires the trigger, and swaps to the destroyed model. */
#pragma opt_loop_invariants off
void blasted_update(int obj)
{
    int i;
    BlastedTargetSetup* setup = (BlastedTargetSetup*)((GameObject*)obj)->anim.placementData;
    BlastedTargetState* state = ((GameObject*)obj)->extra;
    s16 total = setup->pieceCount;

    if (state->triggerFired != 0)
    {
        return;
    }
    if ((u32)GameBit_Get(setup->completedGameBit) != 0)
    {
        state->triggerFired = fn_801A27B8(obj, setup->triggerId);
        return;
    }
    {
        for (i = 0; i < ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->priorityHitCount; i++)
        {
            int cnt;
            u32 v;
            int m;
            int found;
            m = *(s8*)((int)((GameObject*)obj)->anim.hitReactState + i + 117);
            v = ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitObjects[i];
            found = 0;
            if (m != 5)
            {
                continue;
            }
            if (total == 0)
            {
                GameBit_Set(setup->completedGameBit, 1);
                return;
            }
            if (m == 5)
            {
                int k = 0;
                cnt = state->damageStep;
                while (k != cnt)
                {
                    if (v == state->destroyedHitObjects[k++])
                    {
                        k = cnt;
                        found = 1;
                    }
                }
            }
            if (found == 0)
            {
                state->destroyedHitObjects[state->damageStep] = v;
                GameBit_Set(state->damageStep + BLASTED_GAMEBIT_DAMAGE_BASE, 0);
                GameBit_Set(state->damageStep + (BLASTED_GAMEBIT_DAMAGE_BASE + 1), 1);
                if (setup->progressGameBit != -1)
                {
                    GameBit_Set(setup->progressGameBit, state->damageStep + 1);
                }
                lbl_803DDB18 = 0x12c;
                if (state->damageStep + 1 > total)
                {
                    int n;
                    for (n = 0; n < total + 1; n++)
                    {
                        GameBit_Set(n + BLASTED_GAMEBIT_DAMAGE_BASE, 0);
                    }
                    GameBit_Set(setup->completedGameBit, 1);
                    fn_801A27B8(obj, setup->triggerId);
                    Obj_SetActiveModelIndex(obj, 2);
                    state->triggerFired = 1;
                }
                else
                {
                    state->damageStep++;
                    Obj_SetActiveModelIndex(obj, state->damageStep);
                }
            }
        }
    }
}
#pragma opt_loop_invariants reset

/* Tail of the TU (0x801A2AF8..0x801A2BDC) - formerly the head of
 * gasventControl.c. */

typedef struct BlastedState
{
    u8 pad0[0x10 - 0x0];
    u8 pieceCount;
    u8 gameBitLatchState;
    u8 pad12[0x6E4 - 0x12];
    u8 unk6E4;
    u8 pad6E5[0x6E8 - 0x6E5];
} BlastedState;

void blasted_init(int obj, int placement)
{
    BlastedTargetSetup* setup = (BlastedTargetSetup*)placement;
    int* state = ((GameObject*)obj)->extra;
    int* targ;
    s16 gbid;
    u8 v;

    state[0xc / 4] = 0;
    objSetSlot((int*)obj, 0x51);
    targ = *(int**)&((GameObject*)obj)->anim.hitReactState;
    ((ObjHitsPriorityState*)targ)->flags = (s16)(((ObjHitsPriorityState*)targ)->flags | 1);
    ((BlastedState*)state)->pieceCount = (u8)setup->pieceCount;
    gbid = setup->progressGameBit;
    if (gbid != -1)
    {
        v = GameBit_Get(gbid);
        ((BlastedState*)state)->gameBitLatchState = v;
        if (v != 0)
        {
            Obj_SetActiveModelIndex(obj, (int)((BlastedState*)state)->gameBitLatchState);
        }
    }
    GameBit_Set(BLASTED_GAMEBIT_DAMAGE_BASE, 1);
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(placement + 0x18) << 8);
    if ((u32)GameBit_Get(setup->completedGameBit) != 0)
    {
        state[0xc / 4] = fn_801A27B8(obj, (int)setup->triggerId);
    }
}

void blasted_release(void)
{
}

void blasted_initialise(void)
{
}
