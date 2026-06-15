/* DLL 0x0183 — MMP geyser-vent objects [801A6638-801A6778) */
#include "main/dll/mmptrenchfxstate_struct.h"
#include "main/dll/moonseedbushstate_struct.h"

extern u32 randomGetRange(int min, int max);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32 v);

extern u8 framesThisStep;

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* segment pragma-stack balance (re-split): */

#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavaball.h"

typedef struct MmpGyserventPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    u8 unk20;
    u8 pad21[0x28 - 0x21];
} MmpGyserventPlacement;

/*
 * Per-object extra state for the MoonSeedBush plant spot
 * (MoonSeedBush_getExtraSize == 0x2).
 */

STATIC_ASSERT(sizeof(MoonSeedBushState) == 0x2);

/*
 * Per-object extra state for the mmp asteroid set piece
 * (mmp_asteroid_re_getExtraSize == 0x1C).
 */

STATIC_ASSERT(sizeof(MmpAsteroidReState) == 0x1C);

/*
 * Per-object extra state for the mmp trench fx emitter
 * (mmp_trenchfx_getExtraSize == 0x30).
 */

STATIC_ASSERT(sizeof(MmpTrenchfxState) == 0x30);

/*
 * Per-object extra state for the mmp moonrock carryable
 * (mmp_moonrock_getExtraSize == 0x30). The leading bytes belong to the
 * gCarryableInterface record (the state pointer itself is handed to it).
 */

STATIC_ASSERT(sizeof(MmpMoonrockState) == 0x30);

extern undefined8 FUN_80006728();
extern uint GameBit_Get(int eventId);
extern int FUN_80017a98();
extern undefined4 FUN_8005d0ac();

extern f32 lbl_803E5180;


undefined4
FUN_801a68b8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    byte bVar1;
    undefined4 uVar2;
    int iVar3;

    uVar2 = FUN_80017a98();
    animUpdate->sequenceEventActive = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
    {
        bVar1 = animUpdate->eventIds[iVar3];
        if (bVar1 == 2)
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , uVar2, 0x138, 0, param_13, param_14, param_15, param_16);
        }
        else if ((bVar1 < 2) && (bVar1 != 0))
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , uVar2, 0x13b, 0, param_13, param_14, param_15, param_16);
        }
    }
    FUN_801a6b10(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
    return 0;
}

undefined4
FUN_801a7874(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9,
             undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    extern undefined4 GameBit_Set(int eventId, int value);
    byte bVar1;
    uint uVar2;
    int iVar3;
    byte* pbVar4;

    pbVar4 = ((GameObject*)param_9)->extra;
    animUpdate->sequenceEventActive = 0;
    for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
    {
        bVar1 = animUpdate->eventIds[iVar3];
        if (bVar1 == 2)
        {
            *pbVar4 = *pbVar4 & 0xf6;
            *pbVar4 = *pbVar4 | 0x30;
            ((ObjAnimComponent*)param_9)->bankIndex = 1;
        }
        else if (bVar1 < 2)
        {
            if (bVar1 == 0)
            {
                param_1 = FUN_8005d0ac(0);
            }
            else
            {
                *pbVar4 = 0xd;
                pbVar4[1] = 1;
                param_1 = GameBit_Set(0x87b, (uint)pbVar4[1]);
                ((GameObject*)param_9)->anim.alpha = 0xff;
            }
        }
        else if (bVar1 == 4)
        {
            *(float*)(pbVar4 + 4) = lbl_803E5180;
            param_1 = FUN_8005d0ac(1);
        }
        else if (bVar1 < 4)
        {
            *pbVar4 = *pbVar4 & 0xdf;
            *pbVar4 = *pbVar4 | 0x50;
            uVar2 = randomGetRange(10, 0x3c);
            *(float*)(pbVar4 + 8) =
                (f32)(s32)(uVar2);
            pbVar4[1] = 1;
            param_1 = GameBit_Set(0x87b, (uint)pbVar4[1]);
        }
    }
    *pbVar4 = *pbVar4 | 0x80;
    FUN_801a7a94(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
    return 0;
}


void mmp_gyservent_free(void)
{
}

void mmp_gyservent_render(void)
{
}

void mmp_gyservent_hitDetect(void)
{
}

void mmp_gyservent_release(void)
{
}

void mmp_gyservent_initialise(void)
{
}

int mmp_gyservent_getExtraSize(void) { return 0x0; }
int mmp_gyservent_getObjectTypeId(void) { return 0x0; }

extern void objRenderFn_8003b8f4(f32);

#pragma scheduling off
#pragma peephole off
void mmp_gyservent_update(int obj)
{
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((MmpGyserventPlacement*)def)->unk1E) != 0) return;
    ((GameObject*)obj)->unkF4 -= framesThisStep;
    if (((GameObject*)obj)->unkF4 < 0)
    {
        ((GameObject*)obj)->unkF4 = randomGetRange(0x46, 0xF0);
        ((GameObject*)obj)->unkF8 = randomGetRange(0x1E, 0x3C);
    }
    if (((GameObject*)obj)->unkF8 == 0) return;
    ((GameObject*)obj)->unkF8 -= framesThisStep;
    if (((GameObject*)obj)->unkF8 <= 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
    }
    else
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x724, NULL, 2, -1, NULL);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x450);
    }
}

void mmp_gyservent_init(int obj)
{
    ((GameObject*)obj)->objectFlags |= 0x6000;
    *(u32*)&((GameObject*)obj)->unkF4 = randomGetRange(0xa, 0xc8);
    ((GameObject*)obj)->anim.alpha = 0;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
}

