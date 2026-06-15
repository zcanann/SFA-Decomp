/* DLL 0x17E - MMPLevelControl [801A6638-801A6778) */
#include "main/dll/mmptrenchfxstate_struct.h"
#include "main/dll/moonseedbushstate_struct.h"
#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavaball.h"

extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32 v);
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern int getEnvfxAct(int obj, int player, int id, int p);

extern f32 timeDelta;

extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;

extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

STATIC_ASSERT(sizeof(MoonSeedBushState) == 0x2);
STATIC_ASSERT(sizeof(MmpAsteroidReState) == 0x1C);
STATIC_ASSERT(sizeof(MmpTrenchfxState) == 0x30);
STATIC_ASSERT(sizeof(MmpMoonrockState) == 0x30);
extern undefined8 FUN_80006728();
extern uint GameBit_Get(int eventId);
extern int FUN_80017a98();
extern undefined4 FUN_8005d0ac();
extern f32 lbl_803E5180;
extern void gameTextShow(int textId);
extern void envFxActFn_800887f8(int value);
extern void skyFn_80088c94(int flags, int mode);
extern int getEnvfxActImmediately(int obj, int target, int actId, int flags);
extern int getEnvfxAct(int obj, int target, int actId, int flags);
extern int coordsToMapCell(f32 x, f32 z);
extern void Music_Trigger(int id, int mode);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int setBit, int textId);
extern void objRenderFn_8003b8f4(f32);
extern int mapGetDirIdx(int);
extern void unlockLevel(int, int, int);
extern f32 lbl_803E44C8;

void MMP_levelcontrol_hitDetect(void)
{
}

int MMP_levelcontrol_getExtraSize(void) { return 0x0; }
int MMP_levelcontrol_getObjectTypeId(void) { return 0x0; }

void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E44C4);
}

void MMP_levelcontrol_free(int obj)
{
    lbl_803DDB28 = lbl_803E44C0;
    lbl_803DDB2C = 0;
    Music_Trigger(0xd5, 0);
}

int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int Obj_GetPlayerObject(void);
    int player;
    int i;

    player = Obj_GetPlayerObject();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            getEnvfxAct(obj, player, 315, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, 312, 0);
            break;
        }
    }
    MMP_levelcontrol_update(obj);
    return 0;
}

/* segment pragma-stack balance (re-split): */

/*
 * Per-object extra state for the MoonSeedBush plant spot
 * (MoonSeedBush_getExtraSize == 0x2).
 */

/*
 * Per-object extra state for the mmp asteroid set piece
 * (mmp_asteroid_re_getExtraSize == 0x1C).
 */

/*
 * Per-object extra state for the mmp trench fx emitter
 * (mmp_trenchfx_getExtraSize == 0x30).
 */

/*
 * Per-object extra state for the mmp moonrock carryable
 * (mmp_moonrock_getExtraSize == 0x30). The leading bytes belong to the
 * gCarryableInterface record (the state pointer itself is handed to it).
 */

#pragma peephole on
void MMP_levelcontrol_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    int playerForMap;
    int playerForFx;

    playerForMap = (int)Obj_GetPlayerObject();
    playerForFx = (int)Obj_GetPlayerObject();

    if (lbl_803DDB28 > lbl_803E44C0)
    {
        gameTextShow(0x34f);
        {
            f32 t = lbl_803DDB28 - timeDelta;
            lbl_803DDB28 = t;
            if (t < lbl_803E44C0)
            {
                lbl_803DDB28 = lbl_803E44C0;
            }
        }
    }

    if (((GameObject*)obj)->unkF4 != 0)
    {
        envFxActFn_800887f8(0);
        if (GameBit_Get(0xd47) != 0)
        {
            skyFn_80088c94(7, 1);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x234, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x235, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x234, 0);
                getEnvfxAct(obj, playerForFx, 0x235, 0);
            }
            ((GameObject*)obj)->unkF8 = 0;
        }
        else if (GameBit_Get(0xf33) != 0)
        {
            skyFn_80088c94(7, 1);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x10c, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x10d, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x10c, 0);
                getEnvfxAct(obj, playerForFx, 0x10d, 0);
            }
            ((GameObject*)obj)->unkF8 = 1;
        }
        else if (coordsToMapCell(*(f32*)(playerForMap + 0xc), *(f32*)(playerForMap + 0x14)) == 0x12)
        {
            skyFn_80088c94(7, 0);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x138, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x139, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x138, 0);
                getEnvfxAct(obj, playerForFx, 0x139, 0);
            }
            ((GameObject*)obj)->unkF8 = 0;
        }
        Music_Trigger(0x31, 1);
        ((GameObject*)obj)->unkF4 = 0;
    }

    if (((GameObject*)obj)->unkF8 != 0 && GameBit_Get(0xf33) == 0)
    {
        skyFn_80088c94(7, 0);
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x138, 0);
        getEnvfxAct(obj, playerForFx, 0x139, 0);
        ((GameObject*)obj)->unkF8 = 0;
    }
    else if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get(0xf33) != 0)
    {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x10c, 0);
        getEnvfxAct(obj, playerForFx, 0x10d, 0);
        ((GameObject*)obj)->unkF8 = 1;
    }

    SCGameBitLatch_Update(&lbl_803DDB2C, 1, -1, -1, 0x389, 0xd5);
    SCGameBitLatch_Update(&lbl_803DDB2C, 2, -1, -1, 0xcbb, 0xc4);
}

undefined4
#pragma scheduling on
FUN_801a68b8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    byte eventType;
    undefined4 fxHandle;
    int i;

    fxHandle = FUN_80017a98();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventType = animUpdate->eventIds[i];
        if (eventType == 2)
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , fxHandle, 0x138, 0, param_13, param_14, param_15, param_16);
        }
        else if ((eventType < 2) && (eventType != 0))
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , fxHandle, 0x13b, 0, param_13, param_14, param_15, param_16);
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
    byte eventType;
    uint rnd;
    int i;
    byte* state;

    state = ((GameObject*)param_9)->extra;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventType = animUpdate->eventIds[i];
        if (eventType == 2)
        {
            *state = *state & 0xf6;
            *state = *state | 0x30;
            ((ObjAnimComponent*)param_9)->bankIndex = 1;
        }
        else if (eventType < 2)
        {
            if (eventType == 0)
            {
                param_1 = FUN_8005d0ac(0);
            }
            else
            {
                *state = 0xd;
                state[1] = 1;
                param_1 = GameBit_Set(0x87b, (uint)state[1]);
                ((GameObject*)param_9)->anim.alpha = 0xff;
            }
        }
        else if (eventType == 4)
        {
            *(float*)(state + 4) = lbl_803E5180;
            param_1 = FUN_8005d0ac(1);
        }
        else if (eventType < 4)
        {
            *state = *state & 0xdf;
            *state = *state | 0x50;
            rnd = randomGetRange(10, 0x3c);
            *(float*)(state + 8) =
                (f32)(s32)(rnd);
            state[1] = 1;
            param_1 = GameBit_Set(0x87b, (uint)state[1]);
        }
    }
    *state = *state | 0x80;
    FUN_801a7a94(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
    return 0;
}

void MMP_levelcontrol_release(void)
{
}

void MMP_levelcontrol_initialise(void)
{
}


#pragma scheduling off
#pragma peephole off
void MMP_levelcontrol_init(int obj)
{
    extern undefined4 GameBit_Set(int eventId, int value);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    *(u32*)&((GameObject*)obj)->unkF8 = GameBit_Get(0xF33);
    ((GameObject*)obj)->animEventCallback = (void*)MMP_LevelControl_SeqFn;
    unlockLevel(mapGetDirIdx(0x12), 0, 0);
    lbl_803DDB28 = lbl_803E44C8;
    lbl_803DDB2C = 0;
    Music_Trigger(0xCC, 0);
    Music_Trigger(0xDB, 0);
    Music_Trigger(0xF2, 0);
    Music_Trigger(0xCE, 0);
    Music_Trigger(0xC2, 0);
    GameBit_Set(0xDCF, 0);
}
