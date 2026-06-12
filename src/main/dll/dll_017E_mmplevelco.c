/* === moved from main/dll/IM/IMspacecraft.c [801A6638-801A6778) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"

/* SDK / engine externs */
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern u32 randomGetRange(int min, int max);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);


extern int ObjHits_GetPriorityHit(int obj, int* outHitObj, int* outB, u32* outC);

extern void doRumble(f32 v);

extern void objRenderFn_8003b8f4(f32 v);
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern int getEnvfxAct(int obj, int player, int id, int p);
extern void MMP_levelcontrol_update(int obj);

extern ObjectTriggerInterface** gObjectTriggerInterface;

extern f32 timeDelta;
extern u8 framesThisStep;

extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;

extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

/* Trivial 4b 0-arg blr leaves. */





void MMP_levelcontrol_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int MMP_levelcontrol_getExtraSize(void) { return 0x0; }
int MMP_levelcontrol_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */

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





#pragma peephole on

#pragma peephole off
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

#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma peephole reset
#pragma peephole reset

#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavaball.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct MmpGyserventPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    u8 unk20;
    u8 pad21[0x28 - 0x21];
} MmpGyserventPlacement;


typedef struct MmpMoonrockPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} MmpMoonrockPlacement;




typedef struct MoonSeedBushPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} MoonSeedBushPlacement;


/*
 * Per-object extra state for the MoonSeedBush plant spot
 * (MoonSeedBush_getExtraSize == 0x2).
 */
typedef struct MoonSeedBushState
{
    u8 seedState; /* gamebit value: 0 unplanted, 2 grown (SeqFn) */
    u8 flags; /* bit 1 = pending update */
} MoonSeedBushState;

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
typedef struct MmpTrenchfxState
{
    s16 enableBit; /* data+0x24 gamebit gate, -1 = always on */
    u16 extentX; /* data[0x1C..0x1E] << 2 random offset half-extents */
    u16 extentZ;
    u16 extentY;
    s16 emitAngles[3]; /* roll/pitch/yaw presets, mirrored to obj+4/2/0 */
    u8 pad0E[2];
    u32 fxUnk10; /* embedded partfx args record (state+0x10 passed to spawn) */
    u32 fxUnk14;
    f32 fxScale;
    f32 fxX;
    f32 fxY;
    f32 fxZ;
    f32 emitCooldown; /* rand(100,200) frames between bursts */
    f32 emitTimer; /* rand(50,100); spawns effect 0x71F while > 0 */
} MmpTrenchfxState;

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
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_8005d0ac();

extern EffectInterface** gPartfxInterface;
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

/*
 * --INFO--
 *
 * Function: MMP_levelcontrol_update
 * EN v1.0 Address: 0x801A6778
 * EN v1.0 Size: 972b
 * EN v1.1 Address: 0x801A6AD0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
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
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801a68b8
 * EN v1.0 Address: 0x801A68B8
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801A6BEC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_801a7874
 * EN v1.0 Address: 0x801A7874
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801A7500
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/* Trivial 4b 0-arg blr leaves. */
void MMP_levelcontrol_release(void)
{
}

void MMP_levelcontrol_initialise(void)
{
}

void MoonSeedBush_free(void);

void MoonSeedBush_hitDetect(void);

void MoonSeedBush_release(void);

void MoonSeedBush_initialise(void);

void mmp_asteroid_re_free(void);

void mmp_asteroid_re_hitDetect(void);

void mmp_asteroid_re_release(void);

void mmp_asteroid_re_initialise(void);

void mmp_moonrock_hitDetect(void);

void mmp_moonrock_release(void);

void mmp_moonrock_initialise(void);

void mmp_trenchfx_hitDetect(void);

void mmp_trenchfx_release(void);

void mmp_trenchfx_initialise(void);

void mmp_gyservent_free(void);

void mmp_gyservent_render(void);

void mmp_gyservent_hitDetect(void);

void mmp_gyservent_release(void);

void mmp_gyservent_initialise(void);

/* 8b "li r3, N; blr" returners. */
int MoonSeedBush_getExtraSize(void);
int MoonSeedBush_getObjectTypeId(void);
int mmp_asteroid_re_getExtraSize(void);
int mmp_asteroid_re_getObjectTypeId(void);
int mmp_moonrock_getExtraSize(void);
int mmp_moonrock_getObjectTypeId(void);
int mmp_trenchfx_getExtraSize(void);
int mmp_trenchfx_getObjectTypeId(void);
int mmp_gyservent_getExtraSize(void);
int mmp_gyservent_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E44D0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E44F8;
#pragma peephole off
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

extern f32 lbl_803E44D4;
extern f32 lbl_803E44D8;

#pragma scheduling off
#pragma peephole off
void MoonSeedBush_update(int obj);
#pragma peephole reset
#pragma scheduling reset

extern int mapGetDirIdx(int);
extern void unlockLevel(int, int, int);
extern f32 lbl_803E44C8;
#pragma scheduling off
#pragma peephole off
void mmp_gyservent_update(int obj);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset
#pragma scheduling reset

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
#pragma peephole reset
#pragma scheduling reset

extern void setDrawLights(int v);
extern f32 lbl_803E44E8;

extern int objPosToMapBlockIdx(double x, double y, double z);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32* out1, int* out2);
extern f32 lbl_803E4554;
extern f32 lbl_803E455C;
extern f32 lbl_803E4560;
extern f32 lbl_803E4564;
extern f32 lbl_803E4568;

#pragma scheduling off
#pragma peephole off
void fn_801A7B10(int obj);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801A6F4C(int obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mmp_asteroid_re_init(int obj);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MoonSeedBush_init(int obj, int data);
#pragma peephole reset
#pragma scheduling reset

extern void saveGame_saveObjectPos(int obj);

extern int objBboxFn_800640cc(int* from, int* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E454C;
extern f32 lbl_803E4550;
extern f32 lbl_803E4558;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801A79E0(int obj);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

void fn_801A80C4(int obj, f32 x, f32 y, f32 z);

/* mmp_trenchfx_free: expgfx interface freeObject callback. */
void mmp_trenchfx_free(int obj);

extern f32 lbl_803E45C0;
#pragma peephole off
void mmp_trenchfx_init(int obj, int data);
#pragma peephole reset

/* ObjGroup_RemoveObject + vtable[4] tail-call. */
extern int* gCarryableInterface;
#pragma scheduling off
void mmp_moonrock_free(int obj);
#pragma scheduling reset

extern f32 lbl_803E457C;
#pragma scheduling off
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
#pragma scheduling reset

extern void vecRotateZXY(void* in, void* out);
extern f32 lbl_803E456C;
extern f32 lbl_803E4570;
extern f32 lbl_803E4574;
extern f32 lbl_803E4578;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801A7CC4(int obj);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_801A80F0(int obj, u8 flag);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mmp_gyservent_init(int obj);

void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset
#pragma scheduling reset

extern void fn_801A7D74(int obj, u8 a, u8 b);

extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, f32*** out, int a, int b);
extern f32 lbl_803E4548;

#pragma scheduling off
#pragma peephole off
int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32* out1, int* out2);
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void mmp_moonrock_init(int obj, int param2);
#pragma peephole reset
#pragma scheduling reset

extern int* ObjList_GetObjects(int* idx, int* count);
extern void setAButtonIcon(int icon);
extern f32 lbl_803E4580;

#pragma scheduling off
#pragma peephole off
void fn_801A7D74(int obj, u8 a, u8 b);
#pragma peephole reset
#pragma scheduling reset

extern char lbl_803AC930[];
extern f32 lbl_803E45B0;
extern f32 lbl_803E45B4;

#pragma scheduling off
#pragma peephole off
void mmp_trenchfx_update(int obj);
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 volume, f32 scale);
extern f32 mathSinf(f32);
extern void doRumble(f32 duration);
extern char lbl_803231D0[];
extern char lbl_803AC900[];
extern int lbl_803DDB30;
extern f32 lbl_803E44FC;
extern f32 lbl_803E4500;
extern f32 lbl_803E4504;
extern f32 lbl_803E4508;
extern f32 lbl_803E450C;
extern f32 lbl_803E4510;
extern f32 lbl_803E4514;
extern f32 lbl_803E4518;
extern f32 lbl_803E451C;
extern f32 lbl_803E4520;
extern f32 lbl_803E4524;
extern f32 lbl_803E4528;
extern f32 lbl_803E452C;
extern f32 lbl_803E4530;
extern f32 lbl_803E4534;
extern f32 lbl_803E4538;
extern f32 lbl_803E453C;

#pragma scheduling off
#pragma peephole off
void mmp_asteroid_re_update(int obj);
#pragma peephole reset
#pragma scheduling reset

extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern void objParticleFn_80099d84(int obj, f32 a, int c, f32 b, int d);
extern u32 playerGetStateFlag310(int player);
extern char lbl_803AC918[];
extern f32 lbl_803E4584;
extern f32 lbl_803E4588;
extern f32 lbl_803E458C;
extern f32 lbl_803E4590;
extern f32 lbl_803E4594;
extern f32 lbl_803E4598;
extern f32 lbl_803E459C;
extern f32 lbl_803E45A0;

#pragma scheduling off
#pragma peephole off
void mmp_moonrock_update(int obj);
#pragma peephole reset
#pragma scheduling reset
