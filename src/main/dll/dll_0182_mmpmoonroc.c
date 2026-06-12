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





void MMP_levelcontrol_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int MMP_levelcontrol_getExtraSize(void);
int MMP_levelcontrol_getObjectTypeId(void);

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */

void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);



void MMP_levelcontrol_free(int obj);





#pragma peephole on

#pragma peephole off
int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

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
void MMP_levelcontrol_update(int obj);
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
void MMP_levelcontrol_release(void);

void MMP_levelcontrol_initialise(void);

void MoonSeedBush_free(void);

void MoonSeedBush_hitDetect(void);

void MoonSeedBush_release(void);

void MoonSeedBush_initialise(void);

void mmp_asteroid_re_free(void);

void mmp_asteroid_re_hitDetect(void);

void mmp_asteroid_re_release(void);

void mmp_asteroid_re_initialise(void);

void mmp_moonrock_hitDetect(void)
{
}

void mmp_moonrock_release(void)
{
}

void mmp_moonrock_initialise(void)
{
}

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
int mmp_moonrock_getExtraSize(void) { return 0x30; }
int mmp_moonrock_getObjectTypeId(void) { return 0x0; }
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
void MMP_levelcontrol_init(int obj);
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
void fn_801A7B10(int obj)
{
    extern undefined4 ObjHits_EnableObject();
    extern undefined4 ObjHits_SetHitVolumeSlot();
    extern int fn_801A78C8(int obj, f32 x, f32 y, f32 z, f32 y2, f32* out1, int* out2);
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    int auStack_14[1];
    f32 local_18;
    int idx;
    f32 v;
    int ret;
    idx = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                              ((GameObject*)obj)->anim.localPosZ);
    if (idx == -1) return;
    ObjHits_SetHitVolumeSlot(obj, 14, 1, 0);
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E455C * timeDelta;
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityX;
        f32 v2;
        if (v1 < lbl_803E4560)
        {
            v2 = lbl_803E4560;
        }
        else if (v1 > lbl_803E4564)
        {
            v2 = lbl_803E4564;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityX = v2;
    }
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityY;
        f32 v2;
        if (v1 < lbl_803E4560)
        {
            v2 = lbl_803E4560;
        }
        else if (v1 > lbl_803E4564)
        {
            v2 = lbl_803E4564;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityY = v2;
    }
    {
        f32 v1 = ((GameObject*)obj)->anim.velocityX;
        f32 v2;
        if (v1 < lbl_803E4560)
        {
            v2 = lbl_803E4560;
        }
        else if (v1 > lbl_803E4564)
        {
            v2 = lbl_803E4564;
        }
        else
        {
            v2 = v1;
        }
        ((GameObject*)obj)->anim.velocityX = v2;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    state->flags &= ~0x80;
    v = ((GameObject*)obj)->anim.localPosY;
    ret = fn_801A78C8(obj, ((GameObject*)obj)->anim.localPosX, v, ((GameObject*)obj)->anim.localPosZ, lbl_803E4568 + v,
                      &local_18, auStack_14);
    if (ret == 0) return;
    if (ret == 2)
    {
        f32 c;
        state->flags |= 0x100;
        c = lbl_803E4554;
        ((GameObject*)obj)->anim.velocityX = c;
        ((GameObject*)obj)->anim.velocityY = c;
        ((GameObject*)obj)->anim.velocityZ = c;
    }
    else
    {
        f32 c;
        state->flags |= 0x180;
        ((GameObject*)obj)->anim.localPosY = local_18;
        c = lbl_803E4554;
        ((GameObject*)obj)->anim.velocityX = c;
        ((GameObject*)obj)->anim.velocityY = c;
        ((GameObject*)obj)->anim.velocityZ = c;
    }
}
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
void fn_801A79E0(int obj)
{
    extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
    int auStack_14[21];
    int local_18;
    MmpMoonrockState * state;
    int ret;
    state = ((GameObject*)obj)->extra;
    ret = ObjHits_GetPriorityHit(obj, &local_18, (int*)0, (int*)0);
    if (ret == 0)
    {
        ret = objBboxFn_800640cc((int*)&((GameObject*)obj)->anim.previousLocalPosX,
                                 (int*)&((GameObject*)obj)->anim.localPosX, lbl_803E454C, 1, auStack_14, obj, 1, -1,
                                 0xff, 0);
    }
    if ((ret != 0) ||
        (((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags != 0 && (state->flags & 0x40)
                != 0) ||
            (state->flags & 0x100) != 0))
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E4550;
        spawnExplosion(obj, lbl_803E4554, 1, 1, 0, 0, 0, 1, 0);
        state->flags |= 0x200;
        state->respawnTimer = lbl_803E4558;
        ((GameObject*)obj)->anim.alpha = 0;
        ((GameObject*)obj)->anim.localPosX = state->homeX;
        ((GameObject*)obj)->anim.localPosY = state->homeY;
        ((GameObject*)obj)->anim.localPosZ = state->homeZ;
        saveGame_saveObjectPos(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

void fn_801A80C4(int obj, f32 x, f32 y, f32 z)
{
    ((GameObject*)obj)->anim.localPosX = x;
    ((GameObject*)obj)->anim.localPosY = y;
    ((GameObject*)obj)->anim.localPosZ = z;
    saveGame_saveObjectPos(obj);
}

/* mmp_trenchfx_free: expgfx interface freeObject callback. */
void mmp_trenchfx_free(int obj);

extern f32 lbl_803E45C0;
#pragma peephole off
void mmp_trenchfx_init(int obj, int data);
#pragma peephole reset

/* ObjGroup_RemoveObject + vtable[4] tail-call. */
extern int* gCarryableInterface;
#pragma scheduling off
void mmp_moonrock_free(int obj)
{
    extern undefined8 ObjGroup_RemoveObject();
    ObjGroup_RemoveObject((uint)obj, 4);
    (*(void (*)(int))(*(int*)(*gCarryableInterface + 0x10)))(obj);
}
#pragma scheduling reset

extern f32 lbl_803E457C;
#pragma scheduling off
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if ((*(int (*)(int, int))(*(int*)(*gCarryableInterface + 0xC)))(obj, (s32)visible) != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (obj, p2, p3, p4, p5, lbl_803E457C);
    }
}
#pragma scheduling reset

extern void vecRotateZXY(void* in, void* out);
extern f32 lbl_803E456C;
extern f32 lbl_803E4570;
extern f32 lbl_803E4574;
extern f32 lbl_803E4578;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801A7CC4(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    struct
    {
        s16 a;
        s16 b;
        s16 c;
        s16 _pad;
        f32 d;
        f32 e;
        f32 f;
        f32 g;
    } stk;
    int* player = (int*)Obj_GetPlayerObject();
    int* playerState = ((GameObject*)player)->extra;
    f32 c1 = lbl_803E4554;
    ((GameObject*)obj)->anim.velocityX = c1;
    ((GameObject*)obj)->anim.velocityY = lbl_803E4570 * *(f32*)((char*)playerState + 0x298) + lbl_803E456C;
    ((GameObject*)obj)->anim.velocityZ = lbl_803E4578 * *(f32*)((char*)playerState + 0x298) + lbl_803E4574;
    stk.e = c1;
    stk.f = c1;
    stk.g = c1;
    stk.d = lbl_803E457C;
    stk.c = 0;
    stk.b = 0;
    stk.a = *(s16*)player;
    vecRotateZXY(&stk, (void*)(obj + 0x24));
    state->flags |= 0x40;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_801A80F0(int obj, u8 flag)
{
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    if (flag != 0)
    {
        state->flags |= 0x4;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
    }
    else
    {
        state->flags &= ~0x4;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
    }
}
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
int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32* out1, int* out2)
{
    f32** results;
    f32* e;
    int i;
    int count;

    count = hitDetectFn_80065e50(obj, x, y, z, &results, 0, 1);
    *out1 = y;
    *out2 = 0;
    for (i = 0; i < count; i++)
    {
        if (*(s8*)((u8*)results[i] + 0x14) != 0xE && y < results[i][0] && (y2 > results[i][0] || i == count - 1))
        {
            *out2 = *(int*)((u8*)results[i] + 0x10);
            *out1 = results[i][0];
            return (results[i][2] < lbl_803E4548) + 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void mmp_moonrock_init(int obj, int param2)
{
    extern undefined4 ObjGroup_AddObject();
    extern undefined4 ObjHits_DisableObject();
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    u8 kind;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
    *(s16*)&state->flags = 0;
    state->kind = (u8)GameBit_Get(*(s16*)(param2 + 0x1a));
    kind = state->kind;
    if (kind != 0)
    {
        if ((u8)(kind - 3) <= 1 || kind == 6)
        {
            state->flags = state->flags | 0x400;
        }
        (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x20))((int)state, 0);
    }
    else
    {
        (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x20))((int)state, 1);
    }
    {
        f32 z = ((GameObject*)obj)->anim.localPosY;
        state->baseY = z;
        state->baseY2 = z;
    }
    (*(int (**)(int, int, int))(*(int*)gCarryableInterface + 0x4))(obj, *(int*)&((GameObject*)obj)->extra, 0x32);
    (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x2c))((int)state, 1);
    ObjGroup_AddObject(obj, 4);
    state->homeX = ((GameObject*)obj)->anim.localPosX;
    state->homeY = ((GameObject*)obj)->anim.localPosY;
    state->homeZ = ((GameObject*)obj)->anim.localPosZ;
    ObjHits_DisableObject(obj);
    fn_801A7D74(obj, 1, 2);
}
#pragma peephole reset
#pragma scheduling reset

extern int* ObjList_GetObjects(int* idx, int* count);
extern void setAButtonIcon(int icon);
extern f32 lbl_803E4580;

#pragma scheduling off
#pragma peephole off
void fn_801A7D74(int obj, u8 a, u8 b)
{
    extern void Sfx_PlayFromObject(int obj, u16 sfxId);
    extern f32 Vec_distance(void* a, void* b);
    extern undefined4 GameBit_Set(int eventId, int value);
    int i;
    int count;
    int* list;
    MmpMoonrockState * state;
    int odef;
    int mydef;
    s8 g1;
    s8 g2;

    state = ((GameObject*)obj)->extra;
    list = ObjList_GetObjects(&i, &count);
    for (; i < count; i++)
    {
        u32 o = (u32)list[i];
        if (o != (u32)obj && *(s16*)(o + 0x46) == 0x518 &&
            Vec_distance((void*)(obj + 0x18), (void*)(o + 0x18)) < lbl_803E4580)
        {
            u32 c;
            odef = *(int*)(list[i] + 0x4C);
            mydef = *(int*)&((GameObject*)obj)->anim.placementData;
            g1 = GameBit_Get(0x88C);
            g2 = GameBit_Get(0x894);
            if (a == 0)
            {
                (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x20))((int)state, 1);
                if (*(s16*)(odef + 0x1E) != -1)
                {
                    GameBit_Set(*(s16*)(odef + 0x1E), 0);
                }
                c = state->kind;
                if (c == 3) goto dec;
                if (c == 4) goto dec;
                if (c == 6)
                {
                dec:
                    g1 -= 1;
                }
                else
                {
                    g2 -= 1;
                }
                if (*(s16*)(mydef + 0x1A) != -1)
                {
                    GameBit_Set(*(s16*)(mydef + 0x1A), 0);
                    state->kind = 0;
                }
                {
                    f32 y = ((GameObject*)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                state->flags &= ~0x400;
                ((GameObject*)obj)->anim.localPosX = state->homeX;
                ((GameObject*)obj)->anim.localPosY = state->homeY;
                ((GameObject*)obj)->anim.localPosZ = state->homeZ;
                saveGame_saveObjectPos(obj);
            }
            else
            {
                (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x20))((int)state, 0);
                if (*(s16*)(odef + 0x1E) != -1)
                {
                    GameBit_Set(*(s16*)(odef + 0x1E), 1);
                }
                if (b == 0)
                {
                    ((GameObject*)obj)->anim.localPosX = *(f32*)(list[i] + 0xC);
                    ((GameObject*)obj)->anim.localPosY = *(f32*)(list[i] + 0x10);
                    ((GameObject*)obj)->anim.localPosZ = *(f32*)(list[i] + 0x14);
                    saveGame_saveObjectPos(obj);
                }
                {
                    f32 y = ((GameObject*)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                if (*(s16*)(mydef + 0x1A) != -1)
                {
                    GameBit_Set(*(s16*)(mydef + 0x1A), *(s16*)(odef + 0x1A));
                    state->kind = *(s16*)(odef + 0x1A);
                }
                c = state->kind;
                if (c == 3) goto held;
                if (c == 4) goto held;
                if (c == 6)
                {
                held:
                    if (b != 2)
                    {
                        g1 = g1 + 1;
                    }
                    if (b == 0)
                    {
                        Sfx_PlayFromObject(0, g1 < 3 ? 0x109 : 0x7E);
                        GameBit_Set(0x9AE, 1);
                    }
                    state->flags |= 0x400;
                    setAButtonIcon(0);
                }
                else if (b != 2)
                {
                    g2 += 1;
                }
            }
            if (g1 >= 3)
            {
                GameBit_Set(0x89B, 1);
            }
            else
            {
                GameBit_Set(0x89B, 0);
            }
            if (g1 > 3)
            {
                g1 = 3;
            }
            else if (g1 < 0)
            {
                g1 = 0;
            }
            if (g2 > 3)
            {
                g2 = 3;
            }
            else if (g2 < 0)
            {
                g2 = 0;
            }
            GameBit_Set(0x88C, g1);
            GameBit_Set(0x894, g2);
        }
    }
}
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
void mmp_moonrock_update(int obj)
{
    extern void Sfx_PlayFromObject(int obj, u16 sfxId);
    extern void* Obj_GetPlayerObject(void);
    extern void* ObjGroup_GetObjects();
    extern undefined4 ObjHits_DisableObject();
    MmpMoonrockState * state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    u8 grabbed;
    int d;
    int count;
    if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                            ((GameObject*)obj)->anim.localPosZ) == -1)
    {
        return;
    }
    if ((state->flags & 4) != 0)
    {
        return;
    }
    if ((state->flags & 0x200) != 0)
    {
        f32 v = state->respawnTimer;
        f32 k = lbl_803E4554;
        if (v > k)
        {
            state->respawnTimer = v - timeDelta;
            if (state->respawnTimer <= k)
            {
                *(s16*)&state->flags = 0;
                ((GameObject*)obj)->anim.alpha = 0xFF;
                ObjHits_DisableObject(obj);
                fn_801A7D74(obj, 1, 1);
            }
            else
            {
                ((GameObject*)obj)->anim.alpha =
                    (u8)(int)(lbl_803E4584 * (lbl_803E457C - state->respawnTimer / lbl_803E4558));
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / lbl_803E4558, 0);
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / lbl_803E4558, 0);
            }
        }
        return;
    }
    objfx_spawnDirectionalBurst(obj, 1, lbl_803E457C, 5, 1, 0xA, lbl_803E454C, 0, 0);
    objfx_spawnDirectionalBurst(obj, 5, lbl_803E457C, 5, 1, 0x14, lbl_803E454C, 0, 0);
    if ((state->flags & 0x40) != 0)
    {
        fn_801A7B10(obj);
        fn_801A79E0(obj);
        return;
    }
    grabbed = 0;
    if ((state->flags & 8) != 0 &&
        (*gMapEventInterface)->getAnimEvent(0x12, 6) == 0)
    {
        state->flags |= 1;
    }
    else if ((state->flags & 0x400) == 0)
    {
        if (((MmpMoonrockPlacement*)def)->unk20 != -1 && GameBit_Get(((MmpMoonrockPlacement*)def)->unk20) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        else if ((*(int (**)(int, int))(*(int*)gCarryableInterface + 0x8))(obj, *(int*)&((GameObject*)obj)->extra) != 0)
        {
            grabbed = 1;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    state->flags &= ~0x8;
    if (grabbed != 0)
    {
        int stateCopy;
        int i;
        int* list;
        u8 found;
        if ((playerGetStateFlag310((int)Obj_GetPlayerObject()) & 0x4000) != 0)
        {
            setAButtonIcon(5);
            state->flags |= 0x18;
            state->flags &= ~0x20;
        }
        else
        {
            setAButtonIcon(4);
            state->flags |= 0x28;
            state->flags &= ~0x10;
        }
        stateCopy = *(int*)&((GameObject*)obj)->extra;
        (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x24))(stateCopy, 0);
        list = (int*)ObjGroup_GetObjects(0x10, &count);
        {
            f32 k = lbl_803E4580;
            for (i = 0; i < count; i++)
            {
                u32 o = (u32) * list;
                if (o != (u32)obj && *(s16*)(o + 0x46) == 0x519 &&
                    Vec_xzDistance((f32*)(obj + 0x18), (f32*)(o + 0x18)) < k)
                {
                    (*(int (**)(int, int))(*(int*)gCarryableInterface + 0x24))(stateCopy, 1);
                    found = 0;
                    goto checked;
                }
                list++;
            }
        }
        found = 1;
    checked:
        if (found != 0)
        {
            state->flags |= 1;
        }
        if ((state->flags & 2) != 0)
        {
            fn_801A7D74(obj, 0, 0);
            state->flags &= ~0x2;
        }
        return;
    }
    {
        u16 flags = state->flags;
        if ((flags & 0x400) == 0 && (flags & 1) != 0)
        {
            if ((flags & 0x20) != 0)
            {
                fn_801A7CC4(obj);
            }
            else
            {
                fn_801A7D74(obj, 1, 0);
            }
            state->flags &= ~0x1;
        }
    }
    state->flags |= 2;
    if (state->kind == 0)
    {
        return;
    }
    if ((state->flags & 0x400) != 0)
    {
        state->raised = GameBit_Get(0x894);
    }
    else
    {
        state->raised = 0;
    }
    Sfx_PlayFromObject(obj, 0x108);
    Sfx_SetObjectChannelVolume(obj, 0x40, state->raised * 0x20 + 0x20, lbl_803E4588);
    {
        f32 speed = ((GameObject*)obj)->anim.velocityY;
        if (speed < lbl_803E458C * ((lbl_803E4568 * (f32)state->raised + state->baseY) - ((GameObject*)obj)->anim.
            localPosY))
        {
            ((GameObject*)obj)->anim.velocityY = speed + lbl_803E4590;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityY = speed - lbl_803E4594;
        }
    }
    state->bobPhase += 0x1000;
    state->rollPhase += 0xDAC;
    state->pitchPhase += 0x800;
    ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4554, ((GameObject*)obj)->anim.velocityY * timeDelta,
                                            lbl_803E4554);
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + mathSinf(
        (lbl_803E4598 * (f32)state->bobPhase) / lbl_803E459C);
    if (((GameObject*)obj)->anim.localPosY < state->baseY)
    {
        ((GameObject*)obj)->anim.localPosY = state->baseY;
    }
    ((GameObject*)obj)->anim.rotZ = (s16)(
        ((GameObject*)obj)->anim.rotZ + (int)(lbl_803E45A0 * mathSinf(
            (lbl_803E4598 * (f32)state->rollPhase) / lbl_803E459C)));
    ((GameObject*)obj)->anim.rotY = (s16)(
        ((GameObject*)obj)->anim.rotY + (int)(lbl_803E45A0 * mathSinf(
            (lbl_803E4598 * (f32)state->pitchPhase) / lbl_803E459C)));
    *(f32*)(lbl_803AC918 + 8) = lbl_803E457C;
    *(f32*)(lbl_803AC918 + 0xC) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(lbl_803AC918 + 0x10) = state->baseY;
    *(f32*)(lbl_803AC918 + 0x14) = ((GameObject*)obj)->anim.localPosZ;
    d = (int)(((GameObject*)obj)->anim.localPosY - state->baseY);
    (*gPartfxInterface)->spawnObject((void*)obj, 0x723, lbl_803AC918, 0x200001, -1, &d);
}
#pragma peephole reset
#pragma scheduling reset
