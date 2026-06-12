/* === moved from main/dll/IM/IMspacecraft.c [801A6638-801A6778) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"

/* SDK / engine externs */
extern u32 randomGetRange(int min, int max);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);



extern void doRumble(f32 v);

extern void objRenderFn_8003b8f4(f32 v);


extern f32 timeDelta;



/* Trivial 4b 0-arg blr leaves. */






/* 8b "li r3, N; blr" returners. */

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */









#pragma peephole on

#pragma peephole off

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
extern undefined4 FUN_8005d0ac();

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E5180;


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






void mmp_asteroid_re_free(void)
{
}

void mmp_asteroid_re_hitDetect(void)
{
}

void mmp_asteroid_re_release(void)
{
}

void mmp_asteroid_re_initialise(void)
{
}

void mmp_moonrock_hitDetect(void);











/* 8b "li r3, N; blr" returners. */
int mmp_asteroid_re_getExtraSize(void) { return 0x1c; }
int mmp_asteroid_re_getObjectTypeId(void) { return 0x0; }
int mmp_moonrock_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E44F8;
#pragma peephole off

void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E44F8);
}
#pragma peephole reset

extern f32 lbl_803E44D4;

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void setDrawLights(int v);
extern f32 lbl_803E44E8;

extern void objMove(int obj, f32 vx, f32 vy, f32 vz);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801A6F4C(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern undefined4 GameBit_Set(int eventId, int value);
    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
    int i;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)animUpdate->eventCount; i++)
    {
        u8 type = animUpdate->eventIds[i];
        switch (type)
        {
        case 0:
            setDrawLights(0);
            break;
        case 1:
            state->eventFlags = 13;
            state->phase = 1;
            GameBit_Set(0x87b, state->phase);
            ((GameObject*)obj)->anim.alpha = 0xff;
            break;
        case 2:
            state->eventFlags = state->eventFlags & ~9;
            state->eventFlags = state->eventFlags | 0x30;
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            break;
        case 3:
            {
                int r;
                state->eventFlags = state->eventFlags & ~0x20;
                state->eventFlags = state->eventFlags | 0x50;
                r = (int)randomGetRange(10, 60);
                state->periodicFxTimer = (f32)r;
                state->phase = 1;
                GameBit_Set(0x87b, state->phase);
                break;
            }
        case 4:
            state->stateTimer = lbl_803E44E8;
            setDrawLights(1);
            break;
        }
    }
    state->eventFlags |= 0x80;
    mmp_asteroid_re_update(obj);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mmp_asteroid_re_init(int obj)
{
    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801A6F4C;
    state->eventFlags = 0;
    state->intensity = (u8)GameBit_Get(0x88C);
    state->phase = (u8)GameBit_Get(0x87B);
    switch ((s32)state->phase)
    {
    case 0:
        ((GameObject*)obj)->anim.alpha = 0;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 0;
        break;
    case 1:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        state->eventFlags |= 0x40;
        break;
    case 2:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        break;
    case 3:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        break;
    }
    {
        f32 v = ((GameObject*)obj)->anim.localPosY;
        state->baseY = v;
        state->baseY2 = v;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MoonSeedBush_init(int obj, int data);
#pragma peephole reset
#pragma scheduling reset



#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* mmp_trenchfx_free: expgfx interface freeObject callback. */

#pragma peephole off
#pragma peephole reset

/* ObjGroup_RemoveObject + vtable[4] tail-call. */
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset


#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset



#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
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
void mmp_asteroid_re_update(int obj)
{
    extern void CameraShake_Start(f32 a, f32 b, f32 c);
    extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
    extern undefined4 GameBit_Set(int eventId, int value);
    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
    if ((state->eventFlags & 0x80) == 0)
    {
        if (GameBit_Get(0xD52) != 0)
        {
            state->intensity = 1;
        }
        else
        {
            state->intensity = GameBit_Get(0x88C);
        }
        state->phase = 2;
        Sfx_KeepAliveLoopedObjectSound(obj, 0x107);
        {
            int vol = state->intensity * 0x20 + 0x20;
            if (vol > 0x7F)
            {
                vol = 0x7F;
            }
            Sfx_SetObjectChannelVolume(obj, 0x40, vol, lbl_803E44FC);
        }
        if (state->intensity != 0)
        {
            f32 speed = ((GameObject*)obj)->anim.velocityY;
            if (speed < lbl_803E4500 * ((state->baseY + *(f32*)(lbl_803231D0 + state->intensity * 4)) - ((GameObject*)
                obj)->anim.localPosY))
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E4504 * timeDelta + speed;
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = -(lbl_803E4508 * timeDelta - speed);
            }
            *(s16*)&state->bobPhase = lbl_803E450C * timeDelta + (f32)state->bobPhase;
            *(s16*)&state->rollPhase = lbl_803E4510 * timeDelta + (f32)state->rollPhase;
            *(s16*)&state->pitchPhase = lbl_803E4514 * timeDelta + (f32)state->pitchPhase;
            ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4518, ((GameObject*)obj)->anim.velocityY * timeDelta,
                                                    lbl_803E4518);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + mathSinf(
                (lbl_803E451C * (f32)state->bobPhase) / lbl_803E4520);
            if (((GameObject*)obj)->anim.localPosY < state->baseY)
            {
                ((GameObject*)obj)->anim.localPosY = state->baseY;
            }
            ((GameObject*)obj)->anim.rotZ = (s16)(
                ((GameObject*)obj)->anim.rotZ + (int)(lbl_803E4524 * mathSinf(
                    (lbl_803E451C * (f32)state->rollPhase) / lbl_803E4520)));
            ((GameObject*)obj)->anim.rotY = (s16)(
                ((GameObject*)obj)->anim.rotY + (int)(lbl_803E4524 * mathSinf(
                    (lbl_803E451C * (f32)state->pitchPhase) / lbl_803E4520)));
            *(f32*)(lbl_803AC900 + 8) = lbl_803E44F8;
            *(f32*)(lbl_803AC900 + 0xC) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)(lbl_803AC900 + 0x10) = state->baseY - lbl_803E4528;
            *(f32*)(lbl_803AC900 + 0x14) = ((GameObject*)obj)->anim.localPosZ;
            lbl_803DDB30 = (int)(((GameObject*)obj)->anim.localPosY - state->baseY);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x722, NULL, 2, -1, &lbl_803DDB30);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x723, lbl_803AC900, 0x200001, -1,
                                             &lbl_803DDB30);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x723, lbl_803AC900, 0x200001, -1,
                                             &lbl_803DDB30);
        }
    }
    if (state->eventFlags != 0)
    {
        if ((state->eventFlags & 1) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 8) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71A, NULL, 2, -1, NULL);
        }
        if ((state->eventFlags & 0x10) != 0)
        {
            int n;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71B, NULL, 1, -1, NULL);
            n = 0x28;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x71C, NULL, 1, -1, NULL);
                n--;
            }
            while (n != 0);
            spawnExplosion(obj, lbl_803E452C, 1, 1, 0, 1, 0, 1, 0);
            CameraShake_Start(lbl_803E4530, lbl_803E4534, lbl_803E4538);
            doRumble(lbl_803E453C);
            state->eventFlags &= ~0x10;
        }
        if ((state->eventFlags & 0x20) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71D, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71D, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 0x40) != 0)
        {
            state->periodicFxTimer -= timeDelta;
            if (state->periodicFxTimer < lbl_803E4518)
            {
                state->periodicFxTimer = (f32)(int)
                randomGetRange(10, 0x3C);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x71E, NULL, 1, -1, NULL);
            }
        }
    }
    {
        f32 v = state->stateTimer;
        f32 k = lbl_803E4518;
        if (v > k)
        {
            state->stateTimer = v - timeDelta;
            if (state->stateTimer <= k)
            {
                GameBit_Set(0x88B, 0);
            }
        }
    }
    state->eventFlags &= ~0x80;
}
#pragma peephole reset
#pragma scheduling reset

extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
