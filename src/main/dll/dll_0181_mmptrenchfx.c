/* === moved from main/dll/IM/IMspacecraft.c [801A6638-801A6778) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"

/* SDK / engine externs */
extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);






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













void mmp_trenchfx_hitDetect(void)
{
}

void mmp_trenchfx_release(void)
{
}

void mmp_trenchfx_initialise(void)
{
}

void mmp_gyservent_free(void);





/* 8b "li r3, N; blr" returners. */
int mmp_trenchfx_getExtraSize(void) { return 0x30; }
int mmp_trenchfx_getObjectTypeId(void) { return 0x0; }
int mmp_gyservent_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off

#pragma peephole reset


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



#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* mmp_trenchfx_free: expgfx interface freeObject callback. */
void mmp_trenchfx_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

extern f32 lbl_803E45C0;
#pragma peephole off
void mmp_trenchfx_init(int obj, int data)
{
    MmpTrenchfxState* state = ((GameObject*)obj)->extra;
    s16 v;
    state->enableBit = *(s16*)(data + 0x24);
    state->extentX = (u16)((*(u8*)(data + 0x1C)) << 2);
    state->extentZ = (u16)((*(u8*)(data + 0x1D)) << 2);
    state->extentY = (u16)((*(u8*)(data + 0x1E)) << 2);
    v = (s16)(((s32) * (s8*)(data + 0x19)) << 8);
    state->emitAngles[2] = v;
    ((GameObject*)obj)->anim.rotZ = v;
    v = (s16)(((s32) * (s8*)(data + 0x1A)) << 8);
    state->emitAngles[1] = v;
    ((GameObject*)obj)->anim.rotY = v;
    v = (s16)(((s32) * (s8*)(data + 0x1B)) << 8);
    state->emitAngles[0] = v;
    *(s16*)obj = v;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E45C0;
}
#pragma peephole reset

/* ObjGroup_RemoveObject + vtable[4] tail-call. */
extern int* gCarryableInterface;
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

extern void vecRotateZXY(void* in, void* out);

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

void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset
#pragma scheduling reset

extern void fn_801A7D74(int obj, u8 a, u8 b);


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
void fn_801A7D74(int obj, u8 a, u8 b);
#pragma peephole reset
#pragma scheduling reset

extern char lbl_803AC930[];
extern f32 lbl_803E45B0;
extern f32 lbl_803E45B4;

#pragma scheduling off
#pragma peephole off
void mmp_trenchfx_update(int obj)
{
    MmpTrenchfxState* state = ((GameObject*)obj)->extra;
    if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0)
    {
        state->emitCooldown -= timeDelta;
        if (state->emitCooldown < lbl_803E45B0)
        {
            state->fxScale = lbl_803E45B4;
            state->fxX = (f32)(int)
            randomGetRange(-(int)state->extentX, state->extentX);
            state->fxY = (f32)(int)
            randomGetRange(-(int)state->extentY, state->extentY);
            state->fxZ = (f32)(int)
            randomGetRange(-(int)state->extentZ, state->extentZ);
            vecRotateZXY((void*)state->emitAngles, (void*)&state->fxX);
            state->fxX += ((GameObject*)obj)->anim.localPosX;
            state->fxY += ((GameObject*)obj)->anim.localPosY;
            state->fxZ += ((GameObject*)obj)->anim.localPosZ;
            state->emitCooldown = (f32)(int)
            randomGetRange(0x64, 0xC8);
            state->emitTimer = (f32)(int)
            randomGetRange(0x32, 0x64);
        }
        state->emitTimer -= timeDelta;
        if (state->emitTimer > lbl_803E45B0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71F, &state->fxUnk10, 0x200001,
                                             -1, NULL);
        }
        *(f32*)(lbl_803AC930 + 8) = lbl_803E45B4;
        *(f32*)(lbl_803AC930 + 0xC) = (f32)(int)
        randomGetRange(-(int)state->extentX, state->extentX);
        *(f32*)(lbl_803AC930 + 0x10) = (f32)(int)
        randomGetRange(-(int)state->extentY, state->extentY);
        *(f32*)(lbl_803AC930 + 0x14) = (f32)(int)
        randomGetRange(-(int)state->extentZ, state->extentZ);
        vecRotateZXY((void*)state->emitAngles, (void*)(lbl_803AC930 + 0xC));
        *(f32*)(lbl_803AC930 + 0xC) += ((GameObject*)obj)->anim.localPosX;
        *(f32*)(lbl_803AC930 + 0x10) += ((GameObject*)obj)->anim.localPosY;
        *(f32*)(lbl_803AC930 + 0x14) += ((GameObject*)obj)->anim.localPosZ;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x720, lbl_803AC930, 0x200001, -1,
                                         NULL);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 volume, f32 scale);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
