/* DLL 0x0181 — mmptrenchfx. TU: 0x801A6638–0x801A6778. */
#include "main/dll/mmptrenchfxstate_struct.h"
#include "main/dll/moonseedbushstate_struct.h"

extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);

extern f32 timeDelta;

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* segment pragma-stack balance (re-split): */

#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavaball.h"

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

extern f32 lbl_803E45C0;
extern int* gCarryableInterface;
extern void vecRotateZXY(void* in, void* out);
extern char lbl_803AC930[];
extern f32 lbl_803E45B0;
extern f32 lbl_803E45B4;

undefined4
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

int mmp_trenchfx_getExtraSize(void) { return 0x30; }
int mmp_trenchfx_getObjectTypeId(void) { return 0x0; }
int mmp_gyservent_getExtraSize(void);

void mmp_trenchfx_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

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

void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

#pragma scheduling off
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
