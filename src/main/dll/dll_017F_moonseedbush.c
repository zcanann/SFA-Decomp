/* DLL 0x17F — moon seed bush / MMP asteroid objects [801A6638-801A6778) */
#include "main/dll/mmptrenchfxstate_struct.h"
#include "main/dll/moonseedbushstate_struct.h"

extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32 v);

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
#include "main/objseq.h"

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

extern f32 lbl_803E44D0;
extern f32 lbl_803E44D4;
extern f32 lbl_803E44D8;

undefined4
FUN_801a68b8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    byte eventId;
    undefined4 obj;
    int i;

    obj = FUN_80017a98();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventId = animUpdate->eventIds[i];
        if (eventId == 2)
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , obj, 0x138, 0, param_13, param_14, param_15, param_16);
        }
        else if ((eventId < 2) && (eventId != 0))
        {
            param_1 = FUN_80006728(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                   , obj, 0x13b, 0, param_13, param_14, param_15, param_16);
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
    byte eventId;
    uint randVal;
    int i;
    byte* flags;

    flags = ((GameObject*)param_9)->extra;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventId = animUpdate->eventIds[i];
        if (eventId == 2)
        {
            *flags = *flags & 0xf6;
            *flags = *flags | 0x30;
            ((ObjAnimComponent*)param_9)->bankIndex = 1;
        }
        else if (eventId < 2)
        {
            if (eventId == 0)
            {
                param_1 = FUN_8005d0ac(0);
            }
            else
            {
                *flags = 0xd;
                flags[1] = 1;
                param_1 = GameBit_Set(0x87b, (uint)flags[1]);
                ((GameObject*)param_9)->anim.alpha = 0xff;
            }
        }
        else if (eventId == 4)
        {
            *(float*)(flags + 4) = lbl_803E5180;
            param_1 = FUN_8005d0ac(1);
        }
        else if (eventId < 4)
        {
            *flags = *flags & 0xdf;
            *flags = *flags | 0x50;
            randVal = randomGetRange(10, 0x3c);
            *(float*)(flags + 8) =
                (f32)(s32)(randVal);
            flags[1] = 1;
            param_1 = GameBit_Set(0x87b, (uint)flags[1]);
        }
    }
    *flags = *flags | 0x80;
    FUN_801a7a94(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
    return 0;
}


void MoonSeedBush_free(void)
{
}

void MoonSeedBush_hitDetect(void)
{
}

void MoonSeedBush_release(void)
{
}

void MoonSeedBush_initialise(void)
{
}


int MoonSeedBush_getExtraSize(void) { return 0x2; }
int MoonSeedBush_getObjectTypeId(void) { return 0x0; }

extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E44D0);
}


#pragma scheduling off
void MoonSeedBush_update(int obj)
{
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    int v;
    if ((state->flags & 1) == 0) return;
    if (((MoonSeedBushPlacement*)def)->unk1C != 0 && state->seedState != 0)
    {
        v = *(u8*)(def + 0x20);
        (*gObjectTriggerInterface)->preempt(obj, ((MoonSeedBushPlacement*)def)->unk1C);
    }
    else
    {
        v = -1;
    }
    {
        s32 idx = (s32)(s8) * (u8*)(def + 0x1E);
        if (idx != -1)
        {
            (*gObjectTriggerInterface)->runSequence(idx, (void*)obj, v);
        }
    }
    state->flags &= ~1;
}

int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern undefined4 GameBit_Set(int eventId, int value);
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;
    int j;
    if (state->seedState == 0)
    {
        if (GameBit_Get(((MoonSeedBushPlacement*)def)->unk18) != 0)
        {
            state->seedState = 2;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((s32)animUpdate->eventIds[i])
        {
        case 1:
            state->seedState = 1;
            if (((MoonSeedBushPlacement*)def)->unk1A != -1)
            {
                GameBit_Set(((MoonSeedBushPlacement*)def)->unk1A, 1);
            }
            break;
        case 2:
            (*gPartfxInterface)->spawnObject((void*)obj, 0x70B, NULL, 2, -1, NULL);
            for (j = 0; j < 0x28; j++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x70C, NULL, 2, -1, NULL);
            }
            break;
        }
    }
    return state->seedState != 2;
}

void MoonSeedBush_init(int obj, int data)
{
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    state->flags = 1;
    *(s16*)obj = (s16)((*(u8*)(data + 0x1F)) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)MoonSeedBush_SeqFn;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)(*(u8*)(data + 0x21)) * lbl_803E44D4;
    if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E44D8)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E44D0;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (*(s16*)(data + 0x1a) != -1)
    {
        state->seedState = (u8)GameBit_Get(*(s16*)(data + 0x1a));
    }
    else
    {
        state->seedState = 0;
    }
}
