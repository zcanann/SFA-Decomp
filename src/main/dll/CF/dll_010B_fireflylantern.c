/*
 * FireFlyLantern (DLL 0x10B). Re-split (descriptor forensics,
 * docs/boundary_audit.md): TU = 0x801871C8..0x80187640, previously cut at
 * 0x80187524 across CFcrystal.c | CFBaby.c (init was CFBaby's first fn).
 * FireFlyLantern_spawnFireFly is placed LAST so it cannot be auto-inlined
 * into init (extern bl before the re-split).
 */
#include "main/dll/CF/CFcrystal.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern undefined4 FUN_800068c4();
extern double FUN_80006a38();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017680();
extern undefined4 FUN_80017688();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int Obj_GetPlayerObject(void);
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern void ObjGroup_AddObject(int obj, int group);
extern void Obj_FreeObject(int obj);
extern void gameBitDecrement(int eventId);
extern void GameBit_Set(int eventId, int value);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80061a80();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de758;
extern f64 DOUBLE_803e4748;
extern f32 FLOAT_803dca40;
extern f32 timeDelta;
extern f32 FLOAT_803e4724;
extern f32 FLOAT_803e4728;
extern f32 FLOAT_803e4730;
extern f32 FLOAT_803e4734;
extern f32 FLOAT_803e4738;
extern f32 FLOAT_803e473c;
extern f32 FLOAT_803e4740;
extern f32 FLOAT_803e4750;
extern f32 FLOAT_803e4754;
extern f32 FLOAT_803e4758;
extern f32 FLOAT_803e475c;
extern f32 FLOAT_803e4760;
extern f32 FLOAT_803e476c;
extern f32 lbl_803E3AA0;
extern f32 lbl_803E3A98;
extern f32 lbl_803E3A9C;
extern f32 lbl_803E3AA8;
extern f64 lbl_803E3AB0;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern f32 lbl_803E3AC8;
extern f32 lbl_803E3ACC;
extern f32 lbl_803E3AD0;
extern f32 lbl_803E3AD4;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3AD8;
extern f32 lbl_803E3ADC;
extern f32 lbl_803E3AE0;
extern f32 lbl_803E3AEC;
extern f32 lbl_803DBDD8;
extern u8 framesThisStep;
extern u8 lbl_803DDAD8;
extern EffectInterface** gPartfxInterface;
extern f32 Curve_EvalBSpline(f32* control, f32 t, f32* out);
extern f32 Vec_distance(void* a, void* b);
extern int objCreateLight(int obj, int type);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(int light, int value);
extern void modelLightStruct_setAffectsAabbLightSelection(int light, int value);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern f32 sqrtf(f32 value);
extern f32 mathSinf(f32 value);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
int FireFlyLantern_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FireFlyLanternState* state;
    void* child;
    int i;

    state = ((GameObject*)obj)->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (state->fireflyCount != 0)
            {
                child = (void*)state->fireflies[state->fireflyCount - 1];
                if (child != 0)
                {
                    (*(void (*)(void*))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x24)))(child);
                }
                --state->fireflyCount;
                --state->remainingCount;
                GameBit_Set(state->gameBit, state->remainingCount);
            }
            break;
        }
        i++;
    }

    ((FireFlyLanternStateFlags*)&state->flags)->finished = 1;
    i = 0;
    while (i < state->fireflyCount)
    {
        child = (void*)state->fireflies[i];
        (*(void (*)(void*, f32, f32, f32))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x28)))(
            child, ((GameObject*)obj)->anim.localPosX, 5.0f + ((GameObject*)obj)->anim.localPosY,
            ((GameObject*)obj)->anim.localPosZ);
        i++;
    }

    return 0;
}

/* 8b "li r3, N; blr" returners. */
/* 8b "li r3, N; blr" returners. */
int FireFlyLantern_getExtraSize(void) { return 0x24; }
int FireFlyLantern_getObjectTypeId(void) { return 0x8; }

extern void* getTrickyObject(void);
extern void trickyImpress(void* trickyObj);

void FireFlyLantern_free(int obj)
{
    void* tricky = getTrickyObject();
    if (tricky != NULL)
    {
        trickyImpress(tricky);
    }
    ObjGroup_RemoveObject(obj, 15);
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3AF0;
void FireFlyLantern_render(void) { objRenderFn_8003b8f4(lbl_803E3AF0); }

void FireFlyLantern_update(int obj)
{
    int* slot;
    FireFlyLanternState* state;
    FireFlyLanternSpawnSetup* def;
    void* child;
    int i;
    int shouldFree;

    state = ((GameObject*)obj)->extra;
    def = *(FireFlyLanternSpawnSetup**)&((GameObject*)obj)->anim.placementData;
    shouldFree = 0;

    if ((s8)def->field19 == 1)
    {
        if (state->fireflyCount != 0)
        {
            child = (void*)state->fireflies[0];
            if (child != 0)
            {
                (*(void (*)(void*))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x24)))(child);
            }
            gameBitDecrement(state->gameBit);
        }
        shouldFree = 1;
    }
    else if (((FireFlyLanternStateFlags*)&state->flags)->finished != 0)
    {
        i = 0;
        slot = state->fireflies;
        while (i < state->fireflyCount)
        {
            Obj_FreeObject(*slot);
            slot++;
            i++;
        }
        shouldFree = 1;
    }

    if (shouldFree != 0)
    {
        Obj_FreeObject(obj);
    }
}

/*
 * --INFO--
 *
 * Function: FireFlyLantern_init
 * EN v1.0 Address: 0x80187524
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80187608
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FireFlyLantern_init(int obj, int def)
{
    void* player;
    u8* childSlot;
    u8* state;
    int i;
    u32 childCount;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)FireFlyLantern_SeqFn;
    player = (void*)Obj_GetPlayerObject();
    if (((GameObject*)player)->anim.seqId != 0)
    {
        *(s16*)(state + 0x20) = 0x13d;
    }
    else
    {
        *(s16*)(state + 0x20) = 0x5d6;
    }

    *(u8*)(state + 0x1c) = 0;
    *(u8*)(state + 0x1d) = GameBit_Get(*(s16*)(state + 0x20));

    if (*(s8*)(def + 0x19) == 1)
    {
        if (*(u8*)(state + 0x1d) != 0)
        {
            *(u8*)(state + 0x1c) = 1;
            *(int*)state = FireFlyLantern_spawnFireFly((int*)obj);
        }
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        *(u8*)(state + 0x1c) = (*(u8*)(state + 0x1d) < 6) ? *(u8*)(state + 0x1d) : 6;

        i = 0;
        childSlot = state;
        while (i < *(u8*)(state + 0x1c))
        {
            *(int*)childSlot = FireFlyLantern_spawnFireFly((int*)obj);
            childSlot += 4;
            i++;
        }
    }
}

/* Placed last (anti-inline; the init caller above used an extern bl). */
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int loadObjectAtObject(int* obj, void* setup);
extern f32 lbl_803E3AE8;

int FireFlyLantern_spawnFireFly(int* obj)
{
    FireFlyLanternSpawnSetup* setup;
    if (Obj_IsLoadingLocked() == 0) return 0;
    setup = (FireFlyLanternSpawnSetup*)Obj_AllocObjectSetup(sizeof(FireFlyLanternSpawnSetup), 1084);
    setup->objectType = 1084;
    setup->setupType = 9;
    setup->field04 = 2;
    setup->field06 = 0xff;
    setup->field05 = 4;
    setup->field07 = 8;
    setup->x = ((GameObject*)obj)->anim.localPosX;
    setup->y = lbl_803E3AE8 + ((GameObject*)obj)->anim.localPosY;
    setup->z = ((GameObject*)obj)->anim.localPosZ;
    setup->field19 = 4;
    setup->field1A = 0x514;
    setup->field1C = 40;
    setup->field18 = 30;
    return loadObjectAtObject(obj, setup);
}
