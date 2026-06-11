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

void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3AA0);
}

void LanternFireFly_hitDetect(void)
{
}

#define LANTERN_SPAWN_FX(obj, id, a, b, c, d) \
    (*gPartfxInterface)->spawnObject((void *)obj, id, (void *)a, b, c, (void *)d)

#define LANTERN_FIREFLY_MODE(state) (((u32)(state)->modeFlags >> 6) & 3)
#define LANTERN_FIREFLY_IS_ACTIVE(state) (LANTERN_FIREFLY_MODE(state) == 1u)

extern void fn_801868D0(int obj);
extern void fn_801869DC(int obj);

void LanternFireFly_update(int obj)
{
    LanternFireFlyState* state;
    int player;
    f32 velocity[3];
    f32* v;
    f32 zz;
    f32 xx;
    f32 yy;
    f32 stepScale;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;

    if (state->splineT > *(f32*)&lbl_803E3AA0)
    {
        state->splineT -= lbl_803E3AA0;
        if (state->animFrame >= 4)
        {
            if (state->animFrame != 7)
            {
                state->animFrame++;
            }
            else
            {
                state->animFrame = 0;
            }
        }
        else
        {
            fn_801868D0(obj);
        }
        fn_801869DC(obj);
    }

    ((GameObject*)obj)->anim.localPosX = state->anchorX + Curve_EvalBSpline(state->controlX, state->splineT, 0);
    ((GameObject*)obj)->anim.localPosY = state->anchorY + Curve_EvalBSpline(state->controlY, state->splineT, 0);
    ((GameObject*)obj)->anim.localPosZ = state->anchorZ + Curve_EvalBSpline(state->controlZ, state->splineT, 0);

    if (LANTERN_FIREFLY_IS_ACTIVE(state))
    {
        state->speed =
            (f32)(lbl_803E3AC4 * Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX,
                                              (void*)(Obj_GetPlayerObject() + 0x18)) + lbl_803E3AC0);
    }
    state->splineT += state->speed * timeDelta;

    if ((state->stateId == 1 || state->stateId == 4) && LANTERN_FIREFLY_IS_ACTIVE(state) && state->lightSpawned == 0)
    {
        int light;

        state->lightSpawned = 1;
        light = objCreateLight(obj, 1);
        if ((void*)light == NULL)
        {
            light = 0;
        }
        else
        {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(light, 100, 0xff, 100, 0);
            lightSetFieldBC_8001db14(light, 1);
            modelLightStruct_setDistanceAttenuation(light, lbl_803E3A98, lbl_803E3A9C);
            modelLightStruct_setAffectsAabbLightSelection(light, 1);
        }
        state->light = light;
        if (!LANTERN_FIREFLY_IS_ACTIVE(state))
        {
            lbl_803DDAD8 = 1;
        }
    }

    v = velocity;
    v[0] = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
    v[1] = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
    v[2] = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
    zz = v[2] * v[2];
    xx = v[0] * v[0];
    yy = v[1] * v[1];
    stepScale = sqrtf(zz + (xx + yy));
    v[0] = v[0] * (stepScale = lbl_803E3AA0 / (f32)((s32)(stepScale / lbl_803E3AC8) + 1));
    v[1] = v[1] * stepScale;
    v[2] = v[2] * stepScale;

    if (LANTERN_FIREFLY_IS_ACTIVE(state))
    {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x43b);
        if ((f32)state->timer > lbl_803DBDD8)
        {
            if (state->stateId == 1 || state->stateId == 4)
            {
                LANTERN_SPAWN_FX(obj, 0x19f, 0, 1, -1, 0);
                LANTERN_SPAWN_FX(obj, 0x1a0, 0, 1, -1, 0);
            }
            else
            {
                LANTERN_SPAWN_FX(obj, 0x1bd, 0, 1, -1, 0);
            }
        }
        if ((state->timer -= framesThisStep) < 0)
        {
            gameBitDecrement(0x698);
            Obj_FreeObject(obj);
            return;
        }
        else
        {
            f32 worldZ;
            f32 worldY;
            LanternFireFlyState* st;

            worldZ = *(f32*)(player + 0x20);
            worldY = lbl_803E3AA8 + *(f32*)(player + 0x1c);
            st = (LanternFireFlyState*)*(int*)(obj + 0xb8);
            st->anchorX = *(f32*)(player + 0x18);
            st->anchorY = worldY;
            st->anchorZ = worldZ;
        }
        if ((void*)state->light != NULL && state->timer < 0xb4)
        {
            f32 atten;

            atten = (f32)state->timer *
                mathSinf((lbl_803E3ACC * (f32)(state->timer << 0xb)) / lbl_803E3AD0);
            Sfx_KeepAliveLoopedObjectSound(0, 0x460);
            modelLightStruct_setDistanceAttenuation(state->light, atten, lbl_803E3AD4 + atten);
        }
    }
    else
    {
        LANTERN_SPAWN_FX(obj, 0x19f, 0, 1, -1, 0);
        LANTERN_SPAWN_FX(obj, 0x1a0, 0, 1, -1, 0);
    }
}

#undef LANTERN_SPAWN_FX
#undef LANTERN_FIREFLY_IS_ACTIVE
#undef LANTERN_FIREFLY_MODE

typedef struct LanternFireFlyModeBits {
    u8 mode : 2;
    u8 rest : 6;
} LanternFireFlyModeBits;

void LanternFireFly_init(int obj, int def)
{
    LanternFireFlyState* state;
    LanternFireFlySpawnDef* spawnDef;
    f32 zero;
    s16 randValue;
    int flagValue;

    state = ((GameObject*)obj)->extra;
    spawnDef = (LanternFireFlySpawnDef*)def;
    ObjGroup_AddObject(obj, 0x30);

    zero = lbl_803E3AB8;
    state->controlX[0] = zero;
    state->controlY[0] = zero;
    state->controlZ[0] = zero;
    state->controlX[1] = zero;
    state->controlY[1] = zero;
    state->controlZ[1] = zero;
    state->controlX[2] = zero;
    state->controlY[2] = zero;
    state->controlZ[2] = zero;
    state->controlX[3] = zero;
    state->controlY[3] = zero;
    state->controlZ[3] = zero;

    state->light = 0;
    state->lightSpawned = 0;
    state->speed = lbl_803E3AD8;
    state->field48 = lbl_803E3ADC;
    state->splineT = lbl_803E3AA0;
    state->animFrame = 0;
    state->field6B = 0;
    randValue = (s16)randomGetRange(0x1F4, 0x5DC);
    state->randPeriod = randValue;
    randValue = (s16)randomGetRange(0, 0xFDE8);
    state->randAngle = randValue;
    state->field68 = 4;
    state->stateId = 4;
    state->field4C = lbl_803E3AB8;
    state->field50 = lbl_803E3AE0;
    state->anchorX = spawnDef->x;
    state->anchorY = spawnDef->y;
    state->anchorZ = spawnDef->z;
    flagValue = 0;
    state->field6F = flagValue;
    ((LanternFireFlyModeBits*)&state->modeFlags)->mode = flagValue;
}

void LanternFireFly_release(void)
{
}

void LanternFireFly_initialise(void)
{
}

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

int FireFlyLantern_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FireFlyLanternState* state;
    int* slot;
    void* child;
    f32 yOffset;
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
    slot = state->fireflies;
    yOffset = lbl_803E3AEC;
    while (i < state->fireflyCount)
    {
        child = (void*)*slot;
        (*(void (*)(void*, f32, f32, f32))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x28)))(
            child, ((GameObject*)obj)->anim.localPosX, yOffset + ((GameObject*)obj)->anim.localPosY,
            ((GameObject*)obj)->anim.localPosZ);
        slot++;
        i++;
    }

    return 0;
}

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
