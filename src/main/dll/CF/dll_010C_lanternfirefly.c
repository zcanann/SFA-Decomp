/*
 * LanternFireFly (DLL 0x10C). Re-split (descriptor forensics,
 * docs/boundary_audit.md): TU = 0x80186704..0x801871C8, previously cut at
 * 0x80186B94 across windlift.c | CFcrystal.c (both drift mislabels).
 */
#include "main/dll/CF/CFcrystal.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/CF/windlift.h"

typedef struct PortalspelldoorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} PortalspelldoorPlacement;


typedef struct LanternFireFlyPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 stateId;
    s16 timer;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} LanternFireFlyPlacement;


/* scarab_getExtraSize == 0x34 (collectible money beetle). */
typedef struct ScarabState
{
    f32 velX; /* 0x00 */
    f32 velZ; /* 0x04 */
    f32 riseAmount; /* 0x08 */
    f32 baseY; /* 0x0c: def spawn height */
    s16 despawnTimer; /* 0x10 */
    u8 pad12[2];
    s16 mode; /* 0x14 */
    s16 yawSpeed; /* 0x16 */
    s16 spawnYaw; /* 0x18 */
    s16 fleeTimer; /* 0x1a */
    s16 riseLimit; /* 0x1c */
    s16 pickupSfx; /* 0x1e */
    s16 particleId; /* 0x20 */
    s16 unk22; /* 0x22 */
    u8 phase; /* 0x24 */
    u8 pad25[2];
    u8 moneyKind; /* 0x27 */
    u8 flags28; /* 0x28: 1 = collected, waiting on the money message */
    u8 pad29[3];
    s16 msgParamA; /* 0x2c */
    s16 msgParamB; /* 0x2e */
    f32 msgParamC; /* 0x30 */
} ScarabState;

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

/* dll_107_getExtraSize == 0x2c (CF wind lift / blow vent). */
typedef struct WindLift107State
{
    int holdTimer; /* 0x00: countdown while the vent is plugged */
    int holdReload; /* 0x04 */
    f32 radius; /* 0x08 */
    s16 yawLow; /* 0x0c */
    s16 yawHigh; /* 0x0e */
    s16 ventState; /* 0x10 */
    s16 maxDist; /* 0x12 */
    s16 unk14; /* 0x14 */
    s16 unk16; /* 0x16 */
    s16 unk18; /* 0x18 */
    s16 liftTimer; /* 0x1a */
    u8 pad1C[2];
    s16 spitTimer; /* 0x1e */
    u8 pad20;
    u8 rideState; /* 0x21 */
    u8 riding; /* 0x22 */
    u8 launchPhase; /* 0x23 */
    u8 pad24;
    u8 unk25; /* 0x25 */
    u8 glowPulse; /* 0x26 */
    u8 unk27; /* 0x27 */
    u8 pad28[4];
} WindLift107State;

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

/* portalspelldoor_getExtraSize == 0x10. */
typedef struct PortalSpellDoorState
{
    u8 pad00[4];
    f32 openAmount; /* 0x04 */
    int openTimer; /* 0x08 */
    u8 flags0C; /* 0x0c: bit 7 = open (via PortalFlags cast) */
    u8 pad0D[3];
} PortalSpellDoorState;

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjHits_MarkObjectPositionDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 Obj_GetYawDeltaToObject();


extern f32 timeDelta;
extern u8 framesThisStep;
extern u32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E39FC;
extern f32 lbl_803E3A00;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A30;
extern f32 lbl_803E3A34;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803DBDD0;
extern f32 lbl_803E3AA0;
extern f32 lbl_803E3AA4;
extern f32 lbl_803E3AA8;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3ABC;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern f32 lbl_803DBDC4;
extern f32 lbl_803DBDC8;
extern f32 lbl_803DBDCC;
extern u32 lbl_802C2298[3];
extern u32 lbl_802C22A4[3];

extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(int obj, int sfx, int limit);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern u32 randomGetRange(int min, int max);
extern void objHitDetectFn_80062e84(int obj, int a, int b);
extern void vecRotateZXY(void* rotation, f32* outVec);
extern int gameBitIncrement(int eventId);
extern f32 Vec_distance(void* a, void* b);
extern void playerAddMoney(int player, u8 b);
extern int objHitboxFn_801843c0(int obj);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, void* p5, int obj, int p7, int p8, int p9, int p10);
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, void* out, int p5, int p6);
extern int hitDetect_calcSweptSphereBounds(void* bounds, void* start, void* end, void* sphere, int n);
extern int hitDetectFn_800691c0(int obj, void* p2, int p3, int p4);
extern int hitDetectFn_80067958(int obj, void* p2, void* p3, int p4, void* p5, int p6);
extern int fn_801845FC(int obj, int p2, int p3, void* p4);

/* 8b "li r3, N; blr" returners. */
int LanternFireFly_getExtraSize(void) { return 0x74; }
int LanternFireFly_getObjectTypeId(void) { return 0x0; }

/* LanternFireFly_modelMtxFn: receives (obj, f1, f2, f3) and stores the
 * three floats into obj->_b8 at +0x54/+0x58/+0x5c. */
void LanternFireFly_modelMtxFn(u8* obj, f32 a, f32 b, f32 c)
{
    LanternFireFlyState* sub = ((GameObject*)obj)->extra;
    sub->anchorX = a;
    sub->anchorY = b;
    sub->anchorZ = c;
}

typedef struct LanternFireFlyVectorParams
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} LanternFireFlyVectorParams;

void LanternFireFly_func0B(int obj)
{
    typedef struct
    {
        u8 mode : 2;
    } LFFlags;
    LanternFireFlyState* state;
    int setup;
    int p;
    f32 vec[3];
    f32* vp = vec;
    f32 px;
    f32 y2;

    state = ((GameObject*)obj)->extra;
    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    state->field68 = ((LanternFireFlyPlacement*)setup)->unk18;
    state->stateId = ((LanternFireFlyPlacement*)setup)->stateId;
    state->field4C = lbl_803E3AA0;
    state->field50 = (f32)(int)((LanternFireFlyPlacement*)setup)->unk1C;
    state->field6F = 0;
    objHitDetectFn_80062e84(obj, 0, 1);
    p = Obj_GetPlayerObject();
    px = *(f32*)(p + 0x18);
    vec[0] = px;
    vec[1] = *(f32*)(p + 0x1c);
    vec[2] = *(f32*)(p + 0x20);
    vec[1] = *(f32*)(p + 0x1c) + lbl_803E3AA4;
    y2 = lbl_803E3AA8 + *(f32*)(p + 0x1c);
    {
        LanternFireFlyState* st = ((GameObject*)obj)->extra;
        st->anchorX = px;
        st->anchorY = y2;
        st->anchorZ = vec[2];
        st = ((GameObject*)obj)->extra;
        vec[0] = vec[0] - st->anchorX;
        vec[1] = vec[1] - st->anchorY;
        vec[2] = vec[2] - st->anchorZ;
        st->offX = vec[0];
        st->offY = vec[1];
        st->offZ = vec[2];
        st->animFrame = 4;
    }
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    ((LFFlags*)&state->modeFlags)->mode = 1;
    state->timer = ((LanternFireFlyPlacement*)setup)->timer;
    gameBitIncrement(0x698);
}



/* LanternFireFly_setScale: subtract sub->_54..5c from vec[0..2] (overwriting
 * vec), copy the result to sub->_34..3c, set sub->_6c = 4. */
void LanternFireFly_setScale(u8* obj, f32* vec)
{
    LanternFireFlyState* sub = ((GameObject*)obj)->extra;
    vec[0] = vec[0] - sub->anchorX;
    vec[1] = vec[1] - sub->anchorY;
    vec[2] = vec[2] - sub->anchorZ;
    sub->offX = vec[0];
    sub->offY = vec[1];
    sub->offZ = vec[2];
    sub->animFrame = 4;
}

/* LanternFireFly_free: free the light struct at sub[0] if present, then
 * (when p2==0 and the freshly-cleared sub[0] is NULL and mode bits 6..7
 * aren't 1) reset lbl_803DDAD8 to 0; finally ObjGroup_RemoveObject(obj, 0x30)
 * and dispatch vtable[6] of *gExpgfxInterface. */
extern void ModelLightStruct_free(void* p);
extern u8 lbl_803DDAD8;

void LanternFireFly_free(u8* obj, int p2)
{
    LanternFireFlyState* sub = ((GameObject*)obj)->extra;
    if (*(void**)&sub->light != NULL)
    {
        ModelLightStruct_free(*(void**)&sub->light);
        *(void**)&sub->light = NULL;
    }
    if (p2 == 0 && *(void**)&sub->light != NULL && ((sub->modeFlags >> 6) & 3) != 1u)
    {
        lbl_803DDAD8 = 0;
    }
    ObjGroup_RemoveObject(obj, 0x30);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

/* ================================================================ */
/* [0x80186B94..0x801871C8) - formerly the head of CFcrystal.c. */

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
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017ac8();
extern void gameBitDecrement(int eventId);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80061a80();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de758;
extern f64 DOUBLE_803e4748;
extern f32 FLOAT_803dca40;
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
extern f32 lbl_803E3A98;
extern f32 lbl_803E3A9C;
extern f64 lbl_803E3AB0;
extern f32 lbl_803E3AC8;
extern f32 lbl_803E3ACC;
extern f32 lbl_803E3AD0;
extern f32 lbl_803E3AD4;
extern f32 lbl_803E3AD8;
extern f32 lbl_803E3ADC;
extern f32 lbl_803E3AE0;
extern f32 lbl_803E3AEC;
extern f32 lbl_803DBDD8;
extern EffectInterface** gPartfxInterface;
extern f32 Curve_EvalBSpline(f32* control, f32 t, f32* out);
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

/* Helpers placed last (anti-inline): LanternFireFly_update above calls
 * both via what were extern bls before the re-split. */
void fn_801868D0(int obj)
{
    typedef struct
    {
        s16 ang;
        s16 b;
        s16 c;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } LFRot;
    extern f32 lbl_803E3ABC;
    LFRot rot;
    LanternFireFlyState* state;
    s16 r;
    f32 fz;

    state = ((GameObject*)obj)->extra;
    state->offX = lbl_803E3AB8;
    state->offY = (f32)(int)
    randomGetRange(-state->field68, state->field68);
    if (state->field50 < lbl_803E3ABC)
    {
        state->offZ = lbl_803E3AB8;
    }
    else
    {
        state->offZ = state->field50 -
            (f32)(int)
        randomGetRange(0x14, (s16)(int)state->field50);
    }
    r = (s16)randomGetRange(3000, 5000);
    state->randAngle += r;
    fz = lbl_803E3AB8;
    rot.x = fz;
    rot.y = fz;
    rot.z = fz;
    rot.scale = lbl_803E3AA0;
    rot.c = 0;
    rot.b = 0;
    rot.ang = state->randAngle;
    vecRotateZXY(&rot, &state->offX);
}

void fn_801869DC(int obj)
{
    typedef struct
    {
        u8 mode : 2;
    } LFF2;
    LanternFireFlyState* state;

    state = ((GameObject*)obj)->extra;
    state->controlX[0] = state->controlX[1];
    state->controlY[0] = state->controlY[1];
    state->controlZ[0] = state->controlZ[1];
    state->controlX[1] = state->controlX[2];
    state->controlY[1] = state->controlY[2];
    state->controlZ[1] = state->controlZ[2];
    state->controlX[2] = state->controlX[3];
    state->controlY[2] = state->controlY[3];
    state->controlZ[2] = state->controlZ[3];
    if (((LFF2*)&state->modeFlags)->mode == 1)
    {
        int player = Obj_GetPlayerObject();
        state->speed =
            lbl_803E3AC4 * Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX,
                                        (void*)&((GameObject*)player)->anim.worldPosX) + lbl_803E3AC0;
    }
    else
    {
        state->speed = lbl_803E3AC4 * (f32)(s32)
        randomGetRange(0x3c, 0x5a);
    }
    state->controlX[3] = state->offX;
    state->controlY[3] = state->offY;
    state->controlZ[3] = state->offZ;
}
