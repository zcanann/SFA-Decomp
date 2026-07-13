/*
 * LanternFireFly (DLL 0x10C). TU = 0x80186704..0x801871C8.
 */
#include "main/dll/CF/CFcrystal.h"
#include "main/object_render_legacy.h"
#include "main/vecmath.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/track_dolphin_api.h"
#include "main/modellight_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_group.h"
#include "main/curve.h"
#include "main/dll/CF/windlift.h"
#include "main/audio/sfx.h"
#include "main/gameloop_api.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct LanternFireFlyPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 wanderRange;
    u8 stateId;
    s16 timer;
    s16 driftRangeZ; /* 0x1C: -> state driftRangeZ (Z drift distance) */
    u8 pad1E[0x20 - 0x1E];
} LanternFireFlyPlacement;

typedef struct LanternFireFlyModeBits
{
    u8 mode : 2;
    u8 rest : 6;
} LanternFireFlyModeBits;

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

/* object group this object joins while active */
#define LANTERNFIREFLY_OBJGROUP 0x30

#define MODEL_LIGHT_KIND_POINT 2

extern f32 lbl_803E3AA0;
extern f32 lbl_803E3AA4;
extern f32 lbl_803E3AA8;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3ABC;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern u8 lbl_803DDAD8;
extern f32 lbl_803E3A98;
extern f32 lbl_803E3A9C;
extern f32 lbl_803E3AC8;
extern f32 gLanternFireflyPi;
extern f32 lbl_803E3AD0;
extern f32 lbl_803E3AD4;
extern f32 lbl_803E3AD8;
extern f32 lbl_803E3ADC;
extern f32 lbl_803E3AE0;
extern f32 lbl_803DBDD8;

extern void ModelLightStruct_free(void* p);
extern int objCreateLight(int obj, int type);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);

int LanternFireFly_getExtraSize(void)
{
    return 0x74;
}
int LanternFireFly_getObjectTypeId(void)
{
    return 0x0;
}

/* LanternFireFly_modelMtxFn: receives (obj, anchorX, anchorY, anchorZ) and
 * stores the three floats into obj->extra at +0x54/+0x58/+0x5c. */
void LanternFireFly_modelMtxFn(u8* obj, f32 anchorX, f32 anchorY, f32 anchorZ)
{
    LanternFireFlyState* state = ((GameObject*)obj)->extra;
    state->anchorX = anchorX;
    state->anchorY = anchorY;
    state->anchorZ = anchorZ;
}

void LanternFireFly_func0B(GameObject* obj)
{
    typedef struct
    {
        u8 mode : 2;
    } LFFlags;
    LanternFireFlyState* state;
    int setup;
    int player;
    f32 vec[3];
    f32* vp = vec;
    f32 px;
    f32 y2;

    state = (obj)->extra;
    setup = *(int*)&(obj)->anim.placementData;
    state->wanderRange = ((LanternFireFlyPlacement*)setup)->wanderRange;
    state->stateId = ((LanternFireFlyPlacement*)setup)->stateId;
    state->field4C = lbl_803E3AA0;
    state->driftRangeZ = (f32)(int)((LanternFireFlyPlacement*)setup)->driftRangeZ;
    state->field6F = 0;
    objHitDetectFn_80062e84(obj, NULL, 1);
    player = (int)Obj_GetPlayerObject();
    px = ((GameObject*)player)->anim.worldPosX;
    vec[0] = px;
    vec[1] = ((GameObject*)player)->anim.worldPosY;
    vec[2] = ((GameObject*)player)->anim.worldPosZ;
    vec[1] = ((GameObject*)player)->anim.worldPosY + lbl_803E3AA4;
    y2 = lbl_803E3AA8 + ((GameObject*)player)->anim.worldPosY;
    {
        LanternFireFlyState* st = (obj)->extra;
        st->anchorX = px;
        st->anchorY = y2;
        st->anchorZ = vec[2];
        st = (obj)->extra;
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
 * aren't 1) reset lbl_803DDAD8 to 0; finally ObjGroup_RemoveObject(obj, LANTERNFIREFLY_OBJGROUP)
 * and dispatch vtable[6] of *gExpgfxInterface. */

void LanternFireFly_free(u8* obj, int flag)
{
    LanternFireFlyState* sub = ((GameObject*)obj)->extra;
    if (*(void**)&sub->light != NULL)
    {
        ModelLightStruct_free(*(void**)&sub->light);
        *(void**)&sub->light = NULL;
    }
    if (flag == 0 && *(void**)&sub->light != NULL && ((sub->modeFlags >> 6) & 3) != 1u)
    {
        lbl_803DDAD8 = 0;
    }
    ObjGroup_RemoveObject((int)obj, LANTERNFIREFLY_OBJGROUP);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3AA0);
}

void LanternFireFly_hitDetect(void)
{
}

#define LANTERN_SPAWN_FX(obj, id, a, b, c, d) (*gPartfxInterface)->spawnObject((void*)obj, id, a, b, c, d)

#define LANTERN_FIREFLY_MODE(state)      (((u32)(state)->modeFlags >> 6) & 3)
#define LANTERN_FIREFLY_IS_ACTIVE(state) (LANTERN_FIREFLY_MODE(state) == 1u)

void LanternFireFly_update(GameObject* obj)
{
    LanternFireFlyState* state;
    int player;
    f32 velocity[3];
    f32* v;
    f32 zz;
    f32 xx;
    f32 yy;
    f32 stepScale;

    state = (obj)->extra;
    player = (int)Obj_GetPlayerObject();
    (obj)->anim.previousLocalPosX = (obj)->anim.localPosX;
    (obj)->anim.previousLocalPosY = (obj)->anim.localPosY;
    (obj)->anim.previousLocalPosZ = (obj)->anim.localPosZ;

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

    (obj)->anim.localPosX = state->anchorX + Curve_EvalBSplineValuesFirst(state->controlX, state->splineT, 0);
    (obj)->anim.localPosY = state->anchorY + Curve_EvalBSplineValuesFirst(state->controlY, state->splineT, 0);
    (obj)->anim.localPosZ = state->anchorZ + Curve_EvalBSplineValuesFirst(state->controlZ, state->splineT, 0);

    if (LANTERN_FIREFLY_IS_ACTIVE(state))
    {
        state->speed =
            (f32)(lbl_803E3AC4 * Vec_distance((void*)&(obj)->anim.worldPosX,
                                              &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) +
                  lbl_803E3AC0);
    }
    state->splineT += state->speed * timeDelta;

    if ((state->stateId == 1 || state->stateId == 4) && LANTERN_FIREFLY_IS_ACTIVE(state) && state->lightSpawned == 0)
    {
        int light;

        state->lightSpawned = 1;
        light = objCreateLight((int)obj, 1);
        if ((void*)light == NULL)
        {
            light = 0;
        }
        else
        {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(light, 100, 0xff, 100, 0);
            lightSetFieldBC_8001db14((ModelLightStruct*)light, 1);
            modelLightStruct_setDistanceAttenuation(light, lbl_803E3A98, lbl_803E3A9C);
            modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)light, 1);
        }
        state->light = light;
        if (!LANTERN_FIREFLY_IS_ACTIVE(state))
        {
            lbl_803DDAD8 = 1;
        }
    }

    v = velocity;
    v[0] = (obj)->anim.localPosX - (obj)->anim.previousLocalPosX;
    v[1] = (obj)->anim.localPosY - (obj)->anim.previousLocalPosY;
    v[2] = (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ;
    zz = v[2] * v[2];
    xx = v[0] * v[0];
    yy = v[1] * v[1];
    stepScale = sqrtf(zz + (xx + yy));
    v[0] = v[0] * (stepScale = lbl_803E3AA0 / (f32)((s32)(stepScale / lbl_803E3AC8) + 1));
    v[1] = v[1] * stepScale;
    v[2] = v[2] * stepScale;

    if (LANTERN_FIREFLY_IS_ACTIVE(state))
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_pk_lightcritter_lp);
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

            worldZ = ((GameObject*)player)->anim.worldPosZ;
            worldY = lbl_803E3AA8 + ((GameObject*)player)->anim.worldPosY;
            st = (LanternFireFlyState*)(obj)->extra;
            st->anchorX = ((GameObject*)player)->anim.worldPosX;
            st->anchorY = worldY;
            st->anchorZ = worldZ;
        }
        if ((void*)state->light != NULL && state->timer < 0xb4)
        {
            f32 atten;

            atten = state->timer * mathSinf((gLanternFireflyPi * (f32)(state->timer << 0xb)) / lbl_803E3AD0);
            Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_sc_commsbleep);
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

void LanternFireFly_init(GameObject* obj, int def)
{
    LanternFireFlyState* state;
    LanternFireFlySpawnDef* spawnDef;
    f32 zero;
    s16 randValue;
    int flagValue;

    state = (obj)->extra;
    spawnDef = (LanternFireFlySpawnDef*)def;
    ObjGroup_AddObject((int)obj, LANTERNFIREFLY_OBJGROUP);

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
    randValue = randomGetRange(0x1F4, 0x5DC);
    state->randPeriod = randValue;
    randValue = randomGetRange(0, 0xFDE8);
    state->randAngle = randValue;
    state->wanderRange = 4;
    state->stateId = 4;
    state->field4C = lbl_803E3AB8;
    state->driftRangeZ = lbl_803E3AE0;
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

/* Helpers placed last (anti-inline): LanternFireFly_update above calls both. */
void fn_801868D0(GameObject* obj)
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
    LFRot rot;
    LanternFireFlyState* state;
    s16 angleDelta;
    f32 fz;

    state = obj->extra;
    state->offX = lbl_803E3AB8;
    state->offY = (f32)(int)randomGetRange(-state->wanderRange, state->wanderRange);
    if (state->driftRangeZ < lbl_803E3ABC)
    {
        state->offZ = lbl_803E3AB8;
    }
    else
    {
        state->offZ = state->driftRangeZ - (f32)(int)randomGetRange(0x14, (s16)(int)state->driftRangeZ);
    }
    angleDelta = randomGetRange(3000, 5000);
    state->randAngle += angleDelta;
    fz = lbl_803E3AB8;
    rot.x = fz;
    rot.y = fz;
    rot.z = fz;
    rot.scale = lbl_803E3AA0;
    rot.c = 0;
    rot.b = 0;
    rot.ang = state->randAngle;
    vecRotateZXY(&rot.ang, &state->offX);
}

void fn_801869DC(GameObject* obj)
{
    typedef struct
    {
        u8 mode : 2;
    } LFF2;
    LanternFireFlyState* state;

    state = obj->extra;
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
        int player = (int)Obj_GetPlayerObject();
        state->speed =
            lbl_803E3AC4 * Vec_distance((void*)&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) +
            lbl_803E3AC0;
    }
    else
    {
        state->speed = lbl_803E3AC4 * (f32)(s32)randomGetRange(0x3c, 0x5a);
    }
    state->controlX[3] = state->offX;
    state->controlY[3] = state->offY;
    state->controlZ[3] = state->offZ;
}
