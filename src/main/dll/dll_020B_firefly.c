/*
 * firefly (DLL 0x20B) - the collectible fireflies. Retail object def
 * 1270 'FireFly' (romlist type 0x259); grouped with the WM (Krazoa
 * Palace) dlls by id, but its retail placements are the dark-area
 * maps: dragrock (Dragon Rock), fortress (CloudRunner Fortress),
 * hollow2 and swapcircle.
 * A firefly sleeps until its required game bit (if any) is set, then
 * lights up (a 100/255/100 point light) and wanders a cubic B-spline
 * whose control points are re-targeted by the sibling TU's
 * fn_801F4D54, trailing blue or orange particles by kind. Flying near
 * the player brightens its glow. The first touch anywhere sends the
 * firefly talk message to the player (game bit 0xD28); later touches
 * (or the talk's despawn-message reply) collect it - the lantern
 * counter bits 0x13D/0x5D6 increment, the model hides, sparkles
 * briefly and frees itself 180 frames later.
 */
#include "main/game_object.h"
#include "main/dll/WM/wm_shared.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"

#define FIREFLY_EXTRA_SIZE 0x88

/* state->kind - trail/near particle-fx colour */
#define FIREFLY_KIND_BLUE_MAIN 1
#define FIREFLY_KIND_ORANGE_NEAR 3
#define FIREFLY_KIND_BLUE_NEAR 4
#define FIREFLY_KIND_ORANGE_ALT_NEAR 5

/* state->flags */
#define FIREFLY_FLAG_PLAYER_TOUCHED 0x01

#define FIREFLY_ALPHA_OPAQUE 0xff
#define FIREFLY_OBJFLAG_HIDDEN 0x4000
#define FIREFLY_MESSAGE_TALK 0x7000a
#define FIREFLY_MESSAGE_DESPAWN 0x7000b
#define FIREFLY_FIRST_TOUCH_BIT 0xd28
#define FIREFLY_COLLECT_COUNT_BIT_A 0x13d
#define FIREFLY_COLLECT_COUNT_BIT_B 0x5d6

#define FIREFLY_PARTFX_BLUE_TRAIL 0x1a0
#define FIREFLY_PARTFX_ORANGE_TRAIL 0x1bd
#define FIREFLY_PARTFX_BLUE_NEAR 0x19f
#define FIREFLY_PARTFX_ORANGE_NEAR 0x1bc
#define FIREFLY_PARTFX_KIND 1
#define FIREFLY_PARTFX_INVALID_HANDLE -1

typedef struct FireFlyState
{
    void* light;           /* 0x00: point-light handle (modelLightStruct) */
    f32 splineX[4];        /* 0x04: B-spline control points (X) */
    f32 splineY[4];        /* 0x14 */
    f32 splineZ[4];        /* 0x24 */
    f32 targetX;           /* 0x34: next wander target (fn_801F4D54) */
    f32 targetY;           /* 0x38 */
    f32 targetZ;           /* 0x3C */
    f32 splineT;           /* 0x40: spline parameter; >1 shifts a new segment in */
    f32 splineSpeed;       /* 0x44: dT per frame, re-rolled each segment */
    f32 proximityAlpha;    /* 0x48: glow brightness, eased toward the near/far bound */
    f32 playerRadius;      /* 0x4C: player XZ distance that brightens the glow */
    u8 pad50[0x66 - 0x50]; /* 0x50: wander params owned by the sibling TU
                              (fn_801F4C28 init / fn_801F4D54 re-target) */
    u8 kind;               /* 0x66: FIREFLY_KIND_* */
    u8 pad67;
    u8 pathAge;            /* 0x68: spline segments consumed; 4+ stops re-targeting */
    u8 pad69[0x6C - 0x69];
    u8 activeFlags;        /* 0x6C: FireFlyActiveBits */
    u8 pad6D[0x70 - 0x6D];
    f32 despawnTimer;      /* 0x70: post-collect frames; sparkles above 170, frees at 0 */
    u8 lifeTimer[0x7C - 0x74]; /* 0x74: float-param timer (timerCountDown);
                                  expiry despawns the timed placement variant */
    u8 flags;              /* 0x7C: FIREFLY_FLAG_PLAYER_TOUCHED */
    u8 pad7D[0x80 - 0x7D];
    s16 messageParam;      /* 0x80: outparam for the talk message */
    u8 pad82[FIREFLY_EXTRA_SIZE - 0x82];
} FireFlyState;

typedef struct FireFlyActiveBits
{
    u8 active : 1; /* 0x6C & 0x80: lit and wandering */
} FireFlyActiveBits;

typedef struct FireFlyMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 variantParam;     /* 0x1A: only 0x7F is read (arms the 3600-frame life timer) */
    u8 pad1C[0x20 - 0x1C];
    s16 requiredGameBit;  /* 0x20: game bit gating activation (-1 = none) */
} FireFlyMapData;

STATIC_ASSERT(offsetof(FireFlyState, light) == 0x00);
STATIC_ASSERT(offsetof(FireFlyState, splineX) == 0x04);
STATIC_ASSERT(offsetof(FireFlyState, splineY) == 0x14);
STATIC_ASSERT(offsetof(FireFlyState, splineZ) == 0x24);
STATIC_ASSERT(offsetof(FireFlyState, targetX) == 0x34);
STATIC_ASSERT(offsetof(FireFlyState, splineT) == 0x40);
STATIC_ASSERT(offsetof(FireFlyState, kind) == 0x66);
STATIC_ASSERT(offsetof(FireFlyState, activeFlags) == 0x6C);
STATIC_ASSERT(offsetof(FireFlyState, despawnTimer) == 0x70);
STATIC_ASSERT(offsetof(FireFlyState, lifeTimer) == 0x74);
STATIC_ASSERT(offsetof(FireFlyState, flags) == 0x7C);
STATIC_ASSERT(offsetof(FireFlyState, messageParam) == 0x80);
STATIC_ASSERT(sizeof(FireFlyState) == FIREFLY_EXTRA_SIZE);
STATIC_ASSERT(offsetof(FireFlyMapData, variantParam) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyMapData, requiredGameBit) == 0x20);

/* The active-flight tick: fade in, advance the B-spline (shifting in a
   new segment and re-targeting while pathAge < 4), spawn the trail fx,
   ease the proximity glow, and detect the player touch. Runs as the
   anim-event callback via the sibling TU's fn_801F4C04 wrapper. */
void FireFlyFn_801f4f88(int obj)
{
    FireFlyState* state = ((GameObject*)obj)->extra;
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    int player = (int)Obj_GetPlayerObject();
    if ((int)objAnim->alpha < FIREFLY_ALPHA_OPAQUE)
    {
        int newAlpha = (int)(lbl_803E5EDC * timeDelta + (f32)(int)objAnim->alpha); /* 2.0f */
        if (newAlpha > FIREFLY_ALPHA_OPAQUE) newAlpha = FIREFLY_ALPHA_OPAQUE;
        objAnim->alpha = newAlpha;
    }
    if (state->splineT > lbl_803E5EB4) /* 1.0f */
    {
        state->splineT = state->splineT - lbl_803E5EB4;
        if (state->pathAge >= 4)
        {
            state->pathAge += 1;
        }
        else
        {
            fn_801F4D54(obj, (int)state);
        }
        state->splineX[0] = state->splineX[1];
        state->splineY[0] = state->splineY[1];
        state->splineZ[0] = state->splineZ[1];
        state->splineX[1] = state->splineX[2];
        state->splineY[1] = state->splineY[2];
        state->splineZ[1] = state->splineZ[2];
        state->splineX[2] = state->splineX[3];
        state->splineY[2] = state->splineY[3];
        state->splineZ[2] = state->splineZ[3];
        state->splineSpeed = lbl_803E5ED8 * (f32)(int)randomGetRange(0xa0, 0xb4); /* 0.00015f */
        state->splineX[3] = state->targetX;
        state->splineY[3] = state->targetY;
        state->splineZ[3] = state->targetZ;
    }
    ((GameObject*)obj)->anim.localPosX = ((f32 (*)(f32*, f32, int))Curve_EvalBSpline)(
        state->splineX, state->splineT, 0);
    ((GameObject*)obj)->anim.localPosY = ((f32 (*)(f32*, f32, int))Curve_EvalBSpline)(
        state->splineY, state->splineT, 0);
    ((GameObject*)obj)->anim.localPosZ = ((f32 (*)(f32*, f32, int))Curve_EvalBSpline)(
        state->splineZ, state->splineT, 0);
    state->splineT = state->splineSpeed * timeDelta + state->splineT;
    ((GameObject*)obj)->anim.rotX = getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                                                  ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ);
    if (state->kind == FIREFLY_KIND_BLUE_MAIN || state->kind == FIREFLY_KIND_BLUE_NEAR)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, FIREFLY_PARTFX_BLUE_TRAIL, NULL,
                                         FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, NULL);
    }
    else
    {
        (*gPartfxInterface)->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_TRAIL, NULL,
                                         FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, NULL);
    }
    /* player+0x18 (worldPos) by raw arith - the &member spelling CSEs the
       address into a saved-reg web and shifts the bytes (recipe #77(b)) */
    if (Vec_xzDistance((f32*)(player + 0x18), &((GameObject*)obj)->anim.placement->posX) <
        state->playerRadius)
    {
        f32 maxAlpha;
        f32 curAlpha;
        if (state->kind == FIREFLY_KIND_BLUE_NEAR)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, FIREFLY_PARTFX_BLUE_NEAR, NULL,
                                             FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        }
        else if (state->kind == FIREFLY_KIND_ORANGE_NEAR)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_NEAR, NULL,
                                             FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        }
        else if (state->kind == FIREFLY_KIND_ORANGE_ALT_NEAR)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_NEAR, NULL,
                                             FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        }
        if ((curAlpha = state->proximityAlpha) < (maxAlpha = lbl_803E5EE0)) /* 0.003f */
        {
            state->proximityAlpha = curAlpha + lbl_803E5EE4; /* 0.00001f */
            if (state->proximityAlpha > maxAlpha)
            {
                state->proximityAlpha = maxAlpha;
            }
        }
    }
    else
    {
        f32 minAlpha;
        f32 curAlpha;

        if ((curAlpha = state->proximityAlpha) > (minAlpha = lbl_803E5EE8)) /* 0.001f */
        {
            state->proximityAlpha = curAlpha - lbl_803E5EE4;
            if (state->proximityAlpha < minAlpha)
            {
                state->proximityAlpha = minAlpha;
            }
        }
    }
    {
        f32 dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
        if ((state->flags & FIREFLY_FLAG_PLAYER_TOUCHED) == 0)
        {
            if (dy < lbl_803E5EEC && dy > lbl_803E5EC4) /* 35.0f / 0.0f */
            {
                if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5EF0) /* 225.0f */
                {
                    state->flags = (u8)(state->flags | FIREFLY_FLAG_PLAYER_TOUCHED);
                    if (GameBit_Get(FIREFLY_FIRST_TOUCH_BIT) == 0)
                    {
                        state->messageParam = -1;
                        ObjMsg_SendToObject(player, FIREFLY_MESSAGE_TALK, obj, &state->messageParam);
                        GameBit_Set(FIREFLY_FIRST_TOUCH_BIT, 1);
                    }
                    else
                    {
                        FireFlyState* st = ((GameObject*)obj)->extra;
                        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | FIREFLY_OBJFLAG_HIDDEN);
                        st->despawnTimer = lbl_803E5EA8; /* 180.0f */
                        gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
                        gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
                        Sfx_PlayFromObject(obj, SFXen_treadlpc);
                    }
                }
            }
        }
    }
}

void firefly_free(int obj)
{
    FireFlyState* state = ((GameObject*)obj)->extra;

    modelLightStruct_freeSlot(state);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void firefly_update(int obj)
{
    FireFlyState* state;
    FireFlyMapData* def;
    int msg[2];
    int isActive;

    state = ((GameObject*)obj)->extra;
    def = (FireFlyMapData*)((GameObject*)obj)->anim.placement;
    while (ObjMsg_Pop(obj, msg, 0, 0) != 0)
    {
        switch (msg[0])
        {
        case FIREFLY_MESSAGE_DESPAWN:
            {
                FireFlyState* st = ((GameObject*)obj)->extra;
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | FIREFLY_OBJFLAG_HIDDEN);
                st->despawnTimer = 180.0f;
                gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
                gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
                Sfx_PlayFromObject(obj, SFXen_treadlpc);
                break;
            }
        }
    }

    if (((FireFlyActiveBits*)&state->activeFlags)->active == 0)
    {
        isActive = 0;
        if ((def->requiredGameBit == -1) || ((u32)GameBit_Get(def->requiredGameBit) != 0))
        {
            isActive = 1;
        }
        ((FireFlyActiveBits*)&state->activeFlags)->active = isActive;
        if (((FireFlyActiveBits*)&state->activeFlags)->active != 0)
        {
            state->light = (void*)modelLightStruct_createPointLight(obj, 100, 0xFF, 100, 0);
        }
    }
    else
    {
        if (timerCountDown(state->lifeTimer) != 0)
        {
            state->despawnTimer = 180.0f;
        }
        if (state->despawnTimer > lbl_803E5EC4) /* 0.0f */
        {
            state->despawnTimer -= timeDelta;
            if (state->despawnTimer > lbl_803DC128) /* 170 */
            {
                itemPickupDoParticleFx(obj, lbl_803E5EDC, 4, 5);
            }
            if (state->despawnTimer <= lbl_803E5EC4)
            {
                Obj_FreeObject(obj);
            }
        }
        else
        {
            FireFlyFn_801f4f88(obj);
        }
    }
}

void firefly_init(int obj, int def)
{
    FireFlyState* state;
    FireFlyMapData* mapData;

    state = ((GameObject*)obj)->extra;
    mapData = (FireFlyMapData*)def;
    fn_801F4C28(obj, state);
    ((GameObject*)obj)->anim.alpha = 0;
    ((GameObject*)obj)->animEventCallback = fn_801F4C04;
    ObjMsg_AllocQueue(obj, 1);
    storeZeroToFloatParam(state->lifeTimer);
    if (mapData->variantParam == 0x7f)
    {
        s16toFloat(state->lifeTimer, 0xe10);
    }
}

int firefly_getExtraSize(void) { return FIREFLY_EXTRA_SIZE; }
int firefly_getObjectTypeId(void) { return 0x0; }

void firefly_render(void)
{
}

void firefly_hitDetect(void)
{
}

void firefly_release(void)
{
}

void firefly_initialise(void)
{
}
