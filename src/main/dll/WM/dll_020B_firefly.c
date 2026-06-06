#include "global.h"
#include "main/game_object.h"
#include "main/dll/WM/wm_shared.h"
#include "main/audio/sfx_ids.h"

#define FIREFLY_EXTRA_SIZE 0x88

#define FIREFLY_STATE_LIGHT 0x00
#define FIREFLY_STATE_SPLINE_X0 0x04
#define FIREFLY_STATE_SPLINE_X1 0x08
#define FIREFLY_STATE_SPLINE_X2 0x0c
#define FIREFLY_STATE_SPLINE_X3 0x10
#define FIREFLY_STATE_SPLINE_Y0 0x14
#define FIREFLY_STATE_SPLINE_Y1 0x18
#define FIREFLY_STATE_SPLINE_Y2 0x1c
#define FIREFLY_STATE_SPLINE_Y3 0x20
#define FIREFLY_STATE_SPLINE_Z0 0x24
#define FIREFLY_STATE_SPLINE_Z1 0x28
#define FIREFLY_STATE_SPLINE_Z2 0x2c
#define FIREFLY_STATE_SPLINE_Z3 0x30
#define FIREFLY_STATE_TARGET_X 0x34
#define FIREFLY_STATE_TARGET_Y 0x38
#define FIREFLY_STATE_TARGET_Z 0x3c
#define FIREFLY_STATE_SPLINE_T 0x40
#define FIREFLY_STATE_SPLINE_SPEED 0x44
#define FIREFLY_STATE_PROXIMITY_ALPHA 0x48
#define FIREFLY_STATE_PLAYER_RADIUS 0x4c
#define FIREFLY_STATE_KIND 0x66
#define FIREFLY_STATE_PATH_AGE 0x68
#define FIREFLY_STATE_ACTIVE_FLAGS 0x6c
#define FIREFLY_STATE_DESPAWN_TIMER 0x70
#define FIREFLY_STATE_ACTIVATE_DELAY 0x74
#define FIREFLY_STATE_FLAGS 0x7c
#define FIREFLY_STATE_MESSAGE_PARAM 0x80

#define FIREFLY_KIND_BLUE_MAIN 1
#define FIREFLY_KIND_ORANGE_NEAR 3
#define FIREFLY_KIND_BLUE_NEAR 4
#define FIREFLY_KIND_ORANGE_ALT_NEAR 5

#define FIREFLY_ACTIVE_FLAG_ACTIVE 0x80
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

#define FIREFLY_LIGHT(state) (*(void **)((u8 *)(state) + FIREFLY_STATE_LIGHT))
#define FIREFLY_SPLINE_T(state) (*(f32 *)((u8 *)(state) + FIREFLY_STATE_SPLINE_T))
#define FIREFLY_SPLINE_SPEED(state) (*(f32 *)((u8 *)(state) + FIREFLY_STATE_SPLINE_SPEED))
#define FIREFLY_PROXIMITY_ALPHA(state) (*(f32 *)((u8 *)(state) + FIREFLY_STATE_PROXIMITY_ALPHA))
#define FIREFLY_PLAYER_RADIUS(state) (*(f32 *)((u8 *)(state) + FIREFLY_STATE_PLAYER_RADIUS))
#define FIREFLY_KIND(state) (*(u8 *)((u8 *)(state) + FIREFLY_STATE_KIND))
#define FIREFLY_PATH_AGE(state) (*(u8 *)((u8 *)(state) + FIREFLY_STATE_PATH_AGE))
#define FIREFLY_ACTIVE_FLAGS(state) (*(u8 *)((u8 *)(state) + FIREFLY_STATE_ACTIVE_FLAGS))
#define FIREFLY_DESPAWN_TIMER(state) (*(f32 *)((u8 *)(state) + FIREFLY_STATE_DESPAWN_TIMER))
#define FIREFLY_FLAGS(state) (*(u8 *)((u8 *)(state) + FIREFLY_STATE_FLAGS))
#define FIREFLY_MESSAGE_PARAM(state) (*(s16 *)((u8 *)(state) + FIREFLY_STATE_MESSAGE_PARAM))

typedef struct FireFlyState {
    void *light;
    f32 splineX[4];
    f32 splineY[4];
    f32 splineZ[4];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 splineT;
    f32 splineSpeed;
    f32 proximityAlpha;
    f32 playerRadius;
    u8 pad50[0x66 - 0x50];
    u8 kind;
    u8 pad67;
    u8 pathAge;
    u8 pad69[0x6C - 0x69];
    u8 activeFlags;
    u8 pad6D[0x70 - 0x6D];
    f32 despawnTimer;
    u8 activateDelay[0x7C - 0x74];
    u8 flags;
    u8 pad7D[0x80 - 0x7D];
    s16 messageParam;
    u8 pad82[FIREFLY_EXTRA_SIZE - 0x82];
} FireFlyState;

typedef struct FireFlyActiveBits {
    u8 active : 1;
} FireFlyActiveBits;

typedef struct FireFlyMapData {
    u8 pad00[0x1A];
    s16 startDelayKind;
    u8 pad1C[0x20 - 0x1C];
    s16 requiredGameBit;
} FireFlyMapData;

STATIC_ASSERT(sizeof(FireFlyState) == FIREFLY_EXTRA_SIZE);
STATIC_ASSERT(offsetof(FireFlyState, light) == FIREFLY_STATE_LIGHT);
STATIC_ASSERT(offsetof(FireFlyState, splineX) == FIREFLY_STATE_SPLINE_X0);
STATIC_ASSERT(offsetof(FireFlyState, splineY) == FIREFLY_STATE_SPLINE_Y0);
STATIC_ASSERT(offsetof(FireFlyState, splineZ) == FIREFLY_STATE_SPLINE_Z0);
STATIC_ASSERT(offsetof(FireFlyState, targetX) == FIREFLY_STATE_TARGET_X);
STATIC_ASSERT(offsetof(FireFlyState, splineT) == FIREFLY_STATE_SPLINE_T);
STATIC_ASSERT(offsetof(FireFlyState, kind) == FIREFLY_STATE_KIND);
STATIC_ASSERT(offsetof(FireFlyState, activeFlags) == FIREFLY_STATE_ACTIVE_FLAGS);
STATIC_ASSERT(offsetof(FireFlyState, despawnTimer) == FIREFLY_STATE_DESPAWN_TIMER);
STATIC_ASSERT(offsetof(FireFlyState, activateDelay) == FIREFLY_STATE_ACTIVATE_DELAY);
STATIC_ASSERT(offsetof(FireFlyState, flags) == FIREFLY_STATE_FLAGS);
STATIC_ASSERT(offsetof(FireFlyState, messageParam) == FIREFLY_STATE_MESSAGE_PARAM);


#pragma peephole off
#pragma scheduling off
void FireFlyFn_801f4f88(int obj)
{
    FireFlyState *state = ((GameObject *)obj)->extra;
    int player = (int)Obj_GetPlayerObject();
    if ((int)*(u8 *)(obj + 0x36) < FIREFLY_ALPHA_OPAQUE) {
        int v = (int)(lbl_803E5EDC * timeDelta + (f32)(int)*(u8 *)(obj + 0x36));
        if (v > FIREFLY_ALPHA_OPAQUE) v = FIREFLY_ALPHA_OPAQUE;
        *(u8 *)(obj + 0x36) = v;
    }
    if (FIREFLY_SPLINE_T(state) > lbl_803E5EB4) {
        FIREFLY_SPLINE_T(state) = FIREFLY_SPLINE_T(state) - lbl_803E5EB4;
        if (FIREFLY_PATH_AGE(state) >= 4) {
            FIREFLY_PATH_AGE(state) += 1;
        } else {
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
        FIREFLY_SPLINE_SPEED(state) = lbl_803E5ED8 * (f32)(int)randomGetRange(0xa0, 0xb4);
        state->splineX[3] = state->targetX;
        state->splineY[3] = state->targetY;
        state->splineZ[3] = state->targetZ;
    }
    ((GameObject *)obj)->anim.localPosX = ((f32 (*)(f32 *, f32, int))Curve_EvalBSpline)(state->splineX, FIREFLY_SPLINE_T(state), 0);
    ((GameObject *)obj)->anim.localPosY = ((f32 (*)(f32 *, f32, int))Curve_EvalBSpline)(state->splineY, FIREFLY_SPLINE_T(state), 0);
    ((GameObject *)obj)->anim.localPosZ = ((f32 (*)(f32 *, f32, int))Curve_EvalBSpline)(state->splineZ, FIREFLY_SPLINE_T(state), 0);
    FIREFLY_SPLINE_T(state) = FIREFLY_SPLINE_SPEED(state) * timeDelta + FIREFLY_SPLINE_T(state);
    *(s16 *)obj = (s16)getAngle(((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX,
                                 ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ);
    if (FIREFLY_KIND(state) == FIREFLY_KIND_BLUE_MAIN || FIREFLY_KIND(state) == FIREFLY_KIND_BLUE_NEAR) {
        ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(
            obj, FIREFLY_PARTFX_BLUE_TRAIL, 0, FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, 0);
    } else {
        ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(
            obj, FIREFLY_PARTFX_ORANGE_TRAIL, 0, FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, 0);
    }
    if (Vec_xzDistance((f32 *)(player + 0x18), (f32 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x8)) <
        FIREFLY_PLAYER_RADIUS(state)) {
        f32 lim;
        if (FIREFLY_KIND(state) == FIREFLY_KIND_BLUE_NEAR) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(
                obj, FIREFLY_PARTFX_BLUE_NEAR, 0, FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, 0);
        } else if (FIREFLY_KIND(state) == FIREFLY_KIND_ORANGE_NEAR) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(
                obj, FIREFLY_PARTFX_ORANGE_NEAR, 0, FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, 0);
        } else if (FIREFLY_KIND(state) == FIREFLY_KIND_ORANGE_ALT_NEAR) {
            ((void (*)(int, int, int, int, int, int))((void **)*gPartfxInterface)[2])(
                obj, FIREFLY_PARTFX_ORANGE_NEAR, 0, FIREFLY_PARTFX_KIND, FIREFLY_PARTFX_INVALID_HANDLE, 0);
        }
        if (FIREFLY_PROXIMITY_ALPHA(state) < (lim = lbl_803E5EE0)) {
            FIREFLY_PROXIMITY_ALPHA(state) = FIREFLY_PROXIMITY_ALPHA(state) + lbl_803E5EE4;
            if (FIREFLY_PROXIMITY_ALPHA(state) > lim) {
                FIREFLY_PROXIMITY_ALPHA(state) = lim;
            }
        }
    } else {
        f32 lim;

        if (FIREFLY_PROXIMITY_ALPHA(state) > (lim = lbl_803E5EE8)) {
            FIREFLY_PROXIMITY_ALPHA(state) = FIREFLY_PROXIMITY_ALPHA(state) - lbl_803E5EE4;
            if (FIREFLY_PROXIMITY_ALPHA(state) < lim) {
                FIREFLY_PROXIMITY_ALPHA(state) = lim;
            }
        }
    }
    {
        f32 dy = ((GameObject *)obj)->anim.localPosY - *(f32 *)(player + 0x10);
        if ((FIREFLY_FLAGS(state) & FIREFLY_FLAG_PLAYER_TOUCHED) == 0) {
        if (dy < lbl_803E5EEC && dy > lbl_803E5EC4) {
            if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < lbl_803E5EF0) {
                FIREFLY_FLAGS(state) = (u8)(FIREFLY_FLAGS(state) | FIREFLY_FLAG_PLAYER_TOUCHED);
                if (GameBit_Get(FIREFLY_FIRST_TOUCH_BIT) == 0) {
                    FIREFLY_MESSAGE_PARAM(state) = -1;
                    ObjMsg_SendToObject(player, FIREFLY_MESSAGE_TALK, obj, &state->messageParam);
                    GameBit_Set(FIREFLY_FIRST_TOUCH_BIT, 1);
                } else {
                    FireFlyState *st = ((GameObject *)obj)->extra;
                    ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | FIREFLY_OBJFLAG_HIDDEN);
                    FIREFLY_DESPAWN_TIMER(st) = lbl_803E5EA8;
                    gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
                    gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
                    Sfx_PlayFromObject(obj, SFXen_treadlpc);
                }
            }
        }
    }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void firefly_free(int obj)
{
    FireFlyState *state = ((GameObject *)obj)->extra;

    modelLightStruct_freeSlot(state);
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void firefly_update(int obj)
{
    FireFlyState *state;
    FireFlyMapData *def;
    int msg[2];
    int isActive;
    f32 despawnTimer;

    state = ((GameObject *)obj)->extra;
    def = *(FireFlyMapData **)&((GameObject *)obj)->anim.placementData;
    despawnTimer = lbl_803E5EA8;
    while (ObjMsg_Pop(obj, msg, 0, 0) != 0) {
        switch (msg[0]) {
        case FIREFLY_MESSAGE_DESPAWN:
            ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | FIREFLY_OBJFLAG_HIDDEN);
            ((FireFlyState *)((GameObject *)obj)->extra)->despawnTimer = despawnTimer;
            gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
            gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
            Sfx_PlayFromObject(obj, SFXen_treadlpc);
            break;
        }
    }

    if (((FireFlyActiveBits *)&state->activeFlags)->active == 0) {
        isActive = 0;
        if ((def->requiredGameBit == -1) || ((u32)GameBit_Get(def->requiredGameBit) != 0)) {
            isActive = 1;
        }
        ((FireFlyActiveBits *)&state->activeFlags)->active = isActive;
        if (((FireFlyActiveBits *)&state->activeFlags)->active != 0) {
            state->light = (void *)modelLightStruct_createPointLight(obj, 100, 0xFF, 100, 0);
        }
    } else {
        if (timerCountDown(state->activateDelay) != 0) {
            state->despawnTimer = lbl_803E5EA8;
        }
        if (state->despawnTimer > lbl_803E5EC4) {
            state->despawnTimer -= timeDelta;
            if (state->despawnTimer > (f32)lbl_803DC128) {
                itemPickupDoParticleFx(obj, lbl_803E5EDC, 4, 5);
            }
            if (state->despawnTimer <= lbl_803E5EC4) {
                Obj_FreeObject(obj);
            }
        } else {
            FireFlyFn_801f4f88(obj);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void firefly_init(int obj, int def)
{
    FireFlyState *state;
    FireFlyMapData *mapData;

    state = ((GameObject *)obj)->extra;
    mapData = (FireFlyMapData *)def;
    fn_801F4C28(obj, state);
    *(u8 *)(obj + 0x36) = 0;
    ((GameObject *)obj)->animEventCallback = fn_801F4C04;
    ObjMsg_AllocQueue(obj, 1);
    storeZeroToFloatParam(state->activateDelay);
    if (mapData->startDelayKind == 0x7f) {
        s16toFloat(state->activateDelay, 0xe10);
    }
}
#pragma scheduling reset
#pragma peephole reset

/* Pattern wrappers. */
int firefly_getExtraSize(void) { return FIREFLY_EXTRA_SIZE; }
int firefly_getObjectTypeId(void) { return 0x0; }
void firefly_render(void) {}
void firefly_hitDetect(void) {}
void firefly_release(void) {}
void firefly_initialise(void) {}
