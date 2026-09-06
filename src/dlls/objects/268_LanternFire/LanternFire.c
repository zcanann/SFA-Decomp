#include "dlls/objects/268_LanternFire.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve_eval.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gameloop_gamebit_api.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define LANTERN_FIREFLY_OBJECT_GROUP              0x30
#define LANTERN_FIREFLY_ACTIVE_COUNT_GAMEBIT      0x698
#define LANTERN_FIREFLY_PLAYER_FOLLOW_MOTION_MODE 1
#define LANTERN_FIREFLY_LIGHT_STATE_A             1
#define LANTERN_FIREFLY_LIGHT_STATE_B             4
#define LANTERN_FIREFLY_EFFECT_GLOW_A             0x19F
#define LANTERN_FIREFLY_EFFECT_GLOW_B             0x1A0
#define LANTERN_FIREFLY_EFFECT_TRAIL              0x1BD
#define LANTERN_FIREFLY_LIGHT_FADE_START          180
#define LANTERN_FIREFLY_SEGMENT_DELAY_START       4
#define LANTERN_FIREFLY_SEGMENT_DELAY_END         7
#define LANTERN_FIREFLY_DRIFT_RANDOM_MIN_Z        20
#define LANTERN_FIREFLY_ANGLE_DELTA_MIN           3000
#define LANTERN_FIREFLY_ANGLE_DELTA_MAX           5000
#define LANTERN_FIREFLY_RANDOM_SPEED_MIN          60
#define LANTERN_FIREFLY_RANDOM_SPEED_MAX          90
#define LANTERN_FIREFLY_RANDOM_PERIOD_MIN         500
#define LANTERN_FIREFLY_RANDOM_PERIOD_MAX         1500
#define LANTERN_FIREFLY_RANDOM_ANGLE_MAX          0xFDE8
#define LANTERN_FIREFLY_DEFAULT_WANDER_RANGE      4
#define LANTERN_FIREFLY_LIGHT_ANGLE_SHIFT         11
#define LANTERN_FIREFLY_IS_FOLLOWING_PLAYER(state)                                                          \
    ((state)->modeFlags.motionMode == LANTERN_FIREFLY_PLAYER_FOLLOW_MOTION_MODE)

static f32 sLanternFireFlyEffectSpawnTimerThreshold = 60.0f;
static u8 sLanternFireFlyLightActive;

static void LanternFireFly_advanceControlRing(GameObject* obj);

STATIC_ASSERT(sizeof(LanternFireFlyControlBits) == 0x1);

extern f32 gLanternFireFlyLightNearDistance;
extern f32 gLanternFireFlyLightFarDistance;
extern f32 gLanternFireFlyUnitValue;
extern f32 gLanternFireFlyInitialTargetHeightOffset;
extern f32 gLanternFireFlyPlayerAnchorHeightOffset;

void LanternFireFly_setAnchor(GameObject* obj, f32 anchorX, f32 anchorY, f32 anchorZ) {
    LanternFireFlyState* state = obj->extra;
    state->anchorX = anchorX;
    state->anchorY = anchorY;
    state->anchorZ = anchorZ;
}

void LanternFireFly_releaseFromLantern(GameObject* obj) {
    LanternFireFlyState* state;
    LanternFireFlyPlacement* placement;
    GameObject* player;
    f32 targetPosition[3];
    f32* targetPositionPtr = targetPosition;
    f32 playerX;
    f32 anchorY;

    state = obj->extra;
    placement = (LanternFireFlyPlacement*)obj->anim.placementData;
    state->wanderRange = placement->wanderRange;
    state->stateId = placement->stateId;
    state->unk4C = gLanternFireFlyUnitValue;
    state->driftRangeZ = (f32)(int)placement->driftRangeZ;
    state->unk6F = 0;
    Obj_SetParent(obj, NULL, 1);
    player = Obj_GetPlayerObject();
    playerX = player->anim.worldPosX;
    targetPositionPtr[0] = playerX;
    targetPositionPtr[1] = player->anim.worldPosY;
    targetPositionPtr[2] = player->anim.worldPosZ;
    targetPositionPtr[1] = player->anim.worldPosY + gLanternFireFlyInitialTargetHeightOffset;
    anchorY = gLanternFireFlyPlayerAnchorHeightOffset + player->anim.worldPosY;
    {
        LanternFireFlyState* targetState = obj->extra;
        targetState->anchorX = playerX;
        targetState->anchorY = anchorY;
        targetState->anchorZ = targetPositionPtr[2];
        targetState = obj->extra;
        targetPositionPtr[0] = targetPositionPtr[0] - targetState->anchorX;
        targetPositionPtr[1] = targetPositionPtr[1] - targetState->anchorY;
        targetPositionPtr[2] = targetPositionPtr[2] - targetState->anchorZ;
        targetState->offsetX = targetPositionPtr[0];
        targetState->offsetY = targetPositionPtr[1];
        targetState->offsetZ = targetPositionPtr[2];
        targetState->segmentIndex = LANTERN_FIREFLY_SEGMENT_DELAY_START;
    }
    LanternFireFly_advanceControlRing(obj);
    LanternFireFly_advanceControlRing(obj);
    LanternFireFly_advanceControlRing(obj);
    LanternFireFly_advanceControlRing(obj);
    LanternFireFly_advanceControlRing(obj);
    LanternFireFly_advanceControlRing(obj);
    state->modeFlags.motionMode = LANTERN_FIREFLY_PLAYER_FOLLOW_MOTION_MODE;
    state->timer = placement->timer;
    gameBitIncrement(LANTERN_FIREFLY_ACTIVE_COUNT_GAMEBIT);
}

void LanternFireFly_setTargetPosition(GameObject* obj, f32* vec) {
    LanternFireFlyState* state = obj->extra;
    vec[0] = vec[0] - state->anchorX;
    vec[1] = vec[1] - state->anchorY;
    vec[2] = vec[2] - state->anchorZ;
    state->offsetX = vec[0];
    state->offsetY = vec[1];
    state->offsetZ = vec[2];
    state->segmentIndex = LANTERN_FIREFLY_SEGMENT_DELAY_START;
}

static void LanternFireFly_pickDriftOffset(GameObject* obj) {
    MatrixTransform transform;
    LanternFireFlyState* state;
    s16 angleDelta;
    f32 fz;

    state = obj->extra;
    state->offsetX = 0.0f;
    state->offsetY = randomGetRange(-state->wanderRange, state->wanderRange);
    if (state->driftRangeZ < 21.0f) {
        state->offsetZ = 0.0f;
    } else {
        state->offsetZ =
            state->driftRangeZ - randomGetRange(LANTERN_FIREFLY_DRIFT_RANDOM_MIN_Z, (s16)(int)state->driftRangeZ);
    }
    angleDelta = randomGetRange(LANTERN_FIREFLY_ANGLE_DELTA_MIN, LANTERN_FIREFLY_ANGLE_DELTA_MAX);
    state->randomAngle += angleDelta;
    fz = 0.0f;
    transform.x = fz;
    transform.y = fz;
    transform.z = fz;
    transform.scale = gLanternFireFlyUnitValue;
    transform.rotZ = 0;
    transform.rotY = 0;
    transform.rotX = state->randomAngle;
    vecRotateZXY(&transform.rotX, &state->offsetX);
}

static void LanternFireFly_advanceControlRing(GameObject* obj) {
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
    if (state->modeFlags.motionMode == LANTERN_FIREFLY_PLAYER_FOLLOW_MOTION_MODE) {
        GameObject* player = Obj_GetPlayerObject();
        state->speed = 0.0015f * Vec_distance((void*)&obj->anim.worldPosX, &player->anim.worldPosX) + 0.0001f;
    } else {
        state->speed =
            0.0015f * (f32)(s32)randomGetRange(LANTERN_FIREFLY_RANDOM_SPEED_MIN, LANTERN_FIREFLY_RANDOM_SPEED_MAX);
    }
    state->controlX[3] = state->offsetX;
    state->controlY[3] = state->offsetY;
    state->controlZ[3] = state->offsetZ;
}

int LanternFireFly_getExtraSize(void) {
    return sizeof(LanternFireFlyState);
}

int LanternFireFly_getObjectTypeId(void) {
    return 0;
}

void LanternFireFly_free(GameObject* obj, int flag) {
    LanternFireFlyState* state = obj->extra;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    if (flag == 0 && state->light != NULL && state->modeFlags.motionMode != LANTERN_FIREFLY_PLAYER_FOLLOW_MOTION_MODE) {
        sLanternFireFlyLightActive = 0;
    }
    objFreeObjectType(obj, LANTERN_FIREFLY_OBJECT_GROUP);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void LanternFireFly_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    s32 visibleValue = visible;
    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, gLanternFireFlyUnitValue);
    }
}

void LanternFireFly_hitDetect(void) {
}

void LanternFireFly_update(GameObject* obj) {
    LanternFireFlyState* state;
    GameObject* player;
    f32 velocity[3];
    f32* velocityPtr;
    f32 squaredZ;
    f32 squaredX;
    f32 squaredY;
    f32 stepScale;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;

    if (state->splineT > *(f32*)&gLanternFireFlyUnitValue) {
        state->splineT -= gLanternFireFlyUnitValue;
        if (state->segmentIndex >= LANTERN_FIREFLY_SEGMENT_DELAY_START) {
            if (state->segmentIndex != LANTERN_FIREFLY_SEGMENT_DELAY_END) {
                state->segmentIndex++;
            } else {
                state->segmentIndex = 0;
            }
        } else {
            LanternFireFly_pickDriftOffset(obj);
        }
        LanternFireFly_advanceControlRing(obj);
    }

    obj->anim.localPosX = state->anchorX + Curve_EvalBSpline(state->controlX, state->splineT, NULL);
    obj->anim.localPosY = state->anchorY + Curve_EvalBSpline(state->controlY, state->splineT, NULL);
    obj->anim.localPosZ = state->anchorZ + Curve_EvalBSpline(state->controlZ, state->splineT, NULL);

    if (LANTERN_FIREFLY_IS_FOLLOWING_PLAYER(state)) {
        state->speed = (f32)(0.0015f * Vec_distance((void*)&obj->anim.worldPosX,
                                                    &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) +
                             0.0001f);
    }
    state->splineT += state->speed * timeDelta;

    if ((state->stateId == LANTERN_FIREFLY_LIGHT_STATE_A || state->stateId == LANTERN_FIREFLY_LIGHT_STATE_B) &&
        LANTERN_FIREFLY_IS_FOLLOWING_PLAYER(state) && state->lightSpawned == 0) {
        ModelLightStruct* light;

        state->lightSpawned = 1;
        light = objCreateLight(obj, 1);
        if (light == NULL) {
            light = NULL;
        } else {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(light, 100, 0xff, 100, 0);
            modelLightStruct_setFieldBC(light, 1);
            modelLightStruct_setDistanceAttenuation(light, gLanternFireFlyLightNearDistance,
                                                    gLanternFireFlyLightFarDistance);
            modelLightStruct_setAffectsAabbLightSelection(light, 1);
        }
        state->light = light;
        if (!LANTERN_FIREFLY_IS_FOLLOWING_PLAYER(state)) {
            sLanternFireFlyLightActive = 1;
        }
    }

    velocityPtr = velocity;
    velocityPtr[0] = obj->anim.localPosX - obj->anim.previousLocalPosX;
    velocityPtr[1] = obj->anim.localPosY - obj->anim.previousLocalPosY;
    velocityPtr[2] = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
    squaredZ = velocityPtr[2] * velocityPtr[2];
    squaredX = velocityPtr[0] * velocityPtr[0];
    squaredY = velocityPtr[1] * velocityPtr[1];
    stepScale = sqrtf(squaredZ + (squaredX + squaredY));
    velocityPtr[0] = velocityPtr[0] * (stepScale = gLanternFireFlyUnitValue / (f32)((s32)(stepScale / 2.5f) + 1));
    velocityPtr[1] = velocityPtr[1] * stepScale;
    velocityPtr[2] = velocityPtr[2] * stepScale;

    if (LANTERN_FIREFLY_IS_FOLLOWING_PLAYER(state)) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_pk_lightcritter_lp);
        if ((f32)state->timer > sLanternFireFlyEffectSpawnTimerThreshold) {
            if (state->stateId == LANTERN_FIREFLY_LIGHT_STATE_A || state->stateId == LANTERN_FIREFLY_LIGHT_STATE_B) {
                (*gPartfxInterface)->spawnObject((void*)obj, LANTERN_FIREFLY_EFFECT_GLOW_A, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, LANTERN_FIREFLY_EFFECT_GLOW_B, NULL, 1, -1, NULL);
            } else {
                (*gPartfxInterface)->spawnObject((void*)obj, LANTERN_FIREFLY_EFFECT_TRAIL, NULL, 1, -1, NULL);
            }
        }
        if ((state->timer -= framesThisStep) < 0) {
            gameBitDecrement(LANTERN_FIREFLY_ACTIVE_COUNT_GAMEBIT);
            Obj_FreeObject(obj);
            return;
        } else {
            f32 worldZ;
            f32 worldY;
            LanternFireFlyState* refreshedState;

            worldZ = player->anim.worldPosZ;
            worldY = gLanternFireFlyPlayerAnchorHeightOffset + player->anim.worldPosY;
            refreshedState = (LanternFireFlyState*)obj->extra;
            refreshedState->anchorX = player->anim.worldPosX;
            refreshedState->anchorY = worldY;
            refreshedState->anchorZ = worldZ;
        }
        if (state->light != NULL && state->timer < LANTERN_FIREFLY_LIGHT_FADE_START) {
            f32 attenuation;

            attenuation = state->timer *
                          mathSinf((3.1415927f * (f32)(state->timer << LANTERN_FIREFLY_LIGHT_ANGLE_SHIFT)) / 32768.0f);
            Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_sc_commsbleep);
            modelLightStruct_setDistanceAttenuation(state->light, attenuation, 30.0f + attenuation);
        }
    } else {
        (*gPartfxInterface)->spawnObject((void*)obj, LANTERN_FIREFLY_EFFECT_GLOW_A, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, LANTERN_FIREFLY_EFFECT_GLOW_B, NULL, 1, -1, NULL);
    }
}

void LanternFireFly_init(GameObject* obj, LanternFireFlyPlacement* placement) {
    LanternFireFlyState* state;
    f32 zero;
    s16 randomValue;
    int zeroFlag;

    state = obj->extra;
    objAddObjectType(obj, LANTERN_FIREFLY_OBJECT_GROUP);

    zero = 0.0f;
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

    state->light = NULL;
    state->lightSpawned = 0;
    state->speed = 0.08f;
    state->unk48 = 0.0275f;
    state->splineT = gLanternFireFlyUnitValue;
    state->segmentIndex = 0;
    state->unk6B = 0;
    randomValue = randomGetRange(LANTERN_FIREFLY_RANDOM_PERIOD_MIN, LANTERN_FIREFLY_RANDOM_PERIOD_MAX);
    state->randomPeriod = randomValue;
    randomValue = randomGetRange(0, LANTERN_FIREFLY_RANDOM_ANGLE_MAX);
    state->randomAngle = randomValue;
    state->wanderRange = LANTERN_FIREFLY_DEFAULT_WANDER_RANGE;
    state->stateId = LANTERN_FIREFLY_LIGHT_STATE_B;
    state->unk4C = 0.0f;
    state->driftRangeZ = 5.0f;
    state->anchorX = placement->base.posX;
    state->anchorY = placement->base.posY;
    state->anchorZ = placement->base.posZ;
    zeroFlag = 0;
    state->unk6F = zeroFlag;
    state->modeFlags.motionMode = zeroFlag;
}

void LanternFireFly_release(void) {
}

void LanternFireFly_initialise(void) {
}

ObjectDescriptor13WithPadding gLanternFireFlyObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
        (ObjectDescriptorCallback)LanternFireFly_initialise,
        (ObjectDescriptorCallback)LanternFireFly_release,
        0,
        (ObjectDescriptorCallback)LanternFireFly_init,
        (ObjectDescriptorCallback)LanternFireFly_update,
        (ObjectDescriptorCallback)LanternFireFly_hitDetect,
        (ObjectDescriptorCallback)LanternFireFly_render,
        (ObjectDescriptorCallback)LanternFireFly_free,
        (ObjectDescriptorCallback)LanternFireFly_getObjectTypeId,
        LanternFireFly_getExtraSize,
        (ObjectDescriptorCallback)LanternFireFly_setTargetPosition,
        (ObjectDescriptorCallback)LanternFireFly_releaseFromLantern,
        (ObjectDescriptorCallback)LanternFireFly_setAnchor,
    },
    0,
};
