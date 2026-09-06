/*
 * FireFly (DLL 0x020B) - the collectible fireflies.
 *
 * A firefly sleeps until its required game bit (if any) is set, then
 * lights up (a 100/255/100 point light) and wanders a cubic B-spline
 * whose control points are re-targeted by firefly_pickWanderTarget, trailing blue
 * or orange particles by kind. Flying near
 * the player brightens its glow. The first touch anywhere sends the
 * firefly talk message to the player (game bit 0xD28); later touches
 * (or the talk's despawn-message reply) collect it - the lantern
 * counter bits 0x13D/0x5D6 increment, the model hides, sparkles
 * briefly and frees itself 180 frames later.
 */
#include "dlls/object_descriptor.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve_eval.h"
#include "main/dll/dll_020B_firefly.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/model_light.h"
#include "main/obj_message.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/maketex_timer_api.h"
#include "sys/objects/lifecycle.h"

/* Per-frame angular step bounds (1/65536-turn units). */
#define FIREFLY_ANGLE_STEP_MIN 0x1f4
#define FIREFLY_ANGLE_STEP_MAX 0x5dc

#define FIREFLY_ANGLE_ADVANCE_MIN 0xbb8
#define FIREFLY_ANGLE_ADVANCE_MAX 0x1388
#define FIREFLY_ANGLE_INIT_MAX    0xfde8
#define FIREFLY_AMP_MAX           0x3c
#define FIREFLY_RADIUS_MARGIN     0x14

static const f32 sFireFlyDespawnDelay[] = {180.0f};

int firefly_animEventCallback(GameObject* obj) {
    firefly_activeTick(obj);
    return 0;
}

void firefly_initFlightRec(GameObject* obj, FireFlyFlightState* record) {
    record->splineX[0] = obj->anim.localPosX;
    record->splineY[0] = obj->anim.localPosY;
    record->splineZ[0] = obj->anim.localPosZ;
    record->splineX[1] = obj->anim.localPosX;
    record->splineY[1] = obj->anim.localPosY;
    record->splineZ[1] = obj->anim.localPosZ;
    record->splineX[2] = obj->anim.localPosX;
    record->splineY[2] = obj->anim.localPosY;
    record->splineZ[2] = obj->anim.localPosZ;
    record->splineX[3] = obj->anim.localPosX;
    record->splineY[3] = obj->anim.localPosY;
    record->splineZ[3] = obj->anim.localPosZ;
    record->splineSpeed = 0.01f;
    record->proximityAlpha = 0.0275f;
    record->splineT = 1.0f;
    record->pathAge = 0;
    record->unk67 = 0;
    record->angleStep = randomGetRange(FIREFLY_ANGLE_STEP_MIN, FIREFLY_ANGLE_STEP_MAX);
    record->angle = randomGetRange(0, FIREFLY_ANGLE_INIT_MAX);
    record->ampMax = FIREFLY_AMP_MAX;
    record->kind = 4;
    record->playerRadius = 50.0f;
    record->radius = 40.0f;
    record->posX = obj->anim.localPosX;
    record->posY = obj->anim.localPosY;
    record->posZ = obj->anim.localPosZ;
    record->firstFrame = 1;
    record->unk78 = 1200.0f;
}

void firefly_pickWanderTarget(GameObject* obj, FireFlyFlightState* record) {
    struct {
        s16 rotZ;
        s16 rotX;
        s16 rotY;
        f32 scratch0;
        f32 scratch1;
        f32 scratch2;
        f32 scratch3;
    } rot;

    record->targetX = 0.0f;
    if (record->firstFrame != 0) {
        record->targetY = (f32)(s32)record->ampMax;
        record->firstFrame = 0;
    } else {
        record->targetY = (f32)(s32)randomGetRange(0, record->ampMax);
    }
    if (record->radius < 21.0f) {
        record->targetZ = 0.0f;
    } else {
        record->targetZ = record->radius - (f32)(s32)randomGetRange(FIREFLY_RADIUS_MARGIN, (s16)(s32)record->radius);
    }
    record->angle += (s16)randomGetRange(FIREFLY_ANGLE_ADVANCE_MIN, FIREFLY_ANGLE_ADVANCE_MAX);
    rot.scratch1 = 0.0f;
    rot.scratch2 = 0.0f;
    rot.scratch3 = 0.0f;
    rot.scratch0 = 1.0f;
    rot.rotY = 0;
    rot.rotX = 0;
    rot.rotZ = record->angle;
    vecRotateZXY((s16*)&rot, &record->targetX);
    record->targetX += record->posX;
    record->targetY += record->posY;
    record->targetZ += record->posZ;
}

void firefly_shiftPathHistory(GameObject* obj, FireFlyFlightState* record) {
    record->splineX[0] = record->splineX[1];
    record->splineY[0] = record->splineY[1];
    record->splineZ[0] = record->splineZ[1];
    record->splineX[1] = record->splineX[2];
    record->splineY[1] = record->splineY[2];
    record->splineZ[1] = record->splineZ[2];
    record->splineX[2] = record->splineX[3];
    record->splineY[2] = record->splineY[3];
    record->splineZ[2] = record->splineZ[3];
    record->splineSpeed = 0.00015f * (f32)(s32)randomGetRange(0xa0, 0xb4);
    record->splineX[3] = record->targetX;
    record->splineY[3] = record->targetY;
    record->splineZ[3] = record->targetZ;
}

s16 gFireFlyDespawnThreshold = 0xAA;

/* state->kind - trail/near particle-fx colour */
#define FIREFLY_KIND_BLUE_MAIN       1
#define FIREFLY_KIND_ORANGE_NEAR     3
#define FIREFLY_KIND_BLUE_NEAR       4
#define FIREFLY_KIND_ORANGE_ALT_NEAR 5

/* state->flags */
#define FIREFLY_FLAG_PLAYER_TOUCHED 0x01

#define FIREFLY_ALPHA_OPAQUE        0xff
#define FIREFLY_MESSAGE_TALK        0x7000a
#define FIREFLY_MESSAGE_DESPAWN     0x7000b
#define FIREFLY_FIRST_TOUCH_BIT     0xd28
#define FIREFLY_COLLECT_COUNT_BIT_A 0x13d
#define FIREFLY_COLLECT_COUNT_BIT_B 0x5d6

#define FIREFLY_PARTFX_BLUE_TRAIL     0x1a0
#define FIREFLY_PARTFX_ORANGE_TRAIL   0x1bd
#define FIREFLY_PARTFX_BLUE_NEAR      0x19f
#define FIREFLY_PARTFX_ORANGE_NEAR    0x1bc
#define FIREFLY_PARTFX_KIND           1
#define FIREFLY_PARTFX_INVALID_HANDLE -1

/* Fade in, advance the B-spline, spawn trail effects, and detect touch. */
void firefly_activeTick(GameObject* obj) {
    FireFlyState* state = obj->extra;
    ObjAnimComponent* objAnim = &obj->anim;
    int player = (int)Obj_GetPlayerObject();
    if ((int)objAnim->alpha < FIREFLY_ALPHA_OPAQUE) {
        int newAlpha = (int)(2.0f * timeDelta + (f32)(int)objAnim->alpha);
        if (newAlpha > FIREFLY_ALPHA_OPAQUE) {
            newAlpha = FIREFLY_ALPHA_OPAQUE;
        }
        objAnim->alpha = newAlpha;
    }
    if (state->flight.splineT > 1.0f) {
        state->flight.splineT = state->flight.splineT - 1.0f;
        if (state->flight.pathAge >= 4) {
            state->flight.pathAge += 1;
        } else {
            firefly_pickWanderTarget(obj, &state->flight);
        }
        state->flight.splineX[0] = state->flight.splineX[1];
        state->flight.splineY[0] = state->flight.splineY[1];
        state->flight.splineZ[0] = state->flight.splineZ[1];
        state->flight.splineX[1] = state->flight.splineX[2];
        state->flight.splineY[1] = state->flight.splineY[2];
        state->flight.splineZ[1] = state->flight.splineZ[2];
        state->flight.splineX[2] = state->flight.splineX[3];
        state->flight.splineY[2] = state->flight.splineY[3];
        state->flight.splineZ[2] = state->flight.splineZ[3];
        state->flight.splineSpeed = 0.00015f * randomGetRange(0xa0, 0xb4);
        state->flight.splineX[3] = state->flight.targetX;
        state->flight.splineY[3] = state->flight.targetY;
        state->flight.splineZ[3] = state->flight.targetZ;
    }
    obj->anim.localPosX = Curve_EvalBSpline(state->flight.splineX, state->flight.splineT, 0);
    obj->anim.localPosY = Curve_EvalBSpline(state->flight.splineY, state->flight.splineT, 0);
    obj->anim.localPosZ = Curve_EvalBSpline(state->flight.splineZ, state->flight.splineT, 0);
    state->flight.splineT = state->flight.splineSpeed * timeDelta + state->flight.splineT;
    obj->anim.rotX =
        getAngle(obj->anim.localPosX - obj->anim.previousLocalPosX, obj->anim.localPosZ - obj->anim.previousLocalPosZ);
    if (state->flight.kind == FIREFLY_KIND_BLUE_MAIN || state->flight.kind == FIREFLY_KIND_BLUE_NEAR) {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, FIREFLY_PARTFX_BLUE_TRAIL, NULL, FIREFLY_PARTFX_KIND,
                          FIREFLY_PARTFX_INVALID_HANDLE, NULL);
    } else {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_TRAIL, NULL, FIREFLY_PARTFX_KIND,
                          FIREFLY_PARTFX_INVALID_HANDLE, NULL);
    }
    /* Compare against the player's world position. */
    if (Vec_xzDistance((f32*)(player + 0x18), &obj->anim.placement->posX) < state->flight.playerRadius) {
        f32 maxAlpha;
        f32 curAlpha;
        if (state->flight.kind == FIREFLY_KIND_BLUE_NEAR) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, FIREFLY_PARTFX_BLUE_NEAR, NULL, FIREFLY_PARTFX_KIND,
                              FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        } else if (state->flight.kind == FIREFLY_KIND_ORANGE_NEAR) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_NEAR, NULL, FIREFLY_PARTFX_KIND,
                              FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        } else if (state->flight.kind == FIREFLY_KIND_ORANGE_ALT_NEAR) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, FIREFLY_PARTFX_ORANGE_NEAR, NULL, FIREFLY_PARTFX_KIND,
                              FIREFLY_PARTFX_INVALID_HANDLE, NULL);
        }
        if ((curAlpha = state->flight.proximityAlpha) < (maxAlpha = 0.003f)) {
            state->flight.proximityAlpha += 0.00001f;
            if (state->flight.proximityAlpha > maxAlpha) {
                state->flight.proximityAlpha = maxAlpha;
            }
        }
    } else {
        f32 minAlpha;
        f32 curAlpha;

        if ((curAlpha = state->flight.proximityAlpha) > (minAlpha = 0.001f)) {
            state->flight.proximityAlpha = curAlpha - 0.00001f;
            if (state->flight.proximityAlpha < minAlpha) {
                state->flight.proximityAlpha = minAlpha;
            }
        }
    }
    {
        f32 dy = obj->anim.localPosY - ((GameObject*)player)->anim.localPosY;
        if ((state->flags & FIREFLY_FLAG_PLAYER_TOUCHED) == 0) {
            if (dy < 35.0f && dy > 0.0f) {
                if (getXZDistanceSquared(&obj->anim.worldPosX, (f32*)(player + 0x18)) < 225.0f) {
                    state->flags = (u8)(state->flags | FIREFLY_FLAG_PLAYER_TOUCHED);
                    if (mainGetBit(FIREFLY_FIRST_TOUCH_BIT) == 0) {
                        state->messageParam = -1;
                        ObjMsg_SendToObject((void*)player, FIREFLY_MESSAGE_TALK, obj, (u32)&state->messageParam);
                        mainSetBits(FIREFLY_FIRST_TOUCH_BIT, 1);
                    } else {
                        FireFlyState* st = obj->extra;
                        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
                        st->flight.despawnTimer = sFireFlyDespawnDelay[0];
                        gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
                        gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
                        Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                    }
                }
            }
        }
    }
}

int firefly_getExtraSize(void) {
    return sizeof(FireFlyState);
}

int firefly_getObjectTypeId(void) {
    return 0x0;
}

void firefly_free(GameObject* obj) {
    FireFlyState* state = obj->extra;

    modelLightStruct_freeSlot((ModelLightStruct**)&state->flight.ownerData.pointLight);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void firefly_render(void) {
}

void firefly_hitDetect(void) {
}

void firefly_update(GameObject* obj) {
    FireFlyState* state;
    FireFlyMapData* def;
    int msg[2];
    int isActive;

    state = obj->extra;
    def = (FireFlyMapData*)obj->anim.placement;
    while (ObjMsg_Pop(obj, (u32*)msg, NULL, NULL) != 0) {
        switch (msg[0]) {
        case FIREFLY_MESSAGE_DESPAWN: {
            FireFlyState* st = obj->extra;
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            st->flight.despawnTimer = sFireFlyDespawnDelay[0];
            gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_A);
            gameBitIncrement(FIREFLY_COLLECT_COUNT_BIT_B);
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            break;
        }
        }
    }

    if (state->flight.activeFlags.active == 0) {
        isActive = 0;
        if ((def->requiredGameBit == -1) || (mainGetBit(def->requiredGameBit) != 0)) {
            isActive = 1;
        }
        state->flight.activeFlags.active = isActive;
        if (state->flight.activeFlags.active != 0) {
            state->flight.ownerData.pointLight = modelLightStruct_createPointLight((void*)obj, 100, 0xFF, 100, 0);
        }
    } else {
        if (timerCountDown(&state->flight.lifeTimer) != 0) {
            state->flight.despawnTimer = sFireFlyDespawnDelay[0];
        }
        if (state->flight.despawnTimer > 0.0f) {
            state->flight.despawnTimer -= timeDelta;
            /* The retail threshold is 170 frames. */
            if (state->flight.despawnTimer > gFireFlyDespawnThreshold) {
                itemPickupDoParticleFx(obj, 2.0f, 4, 5);
            }
            if (state->flight.despawnTimer <= 0.0f) {
                Obj_FreeObject(obj);
            }
        } else {
            firefly_activeTick(obj);
        }
    }
}

void firefly_init(GameObject* obj, FireFlyMapData* mapData) {
    FireFlyState* state;

    state = obj->extra;
    firefly_initFlightRec(obj, &state->flight);
    obj->anim.alpha = 0;
    obj->animEventCallback = firefly_animEventCallback;
    ObjMsg_AllocQueue(obj, 1);
    storeZeroToFloatParam(&state->flight.lifeTimer);
    if (mapData->variantParam == 0x7f) {
        s16toFloat(&state->flight.lifeTimer, 0xe10);
    }
}

void firefly_release(void) {
}

void firefly_initialise(void) {
}

ObjectDescriptor gFireFlyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)firefly_initialise,
    (ObjectDescriptorCallback)firefly_release,
    0,
    (ObjectDescriptorCallback)firefly_init,
    (ObjectDescriptorCallback)firefly_update,
    (ObjectDescriptorCallback)firefly_hitDetect,
    (ObjectDescriptorCallback)firefly_render,
    (ObjectDescriptorCallback)firefly_free,
    (ObjectDescriptorCallback)firefly_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)firefly_getExtraSize,
};
