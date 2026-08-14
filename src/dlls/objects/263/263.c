/*
 * DLL 0x107 - unreachable wind-lift/blow-vent object (no OBJECTS.bin def
 * references it: retail cut content).
 */
#include "dlls/objects/263.h"

#include "dolphin/pad.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_state.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/object_render.h"
#include "main/pad.h"
#include "main/pad_api.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/obj_message.h"
#include "main/obj_query.h"
#include "main/objtype.h"

#define WINDLIFT107_HIT_VOLUME_SLOT     0xE
#define WINDLIFT107_OBJECT_GROUP_ID     0x10
#define WINDLIFT107_PARTICLE_EFFECT_ID  0x51C
#define WINDLIFT107_MESSAGE_BURST       0x60004  /* knocks the player back */
#define WINDLIFT107_MESSAGE_GRAB_OBJECT 0x100010 /* tells the player to hold this object */

#define WINDLIFT107_RESOURCE_91_ID  91
#define WINDLIFT107_RESOURCE_170_ID 170
#define WINDLIFT107_RESOURCE_COUNT  1

#define WINDLIFT107_BURST_EFFECT_ID     0xF
#define WINDLIFT107_EFFECT_SPAWN_MODE   2
#define WINDLIFT107_EFFECT_MODEL_ID     -1
#define WINDLIFT107_PARTICLE_SPAWN_MODE 1
#define WINDLIFT107_PARTICLE_RANDOM_MAX 2

#define WINDLIFT107_HIT_DISABLE_FRAMES  50
#define WINDLIFT107_RETURN_DELAY_FRAMES 500
#define WINDLIFT107_FLIGHT_FRAMES       800
#define WINDLIFT107_BURST_FRAMES        600
#define WINDLIFT107_DEFAULT_LEASH_RANGE 30
#define WINDLIFT107_COOLDOWN_SCALE      0x34BC0
#define WINDLIFT107_PLAYER_HOLD_MOVE    0x447

#define WINDLIFT107_CARRY_ANGLE           -0x8000
#define WINDLIFT107_THROW_INPUT_SCALE     0.75f
#define WINDLIFT107_THROW_VERTICAL_SPEED  2.2f
#define WINDLIFT107_THROW_FORWARD_SPEED   -2.2f
#define WINDLIFT107_TERMINAL_VELOCITY     -10.0f
#define WINDLIFT107_GLOW_FAST_THRESHOLD   60
#define WINDLIFT107_GLOW_ACTIVE_THRESHOLD 240
#define WINDLIFT107_GLOW_FAST_STEP        10
#define WINDLIFT107_GLOW_SLOW_STEP        5
#define WINDLIFT107_GLOW_WRAP             0x80
#define WINDLIFT107_GLOW_RED              200
#define WINDLIFT107_GLOW_GREEN            30
#define WINDLIFT107_GLOW_BLUE             30

#define WINDLIFT107_HIT_MASK                0x10
#define WINDLIFT107_CAPSULE_VERTICAL_MIN    -5
#define WINDLIFT107_CAPSULE_VERTICAL_MAX    10
#define WINDLIFT107_HIT_VOLUME_IDLE_STATE   1
#define WINDLIFT107_HIT_VOLUME_THROW_STATE  3
#define WINDLIFT107_BURST_ACTIVE_USER_STATE 2
#define WINDLIFT107_ROTATION_PARAM_SHIFT    8

typedef int (*WindLift107EffectSpawnFn)(GameObject* obj, int effectId, PartFxSpawnParams* params, int mode, int modelId,
                                        void* extraArg);

typedef struct WindLift107EffectVTable {
    u8 pad00[4];
    WindLift107EffectSpawnFn spawn;
} WindLift107EffectVTable;

typedef struct WindLift107EffectResource {
    WindLift107EffectVTable* vtable;
} WindLift107EffectResource;

STATIC_ASSERT(offsetof(WindLift107EffectVTable, spawn) == 0x4);
STATIC_ASSERT(sizeof(WindLift107EffectVTable) == 0x8);
STATIC_ASSERT(offsetof(WindLift107EffectResource, vtable) == 0x0);
STATIC_ASSERT(sizeof(WindLift107EffectResource) == 0x4);

static const f32 gWindLift107LaunchGravity = -0.12f;
static const f32 gWindLift107RadiusScale = 10.0f;
static const f32 gWindLift107DefaultRadius = 50.0f;

WindLift107EffectResource* gWindLift107Resource170;
WindLift107EffectResource* gWindLift107Resource91;

static void windLift107_finishSpitBurst(GameObject* obj, f32 playerDistance) {
    PartFxSpawnParams effectParams;
    WindLift107State* state;
    f32 zero;

    state = obj->extra;
    effectParams.scale = state->radius;
    gWindLift107Resource91->vtable->spawn(obj, WINDLIFT107_BURST_EFFECT_ID, NULL, WINDLIFT107_EFFECT_SPAWN_MODE,
                                          WINDLIFT107_EFFECT_MODEL_ID, NULL);
    gWindLift107Resource170->vtable->spawn(obj, 0, &effectParams, WINDLIFT107_EFFECT_SPAWN_MODE,
                                           WINDLIFT107_EFFECT_MODEL_ID, NULL);
    Sfx_PlayFromObject(obj, SFXTRIG_wp_crthit6);
    zero = 0.0f;
    obj->anim.velocityX = zero;
    obj->anim.velocityZ = zero;
    state->disableTimer = WINDLIFT107_HIT_DISABLE_FRAMES;
    state->flightTimer = WINDLIFT107_FLIGHT_FRAMES;
    state->throwState = WINDLIFT107_THROW_NONE;
    state->carryState = WINDLIFT107_CARRY_IDLE;
    obj->userData2 = 0;
    obj->userData1 = WINDLIFT107_BURST_ACTIVE_USER_STATE;
    ObjHits_EnableObject(obj);
    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    state->burstTimer = 0;
    if (playerDistance < state->radius) {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), WINDLIFT107_MESSAGE_BURST, obj, 0);
    }
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, state->radius, WINDLIFT107_CAPSULE_VERTICAL_MIN,
                               WINDLIFT107_CAPSULE_VERTICAL_MAX);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, WINDLIFT107_HIT_VOLUME_SLOT, WINDLIFT107_HIT_VOLUME_IDLE_STATE, 0);
    ObjHits_EnableObject(obj);
}

int windLift107_getExtraSize(void) {
    return sizeof(WindLift107State);
}

int windLift107_getObjectTypeId(void) {
    return 0;
}

void windLift107_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gWindLift107Resource91);
    gWindLift107Resource91 = NULL;
    Resource_Release(gWindLift107Resource170);
    gWindLift107Resource170 = NULL;
}

void windLift107_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    WindLift107State* state;
    s16 burstTimer;

    state = obj->extra;
    if (state->disableTimer != 0 && state->disableTimer <= WINDLIFT107_HIT_DISABLE_FRAMES) {
        return;
    }
    switch (state->cooldownTimer) {
    case 0:
        break;
    default:
        return;
    }
    if (obj->userData2 != 0) {
        if (visible != -1) {
            return;
        }
    } else if (visible == 0) {
        return;
    }
    burstTimer = state->burstTimer;
    if (burstTimer != 0) {
        if (burstTimer < WINDLIFT107_GLOW_FAST_THRESHOLD) {
            state->glowPulse += framesThisStep * WINDLIFT107_GLOW_FAST_STEP;
            if (state->glowPulse > WINDLIFT107_GLOW_WRAP) {
                state->glowPulse = 0;
            }
            objSetGlowColor(WINDLIFT107_GLOW_RED, WINDLIFT107_GLOW_GREEN, WINDLIFT107_GLOW_BLUE, state->glowPulse);
        } else if (burstTimer < WINDLIFT107_GLOW_ACTIVE_THRESHOLD) {
            state->glowPulse += framesThisStep * WINDLIFT107_GLOW_SLOW_STEP;
            if (state->glowPulse > WINDLIFT107_GLOW_WRAP) {
                state->glowPulse = 0;
            }
            objSetGlowColor(WINDLIFT107_GLOW_RED, WINDLIFT107_GLOW_GREEN, WINDLIFT107_GLOW_BLUE, state->glowPulse);
        }
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void windLift107_hitDetect(GameObject* obj) {
    (void)obj;
}

void windLift107_update(GameObject* obj) {
    PartFxSpawnParams launchParams;
    PartFxSpawnParams impactParamsA;
    PartFxSpawnParams impactParamsB;
    PartFxSpawnParams impactParamsC;
    f32 clockScale;
    f32 yawDistance;
    GameObject* player;
    WindLift107Placement* placement;
    WindLift107State* state;
    PlayerState* playerState;
    WindLift107State* impactState;
    f32 playerDistance;
    ObjHitsPriorityState* hitState;
    s8 throwState;
    char carryActive;
    u8 contactFlags;

    placement = (WindLift107Placement*)obj->anim.placementData;
    clockScale = 1.0f;
    (*gSkyInterface)->getClockTime(&clockScale);
    state = obj->extra;
    player = Obj_GetPlayerObject();
    playerState = player->extra;
    playerDistance = Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX);
    if (state->flightTimer <= 0) {
        state->disableTimer = 1;
        state->throwState = WINDLIFT107_THROW_NONE;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        {
            f32 zero = 0.0f;
            obj->anim.velocityX = zero;
            obj->anim.velocityZ = zero;
        }
    }
    if (state->burstTimer != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_70);
        state->burstTimer -= framesThisStep;
        if (randomGetRange(0, WINDLIFT107_PARTICLE_RANDOM_MAX) == WINDLIFT107_PARTICLE_RANDOM_MAX) {
            (*gPartfxInterface)
                ->spawnObject(obj, WINDLIFT107_PARTICLE_EFFECT_ID, NULL, WINDLIFT107_PARTICLE_SPAWN_MODE,
                              WINDLIFT107_EFFECT_MODEL_ID, NULL);
        }
        if (state->burstTimer <= 0) {
            windLift107_finishSpitBurst(obj, playerDistance);
            return;
        }
    }
    if (state->cooldownTimer != 0) {
        state->cooldownTimer -= (s16)(int)(timeDelta * clockScale);
        if (state->cooldownTimer <= 0) {
            state->cooldownTimer = 0;
            state->disableTimer = 0;
            ObjHits_EnableObject(obj);
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            obj->userData1 = 0;
        }
        return;
    }
    if (state->disableTimer != 0) {
        Sfx_StopObjectChannel(obj, SFXen_firlp6);
        state->disableTimer -= framesThisStep;
        if (state->disableTimer <= 0) {
            if (state->cooldownDuration != 0) {
                state->cooldownTimer = state->cooldownDuration;
            } else {
                state->cooldownTimer = 1;
            }
        }
        if (state->disableTimer <= WINDLIFT107_HIT_DISABLE_FRAMES) {
            return;
        }
    }
    if (state->throwState == WINDLIFT107_THROW_NONE) {
        if (state->carryState == WINDLIFT107_CARRY_IDLE) {
            GameObject* cameraTarget = (*gCameraInterface)->getOverrideTarget();
            carryActive = 0;
            if (cameraTarget != obj && (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 &&
                obj->userData2 == 0) {
                buttonDisable(0, PAD_BUTTON_A);
                Obj_GetYawDeltaToObject(obj, player, &yawDistance);
                state->carryAngle = WINDLIFT107_CARRY_ANGLE;
                state->carryParam = 0;
                carryActive = 1;
            }
            state->carryState = carryActive;
            if (state->carryState != WINDLIFT107_CARRY_IDLE) {
                state->carryAttached = 1;
                state->burstTimer = WINDLIFT107_BURST_FRAMES;
            }
            if (obj->userData2 == 0) {
                ObjHits_EnableObject(obj);
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            }
            obj->anim.previousLocalPosX = obj->anim.localPosX;
            obj->anim.previousLocalPosY = obj->anim.localPosZ;
            obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        } else {
            s8 carryState;
            ObjHits_DisableObject(obj);
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0) {
                state->carryAttached = 0;
            }
            if (state->carryAttached != 0) {
                state->disableTimer = 0;
                state->cooldownTimer = 0;
                ObjMsg_SendToObject(player, WINDLIFT107_MESSAGE_GRAB_OBJECT, obj,
                                    (state->carryParam << 0x10) | ((u16)state->carryAngle));
            }
            if (obj->userData2 == 1) {
                state->carryState = WINDLIFT107_CARRY_HELD;
            }
            carryState = state->carryState;
            if (carryState == WINDLIFT107_CARRY_HELD && obj->userData2 == 0 &&
                player->anim.currentMove != WINDLIFT107_PLAYER_HOLD_MOVE) {
                state->carryState = WINDLIFT107_CARRY_IDLE;
                state->throwState = WINDLIFT107_THROW_LAUNCHED;
                {
                    f32 zero = 0.0f;
                    obj->anim.velocityX = zero;
                    obj->anim.velocityY = WINDLIFT107_THROW_INPUT_SCALE * playerState->baddie.inputMagnitude +
                                          WINDLIFT107_THROW_VERTICAL_SPEED;
                    obj->anim.velocityZ = -WINDLIFT107_THROW_INPUT_SCALE * playerState->baddie.inputMagnitude +
                                          WINDLIFT107_THROW_FORWARD_SPEED;
                    launchParams.posX = zero;
                    launchParams.posY = zero;
                    launchParams.posZ = zero;
                }
                launchParams.scale = 1.0f;
                launchParams.rotZ = 0;
                launchParams.rotY = 0;
                launchParams.rotX = player->anim.rotX;
                vecRotateZXY(&launchParams.rotX, &obj->anim.velocityX);
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_6a);
            } else if (carryState == WINDLIFT107_CARRY_HELD && obj->userData2 == 0) {
                f32 zero;
                state->carryState = WINDLIFT107_CARRY_IDLE;
                state->throwState = WINDLIFT107_THROW_DROPPED;
                zero = 0.0f;
                obj->anim.velocityX = zero;
                obj->anim.velocityY = zero;
                obj->anim.velocityZ = zero;
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_6a);
            }
        }
    }
    throwState = state->throwState;
    if (throwState == WINDLIFT107_THROW_NONE && state->carryState == WINDLIFT107_CARRY_IDLE) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            impactState = obj->extra;
            impactParamsA.scale = impactState->radius;
            gWindLift107Resource170->vtable->spawn(obj, 0, &impactParamsA, WINDLIFT107_EFFECT_SPAWN_MODE,
                                                   WINDLIFT107_EFFECT_MODEL_ID, NULL);
            impactState->burstTimer = 1;
            return;
        }
    } else if (throwState != WINDLIFT107_THROW_NONE) {
        state->flightTimer -= framesThisStep;
        if (state->throwState == WINDLIFT107_THROW_LAUNCHED) {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, WINDLIFT107_HIT_VOLUME_SLOT,
                                     WINDLIFT107_HIT_VOLUME_THROW_STATE, 0);
            if (obj->anim.velocityY > WINDLIFT107_TERMINAL_VELOCITY) {
                obj->anim.velocityY = gWindLift107LaunchGravity * timeDelta + obj->anim.velocityY;
            }
            ObjHits_EnableObject(obj);
        }
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        contactFlags = hitState->contactFlags;
        if ((s8)contactFlags != 0 && state->throwState == WINDLIFT107_THROW_LAUNCHED) {
            obj->anim.velocityY = 0.0f;
            state->throwState = WINDLIFT107_THROW_NONE;
            impactState = obj->extra;
            impactParamsB.scale = impactState->radius;
            gWindLift107Resource170->vtable->spawn(obj, 0, &impactParamsB, WINDLIFT107_EFFECT_SPAWN_MODE,
                                                   WINDLIFT107_EFFECT_MODEL_ID, NULL);
            impactState->burstTimer = 1;
            return;
        }
        if ((s8)contactFlags != 0 && state->throwState == WINDLIFT107_THROW_DROPPED) {
            state->throwState = WINDLIFT107_THROW_NONE;
            impactState = obj->extra;
            impactParamsC.scale = impactState->radius;
            gWindLift107Resource170->vtable->spawn(obj, 0, &impactParamsC, WINDLIFT107_EFFECT_SPAWN_MODE,
                                                   WINDLIFT107_EFFECT_MODEL_ID, NULL);
            impactState->burstTimer = 1;
            obj->anim.velocityY = 0.0f;
            return;
        }
        obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
    }
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    state->timer -= framesThisStep;
    if (state->carryState != WINDLIFT107_CARRY_IDLE) {
        if (getXZDistanceSquared(&obj->anim.worldPosX, &placement->base.posX) >=
            (f32)(state->leashRange * state->leashRange)) {
            f32 zero = 0.0f;
            obj->anim.velocityX = zero;
            obj->anim.velocityZ = zero;
            state->disableTimer = WINDLIFT107_RETURN_DELAY_FRAMES;
            state->throwState = WINDLIFT107_THROW_NONE;
            obj->userData2 = 0;
            ObjHits_EnableObject(obj);
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        }
    }
}

void windLift107_init(GameObject* obj, WindLift107Placement* placement) {
    WindLift107State* state;

    state = obj->extra;
    obj->anim.rotX = 0;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->skeletonHitMask = WINDLIFT107_HIT_MASK;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->objectHitMask = WINDLIFT107_HIT_MASK;
    ObjHits_DisableObject(obj);
    objAddObjectType(obj, WINDLIFT107_OBJECT_GROUP_ID);
    state->disableTimer = 0;
    state->throwState = WINDLIFT107_THROW_NONE;
    {
        s16 cooldownParam = placement->cooldownParam;
        if (cooldownParam == 0) {
            state->cooldownDuration = 0;
        } else {
            state->cooldownDuration = cooldownParam * WINDLIFT107_COOLDOWN_SCALE;
        }
    }
    state->cooldownTimer = 0;
    state->unk25 = 0;
    gWindLift107Resource91 = Resource_Acquire(WINDLIFT107_RESOURCE_91_ID, WINDLIFT107_RESOURCE_COUNT);
    gWindLift107Resource170 = Resource_Acquire(WINDLIFT107_RESOURCE_170_ID, WINDLIFT107_RESOURCE_COUNT);
    state->timer = 100;
    state->unk18 = 400;
    obj->anim.rotX = (s16)(placement->rotXParam << WINDLIFT107_ROTATION_PARAM_SHIFT);
    state->unk14 = placement->unk1E;
    state->leashRange = placement->leashRange;
    if (state->leashRange == 0) {
        state->leashRange = WINDLIFT107_DEFAULT_LEASH_RANGE;
    }
    state->flightTimer = WINDLIFT107_FLIGHT_FRAMES;
    state->burstTimer = 0;
    state->glowPulse = 0xFF;
    state->unk27 = 0;
    if (placement->radiusParam != 0) {
        state->radius = gWindLift107RadiusScale * (f32)(s32)placement->radiusParam;
    } else {
        state->radius = gWindLift107DefaultRadius;
    }
    obj->userData1 = 0;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= 0x8000LL;
    }
}

void windLift107_release(void) {
}

void windLift107_initialise(void) {
}

ObjectDescriptor gWindLift107ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)windLift107_initialise,
    (ObjectDescriptorCallback)windLift107_release,
    0,
    (ObjectDescriptorCallback)windLift107_init,
    (ObjectDescriptorCallback)windLift107_update,
    (ObjectDescriptorCallback)windLift107_hitDetect,
    (ObjectDescriptorCallback)windLift107_render,
    (ObjectDescriptorCallback)windLift107_free,
    (ObjectDescriptorCallback)windLift107_getObjectTypeId,
    windLift107_getExtraSize,
};
