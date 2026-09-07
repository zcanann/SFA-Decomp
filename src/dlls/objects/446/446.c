/*
 * DLL 446 (0x1BE): shared DIMLava, DIMLavaBall, and DIMLavaDebr behavior.
 * The debris identity uses no extra state; the projectile identities follow a
 * target, emit light, and trigger explosions on contact.
 */

#include "dlls/objects/446.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

#define DIM_LAVA_DEBRIS_SEQUENCE_ID       0x1FA
#define DIM_LAVA_DEBRIS_PARTICLE_EFFECT   0x1F5
#define DIM_LAVA_DEBRIS_LIFETIME          0x4B
#define DIM_LAVA_DEBRIS_ROTATION_X_STEP   0x374
#define DIM_LAVA_DEBRIS_ROTATION_Y_STEP   0x12C
#define DIM_LAVA_DEBRIS_GRAVITY           0.05f
#define DIM_LAVA_DEBRIS_ROOT_MOTION_SCALE 0.25f

#define DIM_LAVA_VELOCITY_SCALE          0.1f
#define DIM_LAVA_GRAVITY                 (-0.09f)
#define DIM_LAVA_FALLING_VELOCITY        2.0f
#define DIM_LAVA_PI                      3.14159274f
#define DIM_LAVA_ANGLE_UNITS_HALF_CIRCLE 32768.0f

#define DIM_LAVA_FLAG_UPDATED  0x08
#define DIM_LAVA_FLAG_INACTIVE 0x10
#define DIM_LAVA_FLAG_FALLING  0x20

#define DIM_LAVA_HIT_VOLUME_PRIORITY 0xB
#define DIM_LAVA_HIT_MASK            0x10
#define DIM_LAVA_EXPLOSION_COOLDOWN  0xA
#define DIM_LAVA_EXPLOSION_SCALE     60.0f
#define DIM_LAVA_MODEL_FLAGS         0x810

#define DIM_LAVA_LIGHT_RED        0xFF
#define DIM_LAVA_LIGHT_GREEN      0x80
#define DIM_LAVA_LIGHT_BLUE       0
#define DIM_LAVA_LIGHT_ALPHA      0
#define DIM_LAVA_LIGHT_ATTEN_NEAR 30.0f
#define DIM_LAVA_LIGHT_ATTEN_FAR  50.0f
#define DIM_LAVA_GLOW_ALPHA       0x64
#define DIM_LAVA_GLOW_RADIUS      20.0f

typedef struct DimLavaDebrisLaunch {
    Vec3f velocity;
    Vec3s rotation;
    u8 unknown12[0x24 - 0x12];
} DimLavaDebrisLaunch;

const Vec3f gDimLavaDebrisBaseVec = {1.2f, 0.0f, 0.0f};

STATIC_ASSERT(offsetof(DimLavaDebrisLaunch, velocity) == 0x00);
STATIC_ASSERT(offsetof(DimLavaDebrisLaunch, rotation) == 0x0C);
STATIC_ASSERT(offsetof(DimLavaDebrisLaunch, unknown12) == 0x12);
STATIC_ASSERT(sizeof(DimLavaDebrisLaunch) == 0x24);

static void lavaball1be_applyDebrisGravity(GameObject* obj) {
    obj->anim.velocityY = -(DIM_LAVA_DEBRIS_GRAVITY * timeDelta - obj->anim.velocityY);
}

static void lavaball1be_scaleDebrisRootMotion(GameObject* obj) {
    obj->anim.rootMotionScale *= DIM_LAVA_DEBRIS_ROOT_MOTION_SCALE;
}

void lavaball1be_relaunch(GameObject* obj, int verticalSpeed, int horizontalSpeed) {
    DimLavaProjectileState* state;
    DimLavaProjectilePlacement* placement;
    f32 horizontalVelocity;
    f32 position;

    state = obj->extra;
    placement = (DimLavaProjectilePlacement*)obj->anim.placement;
    horizontalVelocity = DIM_LAVA_VELOCITY_SCALE * horizontalSpeed;
    position = state->target->anim.localPosX;
    obj->anim.worldPosX = position;
    obj->anim.localPosX = position;
    position = state->target->anim.localPosY;
    obj->anim.worldPosY = position;
    obj->anim.localPosY = position;
    position = state->target->anim.localPosZ;
    obj->anim.worldPosZ = position;
    obj->anim.localPosZ = position;
    position = obj->anim.localPosX;
    obj->anim.previousWorldPosX = position;
    obj->anim.previousLocalPosX = position;
    position = obj->anim.localPosY;
    obj->anim.previousWorldPosY = position;
    obj->anim.previousLocalPosY = position;
    position = obj->anim.localPosZ;
    obj->anim.previousWorldPosZ = position;
    obj->anim.previousLocalPosZ = position;
    obj->anim.rotX = (s16)((s32)placement->launchYaw << 8);
    obj->anim.velocityX =
        horizontalVelocity * -mathSinf(DIM_LAVA_PI * (f32)obj->anim.rotX / DIM_LAVA_ANGLE_UNITS_HALF_CIRCLE);
    obj->anim.velocityY = DIM_LAVA_VELOCITY_SCALE * verticalSpeed;
    obj->anim.velocityZ =
        horizontalVelocity * -mathCosf(DIM_LAVA_PI * (f32)obj->anim.rotX / DIM_LAVA_ANGLE_UNITS_HALF_CIRCLE);
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    state->statusFlags &= ~DIM_LAVA_FLAG_INACTIVE;
}

u32 lavaball1be_isInactive(GameObject* obj) {
    DimLavaProjectileState* state = obj->extra;
    return state->statusFlags & DIM_LAVA_FLAG_INACTIVE;
}

int lavaball1be_getExtraSize(GameObject* obj) {
    if (obj->anim.romDefNo == DIM_LAVA_DEBRIS_SEQUENCE_ID) {
        return 0;
    }
    return sizeof(DimLavaProjectileState);
}

int lavaball1be_getObjectTypeId(GameObject* obj) {
    if (obj->anim.romDefNo == DIM_LAVA_DEBRIS_SEQUENCE_ID) {
        return 0;
    }
    return 2;
}

void lavaball1be_free(GameObject* obj) {
    DimLavaProjectileState* state = obj->extra;

    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}

void lavaball1be_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5) {
    DimLavaProjectileState* state = obj->extra;

    if (state->light != NULL) {
        if (modelLightStruct_getActiveState(state->light) != 0) {
            queueGlowRender(state->light);
        }
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void lavaball1be_hitDetect(void) {
}

void lavaball1be_update(GameObject* obj) {
    DimLavaProjectileState* state;
    ObjHitsPriorityState* hitState;

    if (obj->anim.romDefNo == DIM_LAVA_DEBRIS_SEQUENCE_ID) {
        obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
        (*gPartfxInterface)->spawnObject(obj, DIM_LAVA_DEBRIS_PARTICLE_EFFECT, NULL, 1, -1, NULL);
        obj->anim.rotX = obj->anim.rotX + framesThisStep * DIM_LAVA_DEBRIS_ROTATION_X_STEP;
        obj->anim.rotY = obj->anim.rotY + framesThisStep * DIM_LAVA_DEBRIS_ROTATION_Y_STEP;
        lavaball1be_applyDebrisGravity(obj);
        obj->userData1 -= framesThisStep;
        if (obj->userData1 < 0) {
            Obj_FreeObject(obj);
        }
    } else {
        state = obj->extra;
        if (state->statusFlags & DIM_LAVA_FLAG_INACTIVE) {
            ObjHits_DisableObject(obj);
        } else {
            f32 deltaTime = timeDelta;
            u8 frameCount = framesThisStep;

            if (state->explosionCooldown != 0) {
                state->explosionCooldown--;
            }
            obj->anim.rotX += (frameCount << 6);
            obj->anim.rotY -= (frameCount << 9);
            obj->anim.velocityY = DIM_LAVA_GRAVITY * deltaTime + obj->anim.velocityY;
            objMove(obj, obj->anim.velocityX * deltaTime, obj->anim.velocityY * deltaTime,
                    obj->anim.velocityZ * deltaTime);
            if (obj->anim.velocityY < DIM_LAVA_FALLING_VELOCITY) {
                if (!(state->statusFlags & DIM_LAVA_FLAG_FALLING)) {
                    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3dd);
                    state->statusFlags |= DIM_LAVA_FLAG_FALLING;
                }
            } else {
                state->statusFlags &= ~DIM_LAVA_FLAG_FALLING;
            }
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if (hitState != NULL) {
                hitState->hitVolumePriority = DIM_LAVA_HIT_VOLUME_PRIORITY;
                hitState->hitVolumeId = 1;
                hitState->objectHitMask = DIM_LAVA_HIT_MASK;
                hitState->skeletonHitMask = DIM_LAVA_HIT_MASK;
                if (hitState->lastHitObject != 0) {
                    if (state->explosionCooldown != 0) {
                        spawnExplosion(obj, DIM_LAVA_EXPLOSION_SCALE, 0, 1, 0, 0, 0, 0, 0);
                    } else {
                        state->explosionCooldown = DIM_LAVA_EXPLOSION_COOLDOWN;
                        spawnExplosion(obj, DIM_LAVA_EXPLOSION_SCALE, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->statusFlags |= DIM_LAVA_FLAG_INACTIVE;
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
                if (hitState->contactFlags & OBJHITS_CONTACT_FLAG_KIND0) {
                    spawnExplosion(obj, DIM_LAVA_EXPLOSION_SCALE, 1, 1, 0, 0, 0, 0, 0);
                    state->statusFlags |= DIM_LAVA_FLAG_INACTIVE;
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    return;
                }
            }
            if (obj->anim.localPosY < state->floorY) {
                state->statusFlags |= DIM_LAVA_FLAG_INACTIVE;
            }
            if (!(state->statusFlags & DIM_LAVA_FLAG_UPDATED)) {
                state->statusFlags |= DIM_LAVA_FLAG_UPDATED;
            }
            if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0) {
                modelLightStruct_updateGlowAlpha(state->light);
            }
        }
    }
}

void lavaball1be_init(GameObject* obj, DimLavaProjectilePlacement* placement) {
    DimLavaProjectileState* state;

    if (obj->anim.romDefNo == DIM_LAVA_DEBRIS_SEQUENCE_ID) {
        DimLavaDebrisLaunch launch;

        launch.velocity = gDimLavaDebrisBaseVec;
        launch.rotation.z = 0;
        launch.rotation.y = randomGetRange(-0x2ee0, 0x2ee0);
        launch.rotation.x = randomGetRange(0, 0xfffe);
        vecRotateZXY((s16*)((u8*)&launch + offsetof(DimLavaDebrisLaunch, rotation)), (f32*)&launch.velocity);
        obj->userData1 = DIM_LAVA_DEBRIS_LIFETIME;
        obj->anim.velocityX = launch.velocity.x;
        obj->anim.velocityY = launch.velocity.y;
        obj->anim.velocityZ = launch.velocity.z;
        lavaball1be_scaleDebrisRootMotion(obj);
    } else {
        f32 verticalVelocity;
        f32 horizontalVelocity;
        ObjHitsPriorityState* hitState;
        ModelLightStruct* light;

        obj->anim.rotX = (s16)((s32)placement->launchYaw << 8);
        state = obj->extra;
        verticalVelocity = DIM_LAVA_VELOCITY_SCALE * (f32)placement->verticalSpeed;
        horizontalVelocity = DIM_LAVA_VELOCITY_SCALE * (f32)placement->horizontalSpeed;
        state->floorY = obj->anim.localPosY;
        state->targetObjectId = placement->targetObjectId;
        placement->targetObjectId = -1;
        obj->anim.velocityX =
            horizontalVelocity * -mathSinf(DIM_LAVA_PI * (f32)obj->anim.rotX / DIM_LAVA_ANGLE_UNITS_HALF_CIRCLE);
        obj->anim.velocityY = verticalVelocity;
        obj->anim.velocityZ =
            horizontalVelocity * -mathCosf(DIM_LAVA_PI * (f32)obj->anim.rotX / DIM_LAVA_ANGLE_UNITS_HALF_CIRCLE);
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        if (hitState != NULL) {
            hitState->lateralResponseWeight = 0;
        }
        if (obj->anim.modelState != NULL) {
            obj->anim.modelState->flags |= DIM_LAVA_MODEL_FLAGS;
        }
        state->target = ObjList_FindObjectById(state->targetObjectId);
        state->statusFlags |= DIM_LAVA_FLAG_INACTIVE;
        ObjHits_DisableObject(obj);
        obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL) {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(state->light, DIM_LAVA_LIGHT_RED, DIM_LAVA_LIGHT_GREEN,
                                             DIM_LAVA_LIGHT_BLUE, DIM_LAVA_LIGHT_ALPHA);
            modelLightStruct_setDistanceAttenuation(state->light, DIM_LAVA_LIGHT_ATTEN_NEAR, DIM_LAVA_LIGHT_ATTEN_FAR);
            modelLightStruct_setupGlow(state->light, 0, DIM_LAVA_LIGHT_RED, DIM_LAVA_LIGHT_GREEN, DIM_LAVA_LIGHT_BLUE,
                                       DIM_LAVA_GLOW_ALPHA, DIM_LAVA_GLOW_RADIUS);
            modelLightStruct_setGlowProjectionRadius(state->light, DIM_LAVA_GLOW_RADIUS);
        }
    }
}

void lavaball1be_release(void) {
}

void lavaball1be_initialise(void) {
}

ObjectDescriptor12 gLavaBall1BEObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)lavaball1be_initialise,
    (ObjectDescriptorCallback)lavaball1be_release,
    0,
    (ObjectDescriptorCallback)lavaball1be_init,
    (ObjectDescriptorCallback)lavaball1be_update,
    (ObjectDescriptorCallback)lavaball1be_hitDetect,
    (ObjectDescriptorCallback)lavaball1be_render,
    (ObjectDescriptorCallback)lavaball1be_free,
    (ObjectDescriptorCallback)lavaball1be_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)lavaball1be_getExtraSize,
    (ObjectDescriptorCallback)lavaball1be_relaunch,
    (ObjectDescriptorCallback)lavaball1be_isInactive,
};
