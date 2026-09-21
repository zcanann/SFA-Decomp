/*
 * PinPonSpike object (DLL slot 216).
 *
 * Simulates a thrown spike until it hits a character or surface. An impact
 * hides the projectile, emits particles, and starts its despawn countdown.
 * The launch-angle helper is also used by the duster object family.
 */
#include "dlls/objects/216_PinPonSpike.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define PINPONSPIKE_HIT_VOLUME_SLOT 10

#define PINPONSPIKE_PARTFX_IMPACT 0x715

#define PINPONSPIKE_IMPACT_DESPAWN_DELAY  120
#define PINPONSPIKE_IMPACT_PARTICLE_COUNT 25
#define PINPONSPIKE_VERTICAL_ACCELERATION -0.2f
#define PINPONSPIKE_TERMINAL_FALL_SPEED   -20.0f
#define PINPONSPIKE_KILL_PLANE_Y          -2000.0f
#define PINPONSPIKE_AIM_DISTANCE_SCALE    1.05f
#define PINPONSPIKE_FALLBACK_LAUNCH_ANGLE 0x2000

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

int pinponspike_calculateLaunchAngle(const f32* source, const f32* target, f32 speed, u8 useHighArc, f32 gravity) {
    f32 gravityQuarterOrSpeedSquared;
    f32 horizontalDistance;
    f32 coefficientOrHorizontalVelocity;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 flightTime;
    f32 discriminant;

    deltaX = source[0] - target[0];
    deltaZ = source[2] - target[2];
    horizontalDistance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    deltaY = source[1] - target[1];
    horizontalDistance *= PINPONSPIKE_AIM_DISTANCE_SCALE;
    gravityQuarterOrSpeedSquared = 0.25f * gravity;
    coefficientOrHorizontalVelocity = gravityQuarterOrSpeedSquared * gravity;
    {
        f32 linearTerm = -(gravity * deltaY) - (gravityQuarterOrSpeedSquared = speed * speed);
        discriminant = linearTerm * linearTerm - (4.0f * coefficientOrHorizontalVelocity) *
                                                     (deltaY * deltaY + horizontalDistance * horizontalDistance);
        if (discriminant >= 0.0f) {
            if (useHighArc) {
                flightTime = (0.5f * (-linearTerm + sqrtf(discriminant))) / coefficientOrHorizontalVelocity;
            } else {
                flightTime = (0.5f * (-linearTerm - sqrtf(discriminant))) / coefficientOrHorizontalVelocity;
            }
            flightTime = sqrtf(flightTime);
            coefficientOrHorizontalVelocity = horizontalDistance / flightTime;
            return getAngle(sqrtf(-(coefficientOrHorizontalVelocity * coefficientOrHorizontalVelocity -
                                    gravityQuarterOrSpeedSquared)),
                            coefficientOrHorizontalVelocity);
        }
    }
    return PINPONSPIKE_FALLBACK_LAUNCH_ANGLE;
}

int pinponspike_getExtraSize(void) {
    return 0;
}

int pinponspike_getObjectTypeId(void) {
    return 0;
}

void pinponspike_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pinponspike_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    (void)obj;
    (void)fwdArg2;
    (void)fwdArg3;
    (void)fwdArg4;
    (void)fwdArg5;
    (void)visible;
}

void pinponspike_hitDetect(GameObject* obj) {
    (void)obj;
}

void pinponspike_update(GameObject* obj) {
    f32 moveX;
    f32 moveY;
    f32 moveZ;

    if (obj->userData1 > 0) {
        obj->userData1 = (int)((f32)obj->userData1 - timeDelta);
        if (obj->userData1 <= 0) {
            Obj_FreeObject(obj);
            return;
        }
    }
    if (obj->anim.alpha != 0) {
        moveX = obj->anim.velocityX * timeDelta;
        moveY = obj->anim.velocityY * timeDelta;
        moveZ = obj->anim.velocityZ * timeDelta;
        objMove(obj, moveX, moveY, moveZ);
        obj->anim.velocityY += PINPONSPIKE_VERTICAL_ACCELERATION * timeDelta;
        if (obj->anim.velocityY < PINPONSPIKE_TERMINAL_FALL_SPEED) {
            obj->anim.velocityY = PINPONSPIKE_TERMINAL_FALL_SPEED;
        }
        obj->anim.rotX = getAngle(moveX, moveZ) - 0x8000;
        obj->anim.rotY = 0x4000 - getAngle(sqrtf(moveX * moveX + moveZ * moveZ), moveY);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, PINPONSPIKE_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (u32)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (u32)getTrickyObject())) {
            int particleIndex;
            obj->anim.alpha = 0;
            obj->userData1 = PINPONSPIKE_IMPACT_DESPAWN_DELAY;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            for (particleIndex = 0; particleIndex < PINPONSPIKE_IMPACT_PARTICLE_COUNT; particleIndex++) {
                (*gPartfxInterface)->spawnObject((void*)obj, PINPONSPIKE_PARTFX_IMPACT, NULL, 1, -1, &particleIndex);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lummy311);
        } else if (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0) {
            int particleIndex;
            obj->anim.alpha = 0;
            obj->userData1 = PINPONSPIKE_IMPACT_DESPAWN_DELAY;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            for (particleIndex = 0; particleIndex < PINPONSPIKE_IMPACT_PARTICLE_COUNT; particleIndex++) {
                (*gPartfxInterface)->spawnObject((void*)obj, PINPONSPIKE_PARTFX_IMPACT, NULL, 1, -1, &particleIndex);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lummy311);
        } else if (obj->anim.localPosY < PINPONSPIKE_KILL_PLANE_Y) {
            Obj_FreeObject(obj);
        }
    }
}

void pinponspike_init(GameObject* obj) {
    obj->userData1 = 0;
    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXTRIG_whiz3_c);
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void pinponspike_release(void) {
}

void pinponspike_initialise(void) {
}
