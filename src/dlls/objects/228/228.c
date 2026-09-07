/*
 * FlameThrowerspe object family (DLL slot 228 / 0xE4).
 *
 * Drives the pooled flame projectiles used by FlameThrowerspe, FlameBall,
 * and BossDarkorF object variants.
 */
#include "dlls/objects/228_FlameThrowerspe.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "main/dll/firepipe_effect_api.h"
#include "main/maketex_timer_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"

#define FLAMETHROWERSPE_SCALE_DIVISOR 10.0f

#define FLAMETHROWERSPE_PHASE_LAUNCH 1
#define FLAMETHROWERSPE_PHASE_ACTIVE 2

#define FLAMETHROWERSPE_RANDOM_SPEED_MIN 100
#define FLAMETHROWERSPE_RANDOM_SPEED_MAX 150
#define FLAMETHROWERSPE_SPEED_SCALE 0.1f
#define FLAMETHROWERSPE_RANDOM_SPEED_SCALE 0.12f

f32 gFlameThrowerspeScaleMultiplier = 2.0f;
int gFlameThrowerspeLifetimeFrames = 35;
f32 gFlameThrowerspeSpeedMultiplier = 1.0f;
f32 gFlameThrowerspeRadiusMultiplier = 8.0f;

FlameThrowerspeHitProfile gFlameThrowerspeHitProfiles[FLAMETHROWERSPE_HIT_PROFILE_COUNT] = {
    {0x4F, 0xFFC40000, 0x1F},
    {0x4F, 0x00C4FF00, 0x5},
    {0x4F, 0x00C4FF00, 0x1E},
};

ObjectDescriptor13 gFlameThrowerspeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)FlameThrowerspe_initialise,
    (ObjectDescriptorCallback)FlameThrowerspe_release,
    0,
    (ObjectDescriptorCallback)FlameThrowerspe_init,
    (ObjectDescriptorCallback)FlameThrowerspe_update,
    (ObjectDescriptorCallback)FlameThrowerspe_hitDetect,
    (ObjectDescriptorCallback)FlameThrowerspe_render,
    (ObjectDescriptorCallback)FlameThrowerspe_free,
    (ObjectDescriptorCallback)FlameThrowerspe_getObjectTypeId,
    FlameThrowerspe_getExtraSize,
    (ObjectDescriptorCallback)FlameThrowerspe_setTransform,
    (ObjectDescriptorCallback)FlameThrowerspe_launch,
    (ObjectDescriptorCallback)FlameThrowerspe_modelMtxFn,
};

void FlameThrowerspe_modelMtxFn(void) {
}

void FlameThrowerspe_launch(GameObject* obj) {
    s32 phase = FLAMETHROWERSPE_PHASE_LAUNCH;
    FlameThrowerspeState* state = obj->extra;

    state->phase = phase;
}

void FlameThrowerspe_setTransform(GameObject* obj, s16 rotY, s16 rotX, f32 x, f32 y, f32 z) {
    obj->anim.localPosX = x;
    obj->anim.localPosY = y;
    obj->anim.localPosZ = z;
    obj->anim.rotY = rotY;
    obj->anim.rotX = rotX;
}

int FlameThrowerspe_getExtraSize(void) {
    return sizeof(FlameThrowerspeState);
}

int FlameThrowerspe_getObjectTypeId(void) {
    return 0;
}

void FlameThrowerspe_free(GameObject* obj) {
    (void)obj;
}

void FlameThrowerspe_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    f32 scale = 1.0f;

    (void)visible;

    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, scale);
}

void FlameThrowerspe_hitDetect(GameObject* obj) {
    (void)obj;
}

void FlameThrowerspe_update(GameObject* obj) {
    FlameThrowerspeState* state = obj->extra;
    FlameThrowerspePlacement* placement = (FlameThrowerspePlacement*)obj->anim.placementData;

    switch (state->phase) {
    case FLAMETHROWERSPE_PHASE_LAUNCH:
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityZ =
            gFlameThrowerspeSpeedMultiplier *
            (FLAMETHROWERSPE_SPEED_SCALE *
             (state->sizeScale *
              (FLAMETHROWERSPE_RANDOM_SPEED_SCALE *
               randomGetRange(FLAMETHROWERSPE_RANDOM_SPEED_MIN, FLAMETHROWERSPE_RANDOM_SPEED_MAX))));
        vecRotateZXY(&obj->anim.rotX, &obj->anim.velocityX);
        state->sphereRadius = gFlameThrowerspeRadiusMultiplier * state->sizeScale;
        s16toFloat(&state->lifeTimer, (s16)gFlameThrowerspeLifetimeFrames);
        state->phase = FLAMETHROWERSPE_PHASE_ACTIVE;
        break;
    case FLAMETHROWERSPE_PHASE_ACTIVE:
        if (timerCountDown(&state->lifeTimer) != 0) {
            ObjHits_DisableObject(obj);
            firepipe_releaseEffectObject(obj);
            return;
        }
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj,
                                 gFlameThrowerspeHitProfiles[placement->hitVolumeProfile].hitVolumeSlot, 1, 0);
        {
            f32 dt = (f32)(f64)timeDelta;
            (void)objMove(obj, obj->anim.velocityX * dt, obj->anim.velocityY * dt, obj->anim.velocityZ * dt);
        }
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (int)(state->sphereRadius *
                                        (((f32)gFlameThrowerspeLifetimeFrames - state->lifeTimer) /
                                         gFlameThrowerspeLifetimeFrames)));
        break;
    }
}

void FlameThrowerspe_init(GameObject* obj, FlameThrowerspePlacement* placement) {
    FlameThrowerspeState* state = obj->extra;

    storeZeroToFloatParam(&state->lifeTimer);
    {
        f32 scale = (f32)placement->scaleParam / FLAMETHROWERSPE_SCALE_DIVISOR;
        state->sizeScale = scale * gFlameThrowerspeScaleMultiplier;
    }
    obj->anim.velocityY = 0.0f;
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    state->phase = FLAMETHROWERSPE_PHASE_LAUNCH;
    ObjHits_DisableObject(obj);
}

void FlameThrowerspe_release(void) {
}

void FlameThrowerspe_initialise(void) {
}
