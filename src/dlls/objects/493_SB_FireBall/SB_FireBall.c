/*
 * SB_FireBall (DLL 0x1ED) - the fire projectile used by the ShipBattle
 * (SB) boss set. A fireball is spawned with a target (taken from the
 * spawning object's slot), drifts along the velocity captured on its
 * first armed frame, spins, trails particles, and enables its hitbox
 * after a short delay. It expires when its life timer runs out, and on
 * a hit bursts a cloud of impact particles before being freed.
 */
#include "dlls/objects/493_SB_FireBall.h"

#include "main/dll/expgfx_interface.h"
#include "main/dll/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects/lifecycle.h"

#define SB_FIREBALL_SPIN_STEP -800

#define SB_FIREBALL_TRAIL_PARTICLE_ID           0xA9
#define SB_FIREBALL_TRAIL_BURST_MODE            4
#define SB_FIREBALL_TRAIL_BURST_EFFECT_PARAM    0x185
#define SB_FIREBALL_TRAIL_BURST_SECONDARY_PARAM 5

#define SB_FIREBALL_HITBOX_ARM_DELAY    15
#define SB_FIREBALL_HIT_VOLUME_PRIORITY 5
#define SB_FIREBALL_HIT_VOLUME_ID       1
#define SB_FIREBALL_HIT_MASK            0x10

/* These are the smoke and spark impact effects shared by SB_CannonBall.
 * The fireball emits the same 50:10 particle burst on contact. */
enum {
    SB_FIREBALL_IMPACT_SMOKE_PARTICLE_ID = 0xA7,
    SB_FIREBALL_IMPACT_SPARK_PARTICLE_ID = 0xAB
};

enum {
    SB_FIREBALL_IMPACT_SMOKE_COUNT = 50,
    SB_FIREBALL_IMPACT_SPARK_COUNT = 10
};

/* obj->userData1 life timer set at init, decremented by framesThisStep */
#define SB_FIREBALL_LIFETIME 0x4B0

int SB_FireBall_getExtraSize(void) {
    return sizeof(SBFireBallState);
}

int SB_FireBall_getObjectTypeId(void) {
    return 0;
}

void SB_FireBall_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2(obj);
}

void SB_FireBall_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void SB_FireBall_hitDetect(GameObject* obj) {
    ObjHitsPriorityState* hitState = ObjAnim_GetPriorityHitState(&obj->anim);
    int particleCount;

    if (hitState->lastHitObject == 0) {
        return;
    }
    hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
    for (particleCount = SB_FIREBALL_IMPACT_SMOKE_COUNT; particleCount != 0; particleCount--) {
        (*gPartfxInterface)->spawnEffect(obj, SB_FIREBALL_IMPACT_SMOKE_PARTICLE_ID, NULL, 1, -1, NULL);
    }
    for (particleCount = SB_FIREBALL_IMPACT_SPARK_COUNT; particleCount != 0; particleCount--) {
        (*gPartfxInterface)->spawnEffect(obj, SB_FIREBALL_IMPACT_SPARK_PARTICLE_ID, NULL, 1, -1, NULL);
    }
}

void SB_FireBall_update(GameObject* obj) {
    SBFireBallState* state;
    PartFxSpawnParams particleParams;

    state = obj->extra;
    if (state->target == NULL) {
        state->target = (GameObject*)obj->userData2;
    }

    if (state->target != NULL) {
        obj->anim.rotX = 0;
        obj->anim.rotZ = (s16)(obj->anim.rotZ + framesThisStep * SB_FIREBALL_SPIN_STEP);
        obj->userData1 -= framesThisStep;
        if (obj->userData1 < 0) {
            Obj_FreeObject(obj);
            return;
        }

        if (state->launched == 0) {
            state->velocityX = obj->anim.velocityX;
            state->velocityY = obj->anim.velocityY;
            state->velocityZ = obj->anim.velocityZ;
            state->launched = 1;
        }

        obj->anim.localPosX += state->velocityX * timeDelta;
        obj->anim.localPosY += state->velocityY * timeDelta;
        obj->anim.localPosZ += state->velocityZ * timeDelta;

        particleParams.scale = 3.0f;
        objfx_spawnFlaggedTrailBurst(obj, 0.8f, SB_FIREBALL_TRAIL_BURST_MODE, SB_FIREBALL_TRAIL_BURST_EFFECT_PARAM,
                                     SB_FIREBALL_TRAIL_BURST_SECONDARY_PARAM, NULL);
        (*gPartfxInterface)->spawnEffect(obj, SB_FIREBALL_TRAIL_PARTICLE_ID, &particleParams, 1, -1, NULL);

        if (state->age > SB_FIREBALL_HITBOX_ARM_DELAY) {
            ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = SB_FIREBALL_HIT_VOLUME_PRIORITY;
            ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = SB_FIREBALL_HIT_VOLUME_ID;
            ObjAnim_GetPriorityHitState(&obj->anim)->objectHitMask = SB_FIREBALL_HIT_MASK;
            ObjAnim_GetPriorityHitState(&obj->anim)->skeletonHitMask = SB_FIREBALL_HIT_MASK;
            ObjAnim_GetPriorityHitState(&obj->anim)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
        } else {
            ObjAnim_GetPriorityHitState(&obj->anim)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        }

        state->age += framesThisStep;
    }
}

void SB_FireBall_init(GameObject* obj) {
    SBFireBallState* state = obj->extra;

    obj->userData1 = SB_FIREBALL_LIFETIME;
    state->launched = 0;
}

void SB_FireBall_release(void) {
}

void SB_FireBall_initialise(void) {
}

ObjectDescriptor gSB_FireBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_FireBall_initialise,
    SB_FireBall_release,
    0,
    (ObjectDescriptorCallback)SB_FireBall_init,
    (ObjectDescriptorCallback)SB_FireBall_update,
    (ObjectDescriptorCallback)SB_FireBall_hitDetect,
    (ObjectDescriptorCallback)SB_FireBall_render,
    (ObjectDescriptorCallback)SB_FireBall_free,
    (ObjectDescriptorCallback)SB_FireBall_getObjectTypeId,
    SB_FireBall_getExtraSize,
};
