/*
 * SB_CannonBall (DLL 0x01EE) - the cannonball fired by the galleon's deck
 * guns (SB_ShipGun) at the player's Cloudrunner in the ShipBattle prologue
 * (SB = the retail "ShipBattle" map). It launches with an initial particle
 * burst, then each frame integrates its own ballistic trajectory (stored in
 * state), trails smoke particles, and carries a point light. On impact it
 * plays a hit sfx, spawns smoke/spark bursts, and arms a cooldown before
 * freeing itself.
 */
#include "dlls/objects/494_SB_CannonBa.h"

#include "main/audio/sfx_play_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "sys/objects/lifecycle.h"

#define SB_CLOUDBALL_ALIAS_OBJECT_TYPE 0x0119

#define SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG 0x01
#define SB_CANNONBALL_INITIAL_BURST_FLAG          0x02

#define SB_CANNONBALL_BURST_PARTICLE_ID        0xAA
#define SB_CANNONBALL_TRAIL_PARTICLE_ID        0xA9
#define SB_CANNONBALL_IMPACT_SMOKE_PARTICLE_ID 0xA7
#define SB_CANNONBALL_IMPACT_SPARK_PARTICLE_ID 0xAB
#define SB_CANNONBALL_SMOKE_PARTICLE_COUNT     50
#define SB_CANNONBALL_SPARK_PARTICLE_COUNT     10

#define SB_CANNONBALL_TRAIL_MODE         4
#define SB_CANNONBALL_TRAIL_EFFECT_PARAM 0x185
#define SB_CANNONBALL_TRAIL_PARAM        5
#define SB_CANNONBALL_ROTATION_STEP      4000

#define SB_CANNONBALL_HITBOX_ENABLE_DELAY    15
#define SB_CANNONBALL_HIT_VOLUME_PRIORITY    5
#define SB_CANNONBALL_HIT_VOLUME_ID          1
#define SB_CANNONBALL_HIT_VOLUME_OBJECT_MASK 0x10

#define SB_CANNONBALL_IMPACT_SFX   0x31D
#define SB_CANNONBALL_IMPACT_ALPHA 25

#define SB_CANNONBALL_LIGHT_ADD_TO_LIST 1
#define SB_CANNONBALL_LIGHT_KIND        2
#define SB_CANNONBALL_LIGHT_RED         200
#define SB_CANNONBALL_LIGHT_GREEN       60
#define SB_CANNONBALL_LIGHT_BLUE        0
#define SB_CANNONBALL_LIGHT_ALPHA       0
#define SB_CANNONBALL_LIGHT_FIELD_BC    1

#define SB_CANNONBALL_LAUNCH_SFX 0x35
#define SB_CANNONBALL_LOOP_SFX   0x2CA

int SB_CannonBall_getExtraSize(void) {
    return sizeof(SBCannonBallState);
}
int SB_CannonBall_getObjectTypeId(void) {
    return 0;
}

void SB_CannonBall_free(GameObject* obj) {
    SBCannonBallState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->modelLight != NULL) {
        ModelLightStruct_free(state->modelLight);
        state->modelLight = NULL;
    }
}

void SB_CannonBall_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void SB_CannonBall_hitDetect(GameObject* obj) {
    SBCannonBallState* state = obj->extra;
    f32 cooldown = state->impactCooldown;
    f32 zero = 0.0f;

    if (cooldown > zero) {
        state->impactCooldown = cooldown - timeDelta;
        if (state->impactCooldown <= zero) {
            Obj_FreeObject(obj);
        }
        return;
    }

    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        GameObject* target = (GameObject*)hitState->lastHitObject;
        s16 objectType;
        if (target == NULL) {
            return;
        }
        objectType = target->anim.romDefNo;
        if (objectType == SB_CLOUDBALL_ALIAS_OBJECT_TYPE) {
            return;
        }
        if (objectType == SB_CANNONBALL_ALIAS_OBJECT_TYPE) {
            return;
        }
    }

    if (zero != cooldown) {
        return;
    }

    Sfx_PlayFromObject(obj, SB_CANNONBALL_IMPACT_SFX);
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    }
    state->impactCooldown = 100.0f;
    obj->anim.alpha = SB_CANNONBALL_IMPACT_ALPHA;

    {
        int i;
        for (i = SB_CANNONBALL_SMOKE_PARTICLE_COUNT; i != 0; i--) {
            (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_IMPACT_SMOKE_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
    {
        int i;
        for (i = SB_CANNONBALL_SPARK_PARTICLE_COUNT; i != 0; i--) {
            (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_IMPACT_SPARK_PARTICLE_ID, NULL, 1, -1, NULL);
        }
    }
}

void SB_CannonBall_update(GameObject* obj) {
    SBCannonBallState* state = obj->extra;
#define hitState ((ObjHitsPriorityState*)obj->anim.hitReactState)
    if ((state->flags & SB_CANNONBALL_INITIAL_BURST_FLAG) != 0) {
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_BURST_PARTICLE_ID, NULL, 1, -1, NULL);
        state->flags = (s8)(state->flags & ~SB_CANNONBALL_INITIAL_BURST_FLAG);
    } else {
        objfx_spawnFlaggedTrailBurst(obj, 0.22f, SB_CANNONBALL_TRAIL_MODE, SB_CANNONBALL_TRAIL_EFFECT_PARAM,
                                     SB_CANNONBALL_TRAIL_PARAM, NULL);
        objfx_spawnFlaggedTrailBurst(obj, 0.22f, SB_CANNONBALL_TRAIL_MODE, SB_CANNONBALL_TRAIL_EFFECT_PARAM,
                                     SB_CANNONBALL_TRAIL_PARAM, NULL);
    }
    (*gPartfxInterface)->spawnObject(obj, SB_CANNONBALL_TRAIL_PARTICLE_ID, NULL, 1, -1, NULL);
    obj->anim.rotY += SB_CANNONBALL_ROTATION_STEP;
    if ((state->flags & SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG) == 0) {
        state->velocityX = obj->anim.velocityX;
        state->velocityY = obj->anim.velocityY;
        state->velocityZ = obj->anim.velocityZ;
        state->flags = (s8)(state->flags | SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG);
        state->posX = obj->anim.localPosX;
        state->posY = obj->anim.localPosY;
        state->posZ = obj->anim.localPosZ;
    }
    {
        f64 ballisticScale = 1.5;
        state->posX = (f32)(ballisticScale * (f64)(state->velocityX * timeDelta) + state->posX);
        state->posY = (f32)(ballisticScale * (f64)(state->velocityY * timeDelta) + state->posY);
        state->posZ = (f32)(ballisticScale * (f64)(state->velocityZ * timeDelta) + state->posZ);
    }
    obj->anim.localPosX = state->posX;
    obj->anim.localPosY = state->posY;
    obj->anim.localPosZ = state->posZ;
    obj->userData1 -= framesThisStep;
    if (obj->userData1 < 0) {
        Obj_FreeObject(obj);
    }
    if (state->lifetimeFrames > SB_CANNONBALL_HITBOX_ENABLE_DELAY) {
        hitState->hitVolumePriority = SB_CANNONBALL_HIT_VOLUME_PRIORITY;
        hitState->hitVolumeId = SB_CANNONBALL_HIT_VOLUME_ID;
        hitState->objectHitMask = SB_CANNONBALL_HIT_VOLUME_OBJECT_MASK;
        hitState->skeletonHitMask = SB_CANNONBALL_HIT_VOLUME_OBJECT_MASK;
        hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
    } else {
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
    }
    state->lifetimeFrames += framesThisStep;
#undef hitState
}

void SB_CannonBall_init(GameObject* obj) {
    SBCannonBallState* state = obj->extra;
    if (state->modelLight == NULL) {
        state->modelLight = objCreateLight(obj, SB_CANNONBALL_LIGHT_ADD_TO_LIST);
        if (state->modelLight != NULL) {
            modelLightStruct_setLightKind(state->modelLight, SB_CANNONBALL_LIGHT_KIND);
            modelLightStruct_setDiffuseColor(state->modelLight, SB_CANNONBALL_LIGHT_RED, SB_CANNONBALL_LIGHT_GREEN,
                                             SB_CANNONBALL_LIGHT_BLUE, SB_CANNONBALL_LIGHT_ALPHA);
            modelLightStruct_setFieldBC(state->modelLight, SB_CANNONBALL_LIGHT_FIELD_BC);
            modelLightStruct_setDistanceAttenuation(state->modelLight, 150.0f, 250.0f);
        }
    }
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    }
    obj->anim.rootMotionScale *= 0.0125f;
    state->flags = (s8)(state->flags | SB_CANNONBALL_INITIAL_BURST_FLAG);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LAUNCH_SFX);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LOOP_SFX);
}

void SB_CannonBall_release(void) {
}

void SB_CannonBall_initialise(void) {
}

ObjectDescriptor gSB_CannonBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_CannonBall_initialise,
    SB_CannonBall_release,
    0,
    (ObjectDescriptorCallback)SB_CannonBall_init,
    (ObjectDescriptorCallback)SB_CannonBall_update,
    (ObjectDescriptorCallback)SB_CannonBall_hitDetect,
    (ObjectDescriptorCallback)SB_CannonBall_render,
    (ObjectDescriptorCallback)SB_CannonBall_free,
    (ObjectDescriptorCallback)SB_CannonBall_getObjectTypeId,
    SB_CannonBall_getExtraSize,
};
