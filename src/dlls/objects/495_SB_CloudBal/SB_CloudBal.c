/*
 * SB_CloudBal (DLL 0x1EF) - the cloud-ball projectile fired during the
 * ShipBattle (SB) set. On launch it captures its initial velocity, then
 * drifts on that velocity each tick (scaled), faces its travel direction,
 * and arms a contact hitbox. On a hit against the target type, or once it
 * outlives its lifetime / the player clears the wave, it plays a burst
 * effect, fades out (fadeTimer) and frees itself. A trailing particle
 * burst is spawned every frame while alive.
 */
#include "dlls/objects/495_SB_CloudBal.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/modellight_api.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

enum {
    SB_CLOUD_BALL_LIGHT_KIND = 2
};

ModelLightStruct* objCreateLight(void* owner, u8 addToList);
void ModelLightStruct_free(ModelLightStruct* light);
void modelLightStruct_setLightKind(ModelLightStruct* light, int lightKind);
void modelLightStruct_setDistanceAttenuation(ModelLightStruct* light, f32 near, f32 far);
void modelLightStruct_setDiffuseColor(ModelLightStruct* light, int red, int green, int blue, int alpha);

/* Animation sequence ID that plays the shatter sound on contact. */
#define SB_CLOUD_BALL_HIT_SFX_TARGET_SEQUENCE_ID 0x8E

#define SB_CLOUD_BALL_FADE_TIME            50.0f
#define SB_CLOUD_BALL_VELOCITY_SCALE       2.0f
#define SB_CLOUD_BALL_TRAIL_VELOCITY_SCALE 0.1f
#define SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE 0.22f

#define SB_CLOUD_BALL_HIT_VOLUME_PRIORITY 5
#define SB_CLOUD_BALL_HIT_VOLUME_ID       1
#define SB_CLOUD_BALL_HIT_MASK            0x10
#define SB_CLOUD_BALL_CONTACT_MASK        1

#define SB_CLOUD_BALL_TRAIL_BURST_MODE            2
#define SB_CLOUD_BALL_TRAIL_BURST_EFFECT_PARAM    0x156
#define SB_CLOUD_BALL_TRAIL_BURST_SECONDARY_PARAM 0xF
#define SB_CLOUD_BALL_TRAIL_PARTICLE_ID           0xA8

#define SB_CLOUD_BALL_RANDOM_SCALE      0.005f
#define SB_CLOUD_BALL_RANDOM_SCALE_BASE 3.0f
#define SB_CLOUD_BALL_RANDOM_RANGE_MIN  -100
#define SB_CLOUD_BALL_RANDOM_RANGE_MAX  100

#define SB_CLOUD_BALL_LIGHT_ADD_TO_LIST 1
#define SB_CLOUD_BALL_LIGHT_RED         0
#define SB_CLOUD_BALL_LIGHT_GREEN       90
#define SB_CLOUD_BALL_LIGHT_BLUE        150
#define SB_CLOUD_BALL_LIGHT_ALPHA       0
#define SB_CLOUD_BALL_LIGHT_FIELD_BC    1

int SB_CloudBall_getExtraSize(void) {
    return sizeof(SBCloudBallState);
}

int SB_CloudBall_getObjectTypeId(void) {
    return 0;
}

void SB_CloudBall_free(GameObject* obj) {
    SBCloudBallState* state = obj->extra;

    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}

void SB_CloudBall_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void SB_CloudBall_hitDetect(GameObject* obj) {
    SBCloudBallState* state = obj->extra;
    GameObject* target = (GameObject*)ObjAnim_GetPriorityHitState(&obj->anim)->lastHitObject;
    f32 zero = 0.0f;

    if (target == NULL) {
        return;
    }
    if (state->fadeTimer != zero) {
        return;
    }
    if (target->anim.romDefNo == SB_CLOUD_BALL_HIT_SFX_TARGET_SEQUENCE_ID) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_gcfir1_c);
    }
    {
        ObjHitsPriorityState* hitState = ObjAnim_GetPriorityHitState(&obj->anim);
        hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    }
    state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
    obj->anim.alpha = 0;
    projectileDoParticleFx(obj, 1.0f, 2);
}

void SB_CloudBall_update(GameObject* obj) {
    SBCloudBallState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    f32 timer = state->fadeTimer;
    f32 zero = 0.0f;

    if (timer != zero) {
        state->fadeTimer = timer - timeDelta;
        if (state->fadeTimer <= zero) {
            state->fadeTimer = zero;
            Obj_FreeObject(obj);
        }
    } else {
        f32 particleVelocity[3];
        f32 velocityScale;

        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        obj->anim.rootMotionScale = SB_CLOUD_BALL_RANDOM_SCALE * randomGetRange(SB_CLOUD_BALL_RANDOM_RANGE_MIN,
                                                                                     SB_CLOUD_BALL_RANDOM_RANGE_MAX) +
                                    SB_CLOUD_BALL_RANDOM_SCALE_BASE;
        if (state->launched == 0) {
            state->velocityX = obj->anim.velocityX;
            state->velocityY = obj->anim.velocityY;
            state->velocityZ = obj->anim.velocityZ;
            state->launched = 1;
            state->positionX = obj->anim.localPosX;
            state->positionY = obj->anim.localPosY;
            state->positionZ = obj->anim.localPosZ;
        }
        velocityScale = SB_CLOUD_BALL_VELOCITY_SCALE;
        state->positionX = velocityScale * (state->velocityX * timeDelta) + state->positionX;
        state->positionY = velocityScale * (state->velocityY * timeDelta) + state->positionY;
        state->positionZ = velocityScale * (state->velocityZ * timeDelta) + state->positionZ;
        obj->anim.localPosX = state->positionX;
        obj->anim.localPosY = state->positionY;
        obj->anim.localPosZ = state->positionZ;
        obj->userData1 -= framesThisStep;
        if (obj->userData1 < 0 || (player != NULL && (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)) {
            if (state->fadeTimer == zero) {
                obj->anim.alpha = 0;
                state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
            }
        }
        obj->anim.rotX = (s16)getAngle(obj->anim.localPosX - obj->anim.previousLocalPosX,
                                       obj->anim.localPosZ - obj->anim.previousLocalPosZ);
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumePriority = SB_CLOUD_BALL_HIT_VOLUME_PRIORITY;
        ObjAnim_GetPriorityHitState(&obj->anim)->hitVolumeId = SB_CLOUD_BALL_HIT_VOLUME_ID;
        ObjAnim_GetPriorityHitState(&obj->anim)->objectHitMask = SB_CLOUD_BALL_HIT_MASK;
        ObjAnim_GetPriorityHitState(&obj->anim)->skeletonHitMask = SB_CLOUD_BALL_HIT_MASK;
        ObjAnim_GetPriorityHitState(&obj->anim)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
        if (ObjAnim_GetPriorityHitState(&obj->anim)->contactFlags != 0 && state->fadeTimer == zero) {
            projectileDoParticleFx(obj, 1.0f, 2);
            state->fadeTimer = SB_CLOUD_BALL_FADE_TIME;
            obj->anim.alpha = 0;
        }
        particleVelocity[0] = SB_CLOUD_BALL_TRAIL_VELOCITY_SCALE * -state->velocityX;
        particleVelocity[1] = SB_CLOUD_BALL_TRAIL_VELOCITY_SCALE * -state->velocityY;
        particleVelocity[2] = SB_CLOUD_BALL_TRAIL_VELOCITY_SCALE * -state->velocityZ;
        objfx_spawnFlaggedTrailBurst(obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, SB_CLOUD_BALL_TRAIL_BURST_MODE,
                                     SB_CLOUD_BALL_TRAIL_BURST_EFFECT_PARAM, SB_CLOUD_BALL_TRAIL_BURST_SECONDARY_PARAM,
                                     particleVelocity);
        objfx_spawnFlaggedTrailBurst(obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, SB_CLOUD_BALL_TRAIL_BURST_MODE,
                                     SB_CLOUD_BALL_TRAIL_BURST_EFFECT_PARAM, SB_CLOUD_BALL_TRAIL_BURST_SECONDARY_PARAM,
                                     particleVelocity);
        objfx_spawnFlaggedTrailBurst(obj, SB_CLOUD_BALL_TRAIL_PARTICLE_SCALE, SB_CLOUD_BALL_TRAIL_BURST_MODE,
                                     SB_CLOUD_BALL_TRAIL_BURST_EFFECT_PARAM, SB_CLOUD_BALL_TRAIL_BURST_SECONDARY_PARAM,
                                     particleVelocity);
        (*gPartfxInterface)
            ->spawnObject((void*)obj, SB_CLOUD_BALL_TRAIL_PARTICLE_ID, NULL, SB_CLOUD_BALL_TRAIL_BURST_MODE, -1, NULL);
    }
}

void SB_CloudBall_init(GameObject* obj) {
    SBCloudBallState* state = obj->extra;

    ObjAnim_GetPriorityHitState(&obj->anim)->flags =
        (s16)(ObjAnim_GetPriorityHitState(&obj->anim)->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask =
        (u16)(ObjAnim_GetPriorityHitState(&obj->anim)->trackContactMask | SB_CLOUD_BALL_CONTACT_MASK);
    if (state->light == NULL) {
        state->light = objCreateLight(obj, SB_CLOUD_BALL_LIGHT_ADD_TO_LIST);
        if (state->light != NULL) {
            modelLightStruct_setLightKind(state->light, SB_CLOUD_BALL_LIGHT_KIND);
            modelLightStruct_setDiffuseColor(state->light, SB_CLOUD_BALL_LIGHT_RED, SB_CLOUD_BALL_LIGHT_GREEN,
                                             SB_CLOUD_BALL_LIGHT_BLUE, SB_CLOUD_BALL_LIGHT_ALPHA);
            modelLightStruct_setFieldBC(state->light, SB_CLOUD_BALL_LIGHT_FIELD_BC);
            modelLightStruct_setDistanceAttenuation(state->light, 150.0f, 250.0f);
        }
    }
}

void SB_CloudBall_release(void) {
}

void SB_CloudBall_initialise(void) {
}

ObjectDescriptor gSB_CloudBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_CloudBall_initialise,
    SB_CloudBall_release,
    0,
    (ObjectDescriptorCallback)SB_CloudBall_init,
    (ObjectDescriptorCallback)SB_CloudBall_update,
    (ObjectDescriptorCallback)SB_CloudBall_hitDetect,
    (ObjectDescriptorCallback)SB_CloudBall_render,
    (ObjectDescriptorCallback)SB_CloudBall_free,
    (ObjectDescriptorCallback)SB_CloudBall_getObjectTypeId,
    SB_CloudBall_getExtraSize,
};
