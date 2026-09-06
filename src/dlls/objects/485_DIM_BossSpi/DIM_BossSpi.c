/*
 * DIM_BossSpi (DLL 0x1E5) - DarkIce Mines boss spit projectile.
 * The projectile tumbles under gravity and emits a particle trail until
 * contact, then expands, fades, shakes the camera, rumbles, and changes its
 * spherical hitbox while its green glow flickers.
 */
#include "dlls/objects/485_DIM_BossSpi.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_shake_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/pad_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIMBOSSSPIT_PHASE_FLIGHT                     0
#define DIMBOSSSPIT_BURST_START_FRAME                1
#define DIMBOSSSPIT_PARTFX_BURST_START               0x340
#define DIMBOSSSPIT_PARTFX_BURST_FLASH               0x4BB
#define DIMBOSSSPIT_PARTFX_FLIGHT_TRAIL              0x4BA
#define DIMBOSSSPIT_PARTFX_BURST                     0x4BC
#define DIMBOSSSPIT_PARTFX_MODE                      1
#define DIMBOSSSPIT_PARTFX_MODEL_NONE                -1
#define DIMBOSSSPIT_BURST_START_PARTICLE_COUNT       0x12
#define DIMBOSSSPIT_FLIGHT_TRAIL_PARTICLE_COUNT      3
#define DIMBOSSSPIT_HIT_VOLUME_SLOT_FLIGHT_AND_BURST 5
#define DIMBOSSSPIT_HIT_VOLUME_SLOT_FADE             9
#define DIMBOSSSPIT_HIT_TYPE_FLIGHT                  4
#define DIMBOSSSPIT_HIT_TYPE_BURST                   2
#define DIMBOSSSPIT_HIT_TYPE_FADE                    1
#define DIMBOSSSPIT_FLIGHT_RADIUS                    10
#define DIMBOSSSPIT_BURST_SCALE_STEP                 0.2f
#define DIMBOSSSPIT_BURST_ROT_X_STEP                 0xAAA
#define DIMBOSSSPIT_BURST_ROT_YZ_STEP                0x38E
#define DIMBOSSSPIT_BURST_EFFECT_END_FRAME           0x200
#define DIMBOSSSPIT_BURST_FREE_FRAME                 0x22A
#define DIMBOSSSPIT_BURST_ALPHA_MAX                  0xFF
#define DIMBOSSSPIT_BURST_ALPHA_SCALE                255.0f
#define DIMBOSSSPIT_BURST_ALPHA_FRAMES               64.0f
#define DIMBOSSSPIT_BURST_RADIUS_START               0x94
#define DIMBOSSSPIT_BURST_RADIUS_BASE                0x40
#define DIMBOSSSPIT_BURST_MIN_HIT_RADIUS             10.0f
#define DIMBOSSSPIT_CONTACT_Y_OFFSET                 10.0f
#define DIMBOSSSPIT_FLIGHT_ROT_X_SPEED               910.0f
#define DIMBOSSSPIT_FLIGHT_ROT_YZ_SPEED              364.0f
#define DIMBOSSSPIT_LIFETIME_FRAMES                  0xB4
#define DIMBOSSSPIT_GLOW_RANDOMIZE_THRESHOLD         0x0C
#define DIMBOSSSPIT_GLOW_RANDOM_MIN                  -12
#define DIMBOSSSPIT_GLOW_RANDOM_MAX                  12
#define DIMBOSSSPIT_GLOW_ALPHA_MAX                   0xFF

void DIMbossspit_updateBurst(GameObject* obj) {
    DIMbossSpitState* stateAddress;
    s16 burstTimer;
    int alphaFade;
    int alpha;
    int radius;
    int i;

    stateAddress = obj->extra;
    obj->anim.rootMotionScale += DIMBOSSSPIT_BURST_SCALE_STEP;
    obj->anim.rotX += DIMBOSSSPIT_BURST_ROT_X_STEP;
    obj->anim.rotZ += DIMBOSSSPIT_BURST_ROT_YZ_STEP;
    obj->anim.rotY += DIMBOSSSPIT_BURST_ROT_YZ_STEP;
    if (stateAddress->burstTimer == DIMBOSSSPIT_BURST_START_FRAME) {
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSSSPIT_PARTFX_BURST_START, NULL, DIMBOSSSPIT_PARTFX_MODE,
                              DIMBOSSSPIT_PARTFX_MODEL_NONE, NULL);
            i += 1;
        } while (i < DIMBOSSSPIT_BURST_START_PARTICLE_COUNT);
        (*gPartfxInterface)
            ->spawnObject(obj, DIMBOSSSPIT_PARTFX_BURST_FLASH, NULL, DIMBOSSSPIT_PARTFX_MODE,
                          DIMBOSSSPIT_PARTFX_MODEL_NONE, NULL);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_gcexp1_c);
        Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311);
        CameraShake_SetOffset(3.0f);
        doRumble(12.0f);
        if (stateAddress->light != NULL) {
            modelLightStruct_setEnabled(stateAddress->light, 0, 1.0f);
        }
    }
    stateAddress->burstTimer += framesThisStep;
    burstTimer = stateAddress->burstTimer;
    if (burstTimer > DIMBOSSSPIT_BURST_EFFECT_END_FRAME) {
        if (burstTimer > DIMBOSSSPIT_BURST_FREE_FRAME) {
            Obj_FreeObject(obj);
        }
        return;
    }
    alphaFade = (int)(DIMBOSSSPIT_BURST_ALPHA_SCALE * ((f32)(s32)burstTimer / DIMBOSSSPIT_BURST_ALPHA_FRAMES));
    alpha = DIMBOSSSPIT_BURST_ALPHA_MAX - alphaFade;
    radius = DIMBOSSSPIT_BURST_RADIUS_START - (burstTimer >> 2);
    if (alpha >= 0) {
        ObjHits_SetHitVolumeSlot(&obj->anim, DIMBOSSSPIT_HIT_VOLUME_SLOT_FLIGHT_AND_BURST, DIMBOSSSPIT_HIT_TYPE_BURST,
                                 0);
        ObjHitbox_SetSphereRadius(&obj->anim, (s16)((radius - DIMBOSSSPIT_BURST_RADIUS_BASE) >> 1));
        obj->anim.alpha = alpha;
    } else {
        if (stateAddress->light != NULL) {
            ModelLightStruct_free(stateAddress->light);
            stateAddress->light = NULL;
        }
        obj->anim.alpha = 0;
        if ((f32)(s32)((radius - DIMBOSSSPIT_BURST_RADIUS_BASE) >> 1) > DIMBOSSSPIT_BURST_MIN_HIT_RADIUS) {
            ObjHits_SetHitVolumeSlot(&obj->anim, DIMBOSSSPIT_HIT_VOLUME_SLOT_FADE, DIMBOSSSPIT_HIT_TYPE_FADE, 0);
            ObjHitbox_SetSphereRadius(&obj->anim, (s16)((radius - DIMBOSSSPIT_BURST_RADIUS_BASE) >> 1));
        }
    }
    (*gPartfxInterface)
        ->spawnObject(obj, DIMBOSSSPIT_PARTFX_BURST, NULL, DIMBOSSSPIT_PARTFX_MODE, DIMBOSSSPIT_PARTFX_MODEL_NONE,
                      &radius);
}


int DIMbossspit_getExtraSize(void) {
    return sizeof(DIMbossSpitState);
}

int DIMbossspit_getObjectTypeId(void) {
    return 0;
}

void DIMbossspit_free(GameObject* objArg) {
    GameObject* obj = objArg;
    DIMbossSpitState* state;
    ModelLightStruct* light;

    state = obj->extra;
    light = state->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

void DIMbossspit_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DIMbossSpitState* state;
    ModelLightStruct* light;

    state = obj->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        light = state->light;
        if (((light != 0) && (light->glowType != 0)) && (light->enabled != 0)) {
            queueGlowRender(light);
        }
    }
    return;
}

void DIMbossspit_hitDetect(void) {
}

void DIMbossspit_update(GameObject* obj) {
    DIMbossSpitState* stateAddress;
    int i;
    s16 glowAlpha;
    ModelLightStruct* light;

    stateAddress = obj->extra;
    if (*(s16*)stateAddress == DIMBOSSSPIT_PHASE_FLIGHT) {
        obj->userData1 -= framesThisStep;
        if (obj->userData1 < 0) {
            Obj_FreeObject(obj);
            return;
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, DIMBOSSSPIT_HIT_VOLUME_SLOT_FLIGHT_AND_BURST, DIMBOSSSPIT_HIT_TYPE_FLIGHT,
                                 0);
        ObjHitbox_SetSphereRadius(&obj->anim, DIMBOSSSPIT_FLIGHT_RADIUS);
        obj->anim.velocityY = obj->anim.velocityY - 0.07f * timeDelta;
        obj->anim.velocityY *= 0.97f;
        obj->anim.rotX = DIMBOSSSPIT_FLIGHT_ROT_X_SPEED * timeDelta + (f32)obj->anim.rotX;
        obj->anim.rotZ = DIMBOSSSPIT_FLIGHT_ROT_YZ_SPEED * timeDelta + (f32)obj->anim.rotZ;
        obj->anim.rotY = DIMBOSSSPIT_FLIGHT_ROT_YZ_SPEED * timeDelta + (f32)obj->anim.rotY;
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSSSPIT_PARTFX_FLIGHT_TRAIL, NULL, DIMBOSSSPIT_PARTFX_MODE,
                              DIMBOSSSPIT_PARTFX_MODEL_NONE, NULL);
            i += 1;
        } while (i < DIMBOSSSPIT_FLIGHT_TRAIL_PARTICLE_COUNT);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0) {
            obj->anim.localPosX = ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosX;
            obj->anim.localPosY =
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosY - DIMBOSSSPIT_CONTACT_Y_OFFSET;
            obj->anim.localPosZ = ((ObjHitsPriorityState*)obj->anim.hitReactState)->contactPosZ;
            *(s16*)stateAddress = DIMBOSSSPIT_BURST_START_FRAME;
        }
    } else {
        DIMbossspit_updateBurst(obj);
    }
    light = stateAddress->light;
    if (light != NULL && light->glowType != 0 && light->enabled != 0) {
        glowAlpha = (s16)(light->glowAlpha + light->glowAlphaStep);
        if (glowAlpha < 0) {
            glowAlpha = 0;
            light->glowAlphaStep = 0;
        } else if (glowAlpha > DIMBOSSSPIT_GLOW_RANDOMIZE_THRESHOLD) {
            glowAlpha = (s16)(glowAlpha + randomGetRange(DIMBOSSSPIT_GLOW_RANDOM_MIN, DIMBOSSSPIT_GLOW_RANDOM_MAX));
            if (glowAlpha > DIMBOSSSPIT_GLOW_ALPHA_MAX) {
                glowAlpha = DIMBOSSSPIT_GLOW_ALPHA_MAX;
                stateAddress->light->glowAlphaStep = 0;
            }
        }
        stateAddress->light->glowAlpha = glowAlpha;
    }
    return;
}

void DIMbossspit_init(GameObject* obj) {
    DIMbossSpitState* state = obj->extra;

    state->light = objCreateLight(obj, 1);
    if (state->light != NULL) {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0, 255, 0, 0);
        modelLightStruct_setSpecularColor(state->light, 0, 255, 0, 0);
        modelLightStruct_setDistanceAttenuation(state->light, 180.0f, 200.0f);
        lightSetField4D(state->light, 1);
        modelLightStruct_setEnabled(state->light, 1, 0.0f);
        modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        modelLightStruct_setupGlow(state->light, 0, 0, 255, 0, 127, 50.0f);
        modelLightStruct_setGlowProjectionRadius(state->light, 100.0f);
    }
    obj->userData1 = DIMBOSSSPIT_LIFETIME_FRAMES;
    ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
    ObjHitbox_SetSphereRadius(&obj->anim, 0);
    state->phase = DIMBOSSSPIT_PHASE_FLIGHT;
    state->unknown02 = 0;
    ObjHits_EnableObject(obj);
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
}

void DIMbossspit_release(void) {
}

void DIMbossspit_initialise(void) {
}

ObjectDescriptor gDIM_BossSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    DIMbossspit_initialise,
    DIMbossspit_release,
    0,
    (ObjectDescriptorCallback)DIMbossspit_init,
    (ObjectDescriptorCallback)DIMbossspit_update,
    DIMbossspit_hitDetect,
    (ObjectDescriptorCallback)DIMbossspit_render,
    (ObjectDescriptorCallback)DIMbossspit_free,
    (ObjectDescriptorCallback)DIMbossspit_getObjectTypeId,
    DIMbossspit_getExtraSize,
};
