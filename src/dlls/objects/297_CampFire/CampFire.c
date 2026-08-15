/*
 * CampFire area object (DLL slot 297 / 0x129).
 *
 * At night the fire enables its light, hit volume, looped sound, and a
 * one-second pulse mode. During the day those are disabled and a slower pulse
 * count is emitted every ten seconds. The glow alpha also receives a small
 * random flicker while the light is active.
 */
#include "dlls/objects/297_CampFire.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objanim_internal.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/sky_interface.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/model_light.h"

#define CAMPFIRE_HIT_VOLUME_SLOT        0x1F
#define CAMPFIRE_DAY_BURST_INTERVAL     10.0f
#define CAMPFIRE_NIGHT_BURST_INTERVAL   1.0f
#define CAMPFIRE_PULSE_SCALE            1.4f
#define CAMPFIRE_GLOW_FLICKER_MIN       -0x19
#define CAMPFIRE_GLOW_FLICKER_MAX       0x19
#define CAMPFIRE_GLOW_BRIGHTNESS_MIN    0
#define CAMPFIRE_GLOW_BRIGHTNESS_MAX    0xFF
#define CAMPFIRE_PLACEMENT_SCALE_FACTOR 0.01f

int CampFire_getExtraSize(void) {
    return sizeof(CampFireState);
}

int CampFire_getObjectTypeId(void) {
    return 0x1;
}

void CampFire_free(GameObject* obj) {
    CampFireState* state;
    ModelLightStruct* light;

    state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    light = state->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
    }
}

void CampFire_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    CampFireState* state;
    ModelLightStruct* light;

    state = obj->extra;
    if (visible) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        light = state->light;
        if (light != NULL && light->glowType != 0 && light->enabled != 0) {
            queueGlowRender(light);
        }
    }
}

void CampFire_update(GameObject* obj) {
    CampFireState* state;
    int effectType;
    int effectCount;
    int effectMode;
    f32 sunTime;
    f32 effectOffset[3];

    state = obj->extra;
    Obj_GetPlayerObject();
    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0) {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 1, 1.0f);
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, CAMPFIRE_HIT_VOLUME_SLOT, 1, 0);
        state->nightBurstTimer -= timeDelta;
        if (state->nightBurstTimer <= 0.0f) {
            effectMode = 1;
            state->nightBurstTimer += CAMPFIRE_NIGHT_BURST_INTERVAL;
        } else {
            effectMode = 0;
        }
        effectType = 2;
        effectCount = 0;
        if (state->loopSoundPlaying == 0) {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->loopSoundPlaying = 1;
        }
    } else {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 1.0f);
        }
        ObjHits_ClearHitVolumes(&obj->anim);
        state->dayBurstTimer -= timeDelta;
        if (state->dayBurstTimer <= 0.0f) {
            effectCount = 3;
            state->dayBurstTimer += CAMPFIRE_DAY_BURST_INTERVAL;
        } else {
            effectCount = 0;
        }
        effectType = 0;
        effectMode = 0;
        if (state->loopSoundPlaying != 0) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->loopSoundPlaying = 0;
        }
    }
    effectOffset[0] = 0.0f;
    effectOffset[1] = 10.0f;
    effectOffset[2] = 0.0f;
    objfx_spawnPulseBurst(obj, CAMPFIRE_PULSE_SCALE * obj->anim.rootMotionScale, effectType, effectCount, effectMode,
                          effectOffset);
    {
        ModelLightStruct* activeLight = state->light;
        if (activeLight != NULL && activeLight->glowType != 0 && activeLight->enabled != 0) {
            int flickerOffset;
            ModelLightStruct* flickerLight;
            s16 brightness;

            flickerOffset = randomGetRange(CAMPFIRE_GLOW_FLICKER_MIN, CAMPFIRE_GLOW_FLICKER_MAX);
            flickerLight = state->light;
            brightness = flickerLight->glowAlpha + flickerLight->glowAlphaStep + flickerOffset;
            if (brightness < CAMPFIRE_GLOW_BRIGHTNESS_MIN) {
                brightness = CAMPFIRE_GLOW_BRIGHTNESS_MIN;
                flickerLight->glowAlphaStep = 0;
            } else if (brightness > CAMPFIRE_GLOW_BRIGHTNESS_MAX) {
                brightness = CAMPFIRE_GLOW_BRIGHTNESS_MAX;
                flickerLight->glowAlphaStep = 0;
            }
            state->light->glowAlpha = brightness;
        }
    }
}

void CampFire_init(GameObject* obj, CampFirePlacement* placement) {
    CampFireState* state;
    f32 sunTime;
    u32 scalePercent;
    s16 placementGameBit;

    state = obj->extra;
    scalePercent = placement->scalePercent;
    if (scalePercent != 0) {
        obj->anim.rootMotionScale = CAMPFIRE_PLACEMENT_SCALE_FACTOR * scalePercent;
    }
    if (mainGetBit(0x8C) != 0) {
        state->flags |= CAMPFIRE_STATE_FLAG_GAME_BIT_8C_SET;
    }
    state->placementGameBit = placement->gameBit;
    placementGameBit = state->placementGameBit;
    if (placementGameBit != -1 && mainGetBit(placementGameBit) != 0) {
        state->flags |= CAMPFIRE_STATE_FLAG_PLACEMENT_GAME_BIT_SET;
    }
    state->placementParam = placement->unk1B;
    {
        f32 scale =
            obj->anim.rootMotionScale / obj->anim.modelInstance->rootMotionScaleBase;
        ObjHitsPriorityState* hitState = ObjAnim_GetPriorityHitState(&obj->anim);

        ObjHitbox_SetCapsuleBounds(&obj->anim, (int)((f32)hitState->primaryRadius * scale),
                                   (int)((f32)hitState->primaryCapsuleOffsetA * scale),
                                   (int)((f32)hitState->primaryCapsuleOffsetB * scale));
    }
    state->dayBurstTimer = CAMPFIRE_DAY_BURST_INTERVAL;
    state->nightBurstTimer = CAMPFIRE_NIGHT_BURST_INTERVAL;
    if (state->light == NULL) {
        state->light = objCreateLight(obj, 1);
    }
    if (state->light != NULL) {
        int attenuation;

        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0xFF, 0x7F, 0, 0xFF);
        modelLightStruct_setSpecularColor(state->light, 0xFF, 0x7F, 0, 0xFF);
        attenuation = (int)(20.0f * obj->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, attenuation, 30.0f + attenuation);
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0) {
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
        } else {
            modelLightStruct_setEnabled(state->light, 0, 0.0f);
        }
        modelLightStruct_setPosition(state->light, 0.0f, 12.0f, 0.0f);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xFF, 0x5C, 0, 0xFF);
        modelLightStruct_setupGlow(state->light, 0, 0xFF, 0x7F, 0, 0x87,
                                   40.0f * obj->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, 30.0f);
    }
}

ObjectDescriptor gCampFireObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)CampFire_init, (ObjectDescriptorCallback)CampFire_update, 0,
    (ObjectDescriptorCallback)CampFire_render, (ObjectDescriptorCallback)CampFire_free,
    (ObjectDescriptorCallback)CampFire_getObjectTypeId, CampFire_getExtraSize,
};
