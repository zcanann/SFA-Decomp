/*
 * DIMbossfire (DLL 0x1E7) - flame-jet emitters around the DarkIce Mines boss
 * arena. Each instance fires on a random cooldown or in response to a game bit,
 * drives burst and sustained particle effects, and owns its temporary hitbox
 * and point light.
 */
#include "dlls/objects/487_DIMbossfire.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_shake_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/model_light.h"
#include "main/objhits.h"
#include "main/pad_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define DIMBOSSFIRE_HIT_VOLUME_SLOT 9

#define DIMBOSSFIRE_FLAG_START_BURST 1
#define DIMBOSSFIRE_COOLDOWN_MIN     0xf0  /* Minimum random cooldown, in frames. */
#define DIMBOSSFIRE_COOLDOWN_MAX     0x1e0 /* Maximum random cooldown, in frames. */
#define DIMBOSSFIRE_BURST_COUNT      50
#define DIMBOSSFIRE_HIT_RADIUS       15

f32 gDimbossfireActiveDurations[DIMBOSSFIRE_FLAME_COUNT] = {
    160.0f, 30.0f, 110.0f, 160.0f, 80.0f, 40.0f, 120.0f, 60.0f, 120.0f, 120.0f,
};

/*
 * Orange effects use flameColor != 0; green effects use flameColor == 0.
 * The sustained base effect is emitted alongside the color-specific effect.
 */
#define DIMBOSSFIRE_PARTFX_BURST_ORANGE     0x4c9
#define DIMBOSSFIRE_PARTFX_BURST_GREEN      0x4cc
#define DIMBOSSFIRE_PARTFX_SUSTAINED        0x4ca
#define DIMBOSSFIRE_PARTFX_SUSTAINED_ORANGE 0x4cb
#define DIMBOSSFIRE_PARTFX_SUSTAINED_GREEN  0x4cd

int dimbossfire_getExtraSize(void) {
    return sizeof(DimBossFireState);
}

int dimbossfire_getObjectTypeId(void) {
    return 0;
}

void dimbossfire_free(GameObject* obj) {
    DimBossFireState* state;
    ModelLightStruct* light;

    state = obj->extra;
    light = state->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
        state->light = NULL;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dimbossfire_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }
}

void dimbossfire_hitDetect(void) {
}

void dimbossfire_update(GameObject* obj) {
    u32 triggerValue;
    ModelLightStruct* light;
    int burstIndex;
    GameObject* player;
    DimBossFireState* state;
    DimBossFirePlacementView* placement;
    f32 playerDistance;

    state = obj->extra;
    placement = (DimBossFirePlacementView*)obj->anim.placementData;
    if (placement->triggerGameBit != -1) {
        triggerValue = mainGetBit(placement->triggerGameBit);
        if (triggerValue != 0) {
            mainSetBits(placement->triggerGameBit, 0);
            state->flags |= DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = gDimbossfireActiveDurations[state->durationIndex];
            state->initialActiveTimer = state->activeTimer;
            state->durationIndex += 1;
            if (state->durationIndex >= DIMBOSSFIRE_FLAME_COUNT) {
                state->durationIndex = 0;
            }
        }
    } else {
        state->cooldownTimer -= timeDelta;
        if (state->cooldownTimer <= 0.0f) {
            state->cooldownTimer = randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
            state->flags |= DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = gDimbossfireActiveDurations[state->durationIndex];
            state->initialActiveTimer = state->activeTimer;
            state->durationIndex += 1;
            if (state->durationIndex >= DIMBOSSFIRE_FLAME_COUNT) {
                state->durationIndex = 0;
            }
        }
    }
    if (state->activeTimer > 0.0f) {
        if ((state->flags & DIMBOSSFIRE_FLAG_START_BURST) != 0) {
            state->flags &= ~DIMBOSSFIRE_FLAG_START_BURST;
            ObjHits_SetHitVolumeSlot(&obj->anim, DIMBOSSFIRE_HIT_VOLUME_SLOT, 1, 0);
            ObjHitbox_SetSphereRadius(&obj->anim, DIMBOSSFIRE_HIT_RADIUS);
            ObjHits_EnableObject(obj);
            if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                burstIndex = 0;
                do {
                    if (placement->flameColor != 0) {
                        (*gPartfxInterface)->spawnObject(obj, DIMBOSSFIRE_PARTFX_BURST_ORANGE, NULL, 2, -1, NULL);
                    } else {
                        (*gPartfxInterface)->spawnObject(obj, DIMBOSSFIRE_PARTFX_BURST_GREEN, NULL, 2, -1, NULL);
                    }
                    burstIndex += 1;
                } while (burstIndex < DIMBOSSFIRE_BURST_COUNT);
            }
            player = Obj_GetPlayerObject();
            if ((player != NULL) && ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
                playerDistance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
                if (playerDistance <= 200.0f) {
                    playerDistance = 1.0f - playerDistance / 200.0f;
                    CameraShake_StartDampened(10.0f * playerDistance, 10.0f, 4.0f);
                    doRumble(22.0f * playerDistance);
                }
            }
            if (state->light == NULL) {
                light = objCreateLight(obj, 1);
                state->light = light;
                if (state->light != NULL) {
                    modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                    modelLightStruct_setFieldBC(state->light, 1);
                    if (placement->flameColor != 0) {
                        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0);
                    } else {
                        modelLightStruct_setDiffuseColor(state->light, 0x7f, 0xff, 0, 0);
                    }
                    modelLightStruct_setDistanceAttenuation(state->light, 150.0f, 180.0f);
                    modelLightStruct_setEnabled(state->light, 1, 0.0f);
                    modelLightStruct_setEnabled(state->light, 0, state->activeTimer / 60.0f);
                }
            }
            Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_188);
        }
        state->activeTimer -= timeDelta;
        if (state->activeTimer <= 0.0f) {
            state->activeTimer = 0.0f;
            if (state->light != NULL) {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
            ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
            ObjHitbox_SetSphereRadius(&obj->anim, 0);
            ObjHits_DisableObject(obj);
        } else {
            (*gPartfxInterface)->spawnObject(obj, DIMBOSSFIRE_PARTFX_SUSTAINED, NULL, 2, -1, NULL);
            if (placement->flameColor != 0) {
                (*gPartfxInterface)->spawnObject(obj, DIMBOSSFIRE_PARTFX_SUSTAINED_ORANGE, NULL, 2, -1, NULL);
            } else {
                (*gPartfxInterface)->spawnObject(obj, DIMBOSSFIRE_PARTFX_SUSTAINED_GREEN, NULL, 2, -1, NULL);
            }
        }
    }
    return;
}

void dimbossfire_init(GameObject* obj, u32 placementAddress, int isAltVariant) {
    u8 durationIndex;
    DimBossFireState* state;

    state = obj->extra;
    ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
    ObjHitbox_SetSphereRadius(&obj->anim, 0);
    ObjHits_DisableObject(obj);
    if (isAltVariant == 0) {
        state->cooldownTimer = randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
        durationIndex = randomGetRange(0, 9);
        state->durationIndex = durationIndex;
    }
    return;
}

void dimbossfire_release(void) {
}

void dimbossfire_initialise(void) {
}

ObjectDescriptor gDIMbossfireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dimbossfire_initialise,
    dimbossfire_release,
    0,
    (ObjectDescriptorCallback)dimbossfire_init,
    (ObjectDescriptorCallback)dimbossfire_update,
    dimbossfire_hitDetect,
    (ObjectDescriptorCallback)dimbossfire_render,
    (ObjectDescriptorCallback)dimbossfire_free,
    (ObjectDescriptorCallback)dimbossfire_getObjectTypeId,
    dimbossfire_getExtraSize,
};
