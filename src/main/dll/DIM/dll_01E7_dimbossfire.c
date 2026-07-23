/*
 * dimbossfire (DLL 0x1E7) - DIM boss flame-jet emitters placed around the boss
 * arena.  Each instance fires on a random cooldown (or is triggered by a game
 * bit).  While active it runs a particle burst, optional camera shake and rumble
 * scaled by player distance, spawns a coloured point light (orange = flameColor≠0,
 * green = flameColor==0) that fades out with the active timer, and maintains a
 * sphere hitbox.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/object_api.h"
#include "main/model_light.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/camera.h"
#include "main/pad.h"
#include "main/dll/DIM/dll_01E7_dimbossfire.h"

#define DIMBOSSFIRE_OBJFLAG_PARENT_SLACK 0x1000
#define DIMBOSSFIRE_HIT_VOLUME_SLOT 9
#define DIMBOSSFIRE_OBJFLAG_RENDERED 0x800

#define DIMBOSSFIRE_FLAG_START_BURST 1
#define DIMBOSSFIRE_COOLDOWN_MIN 0xf0  /* minimum random cooldown in frames */
#define DIMBOSSFIRE_COOLDOWN_MAX 0x1e0 /* maximum random cooldown in frames */
#define DIMBOSSFIRE_BURST_COUNT 50
#define DIMBOSSFIRE_HIT_RADIUS  15

f32 gDimbossfireActiveDurations[DIMBOSSFIRE_FLAME_COUNT] = {
    160.0f, 30.0f, 110.0f, 160.0f, 80.0f, 40.0f, 120.0f, 60.0f, 120.0f, 120.0f,
};

/* partfx ids: burst = spawned 0x32x on START_BURST; sustained = spawned each
 * active frame. orange = flameColor!=0, green = flameColor==0 (matches the
 * point-light diffuse colours 0xff7f00 vs 0x7fff00). */
#define DIMBOSSFIRE_PARTFX_BURST_ORANGE 0x4c9
#define DIMBOSSFIRE_PARTFX_BURST_GREEN 0x4cc
#define DIMBOSSFIRE_PARTFX_SUSTAINED 0x4ca
#define DIMBOSSFIRE_PARTFX_SUSTAINED_ORANGE 0x4cb
#define DIMBOSSFIRE_PARTFX_SUSTAINED_GREEN 0x4cd

int dimbossfire_getExtraSize(void) { return 0x14; }
int dimbossfire_getObjectTypeId(void) { return 0x0; }

void dimbossfire_free(GameObject *obj)
{
    DimbossfireState* state;
    ModelLightStruct* light;

    state = obj->extra;
    light = state->light;
    if (light != 0)
    {
        ModelLightStruct_free(light);
        state->light = NULL;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dimbossfire_render(int obj, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dimbossfire_hitDetect(void)
{
}

void dimbossfire_update(GameObject *obj)
{
    u32 bitVal;
    ModelLightStruct* light;
    int ref;
    GameObject* player;
    DimbossfireState* state;
    DimbossfirePlacement* placement;
    float playerDist;

    state = (obj)->extra;
    placement = (DimbossfirePlacement*)obj->anim.placementData;
    if ((int)placement->triggerGameBit != -1)
    {
        bitVal = mainGetBit((int)placement->triggerGameBit);
        if (bitVal != 0)
        {
            mainSetBits((int)placement->triggerGameBit, 0);
            state->flags = state->flags | DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = gDimbossfireActiveDurations[state->durationIndex];
            state->initialActiveTimer = state->activeTimer;
            state->durationIndex += 1;
            if (state->durationIndex >= DIMBOSSFIRE_FLAME_COUNT)
            {
                state->durationIndex = 0;
            }
        }
    }
    else
    {
        state->cooldownTimer = state->cooldownTimer - timeDelta;
        if (state->cooldownTimer <= gDimbossfireZero)
        {
            state->cooldownTimer = (f32)(int)
            randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
            state->flags = state->flags | DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = gDimbossfireActiveDurations[state->durationIndex];
            state->initialActiveTimer = state->activeTimer;
            state->durationIndex += 1;
            if (state->durationIndex >= DIMBOSSFIRE_FLAME_COUNT)
            {
                state->durationIndex = 0;
            }
        }
    }
    if (state->activeTimer > gDimbossfireZero)
    {
        if ((state->flags & DIMBOSSFIRE_FLAG_START_BURST) != 0)
        {
            state->flags &= ~DIMBOSSFIRE_FLAG_START_BURST;
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DIMBOSSFIRE_HIT_VOLUME_SLOT, 1, 0);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, DIMBOSSFIRE_HIT_RADIUS);
            ObjHits_EnableObject(obj);
            if (((obj)->objectFlags & DIMBOSSFIRE_OBJFLAG_RENDERED) != 0)
            {
                ref = 0;
                do
                {
                    if (placement->flameColor != 0)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSFIRE_PARTFX_BURST_ORANGE, NULL, 2, -1, NULL);
                    }
                    else
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSFIRE_PARTFX_BURST_GREEN, NULL, 2, -1, NULL);
                    }
                    ref = ref + 1;
                }
                while (ref < DIMBOSSFIRE_BURST_COUNT);
            }
            player = Obj_GetPlayerObject();
            if ((player != NULL) && ((player->objectFlags & DIMBOSSFIRE_OBJFLAG_PARENT_SLACK) == 0))
            {
                playerDist = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
                if (playerDist <= gDimbossfireShakeRadius)
                {
                    playerDist = gDimbossfireFullIntensity - playerDist / gDimbossfireShakeRadius;
                    CameraShake_Start(gDimbossfireShakeMagnitudeDuration * playerDist,
                                      gDimbossfireShakeMagnitudeDuration, gDimbossfireShakeFalloff);
                    doRumble(gDimbossfireRumbleMagnitude * playerDist);
                }
            }
            if (state->light == NULL)
            {
                light = objCreateLight(obj, 1);
                state->light = light;
                if (state->light != NULL)
                {
                    modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                    lightSetFieldBC_8001db14(state->light, 1);
                    if (placement->flameColor != 0)
                    {
                        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0);
                    }
                    else
                    {
                        modelLightStruct_setDiffuseColor(state->light, 0x7f, 0xff, 0, 0);
                    }
                    modelLightStruct_setDistanceAttenuation(state->light, gDimbossfireLightNearDistance,
                                                            gDimbossfireLightFarDistance);
                    modelLightStruct_setEnabled(state->light, 1, gDimbossfireZero);
                    modelLightStruct_setEnabled(state->light, 0, state->activeTimer / gDimbossfireLightFadeFrames);
                }
            }
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_cvdrip1c_188);
        }
        state->activeTimer = state->activeTimer - timeDelta;
        if (state->activeTimer <= gDimbossfireZero)
        {
            state->activeTimer = *(f32*)&gDimbossfireZero;
            if (state->light != NULL)
            {
                ModelLightStruct_free(state->light);
                state->light = 0;
            }
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, 0, 0, 0);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0);
            ObjHits_DisableObject(obj);
        }
        else
        {
            (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSFIRE_PARTFX_SUSTAINED, NULL, 2, -1, NULL);
            if (placement->flameColor != 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSFIRE_PARTFX_SUSTAINED_ORANGE, NULL, 2, -1, NULL);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSFIRE_PARTFX_SUSTAINED_GREEN, NULL, 2, -1, NULL);
            }
        }
    }
    return;
}

void dimbossfire_init(GameObject *obj, u32 arg2, int placement)
{
    u32 ua;
    u8 randVal;
    DimbossfireState* state;

    state = obj->extra;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, 0, 0, 0);
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0);
    ObjHits_DisableObject(obj);
    if (placement == 0)
    {
        state->cooldownTimer = (f32)(int)randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
        randVal = randomGetRange(0, 9);
        state->durationIndex = randVal;
    }
    return;
}

void dimbossfire_release(void)
{
}

void dimbossfire_initialise(void)
{
}

ObjectDescriptor gDIMbossfireObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimbossfire_initialise,
    (ObjectDescriptorCallback)dimbossfire_release,
    0,
    (ObjectDescriptorCallback)dimbossfire_init,
    (ObjectDescriptorCallback)dimbossfire_update,
    (ObjectDescriptorCallback)dimbossfire_hitDetect,
    (ObjectDescriptorCallback)dimbossfire_render,
    (ObjectDescriptorCallback)dimbossfire_free,
    (ObjectDescriptorCallback)dimbossfire_getObjectTypeId,
    dimbossfire_getExtraSize,
};
