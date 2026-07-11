/*
 * dimbossfire (DLL 0x1E7) - DIM boss flame-jet emitters placed around the boss
 * arena.  Each instance fires on a random cooldown (or is triggered by a game
 * bit).  While active it runs a particle burst, optional camera shake and rumble
 * scaled by player distance, spawns a coloured point light (orange = flameColor≠0,
 * green = flameColor==0) that fades out with the active timer, and maintains a
 * sphere hitbox.
 */
#include "main/dll_000A_expgfx.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/sfa_shared_decls.h"

#define DIMBOSSFIRE_OBJFLAG_PARENT_SLACK 0x1000
#define DIMBOSSFIRE_HIT_VOLUME_SLOT 9
#define DIMBOSSFIRE_OBJFLAG_RENDERED 0x800
#define MODEL_LIGHT_KIND_POINT 2
extern f32 timeDelta;

extern void ModelLightStruct_free(ModelLightStruct* light);
extern void lightSetFieldBC_8001db14(ModelLightStruct* p, u8 v);

extern f32 Vec_distance(f32* a, f32* b);
extern int Obj_GetPlayerObject(void);
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setDistanceAttenuation(ModelLightStruct* light, f32 min, f32 max);
extern f32 lbl_80325D68[];
extern f32 lbl_803E4DA0;
extern f32 lbl_803E4DA4;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DAC;
extern f32 lbl_803E4DB0;
extern f32 lbl_803E4DB4;
extern f32 lbl_803E4DB8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;

typedef struct DimbossfireState
{
    u8 flags;
    u8 flameIndex;
    u8 pad02[0x4 - 0x2];
    f32 activeTimer;
    f32 initialActiveTimer;
    f32 cooldownTimer;
    ModelLightStruct* light;
    u8 pad14[0x18 - 0x14];
} DimbossfireState;

typedef struct DimbossfirePlacement
{
    ObjPlacement base;
    u8 pad18[0x1A - 0x18];
    s16 flameColor;
    u8 pad1C[0x20 - 0x1C];
    s16 triggerGameBit;
    u8 pad22[0x24 - 0x22];
} DimbossfirePlacement;

#define DIMBOSSFIRE_FLAG_START_BURST 1
#define DIMBOSSFIRE_FLAME_COUNT 10
#define DIMBOSSFIRE_COOLDOWN_MIN 0xf0  /* minimum random cooldown in frames */
#define DIMBOSSFIRE_COOLDOWN_MAX 0x1e0 /* maximum random cooldown in frames */

/* partfx ids: burst = spawned 0x32x on START_BURST; sustained = spawned each
 * active frame. orange = flameColor!=0, green = flameColor==0 (matches the
 * point-light diffuse colours 0xff7f00 vs 0x7fff00). */
#define DIMBOSSFIRE_PARTFX_BURST_ORANGE 0x4c9
#define DIMBOSSFIRE_PARTFX_BURST_GREEN 0x4cc
#define DIMBOSSFIRE_PARTFX_SUSTAINED 0x4ca
#define DIMBOSSFIRE_PARTFX_SUSTAINED_ORANGE 0x4cb
#define DIMBOSSFIRE_PARTFX_SUSTAINED_GREEN 0x4cd

STATIC_ASSERT(offsetof(DimbossfireState, activeTimer) == 0x4);
STATIC_ASSERT(offsetof(DimbossfireState, initialActiveTimer) == 0x8);
STATIC_ASSERT(offsetof(DimbossfireState, cooldownTimer) == 0xC);
STATIC_ASSERT(offsetof(DimbossfireState, light) == 0x10);
STATIC_ASSERT(offsetof(DimbossfirePlacement, flameColor) == 0x1A);
STATIC_ASSERT(offsetof(DimbossfirePlacement, triggerGameBit) == 0x20);

int dimbossfire_getExtraSize(void) { return 0x14; }
int dimbossfire_getObjectTypeId(void) { return 0x0; }

void dimbossfire_free(GameObject *obj)
{
    int o = (int)obj;
    int state;
    void* light;

    state = *(int*)&((GameObject*)o)->extra;
    light = ((DimbossfireState*)state)->light;
    if (light != 0)
    {
        ModelLightStruct_free(light);
        ((DimbossfireState*)state)->light = NULL;
    }
    (*gExpgfxInterface)->freeSource2((u32)o);
}

void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dimbossfire_hitDetect(void)
{
}

void dimbossfire_update(GameObject *obj)
{
    extern int randomGetRange(int lo, int hi);
    u32 bitVal;
    ModelLightStruct* light;
    int ref;
    DimbossfireState* state;
    DimbossfirePlacement* placement;
    float playerDist;

    state = (obj)->extra;
    placement = *(DimbossfirePlacement**)&(obj)->anim.placementData;
    if ((int)placement->triggerGameBit != -1)
    {
        bitVal = mainGetBit((int)placement->triggerGameBit);
        if (bitVal != 0)
        {
            mainSetBits((int)placement->triggerGameBit, 0);
            state->flags = state->flags | DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = lbl_80325D68[state->flameIndex];
            state->initialActiveTimer = state->activeTimer;
            state->flameIndex += 1;
            if (state->flameIndex >= DIMBOSSFIRE_FLAME_COUNT)
            {
                state->flameIndex = 0;
            }
        }
    }
    else
    {
        state->cooldownTimer = state->cooldownTimer - timeDelta;
        if (state->cooldownTimer <= lbl_803E4DA0)
        {
            state->cooldownTimer = (f32)(int)
            randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
            state->flags = state->flags | DIMBOSSFIRE_FLAG_START_BURST;
            state->activeTimer = lbl_80325D68[state->flameIndex];
            state->initialActiveTimer = state->activeTimer;
            state->flameIndex += 1;
            if (state->flameIndex >= DIMBOSSFIRE_FLAME_COUNT)
            {
                state->flameIndex = 0;
            }
        }
    }
    if (state->activeTimer > lbl_803E4DA0)
    {
        if ((state->flags & DIMBOSSFIRE_FLAG_START_BURST) != 0)
        {
            state->flags &= ~DIMBOSSFIRE_FLAG_START_BURST;
            ObjHits_SetHitVolumeSlot((u32)obj, DIMBOSSFIRE_HIT_VOLUME_SLOT, 1, 0);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0xf);
            ObjHits_EnableObject((u32)obj);
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
                while (ref < 0x32);
            }
            ref = Obj_GetPlayerObject();
            if (((void*)ref != NULL) && ((((GameObject*)ref)->objectFlags & DIMBOSSFIRE_OBJFLAG_PARENT_SLACK) == 0))
            {
                playerDist = Vec_distance((float*)&(obj)->anim.worldPosX, (float*)(ref + 0x18));
                if (playerDist <= lbl_803E4DA4)
                {
                    playerDist = lbl_803E4DA8 - playerDist / lbl_803E4DA4;
                    CameraShake_Start(lbl_803E4DAC * playerDist, lbl_803E4DAC, lbl_803E4DB0);
                    doRumble(lbl_803E4DB4 * playerDist);
                }
            }
            if ((void*)state->light == NULL)
            {
                light = objCreateLight((int)obj, 1);
                state->light = light;
                if ((void*)state->light != NULL)
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
                    modelLightStruct_setDistanceAttenuation(state->light, lbl_803E4DB8, lbl_803E4DBC);
                    modelLightStruct_setEnabled(state->light, 1, lbl_803E4DA0);
                    modelLightStruct_setEnabled(state->light, 0, state->activeTimer / lbl_803E4DC0);
                }
            }
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_cvdrip1c_188);
        }
        state->activeTimer = state->activeTimer - timeDelta;
        if (state->activeTimer <= lbl_803E4DA0)
        {
            state->activeTimer = *(f32*)&lbl_803E4DA0;
            if (*(u32*)&state->light != 0)
            {
                ModelLightStruct_free(state->light);
                state->light = 0;
            }
            ObjHits_SetHitVolumeSlot((u32)obj, 0, 0, 0);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0);
            ObjHits_DisableObject((u32)obj);
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
    extern int randomGetRange(int lo, int hi);
    u32 ua;
    u8 randVal;
    DimbossfireState* state;

    state = obj->extra;
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 0);
    ObjHits_DisableObject((u32)obj);
    if (placement == 0)
    {
        state->cooldownTimer = (f32)(int)randomGetRange(DIMBOSSFIRE_COOLDOWN_MIN, DIMBOSSFIRE_COOLDOWN_MAX);
        randVal = randomGetRange(0, 9);
        state->flameIndex = randVal;
    }
    return;
}

void dimbossfire_release(void)
{
}

void dimbossfire_initialise(void)
{
}
