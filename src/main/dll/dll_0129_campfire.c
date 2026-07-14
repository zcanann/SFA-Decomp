/* DLL 0x0129 - campfire area objects [8018CD64-8018CDAC) */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/model_light.h"
#include "main/objfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#define CAMPFIRE_HIT_VOLUME_SLOT 0x1f
/* CampfireExtra - the per-class extra state block (GameObject.extra) for the
 * campfire object class; CampFire_getExtraSize() returns 0x14. Single-owner;
 * offsets mirror the observed deref widths in this unit. */
typedef struct CampfireExtra
{
    ModelLightStruct* light;
    f32 dayTimer;   /* 0x04 flicker/sound timer used in the daytime branch */
    f32 nightTimer; /* 0x08 timer used in the night branch */
    s16 gameBit;    /* 0x0C gamebit index (from spawn descriptor +0x18) */
    u8 unk0E[2];
    u8 unk10;      /* 0x10 (from spawn descriptor +0x1b) */
    u8 flags;      /* 0x11 bit0 = gamebit 0x8c set, bit2 = gameBit set */
    u8 sfxPlaying; /* 0x12 looped-sound active flag */
    u8 unk13;
} CampfireExtra;

STATIC_ASSERT(offsetof(CampfireExtra, gameBit) == 0xC);
STATIC_ASSERT(sizeof(CampfireExtra) == 0x14);

int CampFire_getExtraSize(void)
{
    return 0x14;
}
int CampFire_getObjectTypeId(void)
{
    return 0x1;
}

void CampFire_free(GameObject* obj)
{
    CampfireExtra* state;
    ModelLightStruct* light;

    state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

void CampFire_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CampfireExtra* state;
    ModelLightStruct* light;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        light = state->light;
        if (((light != NULL) && (light->glowType != 0)) && (light->enabled != 0))
        {
            queueGlowRender(light);
        }
    }
}

void CampFire_update(int obj)
{
    CampfireExtra* state;
    int type;
    int mode;
    int flag;
    f32 sunTime;
    f32 params[3];

    state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, 1.0f);
        }
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, CAMPFIRE_HIT_VOLUME_SLOT, 1, 0);
        state->nightTimer -= timeDelta;
        if (state->nightTimer <= 0.0f)
        {
            flag = 1;
            state->nightTimer += 1.0f;
        }
        else
        {
            flag = 0;
        }
        type = 2;
        mode = 0;
        if (state->sfxPlaying == 0)
        {
            Sfx_AddLoopedObjectSoundIntLegacy(obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 1;
        }
    }
    else
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 1.0f);
        }
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        state->dayTimer -= timeDelta;
        if (state->dayTimer <= 0.0f)
        {
            mode = 3;
            state->dayTimer += 10.0f;
        }
        else
        {
            mode = 0;
        }
        type = 0;
        flag = 0;
        if (state->sfxPlaying != 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 0;
        }
    }
    params[0] = 0.0f;
    params[1] = 10.0f;
    params[2] = 0.0f;
    fn_80098B18Legacy(obj, 1.4f * ((GameObject*)obj)->anim.rootMotionScale, type, mode, flag, params);
    {
        ModelLightStruct* light = state->light;
        if (light != NULL && light->glowType != 0 && light->enabled != 0)
        {
            int rnd;
            ModelLightStruct* l2;
            s16 brightness;
            rnd = randomGetRange(-0x19, 0x19);
            l2 = state->light;
            brightness = l2->glowAlpha + l2->glowAlphaStep + rnd;
            if (brightness < 0)
            {
                brightness = 0;
                l2->glowAlphaStep = 0;
            }
            else if (brightness > 0xff)
            {
                brightness = 0xff;
                l2->glowAlphaStep = 0;
            }
            state->light->glowAlpha = brightness;
        }
    }
}

typedef struct CampFirePlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;  /* 0x18: gate game bit */
    u8 sizeParam; /* 0x1a: * 0.01 -> rootMotionScale */
    u8 unk1b;     /* 0x1b */
} CampFirePlacement;

void CampFire_init(int obj, int defArg)
{
    CampFirePlacement* def = (CampFirePlacement*)defArg;
    CampfireExtra* state;
    f32 sunTime;
    u32 size;
    s16 bit;

    state = ((GameObject*)obj)->extra;
    size = def->sizeParam;
    if (size != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = 0.01f * size;
    }
    if (mainGetBit(0x8c) != 0)
    {
        state->flags |= 1;
    }
    state->gameBit = def->gameBit;
    bit = state->gameBit;
    if (bit != -1 && mainGetBit(bit) != 0)
    {
        state->flags |= 4;
    }
    state->unk10 = def->unk1b;
    {
        f32 scale =
            ((GameObject*)obj)->anim.rootMotionScale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
        int hitState = *(int*)&((GameObject*)obj)->anim.hitReactState;
        ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj,
                                   (int)((f32)((ObjHitsPriorityState*)hitState)->primaryRadius * scale),
                                   (int)((f32)((ObjHitsPriorityState*)hitState)->primaryCapsuleOffsetA * scale),
                                   (int)((f32)((ObjHitsPriorityState*)hitState)->primaryCapsuleOffsetB * scale));
    }
    state->dayTimer = 10.0f;
    state->nightTimer = 1.0f;
    if (state->light == NULL)
    {
        state->light = objCreateLight((GameObject*)obj, 1);
    }
    if (state->light != NULL)
    {
        int atten;
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        atten = (int)(20.0f * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, atten, 30.0f + atten);
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
        }
        else
        {
            modelLightStruct_setEnabled(state->light, 0, 0.0f);
        }
        modelLightStruct_setPosition(state->light, 0.0f, 12.0f, 0.0f);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(state->light, 0, 0xff, 0x7f, 0, 0x87,
                                   40.0f * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, 30.0f);
    }
}
