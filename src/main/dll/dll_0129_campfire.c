/* Campfire area object. */
#include "main/game_object.h"
#include "main/obj_placement.h"
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
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_0129_campfire.h"
#define CAMPFIRE_HIT_VOLUME_SLOT 0x1f

int CampFire_getExtraSize(void)
{
    return sizeof(CampFireState);
}
int CampFire_getObjectTypeId(void)
{
    return 0x1;
}

void CampFire_free(GameObject* obj)
{
    CampFireState* state;
    ModelLightStruct* light;

    state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

void CampFire_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CampFireState* state;
    ModelLightStruct* light;
    s32 isVisible;

    state = obj->extra;
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

void CampFire_update(GameObject* obj)
{
    CampFireState* state;
    int type;
    int mode;
    int flag;
    f32 sunTime;
    f32 params[3];

    state = obj->extra;
    Obj_GetPlayerObject();
    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, 1.0f);
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, CAMPFIRE_HIT_VOLUME_SLOT, 1, 0);
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
            Sfx_AddLoopedObjectSound((u32)obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 1;
        }
    }
    else
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 1.0f);
        }
        ObjHits_ClearHitVolumes(&obj->anim);
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
            Sfx_RemoveLoopedObjectSound((u32)obj, SFXTRIG_forcecryslp11);
            state->sfxPlaying = 0;
        }
    }
    params[0] = 0.0f;
    params[1] = 10.0f;
    params[2] = 0.0f;
    fn_80098B18(obj, 1.4f * obj->anim.rootMotionScale, type, mode, flag, params);
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

void CampFire_init(GameObject* obj, CampFireSetup* setup)
{
    CampFireState* state;
    f32 sunTime;
    u32 size;
    s16 bit;

    state = obj->extra;
    size = setup->scalePercent;
    if (size != 0)
    {
        obj->anim.rootMotionScale = 0.01f * size;
    }
    if (mainGetBit(0x8c) != 0)
    {
        state->flags |= CAMPFIRE_STATE_GLOBAL_GAMEBIT_SET;
    }
    state->gameBit = setup->gameBit;
    bit = state->gameBit;
    if (bit != -1 && mainGetBit(bit) != 0)
    {
        state->flags |= CAMPFIRE_STATE_PLACEMENT_GAMEBIT_SET;
    }
    state->unk10 = setup->unk1B;
    {
        f32 scale =
            obj->anim.rootMotionScale / obj->anim.modelInstance->rootMotionScaleBase;
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        ObjHitbox_SetCapsuleBounds(&obj->anim, (int)((f32)hitState->primaryRadius * scale),
                                   (int)((f32)hitState->primaryCapsuleOffsetA * scale),
                                   (int)((f32)hitState->primaryCapsuleOffsetB * scale));
    }
    state->dayTimer = 10.0f;
    state->nightTimer = 1.0f;
    if (state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }
    if (state->light != NULL)
    {
        int atten;
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        atten = (int)(20.0f * obj->anim.rootMotionScale);
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
