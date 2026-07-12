/*
 * lgtpointlight (DLL 0x2A9) - a placeable point light.
 *
 * On init it creates a ModelLight of kind POINT and configures it from the
 * placement record: diffuse colour (or the live ambient colour when
 * POINTLIGHT_FLAG_USE_AMBIENT_COLOR is set), distance attenuation, spot
 * attenuation (brightness clamped to POINTLIGHT_MAX_SPOT_BRIGHTNESS), an
 * initial colour fade, direction, an optional billboard glow, AABB
 * light-selection participation and a selection priority. update() spins the
 * light by its per-axis rotation speeds, toggles the light on/off from its
 * enableBit game bit, refreshes the ambient colour each frame when requested
 * and advances the glow alpha.
 *
 * Each instance joins LGT_POINTLIGHT_GROUP so lgtcontrollight can toggle the
 * point lights within a radius; pointlight_setEffectState is the entry point
 * it calls.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/sky_state.h"
#include "main/game_object.h"
#include "main/dll/LGT/dll_02A9_lgtpointlight.h"

#define POINTLIGHT_FLAG_USE_AMBIENT_COLOR 0x01
#define POINTLIGHT_MAX_SPOT_BRIGHTNESS    0x5a

void pointlight_setEffectState(GameObject* obj, int enabled)
{
    GameObject* object = obj;
    PointLightState* state = object->extra;
    ModelLight* light = state->light;
    if (light != NULL)
    {
        modelLightStruct_setEnabled(light, enabled, 0.0f);
    }
}

int PointLight_getExtraSize(void)
{
    return sizeof(PointLightState);
}

int PointLight_getObjectTypeId(void)
{
    return 0;
}

void PointLight_free(GameObject* obj)
{
    PointLightState* state = (obj)->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
    ObjGroup_RemoveObject((int)obj, LGT_POINTLIGHT_GROUP);
}

void PointLight_render(GameObject* obj)
{
    PointLightState* state = obj->extra;
    ModelLight* light = state->light;
    if (light != NULL && *(u8*)((char*)light + 0x2f8) != 0 && *(u8*)((char*)light + 0x4c) != 0)
    {
        queueGlowRender(light);
    }
}

void PointLight_hitDetect(void)
{
}

void PointLight_update(GameObject* obj)
{
    u8 colorR, colorG, colorB;
    PointLightSetup* setup = (PointLightSetup*)obj->anim.placementData;
    PointLightState* state = obj->extra;

    if (state->light == NULL)
    {
        return;
    }

    obj->anim.rotX = (s16)((f32)setup->rotXSpeed * timeDelta + (f32)obj->anim.rotX);
    obj->anim.rotY = (s16)((f32)setup->rotYSpeed * timeDelta + (f32)obj->anim.rotY);

    if (state->enabled != 0)
    {
        s16 bit = setup->enableBit;
        if (bit > 0 && mainGetBit(bit) == 0)
        {
            state->enabled = 0;
            modelLightStruct_setEnabled(state->light, 0, 1.0f);
        }
        if ((setup->flags & POINTLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
    }
    else
    {
        s16 bit = setup->enableBit;
        if (bit > 0 && mainGetBit(bit) != 0)
        {
            state->enabled = 1;
            modelLightStruct_setEnabled(state->light, 1, 1.0f);
        }
    }

    if (state->light != NULL)
    {
        modelLightStruct_updateGlowAlpha(state->light);
    }
}

void PointLight_init(GameObject* obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    PointLightSetup* setupData = (PointLightSetup*)setup;
    PointLightState* state = (obj)->extra;

    vec = *(PointLightVec*)lbl_802C25F8;

    (obj)->anim.rotX = (s16)(setupData->rotX << 8);
    (obj)->anim.rotY = (s16)(setupData->rotY << 8);

    if (state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }

    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        objSetEventName(state->light, setupData->eventName);
        modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);

        if ((setupData->flags & POINTLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
        else
        {
            modelLightStruct_setDiffuseColor(state->light, setupData->diffuseR, setupData->diffuseG,
                                             setupData->diffuseB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, setupData->targetR, setupData->targetG,
                                                   setupData->targetB, 0xff);
        }

        modelLightStruct_setDistanceAttenuation(state->light, (f32)(u32)setupData->distanceNear,
                                                (f32)(u32)setupData->distanceFar);

        {
            int brightness = (u32)setupData->brightness < POINTLIGHT_MAX_SPOT_BRIGHTNESS
                                 ? setupData->brightness
                                 : POINTLIGHT_MAX_SPOT_BRIGHTNESS;
            modelLightStruct_setSpotAttenuation(state->light, brightness, setupData->spotMode);
        }

        modelLightStruct_setEnabled(state->light, setupData->enabled, 0.0f);
        state->enabled = setupData->enabled;
        modelLightStruct_startColorFade(state->light, setupData->colorFadeSpeed, setupData->colorFadeFrames);
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);

        if (setupData->spotMode != 0)
        {
            Obj_SetActiveModelIndex((int)obj, 1);
        }
        else
        {
            Obj_SetActiveModelIndex((int)obj, 0);
        }

        if (setupData->glowEnabled != 0)
        {
            modelLightStruct_setupGlow(state->light, setupData->glowTexture, setupData->glowR, setupData->glowG,
                                       setupData->glowB, setupData->glowAlpha, (f32)(u32)setupData->glowScale);
            modelLightStruct_setGlowProjectionRadius(state->light, 12.0f);
        }

        if (setupData->affectsAabbLightSelection != 0)
        {
            modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        }

        if (setupData->selectionPriority != 0)
        {
            modelLightStruct_setSelectionPriority(state->light, setupData->selectionPriority);
        }
    }

    ObjGroup_AddObject((int)obj, LGT_POINTLIGHT_GROUP);
}

void PointLight_release(void)
{
}

void PointLight_initialise(void)
{
}
