/*
 * ktlazerlight (DLL 0x253) - the point light cast by a SharpClaw laser
 * fence/wall (see ktlazerwall, DLL 0x252).
 *
 * On init it spawns a model light at the placement's position. Each
 * update tick two placement game bits decide whether the light is on and
 * how far it reaches: the first bit's value scales the distance falloff
 * (defaulting to 0x10 when set but zero), the second bit just keeps the
 * light lit. The light is freed when the object is destroyed.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/dll/DR/dll_0253_ktlazerlight.h"

int ktlazerlight_getExtraSize(void)
{
    return 0x14;
}

int ktlazerlight_getObjectTypeId(void)
{
    return 0x0;
}

void ktlazerlight_free(GameObject* obj)
{
    KtlazerlightState* state = obj->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}

void ktlazerlight_render(void)
{
}

void ktlazerlight_hitDetect(void)
{
}

void ktlazerlight_update(GameObject* obj)
{
    KtlazerlightPlacement* placement = (KtlazerlightPlacement*)obj->anim.placementData;
    KtlazerlightState* state = obj->extra;
    s16 intensity;
    ModelLightStruct* light = state->light;
    intensity = mainGetBit(placement->onIntensityBit);
    if (intensity >= 1 || mainGetBit(placement->onStayLitBit) != 0)
    {
        if (intensity == 0)
        {
            intensity = 0x10;
        }
        if (light != 0)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E68C0);
            modelLightStruct_setDiffuseColor(light, 0x64, 0x6e, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, (f32)(intensity * 0x1a),
                                                    (f32)(intensity * 0x1a + 0x14));
        }
    }
    else
    {
        if (light != 0)
        {
            modelLightStruct_setEnabled(light, 0, lbl_803E68C0);
        }
    }
}

void ktlazerlight_init(GameObject* obj, KtlazerlightPlacement* placement)
{
    KtlazerlightState* state = obj->extra;
    state->light = objCreateLight(NULL, 1);
    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(state->light, placement->posX, placement->posY, placement->posZ);
        modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
    }
}

void ktlazerlight_release(void)
{
}

void ktlazerlight_initialise(void)
{
}
