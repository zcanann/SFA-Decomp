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
#include "main/dll/DR/dll_0253_ktlazerlight.h"

#define MODEL_LIGHT_KIND_POINT 2

int ktlazerlight_getExtraSize(void)
{
    return 0x14;
}

int ktlazerlight_getObjectTypeId(void)
{
    return 0x0;
}

void ktlazerlight_free(int obj)
{
    void* extra = ((GameObject*)obj)->extra;
    void* light = *(void**)((char*)extra + 0x4);
    if (light != 0)
    {
        ModelLightStruct_free(light);
    }
}

void ktlazerlight_render(void)
{
}

void ktlazerlight_hitDetect(void)
{
}

void ktlazerlight_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* extra = ((GameObject*)obj)->extra;
    s16 intensity;
    void* light = *(void**)(extra + 0x4);
    intensity = mainGetBit(((KtlazerlightPlacement*)placement)->onIntensityBit);
    if (intensity >= 1 || mainGetBit(((KtlazerlightPlacement*)placement)->onStayLitBit) != 0)
    {
        if (intensity == 0)
        {
            intensity = 0x10;
        }
        if (light != 0)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E68C0);
            modelLightStruct_setDiffuseColor(light, 0x64, 0x6e, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(*(void**)(extra + 0x4), (f32)(intensity * 0x1a),
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

void ktlazerlight_init(int obj, char* placement)
{
    char* extra = ((GameObject*)obj)->extra;
    *(void**)(extra + 0x4) = objCreateLight(0, 1);
    if (*(void**)(extra + 0x4) != 0)
    {
        modelLightStruct_setLightKind(*(void**)(extra + 0x4), MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(*(void**)(extra + 0x4), ((KtlazerlightPlacement*)placement)->posX,
                                     ((KtlazerlightPlacement*)placement)->posY,
                                     ((KtlazerlightPlacement*)placement)->posZ);
        modelLightStruct_setAffectsAabbLightSelection(*(void**)(extra + 0x4), 1);
    }
}

void ktlazerlight_release(void)
{
}

void ktlazerlight_initialise(void)
{
}
