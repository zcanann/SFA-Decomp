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

typedef struct KtlazerlightPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;            /* 0x8: ObjPlacement head */
    f32 posY;            /* 0xC */
    f32 posZ;            /* 0x10 */
    u8 pad14[0x1A - 0x14];
    s16 onIntensityBit;  /* 0x1A: game bit; value scales distance falloff */
    s16 onStayLitBit;    /* 0x1C: game bit; keeps the light lit */
    u8 pad1E[0x20 - 0x1E];
} KtlazerlightPlacement;

STATIC_ASSERT(offsetof(KtlazerlightPlacement, posX) == 0x8);
STATIC_ASSERT(offsetof(KtlazerlightPlacement, onIntensityBit) == 0x1A);
STATIC_ASSERT(offsetof(KtlazerlightPlacement, onStayLitBit) == 0x1C);
STATIC_ASSERT(sizeof(KtlazerlightPlacement) == 0x20);


int ktlazerlight_getExtraSize(void) { return 0x14; }

int ktlazerlight_getObjectTypeId(void) { return 0x0; }

void ktlazerlight_hitDetect(void)
{
}

void ktlazerlight_initialise(void)
{
}

void ktlazerlight_release(void)
{
}

void ktlazerlight_render(void)
{
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

void ktlazerlight_init(int obj, char* placement)
{
    char* extra = ((GameObject*)obj)->extra;
    *(void**)(extra + 0x4) = objCreateLight(0, 1);
    if (*(void**)(extra + 0x4) != 0)
    {
        modelLightStruct_setLightKind(*(void**)(extra + 0x4), 2);
        modelLightStruct_setPosition(*(void**)(extra + 0x4), ((KtlazerlightPlacement*)placement)->posX, ((KtlazerlightPlacement*)placement)->posY, ((KtlazerlightPlacement*)placement)->posZ);
        modelLightStruct_setAffectsAabbLightSelection(*(void**)(extra + 0x4), 1);
    }
}

void ktlazerlight_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* extra = ((GameObject*)obj)->extra;
    s16 intensity;
    void* light = *(void**)(extra + 0x4);
    intensity = GameBit_Get(((KtlazerlightPlacement*)placement)->onIntensityBit);
    if (intensity >= 1 || GameBit_Get(((KtlazerlightPlacement*)placement)->onStayLitBit) != 0)
    {
        if (intensity == 0)
        {
            intensity = 0x10;
        }
        if (light != 0)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E68C0);
            modelLightStruct_setDiffuseColor(light, 0x64, 0x6e, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(*(void**)(extra + 0x4), (f32)(intensity * 0x1a), (f32)(intensity * 0x1a + 0x14));
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
