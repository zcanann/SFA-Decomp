/*
 * DustMoteSou (DLL 690) is a particle source with no extra state.
 * Init applies packed rotation bytes and disables hit detection. Update
 * requests effects while its optional game bit permits emission; the object
 * type selects tail-light, firework or ordinary burst parameters.
 */
#include "dlls/objects/690_DustMoteSou.h"
#include "game/objects/object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/objfx.h"

#define DUSTMOTESOU_OBJECT_TAIL_LIGHT 0x0807
#define DUSTMOTESOU_OBJECT_FIREWORK 0x080E
#define DUSTMOTESOU_BURST_BOX 0
#define DUSTMOTESOU_BURST_ARCED 1

int dustmotesou_getExtraSize(void)
{
    return 0;
}

int dustmotesou_getObjectTypeId(void)
{
    return 0;
}

void dustmotesou_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dustmotesou_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void dustmotesou_hitDetect(void)
{
}

void dustmotesou_update(GameObject* source)
{
    DustMoteSouPlacementPrefix* mapData = (DustMoteSouPlacementPrefix*)source->anim.placementData;

    if (mapData->gameBit != -1 && mainGetBit(mapData->gameBit) == 0)
    {
        return;
    }
    if (source->anim.romDefNo == DUSTMOTESOU_OBJECT_TAIL_LIGHT)
    {
        if (mapData->spawnTypeIndex == 0 || mapData->effectParamIndex == 0)
        {
            return;
        }
        objfx_spawnMaskedHitEffect(source, mapData->scale, mapData->spawnTypeIndex, mapData->effectParamIndex,
                                   mapData->emission.frameMask, 0);
        return;
    }
    if (source->anim.romDefNo == DUSTMOTESOU_OBJECT_FIREWORK)
    {
        if (mapData->spawnTypeIndex == 0 || mapData->effectParamIndex == 0)
        {
            return;
        }
        objfx_spawnHitEffectBurst(source, mapData->scale, mapData->spawnTypeIndex, mapData->effectParamIndex,
                            mapData->emission.burstCount, NULL);
        return;
    }
    if (mapData->spawnTypeIndex == 0 || mapData->effectParamIndex == 0 || mapData->emission.distributionMode == 0)
    {
        return;
    }
    if (mapData->burstMode == DUSTMOTESOU_BURST_BOX)
    {
        objfx_spawnBoxBurst(source, mapData->spawnTypeIndex, mapData->scale, mapData->effectParamIndex,
                            mapData->emission.distributionMode, mapData->spawnChancePercent, (f32)(u32)mapData->geometry.box.extentX,
                            (f32)(u32)mapData->geometry.box.extentY, (f32)(u32)mapData->geometry.box.extentZ, NULL, 0);
    }
    else if (mapData->burstMode == DUSTMOTESOU_BURST_ARCED)
    {
        objfx_spawnArcedBurst(source, mapData->spawnTypeIndex, mapData->scale, mapData->effectParamIndex,
                             mapData->emission.distributionMode, mapData->spawnChancePercent, (f32)(u32)mapData->geometry.arced.radiusEnd,
                             (f32)(u32)mapData->geometry.arced.radiusStart,
                              (f32)(u32)mapData->geometry.arced.height, 0, 0);
    }
    else
    {
        objfx_spawnDirectionalBurst(source, mapData->spawnTypeIndex, mapData->scale, mapData->effectParamIndex,
                                    mapData->emission.distributionMode, mapData->spawnChancePercent,
                                    (f32)(u32)mapData->geometry.directional.distanceMultiplier, NULL, 0);
    }
}

void dustmotesou_init(GameObject* source, DustMoteSouPlacementPrefix* mapData)
{
    source->anim.rotZ = (s16)(mapData->rotZ << 8);
    source->anim.rotY = (s16)(mapData->rotY << 8);
    source->anim.rotX = (s16)(mapData->rotX << 8);
    source->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dustmotesou_release(void)
{
}

void dustmotesou_initialise(void)
{
}

ObjectDescriptor gDustMoteSouObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dustmotesou_initialise,
    dustmotesou_release,
    0,
    (ObjectDescriptorCallback)dustmotesou_init,
    (ObjectDescriptorCallback)dustmotesou_update,
    dustmotesou_hitDetect,
    (ObjectDescriptorCallback)dustmotesou_render,
    (ObjectDescriptorCallback)dustmotesou_free,
    (ObjectDescriptorCallback)dustmotesou_getObjectTypeId,
    dustmotesou_getExtraSize,
};
