/*
 * WM_SpiritSe (DLL 0x020F) - Krazoa Spirit display object.
 *
 * The object is oriented from its placement data and rendered while
 * its visibility game bit is set.
 */
#include "dlls/object_descriptor.h"
#include "main/dll/WM/dll_020F_wmspiritset.h"
#include "main/gamebits.h"
#include "main/object_render.h"

/* Object variant handled by this DLL. */
#define WMSPIRITSET_SEQID_SPIRITSET 0x264

int wmspiritset_getExtraSize(void)
{
    return sizeof(WmSpiritSetState);
}

int wmspiritset_getObjectTypeId(void)
{
    return 0x0;
}

void wmspiritset_free(void)
{
}

void wmspiritset_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    WmSpiritSetState* state = obj->extra;
    s16 visibilityGameBit = state->visibilityGameBit;

    if ((visibilityGameBit == -1 || mainGetBit(visibilityGameBit) != 0) && vis != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wmspiritset_hitDetect(void)
{
}

void wmspiritset_update(void)
{
}

void wmspiritset_init(GameObject* obj, WmSpiritSetMapData* mapData)
{
    WmSpiritSetState* state = obj->extra;

    obj->anim.rotX = (s16)(mapData->rotXByte << 8);
    if (obj->anim.romDefNo == WMSPIRITSET_SEQID_SPIRITSET)
    {
        obj->anim.rootMotionScale = 0.0085f;
    }
    state->visibilityGameBit = mapData->visibilityGameBit;
}

void wmspiritset_release(void)
{
}

void wmspiritset_initialise(void)
{
}

ObjectDescriptor gWM_SpiritSetObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wmspiritset_initialise,
    (ObjectDescriptorCallback)wmspiritset_release,
    0,
    (ObjectDescriptorCallback)wmspiritset_init,
    (ObjectDescriptorCallback)wmspiritset_update,
    (ObjectDescriptorCallback)wmspiritset_hitDetect,
    (ObjectDescriptorCallback)wmspiritset_render,
    (ObjectDescriptorCallback)wmspiritset_free,
    (ObjectDescriptorCallback)wmspiritset_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wmspiritset_getExtraSize,
};
