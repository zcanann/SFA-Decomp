/*
 * wmspiritset (DLL 0x20F) - the Krazoa-spirit display object at Krazoa
 * Palace (map 'warlock' = Dinosaur Planet's Warlock Mountain, hence
 * the WM dll prefix). Retail object def 921 'WM_SpiritSet' (romlist
 * type 0x264); no romlist on any of the 124 retail maps places one -
 * instances are spawned at runtime.
 * Purely visual: init orients the model from the placement rotX byte
 * and, for the retail spirit type, shrinks it to root-motion scale
 * 0.0085; render then draws it only while the placement's visibility
 * game bit is set (or always, when the bit is -1).
 */
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/WM/dll_020F_wmspiritset.h"
#include "main/object_descriptor.h"

__declspec(section ".sdata2") f32 lbl_803E5F90 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5F94 = 0.0085f;

/* romlist object-def variant driving this DLL (see docblock): def 921
   'WM_SpiritSet' (romlist type 0x264). */
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
    WmSpiritSetState* state = (obj)->extra;
    s16 visibilityGameBit = state->visibilityGameBit;

    if ((visibilityGameBit == -1 || mainGetBit(visibilityGameBit) != 0) && vis != 0)
    {
        objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, lbl_803E5F90); /* 1.0f */
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
    if (obj->anim.seqId == WMSPIRITSET_SEQID_SPIRITSET)
    {
        obj->anim.rootMotionScale = lbl_803E5F94; /* 0.0085f */
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
