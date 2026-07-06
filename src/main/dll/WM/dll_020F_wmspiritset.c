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
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmSpiritSetState
{
    s16 visibilityGameBit; /* 0x00: game bit gating render (-1 = always visible) */
} WmSpiritSetState;

typedef struct WmSpiritSetMapData
{
    ObjPlacement base;
    s8 rotXByte;           /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 visibilityGameBit; /* 0x1E */
} WmSpiritSetMapData;

STATIC_ASSERT(offsetof(WmSpiritSetState, visibilityGameBit) == 0x0);
STATIC_ASSERT(sizeof(WmSpiritSetState) == 0x2);
STATIC_ASSERT(offsetof(WmSpiritSetMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritSetMapData, visibilityGameBit) == 0x1E);
STATIC_ASSERT(sizeof(WmSpiritSetMapData) == 0x20);

int wmspiritset_getExtraSize(void) { return sizeof(WmSpiritSetState); }

int wmspiritset_getObjectTypeId(void) { return 0x0; }

void wmspiritset_free(void)
{
}

void wmspiritset_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    WmSpiritSetState* state = ((GameObject*)p1)->extra;
    s16 visibilityGameBit = state->visibilityGameBit;

    if ((visibilityGameBit == -1 || GameBit_Get(visibilityGameBit) != 0) && vis != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5F90); /* 1.0f */
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
    if (obj->anim.seqId == 0x264)
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
