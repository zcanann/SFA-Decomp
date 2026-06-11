#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmSpiritSetState
{
    s16 visibilityGameBit;
} WmSpiritSetState;

typedef struct WmSpiritSetMapData
{
    ObjPlacement base;
    s8 rotXByte;
    u8 pad19[0x1E - 0x19];
    s16 visibilityGameBit;
} WmSpiritSetMapData;

STATIC_ASSERT (
sizeof
(WmSpiritSetState)
==
0x2
);
STATIC_ASSERT (offsetof
(WmSpiritSetState
,
visibilityGameBit
)
==
0x0
);
STATIC_ASSERT (offsetof
(WmSpiritSetMapData
,
rotXByte
)
==
0x18
);
STATIC_ASSERT (offsetof
(WmSpiritSetMapData
,
visibilityGameBit
)
==
0x1E
);
STATIC_ASSERT (
sizeof
(WmSpiritSetMapData)
==
0x20
);

int wmspiritset_getExtraSize(void) { return 0x2; }

int wmspiritset_getObjectTypeId(void) { return 0x0; }

void wmspiritset_free(void)
{
}

void wmspiritset_hitDetect(void)
{
}

void wmspiritset_update(void)
{
}

void wmspiritset_release(void)
{
}

void wmspiritset_initialise(void)
{
}

void wmspiritset_init(int* obj, u8* init)
{
    WmSpiritSetState* state = ((GameObject*)obj)->extra;
    WmSpiritSetMapData* mapData = (WmSpiritSetMapData*)init;

    *(s16*)obj = (s16)(mapData->rotXByte << 8);
    if (((GameObject*)obj)->anim.seqId == 0x264)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5F94;
    }
    state->visibilityGameBit = mapData->visibilityGameBit;
}

void wmspiritset_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    WmSpiritSetState* state = ((GameObject*)p1)->extra;
    s16 visibilityGameBit = state->visibilityGameBit;

    if ((visibilityGameBit == -1 || (u32)GameBit_Get(visibilityGameBit) != 0) && vis != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F90);
    }
}
