#ifndef MAIN_DLL_WM_DLL_020F_WMSPIRITSET_H_
#define MAIN_DLL_WM_DLL_020F_WMSPIRITSET_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmSpiritSetState
{
    s16 visibilityGameBit; /* 0x00: game bit gating render (-1 = always visible) */
} WmSpiritSetState;

typedef struct WmSpiritSetMapData
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 visibilityGameBit; /* 0x1E */
} WmSpiritSetMapData;

STATIC_ASSERT(offsetof(WmSpiritSetState, visibilityGameBit) == 0x0);
STATIC_ASSERT(sizeof(WmSpiritSetState) == 0x2);
STATIC_ASSERT(offsetof(WmSpiritSetMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritSetMapData, visibilityGameBit) == 0x1E);
STATIC_ASSERT(sizeof(WmSpiritSetMapData) == 0x20);

int wmspiritset_getExtraSize(void);
int wmspiritset_getObjectTypeId(void);
void wmspiritset_free(void);
void wmspiritset_render(int p1, int p2, int p3, int p4, int p5, s8 vis);
void wmspiritset_hitDetect(void);
void wmspiritset_update(void);
void wmspiritset_init(GameObject* obj, WmSpiritSetMapData* mapData);
void wmspiritset_release(void);
void wmspiritset_initialise(void);

#endif /* MAIN_DLL_WM_DLL_020F_WMSPIRITSET_H_ */
