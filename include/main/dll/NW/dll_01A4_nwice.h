#ifndef MAIN_DLL_NW_DLL_01A4_NWICE_H_
#define MAIN_DLL_NW_DLL_01A4_NWICE_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct NwIcePlacement
{
    ObjPlacement base;
    u8 pad18[3];
    u8 pairId;
    u8 pad1C[4];
} NwIcePlacement;

typedef struct NwIceState
{
    GameObject* pairedIce;
} NwIceState;

STATIC_ASSERT(offsetof(NwIcePlacement, pairId) == 0x1b);
STATIC_ASSERT(sizeof(NwIcePlacement) == 0x20);
STATIC_ASSERT(offsetof(NwIceState, pairedIce) == 0x0);
STATIC_ASSERT(sizeof(NwIceState) == 0x4);

int NW_ice_getExtraSize(void);
void NW_ice_free(GameObject* obj);
void NW_ice_render(void);
void NW_ice_update(GameObject* obj);
void NW_ice_init(GameObject* obj);

#endif /* MAIN_DLL_NW_DLL_01A4_NWICE_H_ */
