#ifndef MAIN_DLL_WC_DLL_0291_WCTILE_H_
#define MAIN_DLL_WC_DLL_0291_WCTILE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WCTileState
{
    GameObject* controller;
    s16 tileX;
    s16 tileY;
    s16 targetTile;
    s16 mode;
} WCTileState;

typedef struct WCTileSetup
{
    ObjPlacement base;
    u8 unk18;
    s8 modelIndex;
    s16 initialTile;
    u8 pad1C[8];
} WCTileSetup;

STATIC_ASSERT(sizeof(WCTileState) == 0xc);
STATIC_ASSERT(offsetof(WCTileState, controller) == 0x0);
STATIC_ASSERT(offsetof(WCTileState, tileX) == 0x4);
STATIC_ASSERT(offsetof(WCTileState, tileY) == 0x6);
STATIC_ASSERT(offsetof(WCTileState, targetTile) == 0x8);
STATIC_ASSERT(offsetof(WCTileState, mode) == 0xa);
STATIC_ASSERT(sizeof(WCTileSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTileSetup, base.posY) == 0xc);
STATIC_ASSERT(offsetof(WCTileSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCTileSetup, initialTile) == 0x1a);

extern f32 lbl_803E6DF0;
extern f32 lbl_803E6DF4;
extern f32 lbl_803E6DF8;
extern f32 lbl_803E6DFC;

int wctile_getExtraSize(void);
int wctile_getObjectTypeId(GameObject* obj);
void wctile_free(void);
void wctile_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctile_hitDetect(void);
void wctile_init(GameObject* obj, WCTileSetup* setup);
void wctile_release(void);
void wctile_initialise(void);
void wctile_update(GameObject* obj);

#endif /* MAIN_DLL_WC_DLL_0291_WCTILE_H_ */
