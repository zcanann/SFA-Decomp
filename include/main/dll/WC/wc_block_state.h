#ifndef MAIN_DLL_WC_WC_BLOCK_STATE_H
#define MAIN_DLL_WC_WC_BLOCK_STATE_H

#include "global.h"
#include "game/objects/object.h"

typedef struct WCBlockState {
    u8 pad00[0x268];
    GameObject* controller;
    f32 targetX;
    f32 targetZ;
    f32 baseY;
    f32 bobY;
    u16 bobAngle;
    s16 cellX;
    s16 cellZ;
    u8 pushDir;
    u8 tileIndex;
} WCBlockState;

STATIC_ASSERT(sizeof(WCBlockState) == 0x284);
STATIC_ASSERT(offsetof(WCBlockState, controller) == 0x268);
STATIC_ASSERT(offsetof(WCBlockState, targetX) == 0x26C);
STATIC_ASSERT(offsetof(WCBlockState, targetZ) == 0x270);
STATIC_ASSERT(offsetof(WCBlockState, baseY) == 0x274);
STATIC_ASSERT(offsetof(WCBlockState, bobY) == 0x278);
STATIC_ASSERT(offsetof(WCBlockState, bobAngle) == 0x27C);
STATIC_ASSERT(offsetof(WCBlockState, cellX) == 0x27E);
STATIC_ASSERT(offsetof(WCBlockState, cellZ) == 0x280);
STATIC_ASSERT(offsetof(WCBlockState, pushDir) == 0x282);
STATIC_ASSERT(offsetof(WCBlockState, tileIndex) == 0x283);

int wcblock_isPlayerAwayFromStoredCell(GameObject* obj, WCBlockState* state, GameObject* player);

#endif
