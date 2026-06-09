#ifndef MAIN_DLL_CAM_CAMSHIPBATTLE_STATE_H_
#define MAIN_DLL_CAM_CAMSHIPBATTLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeShipBattleState {
    f32 smoothedZOffset;
    f32 smoothedYOffset;
    f32 lateralOffset;
    f32 targetLateralOffset;
    f32 startLateralOffset;
    f32 blendTimer;
    f32 lateralDelta;
    f32 verticalOffset;
    f32 startVerticalOffset;
    f32 verticalDelta;
    u8 mode;
    u8 unk29[0x2C - 0x29];
} CameraModeShipBattleState;

STATIC_ASSERT(sizeof(CameraModeShipBattleState) == 0x2C);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, smoothedZOffset) == 0x0);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, smoothedYOffset) == 0x4);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, lateralOffset) == 0x8);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, targetLateralOffset) == 0xC);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, startLateralOffset) == 0x10);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, blendTimer) == 0x14);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, lateralDelta) == 0x18);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, verticalOffset) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, startVerticalOffset) == 0x20);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, verticalDelta) == 0x24);
STATIC_ASSERT(offsetof(CameraModeShipBattleState, mode) == 0x28);

#endif /* MAIN_DLL_CAM_CAMSHIPBATTLE_STATE_H_ */
