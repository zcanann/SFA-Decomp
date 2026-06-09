#ifndef MAIN_DLL_CAM_CAMCLIMB_STATE_H_
#define MAIN_DLL_CAM_CAMCLIMB_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeClimbState {
    f32 targetDistance;
    f32 smoothedDistance;
    f32 heightAdjustRate;
    f32 minHeight;
    f32 maxHeight;
    f32 startDistance;
    f32 endDistance;
    f32 startMinHeight;
    f32 endMinHeight;
    f32 startMaxHeight;
    f32 endMaxHeight;
    s16 transitionTimer;
    s16 transitionDuration;
    u16 relativePosition;
    u16 startRelativePosition;
    u16 targetRelativePosition;
    u8 unk36[0x38 - 0x36];
} CameraModeClimbState;

STATIC_ASSERT(sizeof(CameraModeClimbState) == 0x38);
STATIC_ASSERT(offsetof(CameraModeClimbState, targetDistance) == 0x0);
STATIC_ASSERT(offsetof(CameraModeClimbState, smoothedDistance) == 0x4);
STATIC_ASSERT(offsetof(CameraModeClimbState, heightAdjustRate) == 0x8);
STATIC_ASSERT(offsetof(CameraModeClimbState, transitionTimer) == 0x2C);
STATIC_ASSERT(offsetof(CameraModeClimbState, transitionDuration) == 0x2E);
STATIC_ASSERT(offsetof(CameraModeClimbState, relativePosition) == 0x30);
STATIC_ASSERT(offsetof(CameraModeClimbState, startRelativePosition) == 0x32);
STATIC_ASSERT(offsetof(CameraModeClimbState, targetRelativePosition) == 0x34);

#endif /* MAIN_DLL_CAM_CAMCLIMB_STATE_H_ */
