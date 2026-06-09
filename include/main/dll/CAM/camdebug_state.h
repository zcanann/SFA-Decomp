#ifndef MAIN_DLL_CAM_CAMDEBUG_STATE_H_
#define MAIN_DLL_CAM_CAMDEBUG_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeDebugState {
    f32 orbitRadius;
    f32 radiusVelocity;
} CameraModeDebugState;

STATIC_ASSERT(sizeof(CameraModeDebugState) == 0x8);
STATIC_ASSERT(offsetof(CameraModeDebugState, orbitRadius) == 0x0);
STATIC_ASSERT(offsetof(CameraModeDebugState, radiusVelocity) == 0x4);

#endif /* MAIN_DLL_CAM_CAMDEBUG_STATE_H_ */
