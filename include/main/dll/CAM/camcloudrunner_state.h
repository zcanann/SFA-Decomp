#ifndef MAIN_DLL_CAM_CAMCLOUDRUNNER_STATE_H_
#define MAIN_DLL_CAM_CAMCLOUDRUNNER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeCloudRunnerState {
    f32 focusX;
    f32 focusY;
    f32 focusZ;
    f32 radius;
} CameraModeCloudRunnerState;

STATIC_ASSERT(sizeof(CameraModeCloudRunnerState) == 0x10);
STATIC_ASSERT(offsetof(CameraModeCloudRunnerState, focusX) == 0x00);
STATIC_ASSERT(offsetof(CameraModeCloudRunnerState, focusY) == 0x04);
STATIC_ASSERT(offsetof(CameraModeCloudRunnerState, focusZ) == 0x08);
STATIC_ASSERT(offsetof(CameraModeCloudRunnerState, radius) == 0x0C);

#endif /* MAIN_DLL_CAM_CAMCLOUDRUNNER_STATE_H_ */
