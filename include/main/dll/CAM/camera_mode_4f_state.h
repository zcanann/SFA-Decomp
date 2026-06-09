#ifndef MAIN_DLL_CAM_CAMERA_MODE_4F_STATE_H_
#define MAIN_DLL_CAM_CAMERA_MODE_4F_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraMode4FState {
    u8 unk0[4];
    f32 blendProgress;
} CameraMode4FState;

STATIC_ASSERT(sizeof(CameraMode4FState) == 0x08);
STATIC_ASSERT(offsetof(CameraMode4FState, blendProgress) == 0x04);

#endif /* MAIN_DLL_CAM_CAMERA_MODE_4F_STATE_H_ */
