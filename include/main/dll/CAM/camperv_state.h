#ifndef MAIN_DLL_CAM_CAMPERV_STATE_H_
#define MAIN_DLL_CAM_CAMPERV_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModePervState {
    f32 timer;
    f32 cameraY;
} CameraModePervState;

STATIC_ASSERT(sizeof(CameraModePervState) == 0x08);
STATIC_ASSERT(offsetof(CameraModePervState, timer) == 0x00);
STATIC_ASSERT(offsetof(CameraModePervState, cameraY) == 0x04);

#endif /* MAIN_DLL_CAM_CAMPERV_STATE_H_ */
