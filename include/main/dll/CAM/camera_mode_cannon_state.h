#ifndef MAIN_DLL_CAM_CAMERA_MODE_CANNON_STATE_H_
#define MAIN_DLL_CAM_CAMERA_MODE_CANNON_STATE_H_

#include "global.h"
#include "main/game_object.h"

typedef struct CameraModeCannonState {
    GameObject *target;
} CameraModeCannonState;

STATIC_ASSERT(sizeof(CameraModeCannonState) == 0x4);
STATIC_ASSERT(offsetof(CameraModeCannonState, target) == 0x00);

#endif /* MAIN_DLL_CAM_CAMERA_MODE_CANNON_STATE_H_ */
