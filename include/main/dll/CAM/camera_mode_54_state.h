#ifndef MAIN_DLL_CAM_CAMERA_MODE_54_STATE_H_
#define MAIN_DLL_CAM_CAMERA_MODE_54_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/game_object.h"

typedef struct CameraMode54State {
    GameObject *originObj;
    GameObject *lookAtObj;
    GameObject *playerObj;
    u8 transitionDone;
    u8 exitRequested;
    u8 unk0E[0x10 - 0x0E];
    f32 transitionTimer;
    f32 startX;
    f32 startY;
    f32 startZ;
    s16 startYaw;
    s16 startPitch;
    s16 startRoll;
    u8 unk26[0x28 - 0x26];
} CameraMode54State;

STATIC_ASSERT(sizeof(CameraMode54State) == 0x28);
STATIC_ASSERT(offsetof(CameraMode54State, originObj) == 0x00);
STATIC_ASSERT(offsetof(CameraMode54State, lookAtObj) == 0x04);
STATIC_ASSERT(offsetof(CameraMode54State, playerObj) == 0x08);
STATIC_ASSERT(offsetof(CameraMode54State, transitionDone) == 0x0C);
STATIC_ASSERT(offsetof(CameraMode54State, exitRequested) == 0x0D);
STATIC_ASSERT(offsetof(CameraMode54State, transitionTimer) == 0x10);
STATIC_ASSERT(offsetof(CameraMode54State, startX) == 0x14);
STATIC_ASSERT(offsetof(CameraMode54State, startY) == 0x18);
STATIC_ASSERT(offsetof(CameraMode54State, startZ) == 0x1C);
STATIC_ASSERT(offsetof(CameraMode54State, startYaw) == 0x20);
STATIC_ASSERT(offsetof(CameraMode54State, startPitch) == 0x22);
STATIC_ASSERT(offsetof(CameraMode54State, startRoll) == 0x24);

#endif /* MAIN_DLL_CAM_CAMERA_MODE_54_STATE_H_ */
