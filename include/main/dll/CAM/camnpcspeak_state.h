#ifndef MAIN_DLL_CAM_CAMNPCSPEAK_STATE_H_
#define MAIN_DLL_CAM_CAMNPCSPEAK_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeNpcSpeakState {
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 unk0C[0x10 - 0x0C];
    f32 distanceOffset;
    f32 unk14;
    s32 orbitAngleOffset;
    s32 mode;
    s16 unk20;
    s16 orbitAngleVelocity;
    f32 cameraX;
    f32 cameraY;
    f32 cameraZ;
    f32 targetHeightOffset;
    f32 unk34;
    f32 lookAtHeightOffset;
    f32 lookAtYScale;
    f32 minDistance;
    f32 anchorLerpScale;
    f32 lookAtXZScale;
} CameraModeNpcSpeakState;

STATIC_ASSERT(sizeof(CameraModeNpcSpeakState) == 0x4C);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, anchorX) == 0x00);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, anchorY) == 0x04);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, anchorZ) == 0x08);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, distanceOffset) == 0x10);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, orbitAngleOffset) == 0x18);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, mode) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, orbitAngleVelocity) == 0x22);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, cameraX) == 0x24);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, targetHeightOffset) == 0x30);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, lookAtHeightOffset) == 0x38);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, lookAtYScale) == 0x3C);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, minDistance) == 0x40);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, anchorLerpScale) == 0x44);
STATIC_ASSERT(offsetof(CameraModeNpcSpeakState, lookAtXZScale) == 0x48);

#endif /* MAIN_DLL_CAM_CAMNPCSPEAK_STATE_H_ */
