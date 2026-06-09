#ifndef MAIN_DLL_CAM_CAMBIKE_STATE_H_
#define MAIN_DLL_CAM_CAMBIKE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeBikeState {
    f32 defaultFov;
    u8 unk04[0x14 - 0x04];
    f32 defaultScale;
    f32 entryFov;
    f32 turnInput;
    f32 smoothedYawOffset;
    f32 heightInput;
    f32 followDistance;
    f32 rollInput;
    f32 pitchTarget;
    u8 unk34[0x38 - 0x34];
} CameraModeBikeState;

STATIC_ASSERT(sizeof(CameraModeBikeState) == 0x38);
STATIC_ASSERT(offsetof(CameraModeBikeState, defaultScale) == 0x14);
STATIC_ASSERT(offsetof(CameraModeBikeState, entryFov) == 0x18);
STATIC_ASSERT(offsetof(CameraModeBikeState, turnInput) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeBikeState, smoothedYawOffset) == 0x20);
STATIC_ASSERT(offsetof(CameraModeBikeState, heightInput) == 0x24);
STATIC_ASSERT(offsetof(CameraModeBikeState, followDistance) == 0x28);
STATIC_ASSERT(offsetof(CameraModeBikeState, rollInput) == 0x2C);
STATIC_ASSERT(offsetof(CameraModeBikeState, pitchTarget) == 0x30);

#endif /* MAIN_DLL_CAM_CAMBIKE_STATE_H_ */
