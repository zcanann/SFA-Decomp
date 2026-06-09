#ifndef MAIN_DLL_CAM_CAMWORLDMAP_STATE_H_
#define MAIN_DLL_CAM_CAMWORLDMAP_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeWorldMapFlags {
    u8 transitionActive : 1;
    u8 rest : 7;
} CameraModeWorldMapFlags;

typedef struct CameraModeWorldMapState {
    f32 distance;
    f32 distanceVelocity;
    u8 mode;
    u8 previousMode;
    s16 settleFrames;
    s16 targetAngle;
    u8 unk0E[0x10 - 0x0E];
    s32 focusObjectId;
    u8 focusBlendTimer;
    CameraModeWorldMapFlags flags;
    u8 unk16[0x18 - 0x16];
} CameraModeWorldMapState;

STATIC_ASSERT(sizeof(CameraModeWorldMapState) == 0x18);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, distance) == 0x00);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, distanceVelocity) == 0x04);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, mode) == 0x08);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, previousMode) == 0x09);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, settleFrames) == 0x0A);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, targetAngle) == 0x0C);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, focusObjectId) == 0x10);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, focusBlendTimer) == 0x14);
STATIC_ASSERT(offsetof(CameraModeWorldMapState, flags) == 0x15);

#endif /* MAIN_DLL_CAM_CAMWORLDMAP_STATE_H_ */
