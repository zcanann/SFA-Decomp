#ifndef MAIN_DLL_CAM_CAMCOMBAT_STATE_H_
#define MAIN_DLL_CAM_CAMCOMBAT_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeCombatState {
    f32 followDistance;
    f32 heightOffset;
    f32 zoomOffset;
    f32 unk0C;
    u8 unk10;
    u8 unk11;
    u8 invalidTarget;
    u8 pathBlendStartIndex;
    u8 pathBlendTargetIndex;
    u8 unk15[0x18 - 0x15];
    f32 pathBlendWeight;
} CameraModeCombatState;

STATIC_ASSERT(sizeof(CameraModeCombatState) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeCombatState, followDistance) == 0x0);
STATIC_ASSERT(offsetof(CameraModeCombatState, heightOffset) == 0x4);
STATIC_ASSERT(offsetof(CameraModeCombatState, zoomOffset) == 0x8);
STATIC_ASSERT(offsetof(CameraModeCombatState, unk10) == 0x10);
STATIC_ASSERT(offsetof(CameraModeCombatState, unk11) == 0x11);
STATIC_ASSERT(offsetof(CameraModeCombatState, invalidTarget) == 0x12);
STATIC_ASSERT(offsetof(CameraModeCombatState, pathBlendStartIndex) == 0x13);
STATIC_ASSERT(offsetof(CameraModeCombatState, pathBlendTargetIndex) == 0x14);
STATIC_ASSERT(offsetof(CameraModeCombatState, pathBlendWeight) == 0x18);

#endif /* MAIN_DLL_CAM_CAMCOMBAT_STATE_H_ */
