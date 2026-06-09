#ifndef MAIN_DLL_CAM_CAMSTATIC_STATE_H_
#define MAIN_DLL_CAM_CAMSTATIC_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/game_object.h"

typedef struct CameraModeStaticState {
    GameObject *staticObject;
    u8 unk04[0xF4 - 0x04];
    u8 active;
    u8 missingObject;
    u8 unkF6[0xF8 - 0xF6];
} CameraModeStaticState;

STATIC_ASSERT(sizeof(CameraModeStaticState) == 0xF8);
STATIC_ASSERT(offsetof(CameraModeStaticState, staticObject) == 0x0);
STATIC_ASSERT(offsetof(CameraModeStaticState, active) == 0xF4);
STATIC_ASSERT(offsetof(CameraModeStaticState, missingObject) == 0xF5);

#endif /* MAIN_DLL_CAM_CAMSTATIC_STATE_H_ */
