#ifndef MAIN_DLL_DLL_00E3_FIREBALL_H_
#define MAIN_DLL_DLL_00E3_FIREBALL_H_

#include "main/dll/dll_00E3_fireball_api.h"
#include "main/model_light.h"
#include "main/obj_placement.h"

#define FIREBALL_ROT_COUNT 5

typedef struct FireballPlacement
{
    ObjPlacement base;
    u8 unk18;
    s8 hitVolumeMode;
    s16 startupDelayEnabled; /* 0x1A: nonzero arms FireballState.startupDelay */
    s16 startDisabled;       /* 0x1C: nonzero starts with FIREBALL_FLAG_DISABLED */
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} FireballPlacement;

typedef struct FireballState
{
    ModelLightStruct* light;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 flightDuration;
    f32 elapsedTime;
    f32 fadeoutTimer;
    f32 startupDelay;
    s16 unk40;
    s16 unk42;
    u8 pad44[0x46 - 0x44];
    u16 spiralPhase;
    u16 rotZBase[FIREBALL_ROT_COUNT];
    u16 rotZDelta[FIREBALL_ROT_COUNT];
    u16 rotYBase[FIREBALL_ROT_COUNT];
    u16 rotYDelta[FIREBALL_ROT_COUNT];
    u8 stateFlags;
    u8 colorIndex;
    u8 pad72[0x74 - 0x72];
} FireballState;

STATIC_ASSERT(sizeof(FireballPlacement) == 0x30);
STATIC_ASSERT(offsetof(FireballPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(FireballPlacement, hitVolumeMode) == 0x19);
STATIC_ASSERT(offsetof(FireballPlacement, startupDelayEnabled) == 0x1A);
STATIC_ASSERT(offsetof(FireballPlacement, startDisabled) == 0x1C);
STATIC_ASSERT(sizeof(FireballState) == 0x74);
STATIC_ASSERT(offsetof(FireballState, light) == 0x0);
STATIC_ASSERT(offsetof(FireballState, posX) == 0x24);
STATIC_ASSERT(offsetof(FireballState, flightDuration) == 0x30);
STATIC_ASSERT(offsetof(FireballState, startupDelay) == 0x3C);
STATIC_ASSERT(offsetof(FireballState, spiralPhase) == 0x46);
STATIC_ASSERT(offsetof(FireballState, rotZBase) == 0x48);
STATIC_ASSERT(offsetof(FireballState, rotYDelta) == 0x66);
STATIC_ASSERT(offsetof(FireballState, stateFlags) == 0x70);
STATIC_ASSERT(offsetof(FireballState, colorIndex) == 0x71);

#endif
