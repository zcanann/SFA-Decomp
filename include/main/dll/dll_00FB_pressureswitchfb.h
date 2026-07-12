#ifndef MAIN_DLL_DLL_00FB_PRESSURESWITCHFB_H_
#define MAIN_DLL_DLL_00FB_PRESSURESWITCHFB_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct PressureswitchfbPlacement
{
    ObjPlacement base;
    u8 initialYaw;
    u8 modelBankIndex;
    s16 pressedGameBit;
    u8 pressDepth;
    u8 unk1D;
    u8 drivesTricky;
    u8 pad1F;
    s16 enableGameBit;
    s16 unk22;
    s16 unk24;
    u8 pad26[2];
} PressureswitchfbPlacement;

typedef struct PressureSwitchFbFlags
{
    u8 usePressedTexture : 1;
    u8 startPressed : 1;
    u8 canRelease : 1;
    u8 autoPress : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} PressureSwitchFbFlags;

typedef struct PressureSwitchFbUpdateFlags
{
    u8 active : 1;
    u8 playerOnly : 1;
    u8 released : 1;
    u8 latched : 1;
    u8 unused4 : 4;
} PressureSwitchFbUpdateFlags;

typedef union PressureSwitchFbFlagViews
{
    PressureSwitchFbFlags init;
    PressureSwitchFbUpdateFlags update;
    u8 raw;
} PressureSwitchFbFlagViews;

typedef struct PressureSwitchFbTrackedPosition
{
    f32 x;
    f32 z;
} PressureSwitchFbTrackedPosition;

typedef struct PressureSwitchFbState
{
    s8 contactTimer;
    u8 pad01[3];
    GameObject* trackedObjects[10];
    PressureSwitchFbTrackedPosition trackedPositions[10];
    f32 targetPosY;
    f32 velocityY;
    PressureSwitchFbFlagViews flags;
    u8 pad85[3];
} PressureSwitchFbState;

STATIC_ASSERT(offsetof(PressureswitchfbPlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(PressureswitchfbPlacement, pressedGameBit) == 0x1A);
STATIC_ASSERT(offsetof(PressureswitchfbPlacement, enableGameBit) == 0x20);
STATIC_ASSERT(sizeof(PressureswitchfbPlacement) == 0x28);
STATIC_ASSERT(offsetof(PressureSwitchFbState, trackedObjects) == 0x04);
STATIC_ASSERT(offsetof(PressureSwitchFbState, trackedPositions) == 0x2C);
STATIC_ASSERT(offsetof(PressureSwitchFbState, targetPosY) == 0x7C);
STATIC_ASSERT(offsetof(PressureSwitchFbState, flags) == 0x84);
STATIC_ASSERT(sizeof(PressureSwitchFbState) == 0x88);
int PressureSwitchFB_SeqFn(GameObject* obj, int unused, int stateParam);
int PressureSwitchFB_getExtraSize(void);
void PressureSwitchFB_free(GameObject* obj);
void PressureSwitchFB_update(GameObject* obj);
void PressureSwitchFB_init(GameObject* obj, PressureswitchfbPlacement* params);

#endif /* MAIN_DLL_DLL_00FB_PRESSURESWITCHFB_H_ */
