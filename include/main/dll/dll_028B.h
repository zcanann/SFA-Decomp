#ifndef MAIN_DLL_DLL_028B_H
#define MAIN_DLL_DLL_028B_H

#include "global.h"
#include "main/dll/curve_walker.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/game_object.h"

typedef struct Dll28BState
{
    int objectFlagsMirror;
    u8 pad4[0x35C - 0x4];
    MoveLibState moveLib;
    u8 eyeAnim[0x9B0 - 0x980];
    RomCurveWalker route;
    f32 playerDistance;
    u8 padABC[0xAC0 - 0xABC];
    u8 flagsAC0;
    u8 padAC1[0xAC4 - 0xAC1];
} Dll28BState;

typedef struct Dll28BMoveBlendData
{
    int values[4];
} Dll28BMoveBlendData;

STATIC_ASSERT(sizeof(Dll28BState) == 0xAC4);
STATIC_ASSERT(offsetof(Dll28BState, moveLib) == 0x35C);
STATIC_ASSERT(offsetof(Dll28BState, eyeAnim) == 0x980);
STATIC_ASSERT(offsetof(Dll28BState, route) == 0x9B0);
STATIC_ASSERT(offsetof(Dll28BState, playerDistance) == 0xAB8);
STATIC_ASSERT(offsetof(Dll28BState, flagsAC0) == 0xAC0);
STATIC_ASSERT(sizeof(Dll28BMoveBlendData) == 0x10);

extern const Dll28BMoveBlendData gDll28BMoveBlendDataA;
extern const Dll28BMoveBlendData gDll28BMoveBlendDataB;
extern void* gDll28BSubstateHandlers[4];
extern void* gDll28BStateHandlers[4];
extern f32 lbl_803E6D18;
extern f32 gDll28BCurveInitParam;

extern f32 gWcEarthWalkerFarPlayerDistance;
extern f32 gWcEarthWalkerNearPlayerDistance;
extern f32 gWcEarthWalkerIdleTimerThreshold;
extern f32 gWcEarthWalkerCurveAdvanceStep;
extern f32 gWcEarthWalkerApproachPlayerDistance;
extern f32 gWcEarthWalkerChaseMoveSpeed;
extern f32 gWcEarthWalkerWalkMoveSpeed;

int dll_28B_getExtraSize(void);
int dll_28B_getObjectTypeId(void);
void dll_28B_free(int obj);
void dll_28B_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_28B_hitDetect_nop(void);
void dll_28B_update(GameObject* obj);
void dll_28B_init(GameObject* obj);
void dll_28B_release_nop(void);
void dll_28B_initialise(void);

#endif
