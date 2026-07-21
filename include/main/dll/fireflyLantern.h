#ifndef MAIN_DLL_FIREFLYLANTERN_H_
#define MAIN_DLL_FIREFLYLANTERN_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/dll/duster_api.h"

typedef struct FireflyLanternState
{
    u8 pad00[0x324];
    f32 trackTimer;  /* 0x324 */
    f32 breathTimer; /* 0x328 */
    f32 anchorY;     /* 0x32C */
    f32 unk330;      /* 0x330 */
    u8 pad334[0x344 - 0x334];
    WallPlaneState wallPlane; /* 0x344 */
} FireflyLanternState;

STATIC_ASSERT(offsetof(FireflyLanternState, wallPlane) == 0x344);
STATIC_ASSERT(sizeof(FireflyLanternState) == 0x368);

void pinPon_updateEngaged(GameObject* obj, int* state);
void pinPon_init(GameObject* obj, void* state);
void fireflyLanternGetTargetAngleAndDistance(int obj, int state, u16* outAngle, float* outDistance);
u32 fireflyLanternSteerTowardTarget(short* obj, int state, u32 turnTime, f32 maxDistance);

extern f32 gFireflyLanternTargetHeightOffset;

#endif /* MAIN_DLL_FIREFLYLANTERN_H_ */
