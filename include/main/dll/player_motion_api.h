#ifndef MAIN_DLL_PLAYER_MOTION_API_H_
#define MAIN_DLL_PLAYER_MOTION_API_H_

#include "global.h"
#include "main/game_object.h"

typedef struct EmitObj
{
    u8 pad24[0x24];
    f32 x;
    f32 y;
    f32 z;
} EmitObj;

void fn_802B0EA4(GameObject* obj, int motionState, int baddieState);
void fn_802B1B28(GameObject* obj, f32 timeDelta);
void fn_802B1BF8(EmitObj* emit, int motionState, int baddieState);

#define fn_802B1B28IntObjectLegacy(obj, timeDelta)                                                              \
    ((void (*)(int, f32))fn_802B1B28)((obj), (timeDelta))
#define fn_802B1BF8TimeLegacy(obj, motionState, baddieState, timeDelta)                                         \
    ((void (*)(int, int, int, f32))fn_802B1BF8)((obj), (motionState), (baddieState), (timeDelta))

#endif /* MAIN_DLL_PLAYER_MOTION_API_H_ */
