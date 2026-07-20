#ifndef MAIN_DLL_DIMWOODDOOR2STATE_STRUCT_H_
#define MAIN_DLL_DIMWOODDOOR2STATE_STRUCT_H_

#include "types.h"

typedef struct DimWoodDoor2State
{
    s8 burnState; /* 3 intact; 0 burned (gamebit rung) */
    u8 pad01[3];
    f32 animSpeed;
    f32 riseSpeed; /* added to obj Z, decays back to rest */
} DimWoodDoor2State;

STATIC_ASSERT(offsetof(DimWoodDoor2State, burnState) == 0x0);
STATIC_ASSERT(offsetof(DimWoodDoor2State, animSpeed) == 0x4);
STATIC_ASSERT(offsetof(DimWoodDoor2State, riseSpeed) == 0x8);
STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

#endif
