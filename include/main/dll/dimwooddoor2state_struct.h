#ifndef MAIN_DLL_DIMWOODDOOR2STATE_STRUCT_H_
#define MAIN_DLL_DIMWOODDOOR2STATE_STRUCT_H_

#include "types.h"

typedef struct DimWoodDoor2State
{
    u8 burnState; /* 3 intact; 0 burned (gamebit rung) */
    u8 pad01[3];
    f32 animSpeed;
    f32 riseSpeed; /* added to obj Z, decays back to rest */
} DimWoodDoor2State;

#endif
