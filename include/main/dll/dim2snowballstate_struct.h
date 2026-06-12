#ifndef MAIN_DLL_DIM2SNOWBALLSTATE_STRUCT_H_
#define MAIN_DLL_DIM2SNOWBALLSTATE_STRUCT_H_

#include "types.h"
#include "main/curve.h"

typedef struct Dim2SnowballState
{
    Curve curve;
    int* targetObj; /* 0x9c */
    int targetId; /* 0xa0 */
    f32 floorY; /* 0xa4 */
    int* curveData; /* 0xa8 (also address-used as a vcall outparam) */
    u8 flagsAC; /* 0xac */
    u8 padAD[3];
} Dim2SnowballState;

#endif
