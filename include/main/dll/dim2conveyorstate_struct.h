#ifndef MAIN_DLL_DIM2CONVEYORSTATE_STRUCT_H_
#define MAIN_DLL_DIM2CONVEYORSTATE_STRUCT_H_

#include "types.h"

typedef struct Dim2ConveyorState
{
    f32 scrollX; /* 0x00: per-area conveyor scroll vector */
    f32 scrollY; /* 0x04 */
    u8 pad08[4];
    f32 swapTimer; /* 0x0c: 0x49b23 direction-swap countdown */
    int musicHoldTimer; /* 0x10: frames left keeping music track 0xdf alive */
} Dim2ConveyorState;

#endif
