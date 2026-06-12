#ifndef MAIN_DLL_DIM2_TYPES_H_
#define MAIN_DLL_DIM2_TYPES_H_

#include "types.h"

typedef struct Dim2ConveyorState
{
    f32 scrollX; /* 0x00: per-area conveyor scroll vector */
    f32 scrollY; /* 0x04 */
    u8 pad08[4];
    f32 swapTimer; /* 0x0c: 0x49b23 direction-swap countdown */
    int musicHold; /* 0x10: frames left keeping music track 0xdf alive */
} Dim2ConveyorState;

typedef struct Dim2SnowballState
{
    u8 pad00[0x10];
    int curveCursor; /* 0x10 */
    u8 pad14[0x54];
    f32 curveX; /* 0x68 */
    f32 curveY; /* 0x6c */
    f32 curveZ; /* 0x70 */
    f32 dirX; /* 0x74 */
    u8 pad78[4];
    f32 dirZ; /* 0x7c */
    int curveMode; /* 0x80 */
    u8 pad84[0xc]; /* 0x84..0x8f: vcall outparams (address-used) */
    int curveResult; /* 0x90 */
    int evalFn; /* 0x94 */
    int coeffsFn; /* 0x98 */
    int* targetObj; /* 0x9c */
    int targetId; /* 0xa0 */
    f32 floorY; /* 0xa4 */
    int* curveData; /* 0xa8 (also address-used as a vcall outparam) */
    u8 flagsAC; /* 0xac */
    u8 padAD[3];
} Dim2SnowballState;

typedef struct Dim2PathGeneratorState
{
    f32 originX; /* 0x000 */
    f32 originY; /* 0x004 */
    f32 originZ; /* 0x008 */
    f32 curveA[200]; /* 0x00c */
    f32 curveB[200]; /* 0x32c */
    f32 curveC[200]; /* 0x64c */
    f32 curveD[12]; /* 0x96c */
    u8 pad99C[2];
    s16 spawnTimer; /* 0x99e */
    s16 spawnPeriod; /* 0x9a0 */
    s16 spawnTypes[2]; /* 0x9a2: object ids, alternated via the toggle bit */
    u8 curveValid; /* 0x9a6 */
    u8 flags; /* 0x9a7: 1 = toggle, 2 = curve built, 4 = enabled */
} Dim2PathGeneratorState;

#endif
