#ifndef MAIN_DLL_WM_TYPES_H_
#define MAIN_DLL_WM_TYPES_H_

#include "types.h"

typedef struct WmObjCreatorState
{
    s16 gameBit; /* 0x00: spawn gate, -1 = always */
    s16 spawnPeriod; /* 0x02 */
    s16 spawnTimer; /* 0x04 */
    s16 spawnJitter; /* 0x06: randomGetRange(0, jitter) added per cycle */
} WmObjCreatorState;

typedef struct WmObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnPeriod;
    s8 yaw;
    s8 spawnJitter;
    u8 pad20[4];
} WmObjCreatorPlacement;

typedef struct WmGalleonState
{
    u8 pad00[0xC];
    u8 active; /* 0x0c: cleared on a non-map-change free */
    u8 pad0D[3];
} WmGalleonState;

#endif
