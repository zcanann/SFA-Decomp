#ifndef MAIN_DLL_BOMBPLANT_PLACEMENT_H_
#define MAIN_DLL_BOMBPLANT_PLACEMENT_H_

#include "global.h"

typedef struct BombplantPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0c */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 growTimer;
    s16 timerBase; /* 0x1a: base value for grow/regrow timer (+ random spread) */
    s16 gameBit; /* 0x1c: gated GameBit_Get */
    s8 spawnYawByte; /* 0x1e: spore yaw param (<<8 -> spore spawnYaw) */
    s8 objectTypeParam; /* 0x1f: signed byte, <<8 -> object rotX seed */
} BombplantPlacement;

#endif
