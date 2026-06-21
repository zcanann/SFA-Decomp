#ifndef MAIN_DLL_DLL1CEPLACEMENT_STRUCT_H_
#define MAIN_DLL_DLL1CEPLACEMENT_STRUCT_H_

#include "types.h"

typedef struct Dll1CEPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posYOffset;
    f32 posZ;
    u8 pad14[0x1A - 0x14];
    s16 spawnGameBitValue; /* compared against GameBit_Get(0x46D); spawns contents when equal */
    u8 pad1C[0x1E - 0x1C];
    s16 gameBitId;
} Dll1CEPlacement;

#endif
