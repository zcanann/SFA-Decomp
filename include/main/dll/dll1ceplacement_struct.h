#ifndef MAIN_DLL_DLL1CEPLACEMENT_STRUCT_H_
#define MAIN_DLL_DLL1CEPLACEMENT_STRUCT_H_

#include "main/obj_placement.h"

typedef struct Dll1CEPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19;
    s16 contentsSpawnBitValue; /* contents spawn when this equals mainGetBit(0x46D) */
    u8 pad1C[0x1E - 0x1C];
    s16 openedGameBit;
} Dll1CEPlacement;

STATIC_ASSERT(offsetof(Dll1CEPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dll1CEPlacement, contentsSpawnBitValue) == 0x1A);
STATIC_ASSERT(offsetof(Dll1CEPlacement, openedGameBit) == 0x1E);

#endif
