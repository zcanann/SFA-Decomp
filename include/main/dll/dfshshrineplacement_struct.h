#ifndef MAIN_DLL_DFSHSHRINEPLACEMENT_STRUCT_H_
#define MAIN_DLL_DFSHSHRINEPLACEMENT_STRUCT_H_

#include "types.h"

typedef struct DfshShrinePlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 startDelay;
    u8 pad1C[0x24 - 0x1C];
} DfshShrinePlacement;

#endif
