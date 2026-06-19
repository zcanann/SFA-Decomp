#ifndef MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_
#define MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_

#include "types.h"

typedef struct CrrockfallPlacement
{
    u8 pad0[0x1A - 0x0];
    u8 triggerRange;
    u8 explosionScale;
    s16 gameBitId;
    u8 pad1E[0x20 - 0x1E];
} CrrockfallPlacement;

#endif
