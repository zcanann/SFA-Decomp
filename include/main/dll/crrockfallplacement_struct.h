#ifndef MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_
#define MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_

#include "types.h"

typedef struct CrrockfallPlacement
{
    u8 pad0[0x1A - 0x0];
    u8 triggerRange;
    u8 scaleByte;
    s16 gameBitId;
    s16 fallDelay;
} CrrockfallPlacement;

#endif
