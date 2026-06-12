#ifndef MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_
#define MAIN_DLL_CRROCKFALLPLACEMENT_STRUCT_H_

#include "types.h"

typedef struct CrrockfallPlacement
{
    u8 pad0[0x1A - 0x0];
    u8 unk1A;
    u8 unk1B;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} CrrockfallPlacement;

#endif
