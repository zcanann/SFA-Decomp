#ifndef MAIN_DLL_DOORF4STATE_STRUCT_H_
#define MAIN_DLL_DOORF4STATE_STRUCT_H_

#include "types.h"

typedef struct Doorf4State
{
    u8 pad0[0x1C - 0x0];
    u16 unk1C;
    u8 pad1E[0x24 - 0x1E];
} Doorf4State;

#endif
