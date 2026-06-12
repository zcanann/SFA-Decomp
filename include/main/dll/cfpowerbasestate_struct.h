#ifndef MAIN_DLL_CFPOWERBASESTATE_STRUCT_H_
#define MAIN_DLL_CFPOWERBASESTATE_STRUCT_H_

#include "types.h"

typedef struct CfPowerBaseState
{
    s16 typeBit; /* gamebit 0x54..0x56, from params+0x1e */
    s16 litBit; /* gamebit 0x51..0x53 gating the lit state */
    s8 typeIndex; /* 0/1/2 trigger argument */
    u8 pad5;
} CfPowerBaseState;

#endif
