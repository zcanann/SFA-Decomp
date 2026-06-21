#ifndef MAIN_DLL_DIMICEWALLSTATE_STRUCT_H_
#define MAIN_DLL_DIMICEWALLSTATE_STRUCT_H_

#include "types.h"

typedef struct DimicewallState
{
    u8 pad0[0x1 - 0x0];
    u8 shattered; /* set once the wall shatters / its shatter gamebit is armed */
    s16 unk2;
    u8 pad4[0x8 - 0x4];
} DimicewallState;

#endif
