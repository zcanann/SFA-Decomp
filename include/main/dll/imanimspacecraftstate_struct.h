#ifndef MAIN_DLL_IMANIMSPACECRAFTSTATE_STRUCT_H_
#define MAIN_DLL_IMANIMSPACECRAFTSTATE_STRUCT_H_

#include "types.h"

typedef struct ImAnimSpacecraftState
{
    s16 blinkTimer; /* 0x00 */
    u8 maskBits; /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 flags; /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;

#endif
