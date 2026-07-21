#ifndef MAIN_DLL_IMANIMSPACECRAFTSTATE_STRUCT_H_
#define MAIN_DLL_IMANIMSPACECRAFTSTATE_STRUCT_H_

#include "global.h"

typedef struct ImAnimSpacecraftState
{
    s16 blinkTimer; /* 0x00 */
    u8 submodelMask; /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 eventFlags; /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;

STATIC_ASSERT(offsetof(ImAnimSpacecraftState, blinkTimer) == 0x0);
STATIC_ASSERT(offsetof(ImAnimSpacecraftState, submodelMask) == 0x2);
STATIC_ASSERT(offsetof(ImAnimSpacecraftState, eventFlags) == 0x3);
STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

#endif
