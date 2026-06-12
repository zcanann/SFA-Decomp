#ifndef MAIN_DLL_IM_TYPES_H_
#define MAIN_DLL_IM_TYPES_H_

#include "types.h"

typedef struct ImAnimSpacecraftState
{
    s16 blinkTimer; /* 0x00 */
    u8 maskBits; /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 flags; /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;

typedef struct ImSpaceThrusterState
{
    u8 kind; /* 0x00: thruster slot from def+0x19 */
    u8 phase; /* 0x01 */
    s16 blendTimer; /* 0x02 */
    void* bufA; /* 0x04: mmAlloc'd getTabEntry rows */
    void* bufB; /* 0x08 */
} ImSpaceThrusterState;

#endif
