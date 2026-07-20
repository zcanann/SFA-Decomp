#ifndef MAIN_DLL_DLL1CESTATE_STRUCT_H_
#define MAIN_DLL_DLL1CESTATE_STRUCT_H_

#include "types.h"

typedef struct Dll1CEState
{
    f32 openProgress; /* clamped lid coast */
    f32 openVelocity;
    u8 opened; /* 1 once triggered */
    s8 unlockCountdown; /* 1 at init; gamebit + spawn at 0 */
    u8 pad0A[2];
} Dll1CEState;

STATIC_ASSERT(offsetof(Dll1CEState, openProgress) == 0x0);
STATIC_ASSERT(offsetof(Dll1CEState, openVelocity) == 0x4);
STATIC_ASSERT(offsetof(Dll1CEState, opened) == 0x8);
STATIC_ASSERT(offsetof(Dll1CEState, unlockCountdown) == 0x9);
STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

#endif
