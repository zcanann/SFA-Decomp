#ifndef MAIN_DLL_DLL1CESTATE_STRUCT_H_
#define MAIN_DLL_DLL1CESTATE_STRUCT_H_

#include "types.h"

typedef struct Dll1CEState
{
    f32 openProgress; /* clamped lid coast */
    f32 openVelocity;
    u8 opened; /* 1 once triggered */
    u8 igniteCountdown; /* 1 at init; gamebit + spawn at 0 */
    u8 pad0A[2];
} Dll1CEState;

#endif
