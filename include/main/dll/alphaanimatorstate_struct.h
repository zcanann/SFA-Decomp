#ifndef MAIN_DLL_ALPHAANIMATORSTATE_STRUCT_H_
#define MAIN_DLL_ALPHAANIMATORSTATE_STRUCT_H_

#include "types.h"

typedef struct AlphaAnimatorState
{
    int vertCount; /* 0x00 */
    f32 fadeA; /* 0x04 */
    f32 fadeB; /* 0x08 */
    f32 fadeMax; /* 0x0c */
    void* buf; /* 0x10: mode-3 per-vertex alpha buffer */
    s16 alphaLevel; /* 0x14 */
    u8 active; /* 0x16 */
    s8 gateVal; /* 0x17 */
    u8 doneCount; /* 0x18 */
    u8 prevGate; /* 0x19 */
    u8 pad1A[2];
} AlphaAnimatorState;

#endif
