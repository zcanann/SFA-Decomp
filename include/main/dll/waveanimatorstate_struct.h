#ifndef MAIN_DLL_WAVEANIMATORSTATE_STRUCT_H_
#define MAIN_DLL_WAVEANIMATORSTATE_STRUCT_H_

#include "types.h"

typedef struct WaveAnimatorState
{
    int originX; /* 0x00 */
    int originY; /* 0x04 */
    int spanX; /* 0x08 */
    int spanY; /* 0x0c */
    f32 ampX; /* 0x10 */
    f32 ampY; /* 0x14 */
    int sinkDepthScale; /* 0x18 */
    int period; /* 0x1c */
    int gridN; /* 0x20 */
    f32 minHeight; /* 0x24 */
    f32 maxHeight; /* 0x28 */
    f32 scaleA; /* 0x2c */
    f32 scaleB; /* 0x30 */
    u8 flags; /* 0x34: 1 = scale pending, 2 = func0B latch */
    u8 pad35[7];
} WaveAnimatorState;

#endif
