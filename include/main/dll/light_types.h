#ifndef MAIN_DLL_LIGHT_TYPES_H_
#define MAIN_DLL_LIGHT_TYPES_H_

#include "types.h"

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

typedef struct LightSourceState
{
    void* light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit; /* 0x10: -1 none */
    u8 mode; /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit; /* 0x17 */
    u8 litPrev;
    u8 sparks; /* 0x19 */
    u8 loopFlags; /* 0x1a: LightSourceFlagByte */
    u8 pad1B;
} LightSourceState;

#endif
