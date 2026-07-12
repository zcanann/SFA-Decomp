#ifndef MAIN_DLL_LEVELNAMESTATE_STRUCT_H_
#define MAIN_DLL_LEVELNAMESTATE_STRUCT_H_

#include "types.h"

typedef struct LevelnameState
{
    u8 pad0[0x8 - 0x0];
    s32 holdDuration;
    u8 triggerRadius;
    u8 unk0D;
    s16 gameBit;
    s16 holdTimer;
    s16 bannerY;
    u8 phase;
    u8 pad15[0x18 - 0x15];
} LevelnameState;

#endif
