#ifndef MAIN_DLL_LEVELNAMESTATE_STRUCT_H_
#define MAIN_DLL_LEVELNAMESTATE_STRUCT_H_

#include "types.h"

typedef struct LevelnameState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xE - 0xC];
    s16 unkE;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} LevelnameState;

#endif
