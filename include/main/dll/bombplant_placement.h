#ifndef MAIN_DLL_BOMBPLANT_PLACEMENT_H_
#define MAIN_DLL_BOMBPLANT_PLACEMENT_H_

#include "global.h"

typedef struct BombplantPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 growTimer;
    s16 unk1A;
    s16 unk1C;
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} BombplantPlacement;

#endif
