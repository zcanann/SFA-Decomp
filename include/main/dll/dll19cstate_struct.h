#ifndef MAIN_DLL_DLL19CSTATE_STRUCT_H_
#define MAIN_DLL_DLL19CSTATE_STRUCT_H_

#include "types.h"

typedef struct Dll19CState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    s16 unk6;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    u16 unk34;
    u8 unk36;
    u8 pad37[0x38 - 0x37];
} Dll19CState;

#endif
