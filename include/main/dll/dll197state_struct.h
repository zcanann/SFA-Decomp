#ifndef MAIN_DLL_DLL197STATE_STRUCT_H_
#define MAIN_DLL_DLL197STATE_STRUCT_H_

#include "types.h"

typedef struct Dll197State
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    s16 unk8;
    s16 unkA;
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 unkF;
    u8 unk10;
    u8 pad11[0x18 - 0x11];
} Dll197State;

#endif
