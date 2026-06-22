#ifndef MAIN_DLL_DLL197STATE_STRUCT_H_
#define MAIN_DLL_DLL197STATE_STRUCT_H_

#include "types.h"

typedef struct Dll197State
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    s16 scrollPos; /* 0x8: clamped to [1, 0x46], &0xff fed to the title-menu interface */
    s16 scrollVel; /* 0xa: per-frame delta added to scrollPos (0 / -3) */
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 menuState; /* 0xf: menu phase selector (switch cases 4/7/8); also scrollPos = menuState*0x28 + 0x398 */
    u8 unk10;
    u8 pad11[0x18 - 0x11];
} Dll197State;

#endif
