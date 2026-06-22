#ifndef MAIN_DLL_DLL199STATE_STRUCT_H_
#define MAIN_DLL_DLL199STATE_STRUCT_H_

#include "types.h"

typedef struct Dll199State
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    u8 pad4[0xE - 0x4];
    u8 unlockCount;
    u8 phase;
    u8 unk10;
    u8 pad11[0x12 - 0x11];
    u8 triggered; /* 0x12: one-shot latch for the timer-expiry menu action */
    u8 pad13[0x18 - 0x13];
} Dll199State;

#endif
