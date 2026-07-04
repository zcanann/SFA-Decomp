#ifndef MAIN_DLL_DLL22CSTATE_STRUCT_H_
#define MAIN_DLL_DLL22CSTATE_STRUCT_H_

#include "types.h"

typedef struct Dll22CState
{
    f32 raiseHeight; /* def+0x1A */
    s16 mode; /* 0x04 */
    s16 gameBit; /* 0x06: def+0x20 */
    s16 gameBit2; /* 0x08: def+0x1E */
    s16 pauseTimer; /* 0x0A: 100 between moves */
    u8 raiseMode; /* def+0x1C: ==1 raise on proximity alone (skip gameBit gate) */
    u8 sfxLatch; /* 0x0D */
    u8 unk0E[2];
} Dll22CState;

#endif
