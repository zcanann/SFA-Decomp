#ifndef MAIN_DLL_SH_TYPES_H_
#define MAIN_DLL_SH_TYPES_H_

#include "types.h"

typedef struct ShBeaconState
{
    int childObj; /* 0x00: spawned 0x55 flame object */
    f32 seqTimer; /* 0x04 */
    f32 fadeTimer; /* 0x08 */
    f32 burstTimer; /* 0x0c */
    f32 modeTimer; /* 0x10 */
    u8 mode; /* 0x14: 0 unlit, 1 lit, 2 igniting */
    u8 flags15; /* 0x15: bit 7 = looping sfx active (BeaconFlags) */
    u8 pad16[2];
} ShBeaconState;

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} ShWGPipe;

#endif
