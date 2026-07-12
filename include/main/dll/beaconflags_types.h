#ifndef MAIN_DLL_BEACONFLAGS_TYPES_H_
#define MAIN_DLL_BEACONFLAGS_TYPES_H_

#include "main/game_object.h"

typedef struct
{
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

typedef struct ShBeaconState
{
    GameObject* childObj; /* 0x00: spawned 0x55 flame object */
    f32 seqTimer; /* 0x04 */
    f32 fadeTimer; /* 0x08 */
    f32 burstTimer; /* 0x0c */
    f32 modeTimer; /* 0x10 */
    u8 mode; /* 0x14: 0 unlit, 1 lit, 2 igniting */
    u8 flags15; /* 0x15: bit 7 = looping sfx active (BeaconFlags) */
    u8 pad16[2];
} ShBeaconState;

#endif
