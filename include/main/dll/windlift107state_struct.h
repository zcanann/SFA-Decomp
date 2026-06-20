#ifndef MAIN_DLL_WINDLIFT107STATE_STRUCT_H_
#define MAIN_DLL_WINDLIFT107STATE_STRUCT_H_

#include "types.h"

typedef struct WindLift107State
{
    int holdTimer; /* 0x00: countdown while the vent is plugged */
    int holdReload; /* 0x04 */
    f32 radius; /* 0x08 */
    s16 yawLow; /* 0x0c */
    s16 yawHigh; /* 0x0e */
    s16 ventState; /* 0x10 */
    s16 maxDist; /* 0x12 */
    s16 unk14; /* 0x14 */
    s16 timer; /* 0x16 */
    s16 unk18; /* 0x18 */
    s16 liftTimer; /* 0x1a */
    u8 pad1C[2];
    s16 spitTimer; /* 0x1e */
    u8 pad20;
    u8 rideState; /* 0x21 */
    u8 riding; /* 0x22 */
    u8 launchPhase; /* 0x23 */
    u8 pad24;
    u8 unk25; /* 0x25 */
    u8 glowPulse; /* 0x26 */
    u8 unk27; /* 0x27 */
    u8 pad28[4];
} WindLift107State;

#endif
