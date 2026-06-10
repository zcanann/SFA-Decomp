#ifndef MAIN_DLL_MMP_MMP_MOONROCK_STATE_H_
#define MAIN_DLL_MMP_MMP_MOONROCK_STATE_H_

#include "global.h"

typedef struct MmpMoonrockState {
    u8 carryable[0xC];
    f32 baseY; /* lava base height */
    f32 baseY2;
    f32 respawnTimer; /* counts down while flag 0x200 (sunk/reset) */
    f32 homeX; /* spawn position for the reset */
    f32 homeY;
    f32 homeZ;
    u16 flags; /* 1 drop, 2 armed, 4 held?, 8 grab-frame, 0x10/0x20 icon kind, 0x40 thrown, 0x200 respawning, 0x400 placed */
    u16 bobPhase; /* angle accumulators for the float wobble */
    u16 rollPhase;
    u16 pitchPhase;
    u8 pad2C[2];
    u8 kind; /* gamebit-derived 0..6 */
    u8 raised; /* gamebit 0x894 while placed */
} MmpMoonrockState;

#endif
