#ifndef MAIN_DLL_MMP_MMP_ASTEROID_RE_STATE_H_
#define MAIN_DLL_MMP_MMP_ASTEROID_RE_STATE_H_

#include "global.h"

typedef struct MmpAsteroidReState {
    u8 eventFlags; /* 1/8/0x10/0x20 fx bursts, 0x40 periodic fx, 0x80 seq-ran latch */
    u8 phase; /* gamebit 0x87B value 0..3 */
    u8 intensity; /* gamebit 0x88C / 0xD52; scales rise height + sfx volume */
    u8 pad03;
    f32 stateTimer; /* counts down; clears gamebit 0x88B on expiry */
    f32 periodicFxTimer; /* rand(10,60); flag 0x40 fx cadence */
    f32 baseY; /* obj Y at init */
    f32 baseY2;
    u16 bobPhase; /* angle accumulators for the float wobble */
    u16 rollPhase;
    u16 pitchPhase;
    u8 pad1A[2];
} MmpAsteroidReState;

#endif
