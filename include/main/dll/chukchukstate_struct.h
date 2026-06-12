#ifndef MAIN_DLL_CHUKCHUKSTATE_STRUCT_H_
#define MAIN_DLL_CHUKCHUKSTATE_STRUCT_H_

#include "types.h"

typedef struct ChukChukState
{
    f32 glowPhase; /* texture glow ramp index; 10 primes an attack, resets to rand(16,245) */
    f32 steamTimer; /* counts down after destruction, scales the steam particle */
    s16 unk08; /* from params+0x22 */
    s16 gameBit; /* set on destruction; already-set disables on load */
    u16 triggerDistance; /* params[0x29] << 3 */
    u16 arcHalfAngle; /* (s8)params[0x28] * 182 -- facing wedge for the spit attack */
    u16 prevDistance; /* player planar distance last frame */
    u8 flags; /* 1 primed, 2 dead/disabled, 4 forced attack */
    u8 hitsLeft;
    u8 attackChance; /* percent, vs rand(0,99) */
    u8 aimHeightY; /* added to player Y when aiming the iceball */
    u8 pad16[2];
} ChukChukState;

#endif
