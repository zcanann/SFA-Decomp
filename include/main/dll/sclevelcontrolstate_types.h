#ifndef MAIN_DLL_SCLEVELCONTROLSTATE_TYPES_H_
#define MAIN_DLL_SCLEVELCONTROLSTATE_TYPES_H_

#include "types.h"

typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} SnowFlags22;

typedef struct ScLevelControlState
{
    f32 fogNear; /* 0x00: enableHeavyFog base */
    f32 fog04; /* 0x04 */
    f32 fog08; /* 0x08 */
    f32 fog0C; /* 0x0c */
    f32 timer10; /* 0x10 */
    f32 fadeTimer; /* 0x14 */
    u8 gameBitLatches[4]; /* 0x18: persistent latch state for the SCGameBitLatch_Update calls in update */
    u8 musicStep; /* 0x1c: index into the gScLevelControlMusicStepSequence cue table */
    u8 mode; /* 0x1d: anim-event mode latch */
    u8 areaCell; /* 0x1e: 0xff until the player enters map 0xe */
    u8 flags1F; /* 0x1f */
    u8 musicTrack; /* 0x20 */
    s8 ambientMusicTrack; /* 0x21: day/night ambient cue (0x22) latch gating Music_Trigger; -1 = off */
    u8 flags22; /* 0x22: SnowFlags22 overlay (bit 7) */
    u8 pad23;
} ScLevelControlState;

#endif
