#ifndef MAIN_DLL_SC_TYPES_H_
#define MAIN_DLL_SC_TYPES_H_

#include "types.h"

typedef struct ScLevelControlState
{
    f32 fogNear; /* 0x00: enableHeavyFog base */
    f32 fog04; /* 0x04 */
    f32 fog08; /* 0x08 */
    f32 fog0C; /* 0x0c */
    f32 timer10; /* 0x10 */
    f32 fadeTimer; /* 0x14 */
    u8 pad18[4];
    u8 musicStep; /* 0x1c: index into the lbl_803DC060 cue table */
    u8 mode; /* 0x1d: anim-event mode latch */
    u8 areaCell; /* 0x1e: 0xff until the player enters map 0xe */
    u8 flags1F; /* 0x1f */
    u8 musicTrack; /* 0x20 */
    s8 unk21; /* 0x21 */
    u8 flags22; /* 0x22: SnowFlags22 overlay (bit 7) */
    u8 pad23;
} ScLevelControlState;

typedef struct ScLevelcontrolProcessAnimEventsState
{
    u8 pad0[0x1D - 0x0];
    s8 unk1D;
    u8 pad1E[0x20 - 0x1E];
} ScLevelcontrolProcessAnimEventsState;

#endif
