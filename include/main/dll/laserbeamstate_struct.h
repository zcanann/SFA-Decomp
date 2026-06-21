#ifndef MAIN_DLL_LASERBEAMSTATE_STRUCT_H_
#define MAIN_DLL_LASERBEAMSTATE_STRUCT_H_

#include "types.h"

typedef struct LaserBeamState
{
    int texture;
    f32 unk04; /* 0x04: cur/prev pair A (reset each update) */
    f32 unk08;

    f32 beamX; /* 0x0c: beam base position */
    f32 beamX2; /* 0x10 */
    f32 beamZ; /* 0x14 */
    f32 beamZ2; /* 0x18 */
    f32 sweepPhase; /* 0x1c */
    u8 pad20[4];
    u8 beamState; /* 0x24: 0/1/2 active beam state (2 = firing) */
    u8 sweepDone; /* 0x25: set when sweepYaw reaches its limit */
    u8 rangeOffset; /* 0x26: signed range bias added to fire range */
    s8 fireCooldown; /* 0x27: countdown gating fire (framesThisStep) */
    s16 unk28;
    s16 sweepYaw; /* 0x2a */
    s16 fireTimer; /* 0x2c */
    s16 unk2E;
    s16 firePeriod; /* 0x30 */
    s16 emitterSlot; /* 0x32: modgfx handle head */
    u8 pad34[0xc];
    f32 targetX; /* 0x40 */
    u8 pad44[4];
    f32 targetZ; /* 0x48 */
    u8 unk4C;
    u8 active; /* 0x4d */
    u8 beamKind; /* 0x4e: 30/1/other texture pick */
} LaserBeamState;

#endif
