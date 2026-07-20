#ifndef MAIN_DLL_SWARMBADDIESTATE_STRUCT_H_
#define MAIN_DLL_SWARMBADDIESTATE_STRUCT_H_

#include "types.h"
#include "main/dll/curve_walker.h"

typedef struct GameObject GameObject;

typedef struct SwarmBaddieState
{
    RomCurveWalker* curve;
    GameObject* player;
    f32 curveStep;
    f32 playerDistance;
    f32 pathDistance;
    f32 chaseRadius;
    f32 hitVolumeEnvelope;
    u8 flags;
    u8 pad1d;
    s16 yawWavePhase;
    s16 rollWavePhase;
    u8 pad22[2];
} SwarmBaddieState;

STATIC_ASSERT(sizeof(SwarmBaddieState) == 0x24);
STATIC_ASSERT(offsetof(SwarmBaddieState, curve) == 0x0);
STATIC_ASSERT(offsetof(SwarmBaddieState, player) == 0x4);
STATIC_ASSERT(offsetof(SwarmBaddieState, curveStep) == 0x8);
STATIC_ASSERT(offsetof(SwarmBaddieState, chaseRadius) == 0x14);
STATIC_ASSERT(offsetof(SwarmBaddieState, hitVolumeEnvelope) == 0x18);
STATIC_ASSERT(offsetof(SwarmBaddieState, flags) == 0x1C);
STATIC_ASSERT(offsetof(SwarmBaddieState, yawWavePhase) == 0x1E);
STATIC_ASSERT(offsetof(SwarmBaddieState, rollWavePhase) == 0x20);

#endif
