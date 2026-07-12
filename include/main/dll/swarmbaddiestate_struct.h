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

#endif
