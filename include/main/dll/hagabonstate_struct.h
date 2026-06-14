#ifndef MAIN_DLL_HAGABONSTATE_STRUCT_H_
#define MAIN_DLL_HAGABONSTATE_STRUCT_H_

#include "types.h"

typedef struct GameObject GameObject;

typedef struct HagabonState
{
    int curve;
    GameObject* player;
    f32 curveStep;
    f32 animSpeed;
    f32 playerDistance;
    f32 pathDistance;
    f32 chaseRadius;
    u8 pad1C[4];
    u16 wavePhaseA; /* yaw wave */
    u16 wavePhaseB; /* shared bob wave */
    u16 wavePhaseC; /* pitch wave */
    u8 flags;
    u8 pad27;
} HagabonState;

#endif
