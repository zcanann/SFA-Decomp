#ifndef MAIN_DLL_DUSTERSTATE_TYPES_H_
#define MAIN_DLL_DUSTERSTATE_TYPES_H_

#include "types.h"

typedef struct DusterStateFlags
{
    u8 floorCached : 1;
    u8 pad : 7;
} DusterStateFlags;

typedef struct DusterState
{
    f32 moveStepScale;
    f32 floorY;
    s16 settleTimer;
    s16 hitReactTimer;
    s16 completeGameBit;
    s16 activeGameBit;
    s16 heldObjectId;
    u8 pad12[6];
    u8 driftDir;
    u8 hitReactActive;
    u8 priorityHit;
    u8 active;
    u8 complete;
    u8 useLaunchVelocity;
    DusterStateFlags flags;
    u8 pad1F;
} DusterState;

#endif
