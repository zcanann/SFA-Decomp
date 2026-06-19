#ifndef MAIN_DLL_CRROCKFALL_TYPES_H_
#define MAIN_DLL_CRROCKFALL_TYPES_H_

#include "types.h"

typedef struct CrRockfallCfgEntry
{
    f32 unk00;
    s32 landSfx; /* 0 = none */
    f32 restOffsetY; /* scaled by obj scale, added to floorY at rest */
} CrRockfallCfgEntry;

typedef struct CrRockfallState
{
    CrRockfallCfgEntry* cfg; /* gRockfallCfgTable entry 0, or entry 1 for type 0x600 */
    f32 floorY; /* probed landing height */
    f32 startY; /* obj Y at init; fade fraction reference */
    u8 mode; /* 0 armed, 1 falling, 2 resting, 3 shattered */
    u8 fallStarted;
    u8 floorFound;
    u8 pad0F;
    s16 fallDelay; /* params+0x1E; counts down while the player is in range */
    u8 pad12[2];
} CrRockfallState;

#endif
