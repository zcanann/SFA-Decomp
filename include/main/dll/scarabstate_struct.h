#ifndef MAIN_DLL_SCARABSTATE_STRUCT_H_
#define MAIN_DLL_SCARABSTATE_STRUCT_H_

#include "types.h"

typedef struct ScarabState
{
    f32 velX; /* 0x00 */
    f32 velZ; /* 0x04 */
    f32 riseAmount; /* 0x08 */
    f32 baseY; /* 0x0c: def spawn height */
    s16 despawnTimer; /* 0x10 */
    u8 pad12[2];
    s16 mode; /* 0x14 */
    s16 yawSpeed; /* 0x16 */
    s16 spawnYaw; /* 0x18 */
    s16 fleeTimer; /* 0x1a */
    s16 riseLimit; /* 0x1c */
    s16 pickupSfx; /* 0x1e */
    s16 particleId; /* 0x20 */
    s16 burstModel; /* 0x22: model index for objfx_spawnDirectionalBurst */
    u8 phase; /* 0x24 */
    u8 pad25[2];
    u8 moneyKind; /* 0x27 */
    u8 flags28; /* 0x28: 1 = collected, waiting on the money message */
    u8 pad29[3];
    s16 msgParamA; /* 0x2c */
    s16 msgParamB; /* 0x2e */
    f32 msgParamC; /* 0x30 */
} ScarabState;

#endif
