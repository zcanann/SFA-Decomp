#ifndef MAIN_DLL_SIDEKICKBALL_STATE_H_
#define MAIN_DLL_SIDEKICKBALL_STATE_H_

#include "global.h"

/* sidekickball extra block (size 0x2CC = sidekickball_getExtraSize).
 * Converged from the two src-side censuses (sidekickball.c update/hit
 * handlers + autoTransporter.c's fn_80179xxx ball helpers - same family,
 * adjacent v1.0 address range, zero width conflicts; the shared fields
 * 0x26C f32 / 0x274 u8 agree exactly). */
typedef struct SidekickBallState {
    u8 unk000[0x25B];
    u8 hittableLatch; /* 1 while thrown/hittable, 0 when idle (mirrors ObjHits enable/disable) */
    u8 pad25C[0x26C - 0x25C];
    f32 fadeTimer; /* 0x26C */
    u8 pad270[4];
    u8 ballMode; /* 0x274: 0 idle, 1/2 active, 3 thrown */
    u8 onPathPoint; /* 0x275 */
    u8 pad276[0x298 - 0x276];
    f32 unk298;
    u8 pad29C[0x2B0 - 0x29C];
    f32 launchX; /* 0x2B0: obj position at throw */
    f32 launchY;
    f32 launchZ;
    u8 pad2BC[0x2C8 - 0x2BC];
    u8 triggerArmed; /* 0x2C8 */
    u8 triggerHit;   /* 0x2C9 */
    u8 pad2CA[2];
} SidekickBallState;

STATIC_ASSERT(offsetof(SidekickBallState, fadeTimer) == 0x26C);
STATIC_ASSERT(offsetof(SidekickBallState, ballMode) == 0x274);
STATIC_ASSERT(offsetof(SidekickBallState, launchX) == 0x2B0);
STATIC_ASSERT(offsetof(SidekickBallState, triggerArmed) == 0x2C8);
STATIC_ASSERT(sizeof(SidekickBallState) == 0x2CC);

#endif /* MAIN_DLL_SIDEKICKBALL_STATE_H_ */
