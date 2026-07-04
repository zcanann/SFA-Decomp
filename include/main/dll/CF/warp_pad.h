#ifndef MAIN_DLL_CF_WARP_PAD_H_
#define MAIN_DLL_CF_WARP_PAD_H_

#include "global.h"

typedef struct WarpPadPlacement {
    u8 pad00[0x14];
    s32 destinationId;
    u8 rotXHigh;
    u8 pad19;
    s8 warpId;
    u8 pad1B[0x20 - 0x1B];
    s16 enableGameBit;
} WarpPadPlacement;

/*
 * Per-object extra state for the warp-pad transporter
 * (transporter_getExtraSize == 0x10; helpers shared by the
 * CFwalltorch/mmp_asteroid transporter updates).
 */
typedef struct WarpPadState {
    f32 pulseTimer; /* counts up while flag 4; periodic idle fx */
    f32 cooldownTimer; /* counts down; on expiry unk0A is reset to -1 */
    s16 activateDelay; /* frames loaded into obj+0xF4 when triggered */
    s16 unk0A;
    u8 countdownActive;
    u8 triggerMode; /* 0 = proximity warp, 1 = trigger/gamebit warp */
    u8 flags; /* 0x20 disabled/non-interactive (gamebit gate; hitDetect &0x20),
                 0x40/0x10/0x8 warp fx class (A/C/B), 4 pulse fx active, 2 pulse latch,
                 1 runtime interactive bit (set per-frame in hitDetect). 0x80 is set/cleared
                 from the enableGameBit in warpPadPlayerStandingOn but only selects a burst
                 particle variant (the 0xa0 test) - it does NOT disable the pad. */
    u8 pad0F;
} WarpPadState;

/* WarpPadState.flags bits (shared by warppad.c and transporter.c) */
#define WARPPAD_FLAG_INTERACTIVE 0x01     /* runtime interactive bit (set per-frame in hitDetect) */
#define WARPPAD_FLAG_LATCH 0x02           /* pulse latch */
#define WARPPAD_FLAG_PULSE_FX 0x04        /* pulse fx active */
#define WARPPAD_FLAG_WARP_B 0x08          /* warp fx class B */
#define WARPPAD_FLAG_WARP_C 0x10          /* warp fx class C */
#define WARPPAD_FLAG_DISABLED 0x20        /* disabled/non-interactive (gamebit gate) */
#define WARPPAD_FLAG_WARP_A 0x40          /* warp fx class A */
#define WARPPAD_FLAG_GAMEBIT_DISABLED 0x80 /* burst particle variant selector (0xa0 test) */

STATIC_ASSERT(sizeof(WarpPadState) == 0x10);
STATIC_ASSERT(offsetof(WarpPadPlacement, destinationId) == 0x14);
STATIC_ASSERT(offsetof(WarpPadPlacement, rotXHigh) == 0x18);
STATIC_ASSERT(offsetof(WarpPadPlacement, warpId) == 0x1A);
STATIC_ASSERT(offsetof(WarpPadPlacement, enableGameBit) == 0x20);
STATIC_ASSERT(offsetof(WarpPadState, activateDelay) == 0x08);
STATIC_ASSERT(offsetof(WarpPadState, countdownActive) == 0x0C);
STATIC_ASSERT(offsetof(WarpPadState, triggerMode) == 0x0D);
STATIC_ASSERT(offsetof(WarpPadState, flags) == 0x0E);

#endif /* MAIN_DLL_CF_WARP_PAD_H_ */
