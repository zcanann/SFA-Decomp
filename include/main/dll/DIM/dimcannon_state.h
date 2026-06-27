#ifndef MAIN_DLL_DIM_DIMCANNON_STATE_H_
#define MAIN_DLL_DIM_DIMCANNON_STATE_H_

#include "global.h"

typedef struct DimCannonState {
    void* targetPlayer; /* 0x00 player object (cleared when player not eligible) */
    s32 aimTargetX; /* 0x04 shard-aim target X (f32 via cast), passed to DIMwooddoor_updateShardAim */
    s32 aimTargetY; /* 0x08 shard-aim target Y (f32 via cast), max posY across cannonball columns */
    f32 aimTargetZ; /* 0x0C shard-aim target Z */
    f32 distance;   /* 0x10 XZ distance to player (getXZDistance) */
    /* 0x14/0x3c/0x64: trailing aim-history rings of 10 samples each, shifted
     * toward index 0 every refresh; index 9 is the freshest player snapshot. */
    f32 aimHistX[10]; /* 0x14 */
    f32 aimHistY[10]; /* 0x3c */
    f32 aimHistZ[10]; /* 0x64 (aimHistZ[9] @0x88 = fresh player Z) */
    f32 posX;       /* 0x8C snapshot of anim.localPosX */
    f32 posY;       /* 0x90 snapshot of anim.localPosY */
    f32 posZ;       /* 0x94 snapshot of anim.localPosZ */
    f32 unk98;
    u8 pad9C[8];
    s16 aimYaw;     /* 0xa4 */
    s16 aimPitch;   /* 0xa6 */
    int prevAimDelta; /* 0xa8 previous-frame stick aim delta (drives aim-stop sfx) */
    u8 fireState;   /* 0xac */
    u8 fireRequested; /* 0xad set when fired (magic spent) */
    u8 airMeterCharge; /* 0xae accumulated charge, clamped to gDimCannonMaxCharge, drives runAirMeter */
    u8 refreshTimer; /* 0xaf frames since last shard-aim source re-snapshot (>0xa resnaps) */
    s8 chargeTimer; /* 0xB0: countdown (framesThisStep) gating air-meter/fire */
    u8 shutdownTimer; /* 0xb1 counts up once activated; >0x3c triggers shutdown */
    u8 hasActivated; /* 0xb2 one-shot flag once player-operated + game bits set */
    u8 padB3;
} DimCannonState;

#endif
