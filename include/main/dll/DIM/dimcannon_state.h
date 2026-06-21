#ifndef MAIN_DLL_DIM_DIMCANNON_STATE_H_
#define MAIN_DLL_DIM_DIMCANNON_STATE_H_

#include "global.h"

typedef struct DimCannonState {
    u8 pad0[0x4 - 0x0];
    s32 aimTargetX; /* 0x04 shard-aim target X (f32 via cast), passed to DIMwooddoor_updateShardAim */
    s32 aimTargetY; /* 0x08 shard-aim target Y (f32 via cast), max posY across cannonball columns */
    f32 aimTargetZ; /* 0x0C shard-aim target Z */
    f32 distance;   /* 0x10 XZ distance to player (getXZDistance) */
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 unk1B;
    u8 pad1C[0x88 - 0x1C];
    f32 unk88;
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
