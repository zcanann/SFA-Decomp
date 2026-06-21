#ifndef MAIN_DLL_EXPLOSION_STATE_H_
#define MAIN_DLL_EXPLOSION_STATE_H_

#include "global.h"

typedef struct ExplosionState {
    u8 flames[0x960];
    f32 groundY;
    u8 debris[0xD8];
    f32 driftYSpeed; /* upward drift while flag 4 variant */
    int light; /* objCreateLight handle or 0 */
    s16 rayYawA; /* light-ray pair angles */
    s16 rayPitchA;
    s16 rayYawB;
    s16 rayPitchB;
    int frameCounter;
    int lifeFrames; /* scale-derived, clamped 0..60 */
    f32 scale;
    u8 flameCount;
    u8 rayMode; /* 0 none, 1 grounded pair, 2 random pair */
    u8 debrisCount;
    u8 halfLifeFired;
    u8 nearGround; /* spawned close to the probed floor */
    u8 modelKind; /* params & 3, active model index */
    u8 padA5E[2];
} ExplosionState;

#endif
