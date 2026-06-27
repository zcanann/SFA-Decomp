#ifndef MAIN_DLL_EXPLOSION_STATE_H_
#define MAIN_DLL_EXPLOSION_STATE_H_

#include "global.h"

/* Gravity debris record: a launched chunk integrated under driftYSpeed gravity,
 * spawns a particle fx each odd tick, deactivated once age >= lifetime. */
typedef struct GravityDebris {
    f32 posX;     /* 0x00 */
    f32 posY;     /* 0x04 */
    f32 posZ;     /* 0x08 */
    f32 velX;     /* 0x0C */
    f32 velY;     /* 0x10 */
    f32 velZ;     /* 0x14 */
    s32 age;      /* 0x18: += framesThisStep */
    s32 lifetime; /* 0x1C: deactivate at age >= lifetime */
    u8 active;    /* 0x20: nonzero while live */
    u8 pad21[3];
} GravityDebris;

typedef struct ExplosionState {
    u8 flames[0x960];
    f32 groundY;
    GravityDebris debris[6];
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
