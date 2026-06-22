#ifndef MAIN_DLL_EXPLOSIONDEBRIS_STRUCT_H_
#define MAIN_DLL_EXPLOSIONDEBRIS_STRUCT_H_

#include "types.h"

typedef struct ExplosionDebris
{
    f32 posX;  /* 0x00 */
    f32 posY;  /* 0x04 */
    f32 posZ;  /* 0x08 */
    f32 scale; /* 0x0C */
    s32 age;      /* 0x10: elapsed frames, += framesThisStep; deactivates at >= lifetime */
    s32 lifetime; /* 0x14: total lifetime; age/lifetime drives fade + scale */
    f32 baseScale; /* 0x18: scale floor the animated scale converges toward */
    f32 speed;     /* 0x1C: initial launch speed; drives the scale animation */
    s32 spawnTimer;    /* 0x20: counts down by framesThisStep; spawns a sub-flame at <= 0 */
    s32 spawnInterval; /* 0x24: reload value copied into spawnTimer after each spawn */
    s16 spinAngle; /* 0x28: rotation accumulator fed to PSMTXRotRad */
    s16 spinSpeed; /* 0x2A: per-frame rotation increment (signed; can be negated) */
    u8 texVariant; /* 0x2C: texture-chain index (random 0-3 at spawn, wraps mod 4); selects which texture in the linked-list chain is drawn */
    u8 generation; /* 0x2D: spawn recursion depth (gen 0 = root; sub-flames stop at >= 5) */
    u8 alpha;      /* 0x2E: render alpha byte */
    u8 active;     /* 0x2F: nonzero while this debris slot is live */
} ExplosionDebris;

#endif
