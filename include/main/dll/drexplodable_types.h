#ifndef MAIN_DLL_DREXPLODABLE_TYPES_H_
#define MAIN_DLL_DREXPLODABLE_TYPES_H_

#include "types.h"

typedef struct DrExplodableChunk
{
    u8 pad00[4];
    f32 centroidX; /* 0x04: model vertex average */
    f32 centroidY; /* 0x08 */
    f32 centroidZ; /* 0x0c */
    f32 offX; /* 0x10: rotated launch offset */
    f32 offY; /* 0x14 */
    f32 offZ; /* 0x18 */
    f32 spinX; /* 0x1c */
    f32 spinY; /* 0x20 */
    f32 spinZ; /* 0x24 */
    f32 spin2X; /* 0x28: secondary random spin triplet -> fragment setup spin2X/Y/Z */
    f32 spin2Y; /* 0x2c */
    f32 spin2Z; /* 0x30 */
    f32 vel2X; /* 0x34: secondary launch velocity (dx*scale) -> fragment setup vel2X/Y/Z */
    f32 vel2Y; /* 0x38: dy*scale - gravity bias */
    f32 vel2Z; /* 0x3c: dz*scale */
    f32 velX; /* 0x40 */
    f32 velY; /* 0x44 */
    f32 velZ; /* 0x48 */
    f32 posX; /* 0x4c */
    f32 posY; /* 0x50 */
    f32 posZ; /* 0x54 */
    f32 height;
    int launchDelayBase; /* 0x5c: raw def launch-delay base, forwarded to the spawned fragment */
    int launchDelay; /* 0x60: per-fragment delay roll, -1 = none */
    s16 rotZ; /* 0x64: fragment spawn rotation, from def+0x1e */
    s16 rotY; /* 0x66: from def+0x1c */
    s16 rotX; /* 0x68: from def+0x1a */
    u8 gameBitMode; /* 0x6a: gamebit-gated mode */
    u8 unk6B; /* 0x6b: init 0xff */
    u8 launchFlags; /* 0x6c: axis sign bits */
    u8 spinScale; /* 0x6d */
    u8 pad6E[2];
} DrExplodableChunk;

typedef struct DrExplodableState
{
    DrExplodableChunk chunks[15]; /* 0x000 */
    int children[15]; /* 0x690: spawned fragment objects */
    u32 flags6CC;
    int breakSfx;
    u8 count6D4;
    u8 spawnedFlags[15]; /* 0x6d5 */
    u8 phase6E4;
    u8 recipeIndex;
    u8 pad6E6[2];
} DrExplodableState;

#endif
