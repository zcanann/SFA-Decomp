#ifndef MAIN_NEWCLOUDS_STATE_H_
#define MAIN_NEWCLOUDS_STATE_H_

#include "global.h"

/*
 * NewCloud - per-cloud working record (gNewClouds[i] / the NC_CLOUD and
 * D7_CLOUD macros in newclouds.c). Only the 0x1378+ region referenced at
 * constant offsets in newclouds.c is mapped; the head is untyped.
 */
/*
 * SnowQuad - per-quad geometry record in the NewCloud body at offset
 * 0x1008 (20 entries, 0x2C bytes each). verts[] is a 3x3 matrix of
 * the quad's local-space corner coordinates.
 */
typedef struct SnowQuad {
    f32 verts[9];
    u16 angVelA;
    u16 angVelB;
    u16 angA;
    u16 angB;
} SnowQuad;

STATIC_ASSERT(sizeof(SnowQuad) == 0x2C);

/*
 * SnowFlake - per-flake state for the heap buffer pointed to by
 * *(void**)(NewCloud + 4) (the NC_PARTS macro). flakeCount entries,
 * 0x18 bytes each.
 */
typedef struct SnowFlake {
    f32 x;
    f32 y;
    f32 z;
    f32 fallSpeed;
    u16 angle;
    u16 unk12;
    s8 size;
    s8 spin;
    u8 unk16;
    u8 unk17;
} SnowFlake;

STATIC_ASSERT(sizeof(SnowFlake) == 0x18);

typedef struct NewCloud {
    u8 unk0000[0x1378];
    f32 flakeMinX;
    u8 unk137C[0x4];
    f32 flakeMinZ;
    u8 unk1384[0x4];
    f32 unk1388;
    u8 unk138C[0x4];
    f32 driftSpeed;
    u8 unk1394[0x8];
    f32 flakeMaxX;
    u8 unk13A0[0x10];
    f32 flakeMaxZ;
    u8 unk13B4[0x24];
    f32 lastPosX;
    f32 lastPosY;
    f32 lastPosZ;
    f32 curPosX;
    f32 curPosY;
    f32 curPosZ;
    s32 cloudId;
    s32 cloudType;
    s32 despawning;
    s32 flakeCount;
    s32 active;
    u8 unk1404[0x8];
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 cloudHeight;
    f32 scale;
    f32 windVelX;
    f32 windVelZ;
    f32 unk1428;
    f32 flakeFillRate;
    f32 flakeDrainRate;
    f32 activeFlakes;
    f32 driftScale;
    f32 driftLimit;
    f32 driftOffset;
    f32 driftRate;
    s16 lightningTimer;
    u8 unk144A;
    u8 unk144B;
    u8 unk144C;
    u8 unk144D;
    u8 unk144E;
    u8 unk144F;
    u8 unk1450;
    u8 unk1451;
    u8 unk1452;
    u8 unk1453;
} NewCloud;

STATIC_ASSERT(offsetof(NewCloud, flakeMinX) == 0x1378);
STATIC_ASSERT(offsetof(NewCloud, cloudType) == 0x13F4);
STATIC_ASSERT(offsetof(NewCloud, lightningTimer) == 0x1448);
STATIC_ASSERT(offsetof(NewCloud, unk144A) == 0x144A);
STATIC_ASSERT(offsetof(NewCloud, unk1453) == 0x1453);
STATIC_ASSERT(sizeof(NewCloud) == 0x1454);

#endif
