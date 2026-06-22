#ifndef MAIN_NEWCLOUDS_STATE_H_
#define MAIN_NEWCLOUDS_STATE_H_

#include "global.h"

/*
 * NewCloud - per-cloud working record (gNewClouds[i] / the NC_CLOUD and
 * D7_CLOUD macros in newclouds.c). Only the 0x1378+ region referenced at
 * constant offsets in newclouds.c is mapped; the head is untyped.
 */
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
    s16 unk1448;
} NewCloud;

STATIC_ASSERT(offsetof(NewCloud, flakeMinX) == 0x1378);
STATIC_ASSERT(offsetof(NewCloud, cloudType) == 0x13F4);
STATIC_ASSERT(offsetof(NewCloud, unk1448) == 0x1448);

#endif
