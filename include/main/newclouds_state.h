#ifndef MAIN_NEWCLOUDS_STATE_H_
#define MAIN_NEWCLOUDS_STATE_H_

#include "global.h"

/*
 * NewCloud - per-cloud working record (lbl_8039A828[i] / the NC_CLOUD and
 * D7_CLOUD macros in newclouds.c). Only the 0x1378+ region referenced at
 * constant offsets in newclouds.c is mapped; the head is untyped.
 */
typedef struct NewCloud {
    u8 unk0000[0x1378];
    f32 unk1378;
    u8 unk137C[0x4];
    f32 unk1380;
    u8 unk1384[0x4];
    f32 unk1388;
    u8 unk138C[0x4];
    f32 unk1390;
    u8 unk1394[0x8];
    f32 unk139C;
    u8 unk13A0[0x10];
    f32 unk13B0;
    u8 unk13B4[0x24];
    f32 unk13D8;
    f32 unk13DC;
    f32 unk13E0;
    f32 unk13E4;
    f32 unk13E8;
    f32 unk13EC;
    s32 unk13F0;
    s32 unk13F4;
    s32 unk13F8;
    s32 count13FC;
    s32 unk1400;
    u8 unk1404[0x8];
    f32 unk140C;
    f32 unk1410;
    f32 unk1414;
    f32 unk1418;
    f32 unk141C;
    f32 speed1420;
    f32 speed1424;
    f32 unk1428;
    f32 unk142C;
    f32 unk1430;
    f32 unk1434;
    f32 unk1438;
    f32 unk143C;
    f32 unk1440;
    f32 unk1444;
    s16 unk1448;
} NewCloud;

STATIC_ASSERT(offsetof(NewCloud, unk1378) == 0x1378);
STATIC_ASSERT(offsetof(NewCloud, unk13F4) == 0x13F4);
STATIC_ASSERT(offsetof(NewCloud, unk1448) == 0x1448);

#endif
