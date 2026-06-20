#ifndef MAIN_DLL_EXPLOSIONDEBRIS_STRUCT_H_
#define MAIN_DLL_EXPLOSIONDEBRIS_STRUCT_H_

#include "types.h"

typedef struct ExplosionDebris
{
    f32 posX;  /* 0x00 */
    f32 posY;  /* 0x04 */
    f32 posZ;  /* 0x08 */
    f32 scale; /* 0x0C */
    s32 unk10;
    s32 unk14;
    f32 unk18;
    f32 unk1C;
    s32 spawnTimer;    /* 0x20: counts down by framesThisStep; spawns a sub-flame at <= 0 */
    s32 spawnInterval; /* 0x24: reload value copied into spawnTimer after each spawn */
    s16 unk28;
    u16 unk2A;
    u8 unk2C;
    u8 unk2D;
    u8 unk2E;
    u8 unk2F;
} ExplosionDebris;

#endif
