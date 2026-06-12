#ifndef MAIN_DLL_EXPLOSION_TYPES_H_
#define MAIN_DLL_EXPLOSION_TYPES_H_

#include "types.h"

typedef struct ExplosionPartfxSource
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* parent;
    u8 pad34[2];
    u8 alpha;
    u8 pad37;
} ExplosionPartfxSource;

typedef struct ExplosionDebris
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    s32 unk14;
    f32 unk18;
    f32 unk1C;
    s32 unk20;
    s32 unk24;
    u16 unk28;
    u16 unk2A;
    u8 unk2C;
    u8 unk2D;
    u8 unk2E;
    u8 unk2F;
} ExplosionDebris;

#endif
