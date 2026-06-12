#ifndef MAIN_DLL_PARTFXSPAWN_STRUCT_H_
#define MAIN_DLL_PARTFXSPAWN_STRUCT_H_

#include "types.h"

typedef struct PartFxSpawn
{
    void* attachedSource;
    int quadVertex3Pad06;
    int lifetimeFrames;
    s16 sourceVecX;
    s16 sourceVecY;
    s16 sourceVecZ;
    u8 pad12[2];
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 sourcePosW;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 scale;
    s16 textureSetupFlags;
    s16 textureId;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 overrideColor0;
    u32 overrideColor1;
    u32 overrideColor2;
    u16 colorWord0;
    u16 colorWord1;
    u16 colorWord2;
    u8 effectIdByte;
    u8 pad5f[1];
    u8 initialAlpha;
    u8 linkGroup;
    u8 modelIdByte;
} PartFxSpawn;

#endif
