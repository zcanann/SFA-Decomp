#ifndef MAIN_DLL_MODGFX_TYPES_H_
#define MAIN_DLL_MODGFX_TYPES_H_

#include "types.h"

typedef struct ModgfxVertexData
{
    s16 posX;
    s16 posY;
    s16 posZ;
    s16 unused06;
    s16 texCoordS;
    s16 texCoordT;
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 alpha;
} ModgfxVertexData;

typedef struct ModgfxScaleChannel
{
    f32 cur[3];
    f32 step[3];
} ModgfxScaleChannel;

typedef struct ModgfxAlphaChannel
{
    f32 step;
    f32 cur;
} ModgfxAlphaChannel;

typedef struct ModgfxState
{
    u8 pad00[4];
    s16* unk04; /* current vertex-index list */
    u8 pad08[0x24 - 0x08];
    f32 posStepX; /* 0x24: per-step vertex-position delta */
    f32 posStepY;
    f32 posStepZ;
    ModgfxScaleChannel scaleChannels[2];
    f32 posCurX; /* 0x60: accumulated vertex-position offset */
    f32 posCurY;
    f32 posCurZ;
    u8 pad6C[0x78 - 0x6C];
    ModgfxVertexData* vertexBuffers[2];
    ModgfxVertexData* baseVertexData;
    u8 pad84[0xA4 - 0x84];
    u32 flags;
    u8 padA8[4];
    ModgfxAlphaChannel alphaChannels[2];
    f32 blendColorR; /* 0xBC: current blended vertex color */
    f32 blendColorG;
    f32 blendColorB;
    f32 blendColorStepR; /* 0xC8 */
    f32 blendColorStepG;
    f32 blendColorStepB;
    u8 padD4[0xEA - 0xD4];
    s16 vertexCount;
    u8 padEC[2];
    s16 channelFrames[7]; /* 0xEE: per-channel remaining blend frames */
    s16 activeChannel; /* 0xFC */
    s16 blendFrameCount;
    s16 rotStepZ;
    s16 rotStepY;
    s16 rotStepX;
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 effectId;
    u8 pad10E[0x130 - 0x10E];
    u8 activeVertexBufferIndex;
} ModgfxState;

typedef struct ModgfxVertexGroupCmd
{
    u8 unk00[4];
    f32 valueX; /* rgb r / scale x / alpha */
    f32 valueY;
    f32 valueZ;
    s16* indices; /* vertex indices, stride 2 */
    s16 indexCount;
} ModgfxVertexGroupCmd;

typedef struct ModgfxActiveEffect
{
    int instanceHandle;
    int ownerToken;
    u8 pad08[0x98 - 0x08];
    int sharedResourceHandle;
    int releaseTransformSource;
    u8 padA4[0x10C - 0xA4];
    s16 effectType;
    u8 pad10E[0x12C - 0x10E];
    int state;
    u8 pad130[0x13F - 0x130];
    u8 keepSharedResource;
} ModgfxActiveEffect;

typedef struct ModgfxPendingSpawn
{
    int modelOrResource;
    float posX;
    float posY;
    float posZ;
    int param10;
    s16 param14;
    u8 sequenceIndex;
    u8 pad17;
} ModgfxPendingSpawn;

typedef struct ModgfxSpawnContext
{
    ModgfxPendingSpawn* pendingSpawns;
    void* attachedSource;
    u8 pad08[0x20 - 0x08];
    f32 vecX;
    f32 vecY;
    f32 vecZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 scale;
    int drawGroupStride; /* 0x3C: copied into PartfxEffectState.drawGroupStride on spawn */
    int drawGroupCount;  /* 0x40: copied into PartfxEffectState.drawGroupCount on spawn */
    s16 sourceModeCopy;
    s16 sequenceParams[7];
    u32 flags;
    u8 modeByte;
    u8 initialStateByte; /* 0x59: copied into PartfxEffectState.initialStateByte on spawn */
    u8 byte5A;
    u8 textureFrameTimer; /* 0x5B: copied into PartfxEffectState.textureFrameTimer on spawn */
    u8 sourceYawIndex; /* 0x5C: copied into PartfxEffectState.sourceYawIndex on spawn */
    s8 pendingSpawnCount;
    u8 pad5E[0x60 - 0x5E];
} ModgfxSpawnContext;

#endif
