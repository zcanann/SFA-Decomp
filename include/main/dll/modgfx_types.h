#ifndef MAIN_DLL_MODGFX_TYPES_H_
#define MAIN_DLL_MODGFX_TYPES_H_

#include "main/game_object.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

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

#define PARTFX_STAGE_COUNT 7

typedef struct PartfxEffectState
{
    GameObject* instanceObject;
    void* sourceObject;
    void* auxSequenceBuffer;
    s16 sourceRotX;
    s16 sourceRotY;
    s16 sourceRotZ;
    f32 sourceScale;
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 posStepX;
    f32 posStepY;
    f32 posStepZ;
    ModgfxScaleChannel scaleChannels[2];
    f32 drawPosX;
    f32 drawPosY;
    f32 drawPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* vertexBuffers[3];
    void* colorBuffers[3];
    void* baseVertexBuffer;
    void* baseColorBuffer;
    void* textureResource;
    void* emitterCommands;
    void* auxAllocation;
    u32 flags;
    s32 initialDelayFrames;
    ModgfxAlphaChannel alphaChannels[2];
    f32 blendColorR;
    f32 blendColorG;
    f32 blendColorB;
    f32 blendColorStepR;
    f32 blendColorStepG;
    f32 blendColorStepB;
    f32 renderScale;
    u8 padD8[0xE6 - 0xD8];
    s16 soundHandle;
    u8 padE8[0xEA - 0xE8];
    s16 vertexCount;
    s16 colorVertexCount;
    s16 stageDurations[PARTFX_STAGE_COUNT];
    s16 currentStage;
    s16 stageFrameCountdown;
    u8 pad100[0x106 - 0x100];
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 sequenceId;
    s16 nextStage;
    s16 stageTimer;
    u8 pad112[0x114 - 0x112];
    int word114;
    int word118;
    int word11C;
    s16 vec120;
    s16 vec122;
    s16 vec124;
    s8 byte126;
    u8 pad127[0x12C - 0x127];
    void* inlineData;
    u8 activeVertexBufferIndex;
    u8 textureFrame;
    u8 textureFrameTimer;
    u8 textureFrameStep;
    u8 textureFrameFadeStep;
    s8 sourceYawIndex;
    u8 drawGroupCount;
    u8 drawGroupStride;
    u8 initialStateByte;
    s8 emitterCount;
    u8 releaseRequested;
    char byte13B;
    u8 requestedStage;
    u8 byte13D;
    u8 frameUpdated;
    u8 textureIsBorrowed;
} PartfxEffectState;

#endif
