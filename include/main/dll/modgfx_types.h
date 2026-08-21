#ifndef MAIN_DLL_MODGFX_TYPES_H_
#define MAIN_DLL_MODGFX_TYPES_H_

#include "game/objects/object.h"
#include "main/vec_types.h"

typedef struct {
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);
STATIC_ASSERT(offsetof(GfxCmd, tex) == 0x10);
STATIC_ASSERT(offsetof(GfxCmd, flags) == 0x14);
STATIC_ASSERT(offsetof(GfxCmd, layer) == 0x16);

typedef struct ModgfxSpawnPacket {
    union {
        GfxCmd* cmds;
        GfxCmd* commands;
    };
    union {
        int ctx;
        GameObject* sourceObj;
    };
    u8 pad08[0x18];
    union {
        f32 col[3];
        f32 velocity[3];
    };
    union {
        f32 pos[3];
        f32 position[3];
    };
    f32 scale;
    union {
        u32 v3c;
        u32 drawGroupStride;
    };
    union {
        u32 v40;
        u32 drawGroupCount;
    };
    union {
        s16 v44;
        s16 sourceMode;
    };
    union {
        s16 hw[7];
        s16 sequenceParams[7];
    };
    u32 flags;
    union {
        u8 v58;
        u8 modeByte;
    };
    union {
        u8 v59;
        u8 initialStateByte;
    };
    union {
        u8 v5a;
        u8 byte5A;
    };
    union {
        u8 v5b;
        u8 textureFrameTimer;
    };
    union {
        u8 v5c;
        u8 sourceYawIndex;
    };
    union {
        s8 count;
        s8 commandCount;
    };
    u8 pad5E[2];
    GfxCmd entries[32];
} ModgfxSpawnPacket;

STATIC_ASSERT(offsetof(ModgfxSpawnPacket, commands) == 0x00);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, ctx) == 0x04);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceObj) == 0x04);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, velocity) == 0x20);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, position) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, scale) == 0x38);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, drawGroupStride) == 0x3C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, drawGroupCount) == 0x40);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceMode) == 0x44);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sequenceParams) == 0x46);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, flags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, modeByte) == 0x58);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, initialStateByte) == 0x59);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, byte5A) == 0x5A);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, textureFrameTimer) == 0x5B);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceYawIndex) == 0x5C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, commandCount) == 0x5D);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, entries) == 0x60);
STATIC_ASSERT(sizeof(ModgfxSpawnPacket) == 0x360);

STATIC_ASSERT(offsetof(ModgfxSpawnPacket, commands) == 0x00);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, ctx) == 0x04);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceObj) == 0x04);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, velocity) == 0x20);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, position) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, scale) == 0x38);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, drawGroupStride) == 0x3C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, drawGroupCount) == 0x40);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceMode) == 0x44);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sequenceParams) == 0x46);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, flags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, modeByte) == 0x58);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, initialStateByte) == 0x59);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, byte5A) == 0x5A);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, textureFrameTimer) == 0x5B);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, sourceYawIndex) == 0x5C);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, commandCount) == 0x5D);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, entries) == 0x60);
STATIC_ASSERT(sizeof(ModgfxSpawnPacket) == 0x360);

typedef struct ModgfxEffectVertex {
    s16 positionX;
    s16 positionY;
    s16 positionZ;
    s16 texCoordS;
    s16 texCoordT;
} ModgfxEffectVertex;

STATIC_ASSERT(offsetof(ModgfxEffectVertex, positionX) == 0x00);
STATIC_ASSERT(offsetof(ModgfxEffectVertex, positionY) == 0x02);
STATIC_ASSERT(offsetof(ModgfxEffectVertex, positionZ) == 0x04);
STATIC_ASSERT(offsetof(ModgfxEffectVertex, texCoordS) == 0x06);
STATIC_ASSERT(offsetof(ModgfxEffectVertex, texCoordT) == 0x08);
STATIC_ASSERT(sizeof(ModgfxEffectVertex) == 0x0A);

typedef struct ModgfxVertexData {
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

typedef struct ModgfxVertexGroupCmd {
    u8 unk00[4];
    f32 valueX; /* rgb r / scale x / alpha */
    f32 valueY;
    f32 valueZ;
    s16* indices; /* vertex indices, stride 2 */
    s16 indexCount;
} ModgfxVertexGroupCmd;
STATIC_ASSERT(offsetof(ModgfxVertexGroupCmd, valueX) == 0x04);

typedef struct ModgfxActiveEffect {
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

typedef struct ModgfxPendingSpawn {
    int modelOrResource;
    float posX;
    float posY;
    float posZ;
    int param10;
    s16 param14;
    u8 sequenceIndex;
    u8 pad17;
} ModgfxPendingSpawn;

typedef struct ModgfxSpawnContext {
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
    u8 sourceYawIndex;    /* 0x5C: copied into PartfxEffectState.sourceYawIndex on spawn */
    s8 pendingSpawnCount;
    u8 pad5E[0x60 - 0x5E];
} ModgfxSpawnContext;

#define PARTFX_STAGE_COUNT 7

typedef struct PartfxEffectState {
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
    Vec3f scaleVectors[4];
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
    f32 alphaValues[4];
    union {
        f32 blendColorR;
        f32 sourceAlphaStep;
    };
    union {
        f32 blendColorG;
        f32 sourceAlphaCurrent;
    };
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
    s16 rotStepZ; /* 0x100: per-frame rotation delta added into rotOffset* */
    s16 rotStepY;
    s16 rotStepX;
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
    s8 spawnGeneration;
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
