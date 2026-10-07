#ifndef MAIN_DLL_MODGFX_TYPES_H_
#define MAIN_DLL_MODGFX_TYPES_H_

#include "game/objects/object.h"
#include "main/vec_types.h"
#include "main/lightmap_api.h"
#include "main/texture.h"
#include "main/dll/partfx_interface.h"

typedef struct ModgfxCommand {
    s32 flags;
    f32 valueX;
    f32 valueY;
    f32 valueZ;
    s16* vertexIndices;
    s16 parameter; /* Vertex count, sound/effect ID or branch argument, according to flags. */
    u8 stageIndex;
} ModgfxCommand;

STATIC_ASSERT(sizeof(ModgfxCommand) == 0x18);
STATIC_ASSERT(offsetof(ModgfxCommand, valueX) == 0x04);
STATIC_ASSERT(offsetof(ModgfxCommand, vertexIndices) == 0x10);
STATIC_ASSERT(offsetof(ModgfxCommand, parameter) == 0x14);
STATIC_ASSERT(offsetof(ModgfxCommand, stageIndex) == 0x16);

#define MODGFX_STAGE_COUNT 7

typedef struct ModgfxSpawnContext {
    ModgfxCommand* commands;
    GameObject* sourceObject;
    u8 unknown08[0x18];
    f32 velocity[3];
    f32 position[3];
    f32 scale;
    s32 drawGroupStride;
    s32 drawGroupCount;
    s16 variant;
    s16 stageDurations[MODGFX_STAGE_COUNT];
    u32 flags;
    u8 modeByte;
    u8 initialStateByte;
    u8 byte5A;
    u8 textureFrameTimer;
    u8 sourceYawIndex;
    s8 commandCount;
    u8 unknown5E[2];
} ModgfxSpawnContext;

typedef struct ModgfxSpawnPacket {
    ModgfxSpawnContext context;
    ModgfxCommand entries[32];
} ModgfxSpawnPacket;

STATIC_ASSERT(sizeof(ModgfxSpawnContext) == 0x60);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, commands) == 0x00);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, sourceObject) == 0x04);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, velocity) == 0x20);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, position) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, scale) == 0x38);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, drawGroupStride) == 0x3C);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, drawGroupCount) == 0x40);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, variant) == 0x44);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, stageDurations) == 0x46);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, flags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, modeByte) == 0x58);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, initialStateByte) == 0x59);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, byte5A) == 0x5A);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, textureFrameTimer) == 0x5B);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, sourceYawIndex) == 0x5C);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, commandCount) == 0x5D);
STATIC_ASSERT(offsetof(ModgfxSpawnPacket, context) == 0x00);
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

typedef struct ModgfxEffectState {
    GameObject* instanceObject;
    GameObject* sourceObject;
    void* auxSequenceBuffer;
    PartFxSpawnParams sourceTransform;
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
    LightmapVertex* vertexBuffers[3];
    LightmapTriangle* triangleBuffers[3]; /* LightmapTriangle records, expanded from s16 index triplets. */
    void* baseVertexBuffer;
    void* baseTriangleBuffer;
    Texture* textureResource;
    ModgfxCommand* emitterCommands;
    void* auxAllocation;
    u32 flags;
    s32 variant; /* Copied from the spawn context; no retail reader is recovered. */
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
    s16 triangleCount;
    s16 stageDurations[MODGFX_STAGE_COUNT];
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
} ModgfxEffectState;

STATIC_ASSERT(offsetof(ModgfxEffectState, triangleBuffers) == 0x84);
STATIC_ASSERT(offsetof(ModgfxEffectState, baseTriangleBuffer) == 0x94);
STATIC_ASSERT(offsetof(ModgfxEffectState, triangleCount) == 0xEC);

STATIC_ASSERT(sizeof(ModgfxEffectState) == 0x140);
STATIC_ASSERT(offsetof(ModgfxEffectState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(ModgfxEffectState, textureResource) == 0x98);
STATIC_ASSERT(offsetof(ModgfxEffectState, flags) == 0xA4);
STATIC_ASSERT(offsetof(ModgfxEffectState, drawPosX) == 0x60);
STATIC_ASSERT(offsetof(ModgfxEffectState, velocityX) == 0x6C);
STATIC_ASSERT(offsetof(ModgfxEffectState, alphaValues) == 0xAC);
STATIC_ASSERT(offsetof(ModgfxEffectState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(ModgfxEffectState, renderScale) == 0xD4);
STATIC_ASSERT(offsetof(ModgfxEffectState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(ModgfxEffectState, stageDurations) == 0xEE);
STATIC_ASSERT(offsetof(ModgfxEffectState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(ModgfxEffectState, rotOffsetZ) == 0x106);
STATIC_ASSERT(offsetof(ModgfxEffectState, sequenceId) == 0x10C);
STATIC_ASSERT(offsetof(ModgfxEffectState, inlineData) == 0x12C);
STATIC_ASSERT(offsetof(ModgfxEffectState, activeVertexBufferIndex) == 0x130);
STATIC_ASSERT(offsetof(ModgfxEffectState, emitterCount) == 0x139);
STATIC_ASSERT(offsetof(ModgfxEffectState, textureIsBorrowed) == 0x13F);
STATIC_ASSERT(offsetof(ModgfxEffectState, sourceObject) == 0x04);
STATIC_ASSERT(offsetof(ModgfxEffectState, sourceTransform) == 0x0C);
STATIC_ASSERT(offsetof(ModgfxEffectState, emitterCommands) == 0x9C);

#endif
