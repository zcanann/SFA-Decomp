/*
 * DLL 89 / 0x59 - a modgfx particle-sequence spawn DLL.
 */
#include "main/dll/dll_0059_dll59func0.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

#define DLL59_EFFECT_ID 0xC0D

typedef struct Dll59EffectResourceView {
    ModgfxEffectVertex vertices[17];
    u8 padAA[2];
    s16 triangleIndices[8][3];
    s16 indicesWithVertexZero[18];
    s16 indicesWithoutVertexZero[16];
    s16 sequenceParams[7];
    u8 pad12E[2];
} Dll59EffectResourceView;

STATIC_ASSERT(offsetof(Dll59EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, triangleIndices) == 0xAC);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, indicesWithVertexZero) == 0xDC);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, indicesWithoutVertexZero) == 0x100);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, sequenceParams) == 0x120);
STATIC_ASSERT(sizeof(Dll59EffectResourceView) == 0x130);

void dll_59_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resource = (u8*)(int)gDll59EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    GameObject* sourceContext;
    f32 one;
    f32 zero;
    commands[0].stageIndex = 1;
    commands[0].parameter = 0x11;
    commands[0].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[0].flags = 0x4000;
    commands[0].valueX = (zero = 0.0f);
    commands[0].valueY = -3.0f;
    commands[0].valueZ = zero;
    commands[1].stageIndex = 1;
    commands[1].parameter = 0x10;
    commands[1].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithoutVertexZero)];
    commands[1].flags = 2;
    commands[1].valueX = 35.0f;
    commands[1].valueY = 35.0f;
    commands[1].valueZ = 35.0f;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0x11;
    commands[2].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[2].flags = 0x100;
    commands[2].valueX = zero;
    commands[2].valueY = zero;
    commands[2].valueZ = 1500.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 2;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x04000000;
    commands[3].valueX = (one = 1.0f);
    commands[3].valueY = zero;
    commands[3].valueZ = zero;
    commands[4].stageIndex = 2;
    commands[4].parameter = 2;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x04000000;
    commands[4].valueX = one;
    commands[4].valueY = zero;
    commands[4].valueZ = zero;
    commands[5].stageIndex = 2;
    commands[5].parameter = 0x11;
    commands[5].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[5].flags = 0x4000;
    commands[5].valueX = zero;
    commands[5].valueY = -3.0f;
    commands[5].valueZ = zero;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x11;
    commands[6].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[6].flags = 4;
    commands[6].valueX = zero;
    commands[6].valueY = zero;
    commands[6].valueZ = zero;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x11;
    commands[7].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[7].flags = 0x100;
    commands[7].valueX = zero;
    commands[7].valueY = zero;
    commands[7].valueZ = -1000.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x10;
    commands[8].vertexIndices = (s16*)&resource[offsetof(Dll59EffectResourceView, indicesWithoutVertexZero)];
    commands[8].flags = 2;
    commands[8].valueX = 2.0f;
    commands[8].valueY = 2.0f;
    commands[8].valueZ = 2.0f;
    packet.context.modeByte = 0;
    sourceContext = sourceObj;
    packet.context.sourceObject = sourceContext;
    packet.context.variant = variant;
    packet.context.position[0] = zero;
    packet.context.position[1] = 135.0f;
    packet.context.position[2] = zero;
    packet.context.velocity[0] = zero;
    packet.context.velocity[1] = zero;
    packet.context.velocity[2] = zero;
    packet.context.scale = one;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0x11;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.commandCount = (commands + 9) - packet.entries;
    packet.context.stageDurations[0] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x0];
    packet.context.stageDurations[1] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x2];
    packet.context.stageDurations[2] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x4];
    packet.context.stageDurations[3] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x6];
    packet.context.stageDurations[4] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x8];
    packet.context.stageDurations[5] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0xA];
    packet.context.stageDurations[6] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0xC];
    packet.context.commands = packet.entries;
    packet.context.flags = 0x04000000;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)sourceContext != NULL) {
            packet.context.position[0] = zero + sourceContext->anim.worldPosX;
            packet.context.position[1] = 135.0f + sourceContext->anim.worldPosY;
            packet.context.position[2] = zero + sourceContext->anim.worldPosZ;
        } else {
            packet.context.position[0] = zero + spawnParams->posX;
            packet.context.position[1] = 135.0f + spawnParams->posY;
            packet.context.position[2] = zero + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x11, (ModgfxEffectVertex*)(int)gDll59EffectResourceData, 8,
                      (s16*)(&resource[offsetof(Dll59EffectResourceView, triangleIndices)]), DLL59_EFFECT_ID, 0);
}

void dll_59_release(void) {
}

void dll_59_initialise(void) {
}

u8 gDll59EffectResourceData[0x130] = {
    0,   0,   0, 0,   0, 0,   0,   15,  0,   0,   0,   150, 1,   144, 3,   132, 0,   0,   0, 127, 255, 206, 1,   144,
    3,   232, 0, 31,  0, 127, 0,   50,  2,   18,  252, 24,  0,   0,   0,   127, 255, 106, 2, 18,  252, 174, 0,   31,
    0,   127, 3, 232, 0, 100, 0,   150, 0,   0,   0,   127, 4,   176, 0,   100, 255, 206, 0, 31,  0,   127, 252, 24,
    1,   14,  0, 50,  0, 0,   0,   127, 252, 24,  1,   14,  255, 206, 0,   31,  0,   127, 2, 108, 2,   38,  3,   12,
    0,   0,   0, 127, 3, 12,  2,   38,  3,   152, 0,   31,  0,   127, 252, 204, 0,   210, 3, 12,  0,   0,   0,   127,
    253, 188, 0, 210, 3, 52,  0,   31,  0,   127, 3,   52,  0,   100, 252, 244, 0,   0,   0, 127, 3,   12,  0,   100,
    253, 148, 0, 31,  0, 127, 252, 104, 1,   214, 252, 244, 0,   0,   0,   127, 252, 244, 1, 214, 252, 204, 0,   31,
    0,   127, 0, 0,   0, 0,   0,   1,   0,   2,   0,   0,   0,   3,   0,   4,   0,   0,   0, 5,   0,   6,   0,   0,
    0,   7,   0, 8,   0, 0,   0,   9,   0,   10,  0,   0,   0,   11,  0,   12,  0,   0,   0, 13,  0,   14,  0,   0,
    0,   15,  0, 16,  0, 0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0, 7,   0,   8,   0,   9,
    0,   10,  0, 11,  0, 12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   0,   0,   1,   0, 2,   0,   3,   0,   4,
    0,   5,   0, 6,   0, 7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0, 14,  0,   15,  0,   16,
    0,   0,   0, 90,  0, 50,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

Dll59ResourceDescriptor gDll59ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_59_initialise, dll_59_release, NULL, dll_59_spawnEffect,
};
