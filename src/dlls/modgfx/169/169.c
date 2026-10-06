/*
 * DLL 169 / 0xA9 - an alternate-style layered effect spawner.
 */
#include "main/dll/dll_00A9_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA9SevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} DllA9SevenIndexList;

STATIC_ASSERT(offsetof(DllA9SevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllA9SevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllA9SevenIndexList) == 0x10);

typedef struct DllA9EffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangles[12][3];
    DllA9SevenIndexList firstSevenVertexIndices;
    DllA9SevenIndexList lastSevenVertexIndices;
    s16 allVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA9EffectResourceView;

STATIC_ASSERT(offsetof(DllA9EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, triangles) == 0x08C);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, firstSevenVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, lastSevenVertexIndices) == 0x0E4);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, allVertexIndices) == 0x0F4);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(offsetof(DllA9EffectResourceView, opaqueTail) == 0x11E);
STATIC_ASSERT(sizeof(DllA9EffectResourceView) == 0x120);

extern u8 gDllA9EffectResourceData[sizeof(DllA9EffectResourceView)];

void dll_A9_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags, int unused,
                        void* alternateStyle) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDllA9EffectResourceData;
    f32 scaleX;
    ModgfxCommand* commands;
    ModgfxCommand* commandCursor;
    u32 effectFlags;
    f32 originOffset = 0.0f;

    if (alternateStyle != NULL) {
        scaleX = -2.0f;
    } else {
        scaleX = 2.0f;
    }
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0xe;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = originOffset;
    commands[0].valueY = originOffset;
    commands[0].valueZ = originOffset;
    if (alternateStyle != NULL) {
        commands[1].stageIndex = 0;
        commands[1].parameter = 7;
        commands[1].vertexIndices =
            (s16*)&resourceData[offsetof(DllA9EffectResourceView, firstSevenVertexIndices.indices)];
        commands[1].flags = 2;
        commands[1].valueX = 0.8f;
        commands[1].valueY = 0.006f;
        commands[1].valueZ = 0.8f;
        commands[2].stageIndex = 0;
        commands[2].parameter = 7;
        commands[2].vertexIndices =
            (s16*)&resourceData[offsetof(DllA9EffectResourceView, lastSevenVertexIndices.indices)];
        commands[2].flags = 2;
        commands[2].valueX = 1.5f;
        commands[2].valueY = 0.006f;
        commands[2].valueZ = 1.5f;
        commandCursor = commands + 3;
    } else {
        commands[1].stageIndex = 0;
        commands[1].parameter = 7;
        commands[1].vertexIndices =
            (s16*)&resourceData[offsetof(DllA9EffectResourceView, firstSevenVertexIndices.indices)];
        commands[1].flags = 2;
        commands[1].valueX = 0.8f;
        commands[1].valueY = 0.028f;
        commands[1].valueZ = 0.8f;
        commands[2].stageIndex = 0;
        commands[2].parameter = 7;
        commands[2].vertexIndices =
            (s16*)&resourceData[offsetof(DllA9EffectResourceView, lastSevenVertexIndices.indices)];
        commands[2].flags = 2;
        commands[2].valueX = 1.2f;
        commands[2].valueY = 0.028f;
        commands[2].valueZ = 1.2f;
        commandCursor = commands + 3;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 0xe;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 2;
    commandCursor[0].valueX = 1.0f;
    commandCursor[0].valueY = 130.0f;
    commandCursor[0].valueZ = 1.0f;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 0xe;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 255.0f;
    commandCursor[1].valueY = originOffset;
    commandCursor[1].valueZ = originOffset;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 0xe;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 0x4000;
    commandCursor[2].valueX = scaleX;
    commandCursor[2].valueY = originOffset;
    commandCursor[2].valueZ = originOffset;
    commandCursor[3].stageIndex = 2;
    commandCursor[3].parameter = 0xe;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[3].flags = 0x4000;
    commandCursor[3].valueX = scaleX;
    commandCursor[3].valueY = originOffset;
    commandCursor[3].valueZ = originOffset;
    commandCursor[4].stageIndex = 3;
    commandCursor[4].parameter = 1;
    commandCursor[4].vertexIndices = NULL;
    commandCursor[4].flags = 0x2000;
    commandCursor[4].valueX = originOffset;
    commandCursor[4].valueY = originOffset;
    commandCursor[4].valueZ = originOffset;
    commandCursor[5].stageIndex = 4;
    commandCursor[5].parameter = 0xe;
    commandCursor[5].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[5].flags = 4;
    commandCursor[5].valueX = originOffset;
    commandCursor[5].valueY = originOffset;
    commandCursor[5].valueZ = originOffset;
    commandCursor[6].stageIndex = 4;
    commandCursor[6].parameter = 0xe;
    commandCursor[6].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[6].flags = 0x4000;
    commandCursor[6].valueX = scaleX;
    commandCursor[6].valueY = originOffset;
    commandCursor[6].valueZ = originOffset;
    commandCursor[7].stageIndex = 4;
    commandCursor[7].parameter = 0xe;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(DllA9EffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 2;
    commandCursor[7].valueX = 1.0f;
    commandCursor[7].valueY = 0.01f;
    commandCursor[7].valueZ = 1.0f;

    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = originOffset;
    packet.context.position[1] = originOffset;
    packet.context.position[2] = originOffset;
    packet.context.velocity[0] = originOffset;
    packet.context.velocity[1] = originOffset;
    packet.context.velocity[2] = originOffset;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = &commandCursor[8] - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA9EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    effectFlags = 0xc010040;
    packet.context.flags = effectFlags;
    effectFlags |= flags;
    packet.context.flags = effectFlags;
    if (effectFlags & 1) {
        if (sourceObj != NULL) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += sourceObj->anim.worldPosY;
            packet.context.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDllA9EffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(DllA9EffectResourceView, triangles)]), 0x586, 0);
}

void dll_A9_release(void) {
}

void dll_A9_initialise(void) {
}

u8 gDllA9EffectResourceData[sizeof(DllA9EffectResourceView)] = {
    0,   0,   0,   0,   3, 232, 0, 0,   0,   0,   3,   98,  0, 0,   1,   244, 0,   31,  0,   0,   3,   98,  0,   0,
    254, 12,  0,   63,  0, 0,   0, 0,   0,   0,   252, 24,  0, 95,  0,   0,   252, 158, 0,   0,   254, 12,  0,   127,
    0,   0,   252, 158, 0, 0,   1, 244, 0,   158, 0,   0,   0, 0,   0,   0,   3,   232, 0,   188, 0,   0,   0,   0,
    3,   232, 3,   232, 0, 0,   0, 31,  3,   98,  3,   232, 1, 244, 0,   31,  0,   31,  3,   98,  3,   232, 254, 12,
    0,   63,  0,   31,  0, 0,   3, 232, 252, 24,  0,   95,  0, 31,  252, 158, 3,   232, 254, 12,  0,   127, 0,   31,
    252, 158, 3,   232, 1, 244, 0, 158, 0,   31,  0,   0,   3, 232, 3,   232, 0,   188, 0,   31,  0,   0,   0,   1,
    0,   8,   0,   0,   0, 8,   0, 7,   0,   1,   0,   2,   0, 9,   0,   1,   0,   9,   0,   8,   0,   2,   0,   3,
    0,   10,  0,   2,   0, 10,  0, 9,   0,   3,   0,   4,   0, 11,  0,   3,   0,   11,  0,   10,  0,   4,   0,   5,
    0,   12,  0,   4,   0, 12,  0, 11,  0,   5,   0,   6,   0, 13,  0,   5,   0,   13,  0,   12,  0,   0,   0,   1,
    0,   2,   0,   3,   0, 4,   0, 5,   0,   6,   0,   0,   0, 7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,
    0,   13,  0,   0,   0, 0,   0, 1,   0,   2,   0,   3,   0, 4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   9,
    0,   10,  0,   11,  0, 12,  0, 13,  0,   0,   0,   150, 0, 250, 0,   1,   0,   50,  0,   0,   0,   0,   0,   0};
DllA9ResourceDescriptor gDllA9ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A9_initialise, dll_A9_release, NULL, dll_A9_spawnEffect,
};
