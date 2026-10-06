/*
 * DLL 137 / 0x89 - a ten-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0089_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll89EffectResourceView {
    ModgfxEffectVertex vertices[10];
    u8 opaque064[0x104];
    s16 triangles[8][3];
    s16 wrappedVertexIndices[10];
    s16 allVertexIndices[10];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll89EffectResourceView;

STATIC_ASSERT(offsetof(Dll89EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, opaque064) == 0x064);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, triangles) == 0x168);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, wrappedVertexIndices) == 0x198);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, allVertexIndices) == 0x1AC);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, sequenceParams) == 0x1C0);
STATIC_ASSERT(offsetof(Dll89EffectResourceView, opaqueTail) == 0x1CE);
STATIC_ASSERT(sizeof(Dll89EffectResourceView) == 0x1D0);

u8 gDll89ZeroIndexData[8] = {0};

u8 gDll89EffectResourceData[sizeof(Dll89EffectResourceView)] = {
    0, 0,   248, 48,  0, 0,   0, 0,   0,   0,  3, 232, 3, 232, 0,   0,   0, 32,  0,   32, 2, 195, 3, 232, 253, 61,
    0, 0,   0,   32,  0, 0,   3, 232, 252, 24, 0, 32,  0, 32,  253, 61,  3, 232, 253, 61, 0, 0,   0, 32,  252, 24,
    3, 232, 0,   0,   0, 32,  0, 32,  253, 61, 3, 232, 2, 195, 0,   0,   0, 32,  0,   0,  3, 232, 3, 232, 0,   32,
    0, 32,  2,   195, 3, 232, 2, 195, 0,   0,  0, 32,  3, 232, 3,   232, 0, 0,   0,   32, 0, 32,  0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,
    0, 0,   0,   0,   0, 0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   0,   0, 0,   0,   0,  0, 0,   0, 0,   0,   1,
    0, 2,   0,   0,   0, 2,   0, 3,   0,   0,  0, 3,   0, 4,   0,   0,   0, 4,   0,   5,  0, 0,   0, 5,   0,   6,
    0, 0,   0,   6,   0, 7,   0, 0,   0,   7,  0, 8,   0, 0,   0,   8,   0, 9,   0,   1,  0, 2,   0, 3,   0,   4,
    0, 5,   0,   6,   0, 7,   0, 8,   0,   9,  0, 0,   0, 0,   0,   1,   0, 2,   0,   3,  0, 4,   0, 5,   0,   6,
    0, 7,   0,   8,   0, 9,   0, 0,   0,   90, 0, 200, 0, 90,  0,   0,   0, 0,   0,   0,  0, 0};

void dll_89_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll89EffectResourceData;
    ModgfxCommand* commands = packet.entries;

    commands[0].stageIndex = 0;
    commands[0].parameter = 10;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[0].flags = 2;
    commands[0].valueX = 1.1f;
    commands[0].valueY = 1.2f;
    commands[0].valueZ = 1.1f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 10;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[1].flags = 4;
    commands[1].valueX = 0.0f;
    commands[1].valueY = 0.0f;
    commands[1].valueZ = 0.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x400000;
    commands[2].valueX = 8.0f;
    commands[2].valueY = 72.0f;
    commands[2].valueZ = 5.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 10;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[3].flags = 0x4000;
    commands[3].valueX = 1.0f;
    commands[3].valueY = 1.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 0;
    commands[4].parameter = 9;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, wrappedVertexIndices)];
    commands[4].flags = 2;
    commands[4].valueX = 32.1f;
    commands[4].valueY = 1.2f;
    commands[4].valueZ = 32.1f;
    commands[5].stageIndex = 2;
    commands[5].parameter = 1;
    commands[5].vertexIndices = (s16*)(gDll89ZeroIndexData);
    commands[5].flags = 4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 10;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 1.0f;
    commands[6].valueY = 1.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 3;
    commands[7].parameter = 10;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[7].flags = 0x4000;
    commands[7].valueX = 1.0f;
    commands[7].valueY = 1.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 4;
    commands[8].parameter = 10;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[8].flags = 0x4000;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 1.0f;
    commands[8].valueZ = 0.0f;
    commands[9].stageIndex = 4;
    commands[9].parameter = 10;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll89EffectResourceView, allVertexIndices)];
    commands[9].flags = 4;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 0.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 10;
    packet.context.initialStateByte = 10;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 16;
    packet.context.flags = 0x4000494;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 10) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll89EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (sourceObj != NULL) {
            GameObject* anchorObj = sourceObj;
            packet.context.position[0] += anchorObj->anim.worldPosX;
            packet.context.position[1] += anchorObj->anim.worldPosY;
            packet.context.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.context.position[0] += anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 10, (ModgfxEffectVertex*)(int)gDll89EffectResourceData, 8,
                      (s16*)(&resourceData[offsetof(Dll89EffectResourceView, triangles)]), 0x1fd, 0);
}

void dll_89_release(void) {
}

void dll_89_initialise(void) {
}

Dll89ResourceDescriptor gDll89ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_89_initialise, dll_89_release, NULL, dll_89_spawnEffect,
};
