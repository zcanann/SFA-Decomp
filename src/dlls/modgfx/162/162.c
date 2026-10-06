/*
 * DLL 162 / 0xA2 - a layered pickup effect spawner.
 */
#include "main/dll/dll_00A2_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA2SevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} DllA2SevenIndexList;

STATIC_ASSERT(offsetof(DllA2SevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllA2SevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllA2SevenIndexList) == 0x10);

typedef struct DllA2EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    DllA2SevenIndexList sevenVertexIndexLists[3];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA2EffectResourceView;

STATIC_ASSERT(offsetof(DllA2EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, sevenVertexIndexLists) == 0x164);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(DllA2EffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(DllA2EffectResourceView) == 0x208);

extern u8 gDllA2EffectResourceData[sizeof(DllA2EffectResourceView)];

void dll_A2_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDllA2EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    u32 fl;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.05f;
    commands[1].valueY = 0.05f;
    commands[1].valueZ = -0.35f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 7;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[0].indices)];
    commands[2].flags = 8;
    commands[2].valueX = 255.0f;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = 0.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[3].flags = 2;
    commands[3].valueX = 4.0f;
    commands[3].valueY = 4.0f;
    commands[3].valueZ = 8.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[2].indices)];
    commands[4].flags = 2;
    commands[4].valueX = 8.0f;
    commands[4].valueY = 8.0f;
    commands[4].valueZ = 10.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 7;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[5].flags = 4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 1.0f;
    commands[6].valueY = -4.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 7;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[7].flags = 2;
    commands[7].valueX = 1.0f;
    commands[7].valueY = 1.0f;
    commands[7].valueZ = 1.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 7;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[2].indices)];
    commands[8].flags = 2;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 1.0f;
    commands[8].valueZ = 1.0f;
    commands[9].stageIndex = 2;
    commands[9].parameter = 0x15;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, allVertexIndices)];
    commands[9].flags = 0x4000;
    commands[9].valueX = 1.0f;
    commands[9].valueY = -4.0f;
    commands[9].valueZ = 0.0f;
    commands[10].stageIndex = 3;
    commands[10].parameter = 7;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[10].flags = 4;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 0.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 3;
    commands[11].parameter = 0x15;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(DllA2EffectResourceView, allVertexIndices)];
    commands[11].flags = 0x4000;
    commands[11].valueX = 1.0f;
    commands[11].valueY = -4.0f;
    commands[11].valueZ = 0.0f;

    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 12) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA2EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags = 0xc010480;
    packet.context.flags |= flags;
    fl = packet.context.flags;
    if ((fl & 1) != 0) {
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDllA2EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(DllA2EffectResourceView, triangles)]), 0x24, 0);
}

void dll_A2_release(void) {
}

void dll_A2_initialise(void) {
}

u8 gDllA2EffectResourceData[sizeof(DllA2EffectResourceView)] = {
    0,   0,   3,   232, 0,   0,   0,   0,   0,   0,   3, 98,  1,   244, 0,   0,   0,   11,  0,   0,   3,   98, 254, 12,
    0,   0,   0,   22,  0,   0,   0,   0,   252, 24,  0, 0,   0,   31,  0,   0,   252, 158, 254, 12,  0,   0,  0,   22,
    0,   0,   252, 158, 1,   244, 0,   0,   0,   11,  0, 0,   0,   0,   3,   232, 0,   0,   0,   0,   0,   0,  0,   0,
    3,   232, 1,   244, 0,   0,   0,   15,  3,   98,  1, 244, 1,   44,  0,   11,  0,   15,  3,   98,  254, 12, 1,   244,
    0,   22,  0,   15,  0,   0,   252, 24,  1,   44,  0, 31,  0,   15,  252, 158, 254, 12,  1,   244, 0,   22, 0,   15,
    252, 158, 1,   244, 1,   44,  0,   11,  0,   15,  0, 0,   3,   232, 1,   244, 0,   0,   0,   15,  0,   0,  3,   232,
    3,   32,  0,   0,   0,   31,  3,   98,  1,   244, 3, 232, 0,   11,  0,   31,  3,   98,  254, 12,  3,   32, 0,   22,
    0,   31,  0,   0,   252, 24,  3,   232, 0,   31,  0, 31,  252, 158, 254, 12,  3,   32,  0,   22,  0,   31, 252, 158,
    1,   244, 3,   232, 0,   11,  0,   31,  0,   0,   3, 232, 3,   32,  0,   0,   0,   31,  0,   0,   0,   0,  0,   1,
    0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0, 2,   0,   9,   0,   1,   0,   9,   0,   8,   0,   2,  0,   3,
    0,   10,  0,   2,   0,   10,  0,   9,   0,   3,   0, 4,   0,   11,  0,   3,   0,   11,  0,   10,  0,   4,  0,   5,
    0,   12,  0,   4,   0,   12,  0,   11,  0,   5,   0, 6,   0,   13,  0,   5,   0,   13,  0,   12,  0,   7,  0,   8,
    0,   15,  0,   7,   0,   15,  0,   14,  0,   8,   0, 9,   0,   16,  0,   8,   0,   16,  0,   15,  0,   9,  0,   10,
    0,   17,  0,   9,   0,   17,  0,   16,  0,   10,  0, 11,  0,   18,  0,   10,  0,   18,  0,   17,  0,   11, 0,   12,
    0,   19,  0,   11,  0,   19,  0,   18,  0,   12,  0, 13,  0,   20,  0,   12,  0,   20,  0,   19,  0,   0,  0,   1,
    0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0, 0,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11, 0,   12,
    0,   13,  0,   0,   0,   14,  0,   15,  0,   16,  0, 17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,  0,   1,
    0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0, 14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19, 0,   20,
    0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0, 5,   0,   6,   0,   7,   0,   8,   0,   9,   0,   10, 0,   11,
    0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0, 17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   7,  0,   8,
    0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0, 14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19, 0,   20,
    0,   0,   0,   35,  0,   6,   0,   35,  0,   0,   0, 0,   0,   0,   0,   0};
DllA2ResourceDescriptor gDllA2ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A2_initialise, dll_A2_release, NULL, dll_A2_spawnEffect,
};
