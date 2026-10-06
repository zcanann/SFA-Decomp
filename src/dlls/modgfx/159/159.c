/*
 * DLL 159 / 0x9F - a rotation-aware layered pickup effect spawner.
 */
#include "main/dll/dll_009F_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll9FSevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} Dll9FSevenIndexList;

STATIC_ASSERT(offsetof(Dll9FSevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(Dll9FSevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll9FSevenIndexList) == 0x10);

typedef struct Dll9FEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    Dll9FSevenIndexList sevenVertexIndexLists[3];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll9FEffectResourceView;

STATIC_ASSERT(offsetof(Dll9FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, sevenVertexIndexLists) == 0x164);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll9FEffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll9FEffectResourceView) == 0x208);

extern u8 gDll9FEffectResourceData[sizeof(Dll9FEffectResourceView)];

void dll_9F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = gDll9FEffectResourceData;
    ModgfxCommand* commands = packet.entries;
    ModgfxCommand* commandCursor = commands;
    int sourceRotationX = sourceObj->anim.rotX;
    u32 fl;

    if (sourceRotationX != 0) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x80;
        commandCursor->valueX = 0.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = sourceRotationX;
        commandCursor = commands + 1;
    }
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 7;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, sevenVertexIndexLists[0].indices)];
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 0.8f;
    commandCursor[1].valueY = 0.8f;
    commandCursor[1].valueZ = 0.5f;
    commandCursor[2].stageIndex = 0;
    commandCursor[2].parameter = 7;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[2].flags = 2;
    commandCursor[2].valueX = 1.2f;
    commandCursor[2].valueY = 1.2f;
    commandCursor[2].valueZ = 0.5f;
    commandCursor[3].stageIndex = 0;
    commandCursor[3].parameter = 7;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, sevenVertexIndexLists[2].indices)];
    commandCursor[3].flags = 2;
    commandCursor[3].valueX = 0.8f;
    commandCursor[3].valueY = 0.8f;
    commandCursor[3].valueZ = 0.5f;
    commandCursor[4].stageIndex = 1;
    commandCursor[4].parameter = 7;
    commandCursor[4].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[4].flags = 4;
    commandCursor[4].valueX = 195.0f;
    commandCursor[4].valueY = 0.0f;
    commandCursor[4].valueZ = 0.0f;
    commandCursor[5].stageIndex = 1;
    commandCursor[5].parameter = 0x15;
    commandCursor[5].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[5].flags = 0x4000;
    commandCursor[5].valueX = 2.0f;
    commandCursor[5].valueY = -2.0f;
    commandCursor[5].valueZ = 0.0f;
    commandCursor[6].stageIndex = 1;
    commandCursor[6].parameter = 0;
    commandCursor[6].vertexIndices = NULL;
    commandCursor[6].flags = 0x400000;
    commandCursor[6].valueX = 0.0f;
    commandCursor[6].valueY = 0.0f;
    commandCursor[6].valueZ = 160.0f;
    commandCursor[7].stageIndex = 2;
    commandCursor[7].parameter = 0x15;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 0x4000;
    commandCursor[7].valueX = 2.0f;
    commandCursor[7].valueY = -2.0f;
    commandCursor[7].valueZ = 0.0f;
    commandCursor[8].stageIndex = 2;
    commandCursor[8].parameter = 0;
    commandCursor[8].vertexIndices = NULL;
    commandCursor[8].flags = 0x400000;
    commandCursor[8].valueX = 0.0f;
    commandCursor[8].valueY = 0.0f;
    commandCursor[8].valueZ = 740.0f;
    commandCursor[9].stageIndex = 2;
    commandCursor[9].parameter = 0x15;
    commandCursor[9].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[9].flags = 8;
    commandCursor[9].valueX = 255.0f;
    commandCursor[9].valueY = 255.0f;
    commandCursor[9].valueZ = 85.0f;
    commandCursor[10].stageIndex = 3;
    commandCursor[10].parameter = 0x15;
    commandCursor[10].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[10].flags = 0x4000;
    commandCursor[10].valueX = 2.0f;
    commandCursor[10].valueY = 2.0f;
    commandCursor[10].valueZ = 0.0f;
    commandCursor[11].stageIndex = 3;
    commandCursor[11].parameter = 0;
    commandCursor[11].vertexIndices = NULL;
    commandCursor[11].flags = 0x400000;
    commandCursor[11].valueX = 0.0f;
    commandCursor[11].valueY = 0.0f;
    commandCursor[11].valueZ = -740.0f;
    commandCursor[12].stageIndex = 3;
    commandCursor[12].parameter = 0x15;
    commandCursor[12].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[12].flags = 8;
    commandCursor[12].valueX = 255.0f;
    commandCursor[12].valueY = 255.0f;
    commandCursor[12].valueZ = 255.0f;
    commandCursor[13].stageIndex = 4;
    commandCursor[13].parameter = 0x15;
    commandCursor[13].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, allVertexIndices)];
    commandCursor[13].flags = 0x4000;
    commandCursor[13].valueX = 2.0f;
    commandCursor[13].valueY = 2.0f;
    commandCursor[13].valueZ = 0.0f;
    commandCursor[14].stageIndex = 4;
    commandCursor[14].parameter = 7;
    commandCursor[14].vertexIndices = (s16*)&resourceData[offsetof(Dll9FEffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[14].flags = 4;
    commandCursor[14].valueX = 0.0f;
    commandCursor[14].valueY = 0.0f;
    commandCursor[14].valueZ = 0.0f;
    commandCursor[15].stageIndex = 4;
    commandCursor[15].parameter = 0;
    commandCursor[15].vertexIndices = NULL;
    commandCursor[15].flags = 0x400000;
    commandCursor[15].valueX = 0.0f;
    commandCursor[15].valueY = 0.0f;
    commandCursor[15].valueZ = -160.0f;

    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 2.2f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = &commandCursor[16] - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll9FEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    fl = 0xc0104c0;
    packet.context.flags = fl;
    fl |= flags;
    packet.context.flags = fl;
    if (fl & 1) {
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(resourceData), 0x18, (s16*)(&resourceData[offsetof(Dll9FEffectResourceView, triangles)]),
                      0x46c, 0);
}

void dll_9F_release(void) {
}

void dll_9F_initialise(void) {
}

u8 gDll9FEffectResourceData[sizeof(Dll9FEffectResourceView)] = {
    0,   0,   3,  232, 0,   0,   0,   0,   0,   0,   3,   98,  1,  244, 0,   0,   0,   22,  0,   0,   3,   98,  254,
    12,  0,   0,  0,   44,  0,   0,   0,   0,   252, 24,  0,   0,  0,   63,  0,   0,   252, 158, 254, 12,  0,   0,
    0,   44,  0,  0,   252, 158, 1,   244, 0,   0,   0,   22,  0,  0,   0,   0,   3,   232, 0,   0,   0,   0,   0,
    0,   0,   0,  3,   232, 11,  184, 0,   0,   0,   15,  3,   98, 1,   244, 11,  184, 0,   22,  0,   15,  3,   98,
    254, 12,  11, 184, 0,   44,  0,   15,  0,   0,   252, 24,  11, 184, 0,   63,  0,   15,  252, 158, 254, 12,  11,
    184, 0,   44, 0,   15,  252, 158, 1,   244, 11,  184, 0,   22, 0,   15,  0,   0,   3,   232, 11,  184, 0,   0,
    0,   15,  0,  0,   3,   232, 23,  112, 0,   0,   0,   31,  3,  98,  1,   244, 23,  112, 0,   22,  0,   31,  3,
    98,  254, 12, 23,  112, 0,   44,  0,   31,  0,   0,   252, 24, 23,  112, 0,   63,  0,   31,  252, 158, 254, 12,
    23,  112, 0,  44,  0,   31,  252, 158, 1,   244, 23,  112, 0,  22,  0,   31,  0,   0,   3,   232, 23,  112, 0,
    0,   0,   31, 0,   0,   0,   0,   0,   1,   0,   8,   0,   0,  0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,  9,   0,   8,   0,   2,   0,   3,   0,   10,  0,  2,   0,   10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,  0,   11,  0,   10,  0,   4,   0,   5,   0,   12, 0,   4,   0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,  5,   0,   13,  0,   12,  0,   7,   0,   8,   0,  15,  0,   7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16, 0,   8,   0,   16,  0,   15,  0,   9,   0,   10, 0,   17,  0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,  18,  0,   10,  0,   18,  0,   17,  0,   11,  0,  12,  0,   19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13, 0,   20,  0,   12,  0,   20,  0,   19,  0,   0,  0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,  0,   0,   7,   0,   8,   0,   9,   0,   10,  0,  11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16, 0,   17,  0,   18,  0,   19,  0,   20,  0,   0,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,  6,   0,   14,  0,   15,  0,   16,  0,   17,  0,  18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,  0,   4,   0,   5,   0,   6,   0,   7,   0,   8,  0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,  15,  0,   16,  0,   17,  0,   18,  0,   19,  0,  20,  0,   0,   0,   7,   0,   8,   0,   9,   0,
    10,  0,   11, 0,   12,  0,   13,  0,   14,  0,   15,  0,   16, 0,   17,  0,   18,  0,   19,  0,   20,  0,   0,
    0,   50,  0,  250, 0,   250, 0,   50,  0,   0,   0,   0,   0,  0,
};

Dll9FResourceDescriptor gDll9FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_9F_initialise, dll_9F_release, NULL, dll_9F_spawnEffect,
};
