/*
 * DLL 160 / 0xA0 - a direction-selectable layered pickup effect spawner.
 */
#include "main/dll/dll_00A0_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA0SevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} DllA0SevenIndexList;

STATIC_ASSERT(offsetof(DllA0SevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllA0SevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllA0SevenIndexList) == 0x10);

typedef struct DllA0EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    DllA0SevenIndexList sevenVertexIndexLists[3];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA0EffectResourceView;

STATIC_ASSERT(offsetof(DllA0EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, sevenVertexIndexLists) == 0x164);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(DllA0EffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(DllA0EffectResourceView) == 0x208);

extern u8 gDllA0EffectResourceData[sizeof(DllA0EffectResourceView)];

void dll_A0_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = gDllA0EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    ModgfxCommand* commandCursor;
    u32 fl;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    if (variant == 0) {
        commands[1].stageIndex = 0;
        commands[1].parameter = 0x15;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
        commands[1].flags = 2;
        commands[1].valueX = 0.035f;
        commands[1].valueY = -0.45f;
        commands[1].valueZ = 0.035f;
        commandCursor = commands + 2;
    } else {
        commands[1].stageIndex = 0;
        commands[1].parameter = 0x15;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
        commands[1].flags = 2;
        commands[1].valueX = 0.035f;
        commands[1].valueY = 0.45f;
        commands[1].valueZ = 0.035f;
        commandCursor = commands + 2;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 2;
    commandCursor[0].valueX = 10.0f;
    commandCursor[0].valueY = 10.0f;
    commandCursor[0].valueZ = 10.0f;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 7;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 255.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 0x15;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 0x4000;
    commandCursor[2].valueX = -6.0f;
    commandCursor[2].valueY = 1.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor[3].stageIndex = 2;
    commandCursor[3].parameter = 7;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[3].flags = 2;
    commandCursor[3].valueX = 2.0f;
    commandCursor[3].valueY = 1.0f;
    commandCursor[3].valueZ = 2.0f;
    commandCursor[4].stageIndex = 2;
    commandCursor[4].parameter = 7;
    commandCursor[4].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, sevenVertexIndexLists[2].indices)];
    commandCursor[4].flags = 2;
    commandCursor[4].valueX = 4.0f;
    commandCursor[4].valueY = 1.0f;
    commandCursor[4].valueZ = 4.0f;
    commandCursor[5].stageIndex = 2;
    commandCursor[5].parameter = 0x15;
    commandCursor[5].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
    commandCursor[5].flags = 0x4000;
    commandCursor[5].valueX = -6.0f;
    commandCursor[5].valueY = 1.0f;
    commandCursor[5].valueZ = 0.0f;
    commandCursor[6].stageIndex = 3;
    commandCursor[6].parameter = 7;
    commandCursor[6].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, sevenVertexIndexLists[1].indices)];
    commandCursor[6].flags = 4;
    commandCursor[6].valueX = 0.0f;
    commandCursor[6].valueY = 0.0f;
    commandCursor[6].valueZ = 0.0f;
    commandCursor[7].stageIndex = 3;
    commandCursor[7].parameter = 0x15;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(DllA0EffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 0x4000;
    commandCursor[7].valueX = 6.0f;
    commandCursor[7].valueY = 1.0f;
    commandCursor[7].valueZ = 0.0f;

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
    packet.context.commandCount = &commandCursor[8] - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA0EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    fl = 0xc010480;
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(resourceData), 0x18, (s16*)(&resourceData[offsetof(DllA0EffectResourceView, triangles)]),
                      0x1d9, 0);
}

void dll_A0_release(void) {
}

void dll_A0_initialise(void) {
}

u8 gDllA0EffectResourceData[sizeof(DllA0EffectResourceView)] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,   0,   3,   98,  0,   0,   1,   244, 0,   0,   0,   11,  3,   98,  0,
    0,   254, 12,  0,   0,   0,   22,  0,   0,   0,   0,   252, 24,  0,   0,   0,   32,  252, 158, 0,   0,   254, 12,
    0,   0,   0,   22,  252, 158, 0,   0,   1,   244, 0,   0,   0,   11,  0,   0,   0,   0,   3,   232, 0,   0,   0,
    0,   0,   0,   1,   244, 3,   232, 0,   15,  0,   0,   3,   98,  1,   244, 1,   244, 0,   15,  0,   11,  3,   98,
    1,   244, 254, 12,  0,   15,  0,   22,  0,   0,   1,   244, 252, 24,  0,   15,  0,   32,  252, 158, 1,   244, 254,
    12,  0,   15,  0,   22,  252, 158, 1,   244, 1,   244, 0,   15,  0,   11,  0,   0,   1,   244, 3,   232, 0,   15,
    0,   0,   0,   0,   3,   232, 3,   232, 0,   31,  0,   0,   3,   98,  3,   232, 1,   244, 0,   31,  0,   11,  3,
    98,  3,   232, 254, 12,  0,   31,  0,   22,  0,   0,   3,   232, 252, 24,  0,   31,  0,   32,  252, 158, 3,   232,
    254, 12,  0,   31,  0,   22,  252, 158, 3,   232, 1,   244, 0,   31,  0,   11,  0,   0,   3,   232, 3,   232, 0,
    31,  0,   0,   0,   0,   0,   0,   0,   1,   0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,   9,   0,   8,   0,   2,   0,   3,   0,   10,  0,   2,   0,   10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,   0,   11,  0,   10,  0,   4,   0,   5,   0,   12,  0,   4,   0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,   5,   0,   13,  0,   12,  0,   7,   0,   8,   0,   15,  0,   7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16,  0,   8,   0,   16,  0,   15,  0,   9,   0,   10,  0,   17,  0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,   18,  0,   10,  0,   18,  0,   17,  0,   11,  0,   12,  0,   19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13,  0,   20,  0,   12,  0,   20,  0,   19,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   7,   0,   8,   0,   9,   0,
    10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,
    0,   35,  0,   6,   0,   35,  0,   0,   0,   0,   0,   0,   0,   0};
DllA0ResourceDescriptor gDllA0ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A0_initialise, dll_A0_release, NULL, dll_A0_spawnEffect,
};
