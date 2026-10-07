/*
 * DLL 140 / 0x8C - a fourteen-command layered modgfx effect spawner.
 */
#include "main/dll/dll_008C_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll8CEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[7];
    s16 opaque172;
    s16 secondSevenVertexIndices[7];
    s16 opaque182;
    s16 thirdSevenVertexIndices[7];
    s16 opaque192;
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8CEffectResourceView;

STATIC_ASSERT(offsetof(Dll8CEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaque172) == 0x172);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaque182) == 0x182);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaque192) == 0x192);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(offsetof(Dll8CEffectResourceView, opaqueTail) == 0x1EA);
STATIC_ASSERT(sizeof(Dll8CEffectResourceView) == 0x1EC);

u8 gDll8CEffectResourceData[sizeof(Dll8CEffectResourceView)] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,  0,   3,   98,  0,   0,   1,  244, 0,   11,  0,   0,   3,   98,  0,
    0,   254, 12,  0,   22,  0,   0,   0,   0,  0,   0,   252, 24,  0,   32, 0,   0,   252, 158, 0,   0,   254, 12,
    0,   42,  0,   0,   252, 158, 0,   0,   1,  244, 0,   52,  0,   0,   0,  0,   0,   0,   3,   232, 0,   63,  0,
    0,   0,   0,   6,   64,  3,   232, 0,   0,  0,   15,  3,   98,  6,   64, 1,   244, 0,   11,  0,   15,  3,   98,
    6,   64,  254, 12,  0,   22,  0,   15,  0,  0,   6,   64,  252, 24,  0,  32,  0,   15,  252, 158, 6,   64,  254,
    12,  0,   42,  0,   15,  252, 158, 6,   64, 1,   244, 0,   52,  0,   15, 0,   0,   6,   64,  3,   232, 0,   63,
    0,   15,  0,   0,   23,  112, 3,   232, 0,  0,   0,   31,  3,   98,  23, 112, 1,   244, 0,   11,  0,   31,  3,
    98,  23,  112, 254, 12,  0,   22,  0,   31, 0,   0,   23,  112, 252, 24, 0,   32,  0,   31,  252, 158, 23,  112,
    254, 12,  0,   42,  0,   31,  252, 158, 23, 112, 1,   244, 0,   52,  0,  31,  0,   0,   23,  112, 3,   232, 0,
    63,  0,   31,  0,   0,   0,   0,   0,   1,  0,   8,   0,   0,   0,   8,  0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,   9,   0,   8,   0,   2,   0,  3,   0,   10,  0,   2,   0,  10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,   0,   11,  0,   10,  0,   4,  0,   5,   0,   12,  0,   4,  0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,   5,   0,   13,  0,   12,  0,  7,   0,   8,   0,   15,  0,  7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16,  0,   8,   0,   16,  0,   15, 0,   9,   0,   10,  0,   17, 0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,   18,  0,   10,  0,   18,  0,  17,  0,   11,  0,   12,  0,  19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13,  0,   20,  0,   12,  0,   20, 0,   19,  0,   0,   0,   1,  0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,  9,   0,   10,  0,   11,  0,  12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19, 0,   20,  0,   0,   0,   0,  0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,  16,  0,   17,  0,   18,  0,  19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,  0,   7,   0,   8,   0,   9,  0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,  18,  0,   19,  0,   20,  0,  0,   0,   0,   0,   60,  0,   60,  0,
    60,  0,   1,   0,   60,  0,   0,   0,   0};

void dll_8C_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = gDll8CEffectResourceData;
    ModgfxCommand* commands = packet.entries;
    GameObject* anchorObj = sourceObj;
    PartFxSpawnParams* anchorParams = spawnParams;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0xE;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, firstAndThirdVertexIndices)];
    commands[1].flags = 2;
    if ((u32)spawnParams != 0) {
        commands[1].valueX = 0.01f * (0.95f * (f32)anchorParams->unk4);
        commands[1].valueY = 0.01f * (0.2f * (f32)anchorParams->unk0);
        commands[1].valueZ = 0.01f * (0.95f * (f32)anchorParams->unk4);
    } else {
        commands[1].valueX = 0.95f;
        commands[1].valueY = 0.2f;
        commands[1].valueZ = 0.95f;
    }
    commands[2].stageIndex = 0;
    commands[2].parameter = 7;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, secondSevenVertexIndices)];
    commands[2].flags = 2;
    if ((u32)spawnParams != 0) {
        commands[2].valueX = 0.01f * (0.95f * (f32)anchorParams->unk4);
        commands[2].valueY = 0.01f * (0.3f * (f32)anchorParams->unk0);
        commands[2].valueZ = 0.01f * (0.95f * (f32)anchorParams->unk4);
    } else {
        commands[2].valueX = 0.95f;
        commands[2].valueY = 0.2f;
        commands[2].valueZ = 0.95f;
    }
    commands[3].stageIndex = 1;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, secondSevenVertexIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 255.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, thirdSevenVertexIndices)];
    commands[4].flags = 4;
    commands[4].valueX = 255.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x15;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, allVertexIndices)];
    commands[5].flags = 0x100;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    if ((u32)spawnParams != 0) {
        commands[5].valueZ = (f32)anchorParams->unk2;
    } else {
        commands[5].valueZ = 10.0f;
    }
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x3A;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x1800000;
    commands[6].valueX = 1.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 5.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x15;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, allVertexIndices)];
    commands[7].flags = 0x100;
    commands[7].valueX = 0.0f;
    commands[7].valueY = 0.0f;
    if ((u32)spawnParams != 0) {
        commands[7].valueZ = (f32)anchorParams->unk2;
    } else {
        commands[7].valueZ = 10.0f;
    }
    commands[8].stageIndex = 3;
    commands[8].parameter = 0x3B8;
    commands[8].vertexIndices = NULL;
    commands[8].flags = 0x1800000;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 5.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 0x15;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, allVertexIndices)];
    commands[9].flags = 0x100;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    if ((u32)spawnParams != 0) {
        commands[9].valueZ = (f32)anchorParams->unk2;
    } else {
        commands[9].valueZ = 10.0f;
    }
    commands[10].stageIndex = 4;
    commands[10].parameter = 0;
    commands[10].vertexIndices = NULL;
    commands[10].flags = 0x1000;
    commands[10].valueX = 2.0f;
    commands[10].valueY = 0.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 5;
    commands[11].parameter = 7;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, secondSevenVertexIndices)];
    commands[11].flags = 4;
    commands[11].valueX = 0.0f;
    commands[11].valueY = 0.0f;
    commands[11].valueZ = 0.0f;
    commands[12].stageIndex = 5;
    commands[12].parameter = 7;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, thirdSevenVertexIndices)];
    commands[12].flags = 4;
    commands[12].valueX = 0.0f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 0.0f;
    commands[13].stageIndex = 5;
    commands[13].parameter = 0x15;
    commands[13].vertexIndices = (s16*)&resourceData[offsetof(Dll8CEffectResourceView, allVertexIndices)];
    commands[13].flags = 0x100;
    commands[13].valueX = 0.0f;
    commands[13].valueY = 0.0f;
    commands[13].valueZ = 10.0f;
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
    packet.context.initialStateByte = 0xE;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1E;
    packet.context.commandCount = 0xE;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll8CEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0xC0400C0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            packet.context.position[0] += anchorObj->anim.worldPosX;
            packet.context.position[1] += anchorObj->anim.worldPosY;
            packet.context.position[2] += anchorObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(resourceData), 0x18,
                      (s16*)(&resourceData[offsetof(Dll8CEffectResourceView, triangles)]), 0x5E0, 0);
}

void dll_8C_release(void) {
}

void dll_8C_initialise(void) {
}

Dll8CResourceDescriptor gDll8CResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_8C_initialise,
    dll_8C_release,
    NULL,
    dll_8C_spawnEffect,
    0x00000000,
};
