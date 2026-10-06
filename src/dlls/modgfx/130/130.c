/*
 * DLL 130 / 0x82 - a layered object-spawn modgfx effect spawner.
 */
#include "main/dll/dll_0082_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll82EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[7];
    s16 opaque172;
    s16 middleSevenVertexIndices[7];
    s16 opaque182;
    u8 opaqueIndexData184[0x2C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    u8 opaqueIndexData1DC[0x1C];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll82EffectResourceView;

STATIC_ASSERT(offsetof(Dll82EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, padD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaque172) == 0x172);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, middleSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaque182) == 0x182);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaqueIndexData184) == 0x184);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaqueIndexData1DC) == 0x1DC);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll82EffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll82EffectResourceView) == 0x208);

u8 gDll82EffectResourceData[sizeof(Dll82EffectResourceView)] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,   0,   3,   98,  0,   0,   1,   244, 0,   11,  0,   0,   3,   98,  0,
    0,   254, 12,  0,   22,  0,   0,   0,   0,   0,   0,   252, 24,  0,   32,  0,   0,   252, 158, 0,   0,   254, 12,
    0,   22,  0,   0,   252, 158, 0,   0,   1,   244, 0,   11,  0,   0,   0,   0,   0,   0,   3,   232, 0,   0,   0,
    0,   0,   0,   1,   244, 3,   232, 0,   0,   0,   15,  3,   98,  1,   244, 1,   244, 0,   11,  0,   15,  3,   98,
    1,   244, 254, 12,  0,   22,  0,   15,  0,   0,   1,   244, 252, 24,  0,   32,  0,   15,  252, 158, 1,   244, 254,
    12,  0,   22,  0,   15,  252, 158, 1,   244, 1,   244, 0,   11,  0,   15,  0,   0,   1,   244, 3,   232, 0,   0,
    0,   15,  0,   0,   23,  112, 3,   232, 0,   0,   0,   127, 3,   98,  23,  112, 1,   244, 0,   11,  0,   127, 3,
    98,  23,  112, 254, 12,  0,   22,  0,   127, 0,   0,   23,  112, 252, 24,  0,   32,  0,   127, 252, 158, 23,  112,
    254, 12,  0,   22,  0,   127, 252, 158, 23,  112, 1,   244, 0,   11,  0,   127, 0,   0,   23,  112, 3,   232, 0,
    0,   0,   127, 0,   0,   0,   0,   0,   1,   0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
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
    0,   20,  0,   40,  0,   20,  0,   0,   0,   0,   0,   0,   0,   0};

void dll_82_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                        void* extraArg) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll82EffectResourceData;
    ModgfxCommand* commands;
    f32 originOffset = 0.0f;
    if (variant == 1 || variant == 4) {
        *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[2])] = 0x50;
    }
    if (variant == 2) {
        *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[2])] = 0x6e;
    }
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[0].flags = 0x4;
    commands[0].valueX = originOffset;
    commands[0].valueY = originOffset;
    commands[0].valueZ = originOffset;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[1].flags = 0x2;
    commands[1].valueX = 0.85f;
    commands[1].valueY = 0.08f;
    commands[1].valueZ = 0.85f;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0x15;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[2].flags = 0x2;
    commands[2].valueX = 1.0f;
    commands[2].valueY = 10.0f;
    commands[2].valueZ = 1.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 0x7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, firstSevenVertexIndices)];
    commands[3].flags = 0x4;
    commands[3].valueX = 255.0f;
    commands[3].valueY = originOffset;
    commands[3].valueZ = originOffset;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0x7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, middleSevenVertexIndices)];
    commands[4].flags = 0x4;
    commands[4].valueX = 55.0f;
    commands[4].valueY = originOffset;
    commands[4].valueZ = originOffset;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x15;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[5].flags = 0x4000;
    commands[5].valueX = 4.0f;
    commands[5].valueY = 2.0f;
    commands[5].valueZ = originOffset;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x1e;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x20000;
    commands[6].valueX = 1.0f;
    commands[6].valueY = originOffset;
    commands[6].valueZ = originOffset;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x15;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[7].flags = 0x2;
    commands[7].valueX = 2.0f;
    commands[7].valueY = 1.0f;
    commands[7].valueZ = 2.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x15;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[8].flags = 0x4000;
    commands[8].valueX = 4.0f;
    commands[8].valueY = 2.0f;
    commands[8].valueZ = originOffset;
    commands[9].stageIndex = 3;
    commands[9].parameter = 0x15;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[9].flags = 0x2;
    commands[9].valueX = 2.0f;
    commands[9].valueY = 1.0f;
    commands[9].valueZ = 2.0f;
    commands[10].stageIndex = 3;
    commands[10].parameter = 0x15;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, allVertexIndices)];
    commands[10].flags = 0x4000;
    commands[10].valueX = 4.0f;
    commands[10].valueY = 2.0f;
    commands[10].valueZ = originOffset;
    commands[11].stageIndex = 3;
    commands[11].parameter = 0x7;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, firstSevenVertexIndices)];
    commands[11].flags = 0x4;
    commands[11].valueX = originOffset;
    commands[11].valueY = originOffset;
    commands[11].valueZ = originOffset;
    commands[12].stageIndex = 3;
    commands[12].parameter = 0x7;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll82EffectResourceView, middleSevenVertexIndices)];
    commands[12].flags = 0x4;
    commands[12].valueX = originOffset;
    commands[12].valueY = originOffset;
    commands[12].valueZ = originOffset;
    commands[13].stageIndex = 3;
    commands[13].parameter = 0x1e;
    commands[13].vertexIndices = NULL;
    commands[13].flags = 0x20000;
    commands[13].valueX = 1.0f;
    commands[13].valueY = originOffset;
    commands[13].valueZ = originOffset;
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
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xa;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 14) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll82EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags = 0xc010480;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.context.position[0] = originOffset + sourceObj->anim.worldPosX;
            packet.context.position[1] = originOffset + sourceObj->anim.worldPosY;
            packet.context.position[2] = originOffset + sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = originOffset + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    if (variant == 3 || variant == 4) {
        (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll82EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll82EffectResourceView, triangles)]), 0xd9, 0);
    } else {
        (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll82EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll82EffectResourceView, triangles)]), 0x2e, 0);
    }
}

void dll_82_release(void) {
}

void dll_82_initialise(void) {
}

Dll82ResourceDescriptor gDll82ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_82_initialise, dll_82_release, NULL, dll_82_spawnEffect,
};
