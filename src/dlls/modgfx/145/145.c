#include "main/dll/dll_0091_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll91EffectResourceView {
    ModgfxEffectVertex vertices[18];
    s16 triangles[16][3];
    s16 firstNineVertexIndices[9];
    s16 opaque126;
    s16 secondNineVertexIndices[9];
    s16 opaque13A;
    s16 thirdNineVertexIndices[9];
    s16 opaque14E;
    s16 allVertexIndices[18];
    s16 evenVertexIndices[9];
    s16 opaque186;
    s16 oddVertexIndices[5];
    s16 opaque192;
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll91EffectResourceView;

STATIC_ASSERT(offsetof(Dll91EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, triangles) == 0x0B4);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, firstNineVertexIndices) == 0x114);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaque126) == 0x126);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, secondNineVertexIndices) == 0x128);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaque13A) == 0x13A);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, thirdNineVertexIndices) == 0x13C);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaque14E) == 0x14E);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, allVertexIndices) == 0x150);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, evenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaque186) == 0x186);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, oddVertexIndices) == 0x188);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaque192) == 0x192);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, sequenceParams) == 0x194);
STATIC_ASSERT(offsetof(Dll91EffectResourceView, opaqueTail) == 0x1A2);
STATIC_ASSERT(sizeof(Dll91EffectResourceView) == 0x1A4);

s16 gDll91VertexIndices[4] = {10, 12, 14, 16};

extern u8 gDll91EffectResourceData[sizeof(Dll91EffectResourceView)];

void dll_91_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll91EffectResourceData;
    ModgfxCommand* commands = packet.entries;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x12;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[0].flags = 0x4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 9;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, firstNineVertexIndices)];
    commands[1].flags = 0x8;
    commands[1].valueX = 0.0f;
    commands[1].valueY = 0.0f;
    commands[1].valueZ = 255.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 9;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, secondNineVertexIndices)];
    commands[2].flags = 0x2;
    commands[2].valueX = 3.0f;
    commands[2].valueY = 0.03f;
    commands[2].valueZ = 3.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0x12;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[3].flags = 0x2;
    commands[3].valueX = 1.75f;
    commands[3].valueY = 0.5f;
    commands[3].valueZ = 1.75f;
    commands[4].stageIndex = 0;
    commands[4].parameter = 9;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, secondNineVertexIndices)];
    commands[4].flags = 0x8;
    commands[4].valueX = 255.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 255.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x12;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[5].flags = 0x4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 1;
    commands[6].parameter = 9;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, secondNineVertexIndices)];
    commands[6].flags = 0x2;
    commands[6].valueX = 1.0f;
    commands[6].valueY = 150.0f;
    commands[6].valueZ = 1.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0;
    commands[7].vertexIndices = NULL;
    commands[7].flags = 0x20;
    commands[7].valueX = 0.0f;
    commands[7].valueY = 0.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 9;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, firstNineVertexIndices)];
    commands[8].flags = 0x8;
    commands[8].valueX = 255.0f;
    commands[8].valueY = 155.0f;
    commands[8].valueZ = 0.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 0x12;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[9].flags = 0x100;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = -10.0f;
    commands[10].stageIndex = 3;
    commands[10].parameter = 5;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, oddVertexIndices)];
    commands[10].flags = 0x2;
    commands[10].valueX = 0.98f;
    commands[10].valueY = 1.0f;
    commands[10].valueZ = 0.98f;
    commands[11].stageIndex = 3;
    commands[11].parameter = 4;
    commands[11].vertexIndices = (s16*)(gDll91VertexIndices);
    commands[11].flags = 0x2;
    commands[11].valueX = 1.02f;
    commands[11].valueY = 1.0f;
    commands[11].valueZ = 1.02f;
    commands[12].stageIndex = 4;
    commands[12].parameter = 9;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, firstNineVertexIndices)];
    commands[12].flags = 0x8;
    commands[12].valueX = 255.0f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 255.0f;
    commands[13].stageIndex = 4;
    commands[13].parameter = 0x12;
    commands[13].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[13].flags = 0x100;
    commands[13].valueX = 0.0f;
    commands[13].valueY = 0.0f;
    commands[13].valueZ = -10.0f;
    commands[14].stageIndex = 4;
    commands[14].parameter = 5;
    commands[14].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, oddVertexIndices)];
    commands[14].flags = 0x2;
    commands[14].valueX = 1.02f;
    commands[14].valueY = 1.0f;
    commands[14].valueZ = 1.02f;
    commands[15].stageIndex = 4;
    commands[15].parameter = 4;
    commands[15].vertexIndices = (s16*)(gDll91VertexIndices);
    commands[15].flags = 0x2;
    commands[15].valueX = 0.98f;
    commands[15].valueY = 1.0f;
    commands[15].valueZ = 0.98f;
    commands[16].stageIndex = 5;
    commands[16].parameter = 2;
    commands[16].vertexIndices = NULL;
    commands[16].flags = 0x1000;
    commands[16].valueX = 1.0f;
    commands[16].valueY = 0.0f;
    commands[16].valueZ = 0.0f;
    commands[17].stageIndex = 6;
    commands[17].parameter = 0x12;
    commands[17].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[17].flags = 0x4;
    commands[17].valueX = 0.0f;
    commands[17].valueY = 0.0f;
    commands[17].valueZ = 0.0f;
    commands[18].stageIndex = 6;
    commands[18].parameter = 0x12;
    commands[18].vertexIndices = (s16*)&resourceData[offsetof(Dll91EffectResourceView, allVertexIndices)];
    commands[18].flags = 0x2;
    commands[18].valueX = 2.0f;
    commands[18].valueY = 1.0f;
    commands[18].valueZ = 2.0f;
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
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0x12;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xC;
    packet.context.flags = 0x1000082;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 19) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll91EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
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
        ->spawnEffect(&packet.context, 0, 0x12, (ModgfxEffectVertex*)(int)gDll91EffectResourceData, 0x10,
                      (s16*)(&resourceData[offsetof(Dll91EffectResourceView, triangles)]), 0x45, 0);
}

void dll_91_release(void) {
}

void dll_91_initialise(void) {
}

u8 gDll91EffectResourceData[sizeof(Dll91EffectResourceView)] = {
    3,   232, 0,   0,   0,   0,   0,   0,   0,   0,   2,   195, 0, 0,   253, 61,  0,   15,  0,   0,   0,   0,   0, 0,
    252, 24,  0,   31,  0,   0,   253, 61,  0,   0,   253, 61,  0, 47,  0,   0,   252, 24,  0,   0,   0,   0,   0, 63,
    0,   0,   253, 61,  0,   0,   2,   195, 0,   79,  0,   0,   0, 0,   0,   0,   3,   232, 0,   95,  0,   0,   2, 195,
    0,   0,   2,   195, 0,   111, 0,   0,   3,   232, 0,   0,   0, 0,   0,   127, 0,   0,   3,   232, 7,   208, 0, 0,
    0,   0,   0,   31,  2,   195, 7,   208, 253, 61,  0,   15,  0, 31,  0,   0,   7,   208, 252, 24,  0,   31,  0, 31,
    253, 61,  7,   208, 253, 61,  0,   47,  0,   31,  252, 24,  7, 208, 0,   0,   0,   63,  0,   31,  253, 61,  7, 208,
    2,   195, 0,   79,  0,   31,  0,   0,   7,   208, 3,   232, 0, 95,  0,   31,  2,   195, 7,   208, 2,   195, 0, 111,
    0,   31,  3,   232, 7,   208, 0,   0,   0,   127, 0,   31,  0, 0,   0,   1,   0,   10,  0,   0,   0,   10,  0, 9,
    0,   1,   0,   2,   0,   11,  0,   1,   0,   11,  0,   10,  0, 2,   0,   3,   0,   12,  0,   2,   0,   12,  0, 11,
    0,   3,   0,   4,   0,   13,  0,   3,   0,   13,  0,   12,  0, 4,   0,   5,   0,   14,  0,   4,   0,   14,  0, 13,
    0,   5,   0,   6,   0,   15,  0,   5,   0,   15,  0,   14,  0, 6,   0,   7,   0,   16,  0,   6,   0,   16,  0, 15,
    0,   7,   0,   8,   0,   17,  0,   7,   0,   17,  0,   16,  0, 0,   0,   1,   0,   2,   0,   3,   0,   4,   0, 5,
    0,   6,   0,   7,   0,   8,   0,   0,   0,   9,   0,   10,  0, 11,  0,   12,  0,   13,  0,   14,  0,   15,  0, 16,
    0,   17,  0,   0,   0,   18,  0,   19,  0,   20,  0,   21,  0, 22,  0,   23,  0,   24,  0,   25,  0,   26,  0, 0,
    0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0, 6,   0,   7,   0,   8,   0,   9,   0,   10,  0, 11,
    0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,  0, 0,   0,   2,   0,   4,   0,   6,   0,   8,   0, 10,
    0,   12,  0,   14,  0,   16,  0,   0,   0,   9,   0,   11,  0, 13,  0,   15,  0,   17,  0,   0,   0,   0,   0, 45,
    0,   0,   0,   18,  0,   18,  0,   0,   0,   30,  0,   0,
};
Dll91ResourceDescriptor gDll91ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_91_initialise,
    dll_91_release,
    NULL,
    dll_91_spawnEffect,
    0x00000000,
};
