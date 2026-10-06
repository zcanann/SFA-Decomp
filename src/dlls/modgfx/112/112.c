/*
 * DLL 112 / 0x70 - a modgfx effect spawner.
 */
#include "main/dll/dll_0070_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll70EffectResourceView {
    ModgfxEffectVertex vertices[18];
    s16 triangles[16][3];
    s16 firstNineVertexIndices[10];
    s16 secondNineVertexIndices[10];
    s16 thirdNineVertexIndices[10];
    s16 allVertexIndices[18];
    s16 evenVertexIndices[10];
    s16 oddVertexIndices[6];
    s16 sequenceParams[7];
    u8 pad1A2[2];
} Dll70EffectResourceView;

STATIC_ASSERT(offsetof(Dll70EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, triangles) == 0x0B4);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, firstNineVertexIndices) == 0x114);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, secondNineVertexIndices) == 0x128);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, thirdNineVertexIndices) == 0x13C);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, allVertexIndices) == 0x150);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, evenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, oddVertexIndices) == 0x188);
STATIC_ASSERT(offsetof(Dll70EffectResourceView, sequenceParams) == 0x194);
STATIC_ASSERT(sizeof(Dll70EffectResourceView) == 0x1A4);

s16 gDll70FourVertexIndices[4] = {10, 12, 14, 16};

u16 gDll70EffectResourceData[sizeof(Dll70EffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0000, 0x0000, 0x0000, 0x02c3, 0x0000, 0xfd3d, 0x000f,
    0x0000, 0x0000, 0x0000, 0xfc18, 0x001f, 0x0000, 0xfd3d, 0x0000, 0xfd3d,
    0x002f, 0x0000, 0xfc18, 0x0000, 0x0000, 0x003f, 0x0000, 0xfd3d, 0x0000,
    0x02c3, 0x004f, 0x0000, 0x0000, 0x0000, 0x03e8, 0x005f, 0x0000, 0x02c3,
    0x0000, 0x02c3, 0x006f, 0x0000, 0x03e8, 0x0000, 0x0000, 0x007f, 0x0000,
    0x03e8, 0x07d0, 0x0000, 0x0000, 0x001f, 0x02c3, 0x07d0, 0xfd3d, 0x000f,
    0x001f, 0x0000, 0x07d0, 0xfc18, 0x001f, 0x001f, 0xfd3d, 0x07d0, 0xfd3d,
    0x002f, 0x001f, 0xfc18, 0x07d0, 0x0000, 0x003f, 0x001f, 0xfd3d, 0x07d0,
    0x02c3, 0x004f, 0x001f, 0x0000, 0x07d0, 0x03e8, 0x005f, 0x001f, 0x02c3,
    0x07d0, 0x02c3, 0x006f, 0x001f, 0x03e8, 0x07d0, 0x0000, 0x007f, 0x001f,
    0x0000, 0x0001, 0x000a, 0x0000, 0x000a, 0x0009, 0x0001, 0x0002, 0x000b,
    0x0001, 0x000b, 0x000a, 0x0002, 0x0003, 0x000c, 0x0002, 0x000c, 0x000b,
    0x0003, 0x0004, 0x000d, 0x0003, 0x000d, 0x000c, 0x0004, 0x0005, 0x000e,
    0x0004, 0x000e, 0x000d, 0x0005, 0x0006, 0x000f, 0x0005, 0x000f, 0x000e,
    0x0006, 0x0007, 0x0010, 0x0006, 0x0010, 0x000f, 0x0007, 0x0008, 0x0011,
    0x0007, 0x0011, 0x0010, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0007, 0x0008, 0x0000, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x000e, 0x000f, 0x0010, 0x0011, 0x0000, 0x0012, 0x0013, 0x0014, 0x0015,
    0x0016, 0x0017, 0x0018, 0x0019, 0x001a, 0x0000, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b,
    0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0000, 0x0002, 0x0004,
    0x0006, 0x0008, 0x000a, 0x000c, 0x000e, 0x0010, 0x0000, 0x0009, 0x000b,
    0x000d, 0x000f, 0x0011, 0x0000, 0x0000, 0x002d, 0x0000, 0x0012, 0x0012,
    0x0000, 0x001e, 0x0000,
};

void dll_70_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll70EffectResourceData;
    ModgfxCommand* commands = packet.entries;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x12;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 9;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, firstNineVertexIndices)];
    commands[1].flags = 8;
    commands[1].valueX = 255.0f;
    commands[1].valueY = 255.0f;
    commands[1].valueZ = 0.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 9;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, secondNineVertexIndices)];
    commands[2].flags = 2;
    commands[2].valueX = 1.0f;
    commands[2].valueY = 0.01f;
    commands[2].valueZ = 1.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0x12;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[3].flags = 2;
    commands[3].valueX = 3.5f;
    commands[3].valueY = 1.0f;
    commands[3].valueZ = 3.5f;
    commands[4].stageIndex = 0;
    commands[4].parameter = 9;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, secondNineVertexIndices)];
    commands[4].flags = 8;
    commands[4].valueX = 205.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 0;
    commands[5].parameter = 1;
    commands[5].vertexIndices = NULL;
    commands[5].flags = 0x8000;
    commands[5].valueX = 255.0f;
    commands[5].valueY = 125.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 0;
    commands[6].parameter = 0;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x80000;
    commands[6].valueX = 0.0f;
    commands[6].valueY = 10.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 1;
    commands[7].parameter = 0x12;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[7].flags = 4;
    commands[7].valueX = 255.0f;
    commands[7].valueY = 0.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 1;
    commands[8].parameter = 9;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, secondNineVertexIndices)];
    commands[8].flags = 2;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 150.0f;
    commands[8].valueZ = 1.0f;
    commands[9].stageIndex = 1;
    commands[9].parameter = 0x7a;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x10000;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    commands[10].stageIndex = 1;
    commands[10].parameter = 0;
    commands[10].vertexIndices = NULL;
    commands[10].flags = 0x80000;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 10.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 2;
    commands[11].parameter = 0x9d;
    commands[11].vertexIndices = NULL;
    commands[11].flags = 0x20000;
    commands[11].valueX = 0.0f;
    commands[11].valueY = 0.0f;
    commands[11].valueZ = 0.0f;
    commands[12].stageIndex = 3;
    commands[12].parameter = 9;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, firstNineVertexIndices)];
    commands[12].flags = 8;
    commands[12].valueX = 255.0f;
    commands[12].valueY = 155.0f;
    commands[12].valueZ = 0.0f;
    commands[13].stageIndex = 3;
    commands[13].parameter = 0x12;
    commands[13].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[13].flags = 0x100;
    commands[13].valueX = 0.0f;
    commands[13].valueY = 0.0f;
    commands[13].valueZ = -10.0f;
    commands[14].stageIndex = 3;
    commands[14].parameter = 5;
    commands[14].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, oddVertexIndices)];
    commands[14].flags = 2;
    commands[14].valueX = 0.98f;
    commands[14].valueY = 1.0f;
    commands[14].valueZ = 0.98f;
    commands[15].stageIndex = 3;
    commands[15].parameter = 4;
    commands[15].vertexIndices = (s16*)(gDll70FourVertexIndices);
    commands[15].flags = 2;
    commands[15].valueX = 1.02f;
    commands[15].valueY = 1.0f;
    commands[15].valueZ = 1.02f;
    commands[16].stageIndex = 3;
    commands[16].parameter = 0;
    commands[16].vertexIndices = NULL;
    commands[16].flags = 0x80000;
    commands[16].valueX = 0.0f;
    commands[16].valueY = -30.0f;
    commands[16].valueZ = 0.0f;
    commands[17].stageIndex = 4;
    commands[17].parameter = 9;
    commands[17].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, firstNineVertexIndices)];
    commands[17].flags = 8;
    commands[17].valueX = 255.0f;
    commands[17].valueY = 255.0f;
    commands[17].valueZ = 0.0f;
    commands[18].stageIndex = 4;
    commands[18].parameter = 0x12;
    commands[18].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[18].flags = 0x100;
    commands[18].valueX = 0.0f;
    commands[18].valueY = 0.0f;
    commands[18].valueZ = -10.0f;
    commands[19].stageIndex = 4;
    commands[19].parameter = 5;
    commands[19].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, oddVertexIndices)];
    commands[19].flags = 2;
    commands[19].valueX = 1.02f;
    commands[19].valueY = 1.0f;
    commands[19].valueZ = 1.02f;
    commands[20].stageIndex = 4;
    commands[20].parameter = 4;
    commands[20].vertexIndices = (s16*)(gDll70FourVertexIndices);
    commands[20].flags = 2;
    commands[20].valueX = 0.98f;
    commands[20].valueY = 1.0f;
    commands[20].valueZ = 0.98f;
    commands[21].stageIndex = 5;
    commands[21].parameter = 2;
    commands[21].vertexIndices = NULL;
    commands[21].flags = 0x1000;
    commands[21].valueX = 1.0f;
    commands[21].valueY = 0.0f;
    commands[21].valueZ = 0.0f;
    commands[22].stageIndex = 6;
    commands[22].parameter = 0x9d;
    commands[22].vertexIndices = NULL;
    commands[22].flags = 0x20000;
    commands[22].valueX = 0.0f;
    commands[22].valueY = 0.0f;
    commands[22].valueZ = 0.0f;
    commands[23].stageIndex = 6;
    commands[23].parameter = 0x9b;
    commands[23].vertexIndices = NULL;
    commands[23].flags = 0x10000;
    commands[23].valueX = 0.0f;
    commands[23].valueY = 0.0f;
    commands[23].valueZ = 0.0f;
    commands[24].stageIndex = 6;
    commands[24].parameter = 0x12;
    commands[24].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[24].flags = 4;
    commands[24].valueX = 0.0f;
    commands[24].valueY = 0.0f;
    commands[24].valueZ = 0.0f;
    commands[25].stageIndex = 6;
    commands[25].parameter = 0x12;
    commands[25].vertexIndices = (s16*)&resourceData[offsetof(Dll70EffectResourceView, allVertexIndices)];
    commands[25].flags = 2;
    commands[25].valueX = 2.0f;
    commands[25].valueY = 1.0f;
    commands[25].valueZ = 2.0f;
    commands[26].stageIndex = 6;
    commands[26].parameter = 0;
    commands[26].vertexIndices = NULL;
    commands[26].flags = 0x80000;
    commands[26].valueX = 0.0f;
    commands[26].valueY = -30.0f;
    commands[26].valueZ = 0.0f;
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
    packet.context.textureFrameTimer = 0xc;
    packet.context.flags = 0x1000082;
    packet.context.commandCount = 27;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll70EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet.context.velocity[0] + 0x40);
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
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
        ->spawnEffect(&packet.context, 0, 0x12, (ModgfxEffectVertex*)(int)gDll70EffectResourceData, 0x10,
                      (s16*)(&resourceData[offsetof(Dll70EffectResourceView, triangles)]), 0x45, 0);
}

void dll_70_release(void) {
}

void dll_70_initialise(void) {
}

Dll70ResourceDescriptor gDll70ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_70_initialise, dll_70_release, NULL, dll_70_spawnEffect, 0,
};
