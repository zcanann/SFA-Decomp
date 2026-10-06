/*
 * DLL 157 / 0x9D - a multi-layer pickup glow effect spawner.
 */
#include "main/dll/dll_009D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll9DSevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} Dll9DSevenIndexList;

STATIC_ASSERT(offsetof(Dll9DSevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(Dll9DSevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll9DSevenIndexList) == 0x10);

typedef struct Dll9DEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    Dll9DSevenIndexList sevenVertexIndexLists[3];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll9DEffectResourceView;

STATIC_ASSERT(offsetof(Dll9DEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, sevenVertexIndexLists) == 0x164);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll9DEffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll9DEffectResourceView) == 0x208);

extern u32 gDll9DEffectResourceData[sizeof(Dll9DEffectResourceView) / sizeof(u32)];

void dll_9D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll9DEffectResourceData;
    ModgfxCommand* commands = packet.entries;
    u32 effectFlags;
    f32 originOffset = 0.0f;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = originOffset;
    commands[0].valueY = originOffset;
    commands[0].valueZ = originOffset;
    commands[1].stageIndex = 0;
    commands[1].parameter = 7;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, sevenVertexIndexLists[0].indices)];
    commands[1].flags = 2;
    commands[1].valueX = 16.0f;
    commands[1].valueY = 20.0f;
    commands[1].valueZ = 16.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 7;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[2].flags = 2;
    commands[2].valueX = 20.0f;
    commands[2].valueY = 20.0f;
    commands[2].valueZ = 20.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, sevenVertexIndexLists[2].indices)];
    commands[3].flags = 2;
    commands[3].valueX = 16.0f;
    commands[3].valueY = 20.0f;
    commands[3].valueZ = 16.0f;
    commands[4].stageIndex = 0;
    commands[4].parameter = 0;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x400000;
    commands[4].valueX = originOffset;
    commands[4].valueY = -600.0f;
    commands[4].valueZ = originOffset;
    commands[5].stageIndex = 1;
    commands[5].parameter = 7;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[5].flags = 4;
    commands[5].valueX = 105.0f;
    commands[5].valueY = originOffset;
    commands[5].valueZ = originOffset;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = originOffset;
    commands[6].valueY = originOffset;
    commands[6].valueZ = originOffset;
    commands[7].stageIndex = 1;
    commands[7].parameter = 0;
    commands[7].vertexIndices = NULL;
    commands[7].flags = 0x400000;
    commands[7].valueX = originOffset;
    commands[7].valueY = 1200.0f;
    commands[7].valueZ = originOffset;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x15;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, allVertexIndices)];
    commands[8].flags = 0x4000;
    commands[8].valueX = originOffset;
    commands[8].valueY = originOffset;
    commands[8].valueZ = originOffset;
    commands[9].stageIndex = 2;
    commands[9].parameter = 0;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x400000;
    commands[9].valueX = originOffset;
    commands[9].valueY = -1200.0f;
    commands[9].valueZ = originOffset;
    commands[10].stageIndex = 3;
    commands[10].parameter = 0x15;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, allVertexIndices)];
    commands[10].flags = 0x4000;
    commands[10].valueX = originOffset;
    commands[10].valueY = originOffset;
    commands[10].valueZ = originOffset;
    commands[11].stageIndex = 3;
    commands[11].parameter = 0;
    commands[11].vertexIndices = NULL;
    commands[11].flags = 0x400000;
    commands[11].valueX = originOffset;
    commands[11].valueY = 1200.0f;
    commands[11].valueZ = originOffset;
    commands[12].stageIndex = 3;
    commands[12].parameter = 7;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll9DEffectResourceView, sevenVertexIndexLists[1].indices)];
    commands[12].flags = 4;
    commands[12].valueX = originOffset;
    commands[12].valueY = originOffset;
    commands[12].valueZ = originOffset;

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
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + (int)sizeof(ModgfxCommand) * 13) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll9DEffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags = 0xc0100c0;
    packet.context.flags |= spawnFlags;
    effectFlags = packet.context.flags;
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll9DEffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll9DEffectResourceView, triangles)]), 0x46c, 0);
}

void dll_9D_release(void) {
}

void dll_9D_initialise(void) {
}

u32 gDll9DEffectResourceData[sizeof(Dll9DEffectResourceView) / sizeof(u32)] = {
    0x00000000, 0x03e80000, 0x00000362, 0x000001f4, 0x00160000, 0x03620000, 0xfe0c002c, 0x00000000, 0x0000fc18,
    0x003f0000, 0xfc9e0000, 0xfe0c002c, 0x0000fc9e, 0x000001f4, 0x00160000, 0x00000000, 0x03e80000, 0x00000000,
    0x0bb803e8, 0x0000000f, 0x03620bb8, 0x01f40016, 0x000f0362, 0x0bb8fe0c, 0x002c000f, 0x00000bb8, 0xfc18003f,
    0x000ffc9e, 0x0bb8fe0c, 0x002c000f, 0xfc9e0bb8, 0x01f40016, 0x000f0000, 0x0bb803e8, 0x0000000f, 0x00001770,
    0x03e80000, 0x001f0362, 0x177001f4, 0x0016001f, 0x03621770, 0xfe0c002c, 0x001f0000, 0x1770fc18, 0x003f001f,
    0xfc9e1770, 0xfe0c002c, 0x001ffc9e, 0x177001f4, 0x0016001f, 0x00001770, 0x03e80000, 0x001f0000, 0x00000001,
    0x00080000, 0x00080007, 0x00010002, 0x00090001, 0x00090008, 0x00020003, 0x000a0002, 0x000a0009, 0x00030004,
    0x000b0003, 0x000b000a, 0x00040005, 0x000c0004, 0x000c000b, 0x00050006, 0x000d0005, 0x000d000c, 0x00070008,
    0x000f0007, 0x000f000e, 0x00080009, 0x00100008, 0x0010000f, 0x0009000a, 0x00110009, 0x00110010, 0x000a000b,
    0x0012000a, 0x00120011, 0x000b000c, 0x0013000b, 0x00130012, 0x000c000d, 0x0014000c, 0x00140013, 0x00000001,
    0x00020003, 0x00040005, 0x00060000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d0000, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00000001, 0x00020003, 0x00040005, 0x0006000e, 0x000f0010, 0x00110012, 0x00130014,
    0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080009, 0x000a000b, 0x000c000d, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d000e, 0x000f0010, 0x00110012, 0x00130014,
    0x000000fa, 0x00fa00fa, 0x00010000, 0x00000000};
Dll9DResourceDescriptor gDll9DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_9D_initialise, dll_9D_release, NULL, dll_9D_spawnEffect,
};
