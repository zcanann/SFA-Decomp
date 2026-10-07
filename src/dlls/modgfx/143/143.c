/*
 * DLL 143 / 0x8F - a ten-command layered modgfx effect spawner.
 */
#include "main/dll/dll_008F_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll8FEffectResourceView {
    ModgfxEffectVertex vertices[18];
    s16 triangles[16][3];
    s16 firstNineVertexIndices[9];
    s16 opaque126;
    s16 allVertexIndices[18];
    s16 secondNineVertexIndices[9];
    s16 opaque15E;
    s16 sequenceParams[7];
    u8 opaque16E[0x0E];
} Dll8FEffectResourceView;

STATIC_ASSERT(offsetof(Dll8FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, triangles) == 0x0B4);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, firstNineVertexIndices) == 0x114);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque126) == 0x126);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, allVertexIndices) == 0x128);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, secondNineVertexIndices) == 0x14C);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque15E) == 0x15E);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, sequenceParams) == 0x160);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque16E) == 0x16E);
STATIC_ASSERT(sizeof(Dll8FEffectResourceView) == 0x17C);

u16 gDll8FEffectResourceData[sizeof(Dll8FEffectResourceView) / sizeof(u16)] = {
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
    0x0006, 0x0007, 0x0008, 0x0000, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004,
    0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x000e, 0x000f, 0x0010, 0x0011, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x000e, 0x000f, 0x0010, 0x0011, 0x0000, 0x0000, 0x0032, 0x0000, 0x0064,
    0x0000, 0x0032, 0x0000, 0x0000, 0x0032, 0xfa32, 0x0000, 0x0000, 0x0000,
    0x0000,
};

void dll_8F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll8FEffectResourceData;
    ModgfxCommand* commands = packet.entries;

    commands[0].stageIndex = 0;
    commands[0].parameter = 18;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 18;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.2f;
    commands[1].valueY = 2.0f;
    commands[1].valueZ = 0.2f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 18;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[2].flags = 256;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = 300.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 18;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 185.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 18;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[4].flags = 2;
    commands[4].valueX = 9.0f;
    commands[4].valueY = 0.3f;
    commands[4].valueZ = 9.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 18;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[5].flags = 256;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 300.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 18;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[6].flags = 256;
    commands[6].valueX = 0.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 300.0f;
    commands[7].stageIndex = 3;
    commands[7].parameter = 18;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[7].flags = 4;
    commands[7].valueX = 0.0f;
    commands[7].valueY = 0.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 18;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[8].flags = 2;
    commands[8].valueX = 0.1f;
    commands[8].valueY = 7.0f;
    commands[8].valueZ = 0.1f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 18;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[9].flags = 256;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 300.0f;
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
    packet.context.initialStateByte = 18;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 16;
    packet.context.flags = 0x4000000;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 10) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[6])];
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
        ->spawnEffect(&packet.context, 0, 18, (ModgfxEffectVertex*)(int)gDll8FEffectResourceData, 16,
                      (s16*)(&resourceData[offsetof(Dll8FEffectResourceView, triangles)]), 0x2E, 0);
}

void dll_8F_release(void) {
}

void dll_8F_initialise(void) {
}

Dll8FResourceDescriptor gDll8FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_8F_initialise,
    dll_8F_release,
    NULL,
    dll_8F_spawnEffect,
    0x00000000,
};
