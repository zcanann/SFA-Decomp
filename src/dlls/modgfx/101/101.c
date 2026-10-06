/*
 * DLL 101 / 0x65 - a modgfx effect spawner.
 */
#include "main/dll/dll_0065_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll65EffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll65EffectResourceView;

STATIC_ASSERT(offsetof(Dll65EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll65EffectResourceView, triangleIndices) == 0x08C);
STATIC_ASSERT(offsetof(Dll65EffectResourceView, allVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll65EffectResourceView, firstGroupIndices) == 0x0F0);
STATIC_ASSERT(offsetof(Dll65EffectResourceView, secondGroupIndices) == 0x100);
STATIC_ASSERT(offsetof(Dll65EffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(sizeof(Dll65EffectResourceView) == 0x120);

u16 gDll65EffectResourceData[sizeof(Dll65EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x00c8, 0x01f4, 0x0000,
    0x000a, 0x0362, 0x0028, 0xfe0c, 0x0000, 0x0015, 0x0000, 0x0096, 0xfc18,
    0x0000, 0x001f, 0xfc9e, 0x005a, 0xfe0c, 0x0000, 0x002a, 0xfc9e, 0x000a,
    0x01f4, 0x0000, 0x0034, 0x0000, 0x0096, 0x03e8, 0x0000, 0x003f, 0x0000,
    0x1900, 0x03e8, 0x003f, 0x0000, 0x0362, 0x189c, 0x01f4, 0x003f, 0x000a,
    0x0362, 0x1838, 0xfe0c, 0x003f, 0x0015, 0x0000, 0x1932, 0xfc18, 0x003f,
    0x001f, 0xfc9e, 0x1900, 0xfe0c, 0x003f, 0x002a, 0xfc9e, 0x18ec, 0x01f4,
    0x003f, 0x0034, 0x0000, 0x1928, 0x03e8, 0x003f, 0x003f, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x000d, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0000, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x0000, 0x0000, 0x0104, 0x003c, 0x0001, 0x0104, 0x0000, 0x0000, 0x0000,
};

void dll_65_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands = packet.entries;
    u8* resourceData = (u8*)(int)gDll65EffectResourceData;
    u8 effectScaleTenths;

    if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[1])] = 0;
    }
    effectScaleTenths = ((u8*)sourceObj->anim.placementData)[0x1a];
    commands[0].stageIndex = 0;
    commands[0].parameter = 7;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, firstGroupIndices)];
    commands[0].flags = 8;
    commands[0].valueX = 50.0f;
    commands[0].valueY = 50.0f;
    commands[0].valueZ = 50.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 7;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, secondGroupIndices)];
    commands[1].flags = 8;
    commands[1].valueX = 200.0f;
    commands[1].valueY = 200.0f;
    commands[1].valueZ = 200.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0xe;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, allVertexIndices)];
    commands[2].flags = 4;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = 0.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, secondGroupIndices)];
    commands[3].flags = 2;
    commands[3].valueX = 0.225f;
    commands[3].valueY = 0.62f;
    commands[3].valueZ = 0.225f;
    commands[4].stageIndex = 0;
    commands[4].parameter = 7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, firstGroupIndices)];
    commands[4].flags = 2;
    commands[4].valueX = 0.55f;
    commands[4].valueY = 1.0f;
    commands[4].valueZ = 0.55f;
    commands[5].stageIndex = 1;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x12;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, allVertexIndices)];
    commands[5].flags = 0x100;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 20.0f;
    commands[6].stageIndex = 1;
    commands[6].parameter = 7;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, firstGroupIndices)];
    commands[6].flags = 4;
    commands[6].valueX = 70.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 1;
    commands[7].parameter = 7;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, secondGroupIndices)];
    commands[7].flags = 4;
    commands[7].valueX = 12.0f;
    commands[7].valueY = 0.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x12;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, allVertexIndices)];
    commands[8].flags = 0x4000;
    commands[8].valueX = -0.7f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 0.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 1;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x2000;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    commands[10].stageIndex = 4;
    commands[10].parameter = 7;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, firstGroupIndices)];
    commands[10].flags = 4;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 0.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 4;
    commands[11].parameter = 7;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, secondGroupIndices)];
    commands[11].flags = 4;
    commands[11].valueX = 0.0f;
    commands[11].valueY = 0.0f;
    commands[11].valueZ = 0.0f;
    commands[12].stageIndex = 4;
    commands[12].parameter = 0x12;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll65EffectResourceView, allVertexIndices)];
    commands[12].flags = 0x4000;
    commands[12].valueX = -0.7f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    if (effectScaleTenths != 0) {
        packet.context.scale = 0.1f * (f32)(u32)effectScaleTenths;
    } else {
        packet.context.scale = 1.0f;
    }
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = 13;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll65EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x40000c0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.context.position[0] += params->posX;
            packet.context.position[1] += params->posY;
            packet.context.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll65EffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll65EffectResourceView, triangleIndices)]), 0x40, 0);
}

void dll_65_release(void) {
}

void dll_65_initialise(void) {
}

Dll65ResourceDescriptor gDll65ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_65_initialise, dll_65_release, NULL, dll_65_spawnEffect,
};
