/*
 * DLL 97 / 0x61 - a modgfx effect spawner.
 */
#include "main/dll/dll_0061_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll61EffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangleIndices[8][3];
    s16 nineVertexIndices[10];
    s16 eightVertexIndices[8];
    s16 sequenceParams[7];
    u8 padBE[2];
} Dll61EffectResourceView;

STATIC_ASSERT(offsetof(Dll61EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, triangleIndices) == 0x5C);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, nineVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, eightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(sizeof(Dll61EffectResourceView) == 0xC0);

s16 gDll61VertexEightIndices[4] = {8, 0, 0, 0};

u16 gDll61EffectResourceData[sizeof(Dll61EffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0190, 0x001f, 0x001f, 0x02c3, 0xfd3d, 0x0190, 0x0000,
    0x001f, 0x0000, 0xfc18, 0x0190, 0x001f, 0x001f, 0xfd3d, 0xfd3d, 0x0190,
    0x0000, 0x001f, 0xfc18, 0x0000, 0x0190, 0x001f, 0x001f, 0xfd3d, 0x02c3,
    0x0190, 0x0000, 0x001f, 0x0000, 0x03e8, 0x0190, 0x001f, 0x001f, 0x02c3,
    0x02c3, 0x0190, 0x0000, 0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000,
    0x0000, 0x0000, 0x0001, 0x0008, 0x0001, 0x0002, 0x0008, 0x0002, 0x0003,
    0x0008, 0x0003, 0x0004, 0x0008, 0x0004, 0x0005, 0x0008, 0x0005, 0x0006,
    0x0008, 0x0006, 0x0007, 0x0008, 0x0007, 0x0000, 0x0008, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0000, 0x0000,
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0000, 0x0050,
    0x001e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

void dll_61_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    f32 randomScale;
    u8* resourceData = (u8*)(int)gDll61EffectResourceData;
    ModgfxCommand* commands;
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 1;
    commands[1].vertexIndices = NULL;
    commands[1].flags = 0x2008000;
    commands[1].valueX = 125.0f;
    commands[1].valueY = 255.0f;
    commands[1].valueZ = 125.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x2080000;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 17.0f;
    commands[2].valueZ = -17.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 9;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[3].flags = 0x80;
    commands[3].valueX = 0.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = (f32)sourceObj->anim.rotX;
    commands[4].stageIndex = 0;
    commands[4].parameter = 0x7a;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x10000;
    commands[4].valueX = 0.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 0;
    commands[5].parameter = 9;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[5].flags = 2;
    randomScale = 0.05f * randomGetRange(0, 0xc);
    randomScale = 2.6f + randomScale;
    commands[5].valueX = randomScale;
    commands[5].valueY = randomScale;
    commands[5].valueZ = randomScale;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x10000000;
    commands[6].valueX = 28.0f;
    commands[6].valueY = 2.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 1;
    commands[7].parameter = 8;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[7].flags = 0x4000;
    commands[7].valueX = 0.0f;
    commands[7].valueY = -4.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 1;
    commands[8].parameter = 9;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[8].flags = 0x100;
    commands[8].valueX = 600.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 0.0f;
    commands[9].stageIndex = 1;
    commands[9].parameter = 0;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x400000;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = -200.0f;
    commands[10].stageIndex = 1;
    commands[10].parameter = 0;
    commands[10].vertexIndices = NULL;
    commands[10].flags = 0x2080000;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 17.0f;
    commands[10].valueZ = -200.0f;
    commands[11].stageIndex = 2;
    commands[11].parameter = 8;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[11].flags = 0x4000;
    commands[11].valueX = 0.0f;
    commands[11].valueY = -4.0f;
    commands[11].valueZ = 0.0f;
    commands[12].stageIndex = 2;
    commands[12].parameter = 9;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[12].flags = 0x100;
    commands[12].valueX = 600.0f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 0.0f;
    commands[13].stageIndex = 2;
    commands[13].parameter = 1;
    commands[13].vertexIndices = (s16*)(gDll61VertexEightIndices);
    commands[13].flags = 4;
    commands[13].valueX = 0.0f;
    commands[13].valueY = 0.0f;
    commands[13].valueZ = 0.0f;
    commands[14].stageIndex = 2;
    commands[14].parameter = 0;
    commands[14].vertexIndices = NULL;
    commands[14].flags = 0x2008000;
    commands[14].valueX = 0.0f;
    commands[14].valueY = 0.0f;
    commands[14].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 17.0f;
    packet.context.position[2] = -40.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 9;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 15) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000010;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)sourceObj != NULL) {
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
        ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll61EffectResourceData, 8,
                      (s16*)(&resourceData[offsetof(Dll61EffectResourceView, triangleIndices)]), 0x90, 0);
}

void dll_61_release(void) {
}

void dll_61_initialise(void) {
}

Dll61ResourceDescriptor gDll61ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_61_initialise, dll_61_release, NULL, dll_61_spawnEffect,
};
