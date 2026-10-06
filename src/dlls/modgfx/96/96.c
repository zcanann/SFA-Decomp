/*
 * DLL 96 / 0x60 - a modgfx effect spawner.
 */
#include "main/dll/dll_0060_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll60EffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 allVertexIndices[14];
    s16 tenVertexIndices[10];
    s16 sequenceParams[7];
    u8 pad132[2];
} Dll60EffectResourceView;

STATIC_ASSERT(offsetof(Dll60EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, triangleIndices) == 0x08C);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, firstGroupIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, secondGroupIndices) == 0x0E4);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, allVertexIndices) == 0x0F4);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, tenVertexIndices) == 0x110);
STATIC_ASSERT(offsetof(Dll60EffectResourceView, sequenceParams) == 0x124);
STATIC_ASSERT(sizeof(Dll60EffectResourceView) == 0x134);

u16 gDll60EffectResourceData[sizeof(Dll60EffectResourceView) / sizeof(u16)] = {
    0xf448, 0x0000, 0x0000, 0x0000, 0x0000, 0xf768, 0x0000, 0x044c, 0x000b,
    0x0000, 0xfc18, 0x0000, 0x0898, 0x0016, 0x0000, 0x0000, 0x0000, 0x09c4,
    0x0020, 0x0000, 0x03e8, 0x0000, 0x0898, 0x002a, 0x0000, 0x0898, 0x0000,
    0x044c, 0x0034, 0x0000, 0x0bb8, 0x0000, 0x0000, 0x003f, 0x0000, 0xf448,
    0x05dc, 0x0000, 0x0000, 0x001f, 0xf768, 0x05dc, 0x044c, 0x000b, 0x001f,
    0xfc18, 0x05dc, 0x0898, 0x0016, 0x001f, 0x0000, 0x05dc, 0x09c4, 0x0020,
    0x001f, 0x03e8, 0x05dc, 0x0898, 0x002a, 0x001f, 0x0898, 0x05dc, 0x044c,
    0x0034, 0x001f, 0x0bb8, 0x05dc, 0x0000, 0x003f, 0x001f, 0x0000, 0x0008,
    0x0007, 0x0000, 0x0001, 0x0008, 0x0001, 0x0009, 0x0008, 0x0001, 0x0002,
    0x0009, 0x0002, 0x000a, 0x0009, 0x0002, 0x0003, 0x000a, 0x0003, 0x000b,
    0x000a, 0x0003, 0x0004, 0x000b, 0x0004, 0x000c, 0x000b, 0x0004, 0x0005,
    0x000c, 0x0005, 0x000d, 0x000c, 0x0005, 0x0006, 0x000d, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0000, 0x0007, 0x0008, 0x0009,
    0x000a, 0x000b, 0x000c, 0x000d, 0x0000, 0x0000, 0x0001, 0x0002, 0x0003,
    0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c,
    0x000d, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x0000, 0x0032, 0x0190, 0x0032, 0x0000, 0x0000, 0x0000,
    0x0000,
};

void dll_60_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll60EffectResourceData;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;
    f32 randomAngle;
    commands = packet.entries;
    commandCursor = commands;
    commandCursor = (ModgfxCommand*)((int)commandCursor | (int)commands);
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0xe;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 0xe;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 0.1f;
    commandCursor[1].valueY = 0.1f;
    commandCursor[1].valueZ = 0.1f;
    commandCursor[2].stageIndex = 0;
    commandCursor[2].parameter = 0xe;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 8;
    commandCursor[2].valueX = 150.0f + randomGetRange(0, 0x69);
    commandCursor[2].valueY = 150.0f + randomGetRange(0, 0x69);
    commandCursor[2].valueZ = 150.0f + randomGetRange(0, 0x69);
    commandCursor[3].stageIndex = 0;
    commandCursor[3].parameter = 0x7a;
    commandCursor[3].vertexIndices = NULL;
    commandCursor[3].flags = 0x10000;
    commandCursor[3].valueX = 0.0f;
    commandCursor[3].valueY = 0.0f;
    commandCursor[3].valueZ = 0.0f;
    randomAngle = randomGetRange(0, 0xfffe);
    commandCursor[4].stageIndex = 0;
    commandCursor[4].parameter = 0;
    commandCursor[4].vertexIndices = NULL;
    commandCursor[4].flags = 0x80;
    commandCursor[4].valueX = 0.0f;
    commandCursor[4].valueY = 0.0f;
    commandCursor[4].valueZ = randomAngle;
    commandCursor[5].stageIndex = 1;
    commandCursor[5].parameter = 0xa;
    commandCursor[5].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, tenVertexIndices)];
    commandCursor[5].flags = 4;
    commandCursor[5].valueX = 255.0f;
    commandCursor[5].valueY = 0.0f;
    commandCursor[5].valueZ = 0.0f;
    commandCursor[6].stageIndex = 1;
    commandCursor[6].parameter = 0xe;
    commandCursor[6].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[6].flags = 2;
    commandCursor[6].valueX = 5.0f;
    commandCursor[6].valueY = 5.0f;
    commandCursor[6].valueZ = 5.0f;
    commandCursor[7].stageIndex = 2;
    commandCursor[7].parameter = 0xe;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 0x4000;
    commandCursor[7].valueX = 0.5f;
    commandCursor[7].valueY = 0.0f;
    commandCursor[7].valueZ = 0.0f;
    commandCursor[8].stageIndex = 2;
    commandCursor[8].parameter = 0xe;
    commandCursor[8].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[8].flags = 0x4000;
    commandCursor[8].valueX = 0.5f;
    commandCursor[8].valueY = 0.0f;
    commandCursor[8].valueZ = 0.0f;
    commandCursor[9].stageIndex = 2;
    commandCursor[9].parameter = 0x53;
    commandCursor[9].vertexIndices = NULL;
    commandCursor[9].flags = 0x800000;
    commandCursor[9].valueX = 1.0f;
    commandCursor[9].valueY = 0.0f;
    commandCursor[9].valueZ = 0.0f;
    commandCursor[10].stageIndex = 2;
    commandCursor[10].parameter = 0x54;
    commandCursor[10].vertexIndices = NULL;
    commandCursor[10].flags = 0x1800000;
    commandCursor[10].valueX = 1.0f;
    commandCursor[10].valueY = 0.0f;
    commandCursor[10].valueZ = 8.0f;
    commandCursor[11].stageIndex = 2;
    commandCursor[11].parameter = 0xa;
    commandCursor[11].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, tenVertexIndices)];
    commandCursor[11].flags = 4;
    commandCursor[11].valueX = 0.0f;
    commandCursor[11].valueY = 0.0f;
    commandCursor[11].valueZ = 0.0f;
    commandCursor[12].stageIndex = 2;
    commandCursor[12].parameter = 0xe;
    commandCursor[12].vertexIndices = (s16*)&resourceData[offsetof(Dll60EffectResourceView, allVertexIndices)];
    commandCursor[12].flags = 2;
    commandCursor[12].valueX = 5.0f;
    commandCursor[12].valueY = 5.0f;
    commandCursor[12].valueZ = 5.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 5.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.commandCount = (commandCursor + 13) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll60EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x1000000;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll60EffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll60EffectResourceView, triangleIndices)]), 0x46, 0);
}

void dll_60_release(void) {
}

void dll_60_initialise(void) {
}

Dll60ResourceDescriptor gDll60ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_60_initialise, dll_60_release, NULL, dll_60_spawnEffect, 0,
};
