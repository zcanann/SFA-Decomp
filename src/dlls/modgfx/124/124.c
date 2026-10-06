/*
 * DLL 124 / 0x7C - a six-variant foodbag modgfx effect spawner.
 */
#include "main/dll/dll_007C_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll7CEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[8];
    s16 secondSevenVertexIndices[8];
    s16 thirdSevenVertexIndices[8];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[22];
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7CEffectResourceView;

STATIC_ASSERT(offsetof(Dll7CEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, padD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll7CEffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll7CEffectResourceView) == 0x208);

u8 gFoodbagEffectResourceTable[sizeof(Dll7CEffectResourceView)] = {
    0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62, 0x00, 0x00, 0x01, 0xF4, 0x00, 0x0B, 0x00,
    0x00, 0x03, 0x62, 0x00, 0x00, 0xFE, 0x0C, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFC, 0x18, 0x00, 0x20,
    0x00, 0x00, 0xFC, 0x9E, 0x00, 0x00, 0xFE, 0x0C, 0x00, 0x16, 0x00, 0x00, 0xFC, 0x9E, 0x00, 0x00, 0x01, 0xF4, 0x00,
    0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4, 0x03, 0xE8,
    0x00, 0x00, 0x00, 0x0F, 0x03, 0x62, 0x01, 0xF4, 0x01, 0xF4, 0x00, 0x0B, 0x00, 0x0F, 0x03, 0x62, 0x01, 0xF4, 0xFE,
    0x0C, 0x00, 0x16, 0x00, 0x0F, 0x00, 0x00, 0x01, 0xF4, 0xFC, 0x18, 0x00, 0x20, 0x00, 0x0F, 0xFC, 0x9E, 0x01, 0xF4,
    0xFE, 0x0C, 0x00, 0x16, 0x00, 0x0F, 0xFC, 0x9E, 0x01, 0xF4, 0x01, 0xF4, 0x00, 0x0B, 0x00, 0x0F, 0x00, 0x00, 0x01,
    0xF4, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x17, 0x70, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x7F, 0x03, 0x62,
    0x17, 0x70, 0x01, 0xF4, 0x00, 0x0B, 0x00, 0x7F, 0x03, 0x62, 0x17, 0x70, 0xFE, 0x0C, 0x00, 0x16, 0x00, 0x7F, 0x00,
    0x00, 0x17, 0x70, 0xFC, 0x18, 0x00, 0x20, 0x00, 0x7F, 0xFC, 0x9E, 0x17, 0x70, 0xFE, 0x0C, 0x00, 0x16, 0x00, 0x7F,
    0xFC, 0x9E, 0x17, 0x70, 0x01, 0xF4, 0x00, 0x0B, 0x00, 0x7F, 0x00, 0x00, 0x17, 0x70, 0x03, 0xE8, 0x00, 0x00, 0x00,
    0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x09, 0x00, 0x01, 0x00, 0x09, 0x00, 0x08, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x0A, 0x00,
    0x09, 0x00, 0x03, 0x00, 0x04, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x0B, 0x00, 0x0A, 0x00, 0x04, 0x00, 0x05, 0x00, 0x0C,
    0x00, 0x04, 0x00, 0x0C, 0x00, 0x0B, 0x00, 0x05, 0x00, 0x06, 0x00, 0x0D, 0x00, 0x05, 0x00, 0x0D, 0x00, 0x0C, 0x00,
    0x07, 0x00, 0x08, 0x00, 0x0F, 0x00, 0x07, 0x00, 0x0F, 0x00, 0x0E, 0x00, 0x08, 0x00, 0x09, 0x00, 0x10, 0x00, 0x08,
    0x00, 0x10, 0x00, 0x0F, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x11, 0x00, 0x09, 0x00, 0x11, 0x00, 0x10, 0x00, 0x0A, 0x00,
    0x0B, 0x00, 0x12, 0x00, 0x0A, 0x00, 0x12, 0x00, 0x11, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x13, 0x00, 0x0B, 0x00, 0x13,
    0x00, 0x12, 0x00, 0x0C, 0x00, 0x0D, 0x00, 0x14, 0x00, 0x0C, 0x00, 0x14, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A,
    0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x0F, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00,
    0x13, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
    0x00, 0x0E, 0x00, 0x0F, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B,
    0x00, 0x0C, 0x00, 0x0D, 0x00, 0x0E, 0x00, 0x0F, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00, 0x14, 0x00,
    0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0D, 0x00, 0x0E, 0x00, 0x0F,
    0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x3C, 0x00, 0x1E, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void dll_7C_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = gFoodbagEffectResourceTable;
    ModgfxCommand* commands = packet.entries;
    ModgfxCommand* commandCursor = &commands[1];

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    if (variant == 0 || variant == 3) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.5f;
        commandCursor->valueY = 0.05f;
        commandCursor->valueZ = 0.5f;
        commandCursor++;
    } else if (variant == 1 || variant == 2) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.35f;
        commandCursor->valueY = 0.05f;
        commandCursor->valueZ = 0.35f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.35f;
        commandCursor->valueY = 0.05f;
        commandCursor->valueZ = 0.35f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x400000;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = -10.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 0x15;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 1.0f;
    commandCursor[1].valueY = 10.0f;
    commandCursor[1].valueZ = 1.0f;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 7;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, firstSevenVertexIndices)];
    commandCursor[2].flags = 4;
    commandCursor[2].valueX = 155.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor[3].stageIndex = 1;
    commandCursor[3].parameter = 7;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, secondSevenVertexIndices)];
    commandCursor[3].flags = 4;
    commandCursor[3].valueX = 55.0f;
    commandCursor[3].valueY = 0.0f;
    commandCursor[3].valueZ = 0.0f;
    commandCursor[4].stageIndex = 1;
    commandCursor[4].parameter = 0x15;
    commandCursor[4].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
    commandCursor[4].flags = 0x4000;
    commandCursor[4].valueX = 4.0f;
    commandCursor[4].valueY = 8.0f;
    commandCursor[4].valueZ = 0.0f;
    commandCursor[5].stageIndex = 1;
    commandCursor[5].parameter = 0;
    commandCursor[5].vertexIndices = NULL;
    commandCursor[5].flags = 0x400000;
    commandCursor[5].valueX = 0.0f;
    commandCursor[5].valueY = 15.0f;
    commandCursor[5].valueZ = 0.0f;
    commandCursor[6].stageIndex = 2;
    commandCursor[6].parameter = 0x1e;
    commandCursor[6].vertexIndices = NULL;
    commandCursor[6].flags = 0x20000;
    commandCursor[6].valueX = 1.0f;
    commandCursor[6].valueY = 0.0f;
    commandCursor[6].valueZ = 0.0f;
    commandCursor[7].stageIndex = 2;
    commandCursor[7].parameter = 0x15;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 0x4000;
    commandCursor[7].valueX = 4.0f;
    commandCursor[7].valueY = 8.0f;
    commandCursor[7].valueZ = 0.0f;
    commandCursor[8].stageIndex = 2;
    commandCursor[8].parameter = 0;
    commandCursor[8].vertexIndices = NULL;
    commandCursor[8].flags = 0x400000;
    commandCursor[8].valueX = 0.0f;
    commandCursor[8].valueY = 30.0f;
    commandCursor[8].valueZ = 0.0f;
    commandCursor[9].stageIndex = 3;
    commandCursor[9].parameter = 0x15;
    commandCursor[9].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, allVertexIndices)];
    commandCursor[9].flags = 0x4000;
    commandCursor[9].valueX = 4.0f;
    commandCursor[9].valueY = 8.0f;
    commandCursor[9].valueZ = 0.0f;
    commandCursor[10].stageIndex = 3;
    commandCursor[10].parameter = 7;
    commandCursor[10].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, firstSevenVertexIndices)];
    commandCursor[10].flags = 4;
    commandCursor[10].valueX = 0.0f;
    commandCursor[10].valueY = 0.0f;
    commandCursor[10].valueZ = 0.0f;
    commandCursor[11].stageIndex = 3;
    commandCursor[11].parameter = 7;
    commandCursor[11].vertexIndices = (s16*)&resourceData[offsetof(Dll7CEffectResourceView, secondSevenVertexIndices)];
    commandCursor[11].flags = 4;
    commandCursor[11].valueX = 0.0f;
    commandCursor[11].valueY = 0.0f;
    commandCursor[11].valueZ = 0.0f;
    commandCursor[12].stageIndex = 3;
    commandCursor[12].parameter = 0x1e;
    commandCursor[12].vertexIndices = NULL;
    commandCursor[12].flags = 0x20000;
    commandCursor[12].valueX = 1.0f;
    commandCursor[12].valueY = 0.0f;
    commandCursor[12].valueZ = 0.0f;
    commandCursor[13].stageIndex = 3;
    commandCursor[13].parameter = 0;
    commandCursor[13].vertexIndices = NULL;
    commandCursor[13].flags = 0x400000;
    commandCursor[13].valueX = 0.0f;
    commandCursor[13].valueY = 15.0f;
    commandCursor[13].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    switch (variant) {
    case 0:
        packet.context.position[0] = 0.0f;
        packet.context.position[2] = 23.0f;
        break;
    case 1:
        packet.context.position[0] = -17.0f;
        packet.context.position[2] = 18.0f;
        break;
    case 2:
        packet.context.position[0] = 17.0f;
        packet.context.position[2] = 18.0f;
        break;
    case 3:
        packet.context.position[0] = 0.0f;
        packet.context.position[2] = -26.0f;
        break;
    case 4:
        packet.context.position[0] = -17.0f;
        packet.context.position[2] = -12.0f;
        break;
    case 5:
        packet.context.position[0] = 17.0f;
        packet.context.position[2] = -12.0f;
        break;
    }
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xa;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commandCursor + sizeof(ModgfxCommand) * 14) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7CEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc010080;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)packet.context.sourceObject != 0) {
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(resourceData), 0x18,
                      (s16*)(&resourceData[offsetof(Dll7CEffectResourceView, triangles)]), 0x2e, 0);
}

void dll_7C_release(void) {
}

void dll_7C_initialise(void) {
}

Dll7CResourceDescriptor gDll7CResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_7C_initialise, dll_7C_release, NULL, dll_7C_spawnEffect,
};
