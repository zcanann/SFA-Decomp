/*
 * DLL 123 / 0x7B - a two-variant modgfx effect spawner.
 */
#include "main/dll/dll_007B_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll7BEffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangles[12][3];
    s16 firstSevenVertexIndices[8];
    s16 secondSevenVertexIndices[8];
    s16 allVertexIndices[14];
    s16 innerTenVertexIndices[10];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7BEffectResourceView;

STATIC_ASSERT(offsetof(Dll7BEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, triangles) == 0x08C);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, firstSevenVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, secondSevenVertexIndices) == 0x0E4);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, allVertexIndices) == 0x0F4);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, innerTenVertexIndices) == 0x110);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, sequenceParams) == 0x124);
STATIC_ASSERT(offsetof(Dll7BEffectResourceView, opaqueTail) == 0x132);
STATIC_ASSERT(sizeof(Dll7BEffectResourceView) == 0x134);

extern u8 gDll7BEffectResourceData[];

void dll_7B_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll7BEffectResourceData;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands = packet.entries;
    if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[2])] = 0x1130;
    } else {
        *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[2])] = 100;
    }
    commands[0].stageIndex = 0;
    commands[0].parameter = 0xe;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    if (variant == 1) {
        commands[1].stageIndex = 0;
        commands[1].parameter = 0xe;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
        commands[1].flags = 2;
        commands[1].valueX = 1.0f;
        commands[1].valueY = 1.0f;
        commands[1].valueZ = 1.0f;
        commandCursor = &commands[2];
    } else {
        commands[1].stageIndex = 0;
        commands[1].parameter = 0xe;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
        commands[1].flags = 2;
        commands[1].valueX = 1.0f;
        commands[1].valueY = 0.7f * randomGetRange(3, 5);
        commands[1].valueZ = 1.0f;
        commandCursor = &commands[2];
    }
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0xe;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 0x80;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 16767.0f;
    if (variant == 1) {
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 0xe;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 0x400000;
        commandCursor[1].valueX = 100.0f;
        commandCursor[1].valueY = 75.0f;
        commandCursor[1].valueZ = 0.0f;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 0x190;
        commandCursor[2].vertexIndices = NULL;
        commandCursor[2].flags = 0x20000000;
        commandCursor[2].valueX = 999.0f;
        commandCursor[2].valueY = 111.0f;
        commandCursor[2].valueZ = 112.0f;
        commandCursor[3].stageIndex = 0;
        commandCursor[3].parameter = 0;
        commandCursor[3].vertexIndices = NULL;
        commandCursor[3].flags = 0x80000;
        commandCursor[3].valueX = 70.0f;
        commandCursor[3].valueY = 150.0f;
        commandCursor[3].valueZ = 0.0f;
        commandCursor += 4;
    } else {
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 0xe;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 0x400000;
        commandCursor[1].valueX = 90.0f + randomGetRange(0, 0x14);
        commandCursor[1].valueY = 75.0f;
        commandCursor[1].valueZ = randomGetRange(0, 0x1e);
        commandCursor += 2;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 10;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, innerTenVertexIndices)];
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 255.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 0xe;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 1.0f;
    commandCursor[1].valueY = 1.0f;
    commandCursor[1].valueZ = 1.0f;
    commandCursor += 2;
    if (variant != 1) {
        commandCursor[0].stageIndex = 2;
        commandCursor[0].parameter = 0xe;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x400000;
        commandCursor[0].valueX = -0.3f * randomGetRange(1, 0x28);
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor += 1;
    }
    commandCursor[0].stageIndex = 2;
    commandCursor[0].parameter = 0xe;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 0x4000;
    commandCursor[0].valueX = 0.1f * randomGetRange(-3, 3);
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 3;
    commandCursor[1].parameter = 0xe;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 0x4000;
    commandCursor[1].valueX = 0.3f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 3;
    commandCursor[2].parameter = 10;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll7BEffectResourceView, innerTenVertexIndices)];
    commandCursor[2].flags = 4;
    commandCursor[2].valueX = 0.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor += 3;
    if (variant == 1) {
        commandCursor[0].stageIndex = 3;
        commandCursor[0].parameter = 0;
        commandCursor[0].vertexIndices = NULL;
        commandCursor[0].flags = 0x20000000;
        commandCursor[0].valueX = 999.0f;
        commandCursor[0].valueY = 111.0f;
        commandCursor[0].valueZ = 112.0f;
        commandCursor += 1;
    }
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
    packet.context.textureFrameTimer = randomGetRange(0x18, 0x1c);
    packet.context.commandCount = commandCursor - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7BEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
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
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll7BEffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll7BEffectResourceView, triangles)]), 0x8e, 0);
}

void dll_7B_release(void) {
}

void dll_7B_initialise(void) {
}

u8 gDll7BEffectResourceData[sizeof(Dll7BEffectResourceView)] = {
    244, 72,  0, 0,   254, 212, 0, 0,   0,   0,   247, 104, 0,   0,   1, 244, 0, 6,   0,   0,   252, 24, 0,   0,
    0,   0,   0, 11,  0,   0,   0, 0,   0,   0,   253, 168, 0,   16,  0, 0,   3, 232, 0,   0,   0,   0,  0,   21,
    0,   0,   8, 152, 0,   0,   2, 188, 0,   26,  0,   0,   11,  184, 0, 0,   1, 44,  0,   31,  0,   0,  244, 72,
    3,   32,  0, 0,   0,   0,   0, 31,  247, 104, 5,   220, 254, 112, 0, 6,   0, 31,  252, 24,  5,   20, 0,   0,
    0,   22,  0, 31,  0,   0,   5, 220, 3,   132, 0,   11,  0,   31,  3, 232, 4, 176, 254, 212, 0,   16, 0,   31,
    8,   152, 5, 220, 0,   0,   0, 26,  0,   31,  11,  184, 3,   32,  2, 188, 0, 31,  0,   31,  0,   0,  0,   8,
    0,   7,   0, 0,   0,   1,   0, 8,   0,   1,   0,   9,   0,   8,   0, 1,   0, 2,   0,   9,   0,   2,  0,   10,
    0,   9,   0, 2,   0,   3,   0, 10,  0,   3,   0,   11,  0,   10,  0, 3,   0, 4,   0,   11,  0,   4,  0,   12,
    0,   11,  0, 4,   0,   5,   0, 12,  0,   5,   0,   13,  0,   12,  0, 5,   0, 6,   0,   13,  0,   0,  0,   1,
    0,   2,   0, 3,   0,   4,   0, 5,   0,   6,   0,   0,   0,   7,   0, 8,   0, 9,   0,   10,  0,   11, 0,   12,
    0,   13,  0, 0,   0,   0,   0, 1,   0,   2,   0,   3,   0,   4,   0, 5,   0, 6,   0,   7,   0,   8,  0,   9,
    0,   10,  0, 11,  0,   12,  0, 13,  0,   1,   0,   2,   0,   3,   0, 4,   0, 5,   0,   8,   0,   9,  0,   10,
    0,   11,  0, 12,  0,   0,   0, 50,  0,   200, 0,   50,  0,   0,   0, 0,   0, 0,   0,   0,
};

Dll7BResourceDescriptor gDll7BResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_7B_initialise,
    dll_7B_release,
    NULL,
    dll_7B_spawnEffect,
    0x00000000,
};
