/*
 * DLL 99 / 0x63 - save-icon / preview modgfx effect DLL.
 *
 * dll_63_spawnEffect builds a per-object bone-particle command list and
 * submits it through the modgfx interface.
 */
#include "main/dll/dll_0063_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/vecmath.h"

typedef struct Dll63EffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll63EffectResourceView;

STATIC_ASSERT(offsetof(Dll63EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll63EffectResourceView, triangleIndices) == 0x08C);
STATIC_ASSERT(offsetof(Dll63EffectResourceView, allVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll63EffectResourceView, firstGroupIndices) == 0x0F0);
STATIC_ASSERT(offsetof(Dll63EffectResourceView, secondGroupIndices) == 0x100);
STATIC_ASSERT(offsetof(Dll63EffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(sizeof(Dll63EffectResourceView) == 0x120);

s16 gDll63EffectResourceData[sizeof(Dll63EffectResourceView) / sizeof(s16)] = {
    0,    0,    1000, 0,    0,    866,  200,  500,  0,   10,  866,  40,   -500, 0,    21,   0,    150,   -1000,
    0,    31,   -866, 90,   -500, 0,    42,   -866, 10,  500, 0,    52,   0,    150,  1000, 0,    63,    0,
    6400, 1000, 63,   0,    866,  6300, 500,  63,   10,  866, 6200, -500, 63,   21,   0,    6450, -1000, 63,
    31,   -866, 6400, -500, 63,   42,   -866, 6380, 500, 63,  52,   0,    6440, 1000, 63,   63,   0,     1,
    8,    0,    8,    7,    1,    2,    9,    1,    9,   8,   2,    3,    10,   2,    10,   9,    3,     4,
    11,   3,    11,   10,   4,    5,    12,   4,    12,  11,  5,    6,    13,   5,    13,   12,   0,     1,
    2,    3,    4,    5,    6,    7,    8,    9,    10,  11,  12,   13,   0,    1,    2,    3,    4,     5,
    6,    0,    7,    8,    9,    10,   11,   12,   13,  0,   0,    260,  60,   60,   1,    260,  0,     0,
};

s16 dll_63_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags, int unusedModelId,
                       void* unusedParams) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)gDll63EffectResourceData;
    Dll63EffectResourceView* resource = (Dll63EffectResourceView*)resourceData;
    ModgfxEffectVertex* vertex;
    int i;
    u32 effectScaleTenths;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;

    if (variant == 1) {
        resource->sequenceParams[1] = 0;
    }
    effectScaleTenths = ((u8*)sourceObj->anim.placementData)[0x1a];
    if (variant == 2) {
        for (i = 0, vertex = (ModgfxEffectVertex*)resourceData; i < 14; i++) {
            if (vertex->positionX > 0) {
                vertex->positionX += randomGetRange(0, 800);
            } else if (vertex->positionX < 0) {
                vertex->positionX -= randomGetRange(0, 800);
            }
            if (vertex->positionY > 0) {
                vertex->positionX += randomGetRange(0, 300);
            } else if (vertex->positionY < 0) {
                vertex->positionX -= randomGetRange(0, 300);
            }
            if (vertex->positionZ > 0) {
                vertex->positionX += randomGetRange(0, 800);
            } else if (vertex->positionZ < 0) {
                vertex->positionX -= randomGetRange(0, 800);
            }
            vertex++;
        }
    }
    commands = packet.entries;
    if (variant == 2) {
        commands[0].stageIndex = 0;
        commands[0].parameter = 7;
        commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commands[0].flags = 8;
        commands[0].valueX = 100.0f;
        commands[0].valueY = 100.0f;
        commands[0].valueZ = 100.0f;
        commands[1].stageIndex = 0;
        commands[1].parameter = 7;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commands[1].flags = 8;
        commands[1].valueX = 200.0f;
        commands[1].valueY = 200.0f;
        commands[1].valueZ = 200.0f;
        commandCursor = &commands[2];
    } else {
        commands[0].stageIndex = 0;
        commands[0].parameter = 7;
        commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commands[0].flags = 8;
        commands[0].valueX = 50.0f;
        commands[0].valueY = 50.0f;
        commands[0].valueZ = 50.0f;
        commands[1].stageIndex = 0;
        commands[1].parameter = 7;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commands[1].flags = 8;
        commands[1].valueX = 200.0f;
        commands[1].valueY = 200.0f;
        commands[1].valueZ = 200.0f;
        commandCursor = &commands[2];
    }
    commandCursor->stageIndex = 0;
    commandCursor->parameter = 0xe;
    commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor->flags = 4;
    commandCursor->valueX = 0.0f;
    commandCursor->valueY = 0.0f;
    commandCursor->valueZ = 0.0f;
    if (variant != 3 || spawnParams == NULL) {
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 7;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commandCursor[1].flags = 2;
        commandCursor[1].valueX = 0.725f;
        commandCursor[1].valueY = 1.2f;
        commandCursor[1].valueZ = 0.725f;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 7;
        commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commandCursor[2].flags = 2;
        commandCursor[2].valueX = 0.35f;
        commandCursor[2].valueY = 1.0f;
        commandCursor[2].valueZ = 0.35f;
        commandCursor += 3;
    } else {
        PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 7;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commandCursor[1].flags = 2;
        commandCursor[1].valueX = 0.725f * params->scale;
        commandCursor[1].valueY = 1.2f * params->scale;
        commandCursor[1].valueZ = 0.725f * params->scale;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 7;
        commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commandCursor[2].flags = 2;
        commandCursor[2].valueX = 0.35f * params->scale;
        commandCursor[2].valueY = params->scale;
        commandCursor[2].valueZ = 0.35f * params->scale;
        commandCursor += 3;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 7;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 70.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 7;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 12.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 0xe;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 0x100;
    commandCursor[2].valueX = 0.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 20.0f;
    commandCursor[3].stageIndex = 1;
    commandCursor[3].parameter = 0xe;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[3].flags = 0x4000;
    commandCursor[3].valueX = -0.7f;
    commandCursor[3].valueY = 0.0f;
    commandCursor[3].valueZ = 0.0f;
    commandCursor[4].stageIndex = 2;
    commandCursor[4].parameter = 0xe;
    commandCursor[4].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[4].flags = 0x100;
    commandCursor[4].valueX = 0.0f;
    commandCursor[4].valueY = 0.0f;
    commandCursor[4].valueZ = 20.0f;
    commandCursor[5].stageIndex = 2;
    commandCursor[5].parameter = 0xe;
    commandCursor[5].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[5].flags = 0x4000;
    commandCursor[5].valueX = -0.7f;
    commandCursor[5].valueY = 0.0f;
    commandCursor[5].valueZ = 0.0f;
    commandCursor[6].stageIndex = 3;
    commandCursor[6].parameter = 0xe;
    commandCursor[6].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[6].flags = 0x100;
    commandCursor[6].valueX = 0.0f;
    commandCursor[6].valueY = 0.0f;
    commandCursor[6].valueZ = 20.0f;
    commandCursor[7].stageIndex = 3;
    commandCursor[7].parameter = 0xe;
    commandCursor[7].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[7].flags = 0x4000;
    commandCursor[7].valueX = -0.7f;
    commandCursor[7].valueY = 0.0f;
    commandCursor[7].valueZ = 0.0f;
    commandCursor[8].stageIndex = 4;
    commandCursor[8].parameter = 1;
    commandCursor[8].vertexIndices = NULL;
    commandCursor[8].flags = 0x2000;
    commandCursor[8].valueX = 0.0f;
    commandCursor[8].valueY = 0.0f;
    commandCursor[8].valueZ = 0.0f;
    commandCursor[9].stageIndex = 5;
    commandCursor[9].parameter = 7;
    commandCursor[9].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
    commandCursor[9].flags = 4;
    commandCursor[9].valueX = 0.0f;
    commandCursor[9].valueY = 0.0f;
    commandCursor[9].valueZ = 0.0f;
    commandCursor[10].stageIndex = 5;
    commandCursor[10].parameter = 7;
    commandCursor[10].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
    commandCursor[10].flags = 4;
    commandCursor[10].valueX = 0.0f;
    commandCursor[10].valueY = 0.0f;
    commandCursor[10].valueZ = 0.0f;
    commandCursor[11].stageIndex = 5;
    commandCursor[11].parameter = 0xe;
    commandCursor[11].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[11].flags = 0x100;
    commandCursor[11].valueX = 0.0f;
    commandCursor[11].valueY = 0.0f;
    commandCursor[11].valueZ = 20.0f;
    commandCursor[12].stageIndex = 5;
    commandCursor[12].parameter = 0xe;
    commandCursor[12].vertexIndices = (s16*)&resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[12].flags = 0x4000;
    commandCursor[12].valueX = -0.7f;
    commandCursor[12].valueY = 0.0f;
    commandCursor[12].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 4.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    if (effectScaleTenths != 0) {
        packet.context.scale = 0.1f * effectScaleTenths;
    } else {
        packet.context.scale = 1.0f;
    }
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (commandCursor + 13) - commands;
    packet.context.stageDurations[0] = resource->sequenceParams[0];
    packet.context.stageDurations[1] = resource->sequenceParams[1];
    packet.context.stageDurations[2] = resource->sequenceParams[2];
    packet.context.stageDurations[3] = resource->sequenceParams[3];
    packet.context.stageDurations[4] = resource->sequenceParams[4];
    packet.context.stageDurations[5] = resource->sequenceParams[5];
    packet.context.stageDurations[6] = resource->sequenceParams[6];
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
    return (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(resourceData), 0xc,
                      (s16*)(&resourceData[offsetof(Dll63EffectResourceView, triangleIndices)]), 0x40, 0);
}

void dll_63_release(void) {
}

void dll_63_initialise(void) {
}

Dll63ResourceDescriptor gDll63ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_63_initialise, dll_63_release, NULL, dll_63_spawnEffect,
};
