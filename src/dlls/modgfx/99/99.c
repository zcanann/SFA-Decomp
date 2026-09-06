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
    GfxCmd* commandCursor;
    GfxCmd* commands;

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
        commands[0].layer = 0;
        commands[0].flags = 7;
        commands[0].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commands[0].mode = 8;
        commands[0].x = 100.0f;
        commands[0].y = 100.0f;
        commands[0].z = 100.0f;
        commands[1].layer = 0;
        commands[1].flags = 7;
        commands[1].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commands[1].mode = 8;
        commands[1].x = 200.0f;
        commands[1].y = 200.0f;
        commands[1].z = 200.0f;
        commandCursor = &commands[2];
    } else {
        commands[0].layer = 0;
        commands[0].flags = 7;
        commands[0].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commands[0].mode = 8;
        commands[0].x = 50.0f;
        commands[0].y = 50.0f;
        commands[0].z = 50.0f;
        commands[1].layer = 0;
        commands[1].flags = 7;
        commands[1].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commands[1].mode = 8;
        commands[1].x = 200.0f;
        commands[1].y = 200.0f;
        commands[1].z = 200.0f;
        commandCursor = &commands[2];
    }
    commandCursor->layer = 0;
    commandCursor->flags = 0xe;
    commandCursor->tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor->mode = 4;
    commandCursor->x = 0.0f;
    commandCursor->y = 0.0f;
    commandCursor->z = 0.0f;
    if (variant != 3 || spawnParams == NULL) {
        commandCursor[1].layer = 0;
        commandCursor[1].flags = 7;
        commandCursor[1].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commandCursor[1].mode = 2;
        commandCursor[1].x = 0.725f;
        commandCursor[1].y = 1.2f;
        commandCursor[1].z = 0.725f;
        commandCursor[2].layer = 0;
        commandCursor[2].flags = 7;
        commandCursor[2].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commandCursor[2].mode = 2;
        commandCursor[2].x = 0.35f;
        commandCursor[2].y = 1.0f;
        commandCursor[2].z = 0.35f;
        commandCursor += 3;
    } else {
        PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

        commandCursor[1].layer = 0;
        commandCursor[1].flags = 7;
        commandCursor[1].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
        commandCursor[1].mode = 2;
        commandCursor[1].x = 0.725f * params->scale;
        commandCursor[1].y = 1.2f * params->scale;
        commandCursor[1].z = 0.725f * params->scale;
        commandCursor[2].layer = 0;
        commandCursor[2].flags = 7;
        commandCursor[2].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
        commandCursor[2].mode = 2;
        commandCursor[2].x = 0.35f * params->scale;
        commandCursor[2].y = params->scale;
        commandCursor[2].z = 0.35f * params->scale;
        commandCursor += 3;
    }
    commandCursor[0].layer = 1;
    commandCursor[0].flags = 7;
    commandCursor[0].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
    commandCursor[0].mode = 4;
    commandCursor[0].x = 70.0f;
    commandCursor[0].y = 0.0f;
    commandCursor[0].z = 0.0f;
    commandCursor[1].layer = 1;
    commandCursor[1].flags = 7;
    commandCursor[1].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
    commandCursor[1].mode = 4;
    commandCursor[1].x = 12.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    commandCursor[2].layer = 1;
    commandCursor[2].flags = 0xe;
    commandCursor[2].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[2].mode = 0x100;
    commandCursor[2].x = 0.0f;
    commandCursor[2].y = 0.0f;
    commandCursor[2].z = 20.0f;
    commandCursor[3].layer = 1;
    commandCursor[3].flags = 0xe;
    commandCursor[3].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[3].mode = 0x4000;
    commandCursor[3].x = -0.7f;
    commandCursor[3].y = 0.0f;
    commandCursor[3].z = 0.0f;
    commandCursor[4].layer = 2;
    commandCursor[4].flags = 0xe;
    commandCursor[4].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[4].mode = 0x100;
    commandCursor[4].x = 0.0f;
    commandCursor[4].y = 0.0f;
    commandCursor[4].z = 20.0f;
    commandCursor[5].layer = 2;
    commandCursor[5].flags = 0xe;
    commandCursor[5].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[5].mode = 0x4000;
    commandCursor[5].x = -0.7f;
    commandCursor[5].y = 0.0f;
    commandCursor[5].z = 0.0f;
    commandCursor[6].layer = 3;
    commandCursor[6].flags = 0xe;
    commandCursor[6].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[6].mode = 0x100;
    commandCursor[6].x = 0.0f;
    commandCursor[6].y = 0.0f;
    commandCursor[6].z = 20.0f;
    commandCursor[7].layer = 3;
    commandCursor[7].flags = 0xe;
    commandCursor[7].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[7].mode = 0x4000;
    commandCursor[7].x = -0.7f;
    commandCursor[7].y = 0.0f;
    commandCursor[7].z = 0.0f;
    commandCursor[8].layer = 4;
    commandCursor[8].flags = 1;
    commandCursor[8].tex = NULL;
    commandCursor[8].mode = 0x2000;
    commandCursor[8].x = 0.0f;
    commandCursor[8].y = 0.0f;
    commandCursor[8].z = 0.0f;
    commandCursor[9].layer = 5;
    commandCursor[9].flags = 7;
    commandCursor[9].tex = &resourceData[offsetof(Dll63EffectResourceView, firstGroupIndices)];
    commandCursor[9].mode = 4;
    commandCursor[9].x = 0.0f;
    commandCursor[9].y = 0.0f;
    commandCursor[9].z = 0.0f;
    commandCursor[10].layer = 5;
    commandCursor[10].flags = 7;
    commandCursor[10].tex = &resourceData[offsetof(Dll63EffectResourceView, secondGroupIndices)];
    commandCursor[10].mode = 4;
    commandCursor[10].x = 0.0f;
    commandCursor[10].y = 0.0f;
    commandCursor[10].z = 0.0f;
    commandCursor[11].layer = 5;
    commandCursor[11].flags = 0xe;
    commandCursor[11].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[11].mode = 0x100;
    commandCursor[11].x = 0.0f;
    commandCursor[11].y = 0.0f;
    commandCursor[11].z = 20.0f;
    commandCursor[12].layer = 5;
    commandCursor[12].flags = 0xe;
    commandCursor[12].tex = &resourceData[offsetof(Dll63EffectResourceView, allVertexIndices)];
    commandCursor[12].mode = 0x4000;
    commandCursor[12].x = -0.7f;
    commandCursor[12].y = 0.0f;
    commandCursor[12].z = 0.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 4.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    if (effectScaleTenths != 0) {
        packet.scale = 0.1f * effectScaleTenths;
    } else {
        packet.scale = 1.0f;
    }
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = (commandCursor + 13) - commands;
    packet.sequenceParams[0] = resource->sequenceParams[0];
    packet.sequenceParams[1] = resource->sequenceParams[1];
    packet.sequenceParams[2] = resource->sequenceParams[2];
    packet.sequenceParams[3] = resource->sequenceParams[3];
    packet.sequenceParams[4] = resource->sequenceParams[4];
    packet.sequenceParams[5] = resource->sequenceParams[5];
    packet.sequenceParams[6] = resource->sequenceParams[6];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0x40000c0;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.position[0] += params->posX;
            packet.position[1] += params->posY;
            packet.position[2] += params->posZ;
        }
    }
    return (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0xe, resourceData, 0xc, &resourceData[offsetof(Dll63EffectResourceView, triangleIndices)],
                      0x40, 0);
}

void dll_63_release(void) {
}

void dll_63_initialise(void) {
}

Dll63ResourceDescriptor gDll63ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_63_initialise, dll_63_release, NULL, dll_63_spawnEffect,
};
