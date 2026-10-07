/*
 * DLL 122 / 0x7A - a two-variant modgfx effect spawner.
 */
#include "main/dll/dll_007A_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll7AEffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangles[8][3];
    s16 allVertexIndices[10];
    s16 firstEightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7AEffectResourceView;

STATIC_ASSERT(offsetof(Dll7AEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, pad5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, allVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, firstEightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, opaqueTail) == 0xBE);
STATIC_ASSERT(sizeof(Dll7AEffectResourceView) == 0xC0);

u16 gDll7AEffectResourceData[sizeof(Dll7AEffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0190, 0x001f, 0x001f, 0x02c3, 0xfd3d, 0x0190, 0x0000,
    0x001f, 0x0000, 0xfc18, 0x0190, 0x001f, 0x001f, 0xfd3d, 0xfd3d, 0x0190,
    0x0000, 0x001f, 0xfc18, 0x0000, 0x0190, 0x001f, 0x001f, 0xfd3d, 0x02c3,
    0x0190, 0x0000, 0x001f, 0x0000, 0x03e8, 0x0190, 0x001f, 0x001f, 0x02c3,
    0x02c3, 0x0190, 0x0000, 0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000,
    0x0000, 0x0000, 0x0001, 0x0008, 0x0001, 0x0002, 0x0008, 0x0002, 0x0003,
    0x0008, 0x0003, 0x0004, 0x0008, 0x0004, 0x0005, 0x0008, 0x0005, 0x0006,
    0x0008, 0x0006, 0x0007, 0x0008, 0x0007, 0x0000, 0x0008, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0000, 0x0000,
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0000, 0x0064,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

s16 dll_7A_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll7AEffectResourceData;
    ModgfxCommand* commands;
    ModgfxCommand* commandCursor;
    s16 handle;
    handle = 0;
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7AEffectResourceView, firstEightVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 8;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.4f * randomGetRange(10, 15);
    commands[1].valueY = 0.4f * randomGetRange(10, 15);
    commands[1].valueZ = 0.8f * randomGetRange(10, 15);
    commands[2].stageIndex = 0;
    commands[2].parameter = 9;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[2].flags = 0x80;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = -16383.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 0x9c;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x800000;
    commands[3].valueX = 2.0f;
    commands[3].valueY = 1.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x400000;
    commands[4].valueX = randomGetRange(-2000, 200);
    commands[4].valueY = randomGetRange(-200, 200);
    commands[4].valueZ = randomGetRange(-200, 200);
    commands[5].stageIndex = 1;
    commands[5].parameter = 9;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[5].flags = 4;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commandCursor = &commands[6];
    if (variant == 0) {
        commandCursor->stageIndex = 3;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x20000000;
        commandCursor->valueX = 999.0f;
        commandCursor->valueY = 94.0f;
        commandCursor->valueZ = 95.0f;
        commandCursor++;
    }
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    if (variant == 0) {
        packet.context.position[0] = 0.0f;
        packet.context.position[1] = 0.0f;
        packet.context.position[2] = 0.0f;
    } else {
        packet.context.position[0] = 0.0f;
        packet.context.position[1] = 135.0f;
        packet.context.position[2] = 0.0f;
    }
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 9;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = commandCursor - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4000000;
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
    if (variant == 0) {
        packet.context.modeByte = 0;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll7AEffectResourceData, 8,
                                   (s16*)(&resourceData[offsetof(Dll7AEffectResourceView, triangles)]), 0x156, 0);
    } else if (variant == 1) {
        packet.context.modeByte = 0;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll7AEffectResourceData, 8,
                                   (s16*)(&resourceData[offsetof(Dll7AEffectResourceView, triangles)]), 0xc0d, 0);
    }
    return handle;
}

void dll_7A_release(void) {
}

void dll_7A_initialise(void) {
}

Dll7AResourceDescriptor gDll7AResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_7A_initialise, dll_7A_release, NULL, dll_7A_spawnEffect,
};
