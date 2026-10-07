/*
 * DLL 126 / 0x7E - a scaled foodbag billboard-effect spawner.
 */
#include "main/dll/dll_007E_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll7EEffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangles[5][3];
    u8 pad7A[2];
    s16 allVertexIndices[10];
    s16 lastSixVertexIndices[6];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7EEffectResourceView;

STATIC_ASSERT(offsetof(Dll7EEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, pad5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, pad7A) == 0x7A);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, allVertexIndices) == 0x7C);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, lastSixVertexIndices) == 0x90);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, sequenceParams) == 0x9C);
STATIC_ASSERT(offsetof(Dll7EEffectResourceView, opaqueTail) == 0xAA);
STATIC_ASSERT(sizeof(Dll7EEffectResourceView) == 0xAC);

s16 gDll7EThreeVertexIndices[4] = {0, 1, 2, 0};

u8 gDll7EEffectResourceData[sizeof(Dll7EEffectResourceView)] = {
    0, 0,   0, 0,   254, 12,  0,   31,  0, 0,   0, 0,   0, 0, 254, 12,  0, 31,  0, 0,   0, 0,   0,   0,   254, 12,
    0, 31,  0, 0,   0,   107, 0,   100, 1, 151, 0, 78,  0, 8, 2,   195, 0, 100, 2, 195, 0, 63,  0,   31,  2,   226,
    0, 100, 1, 127, 0,   46,  0,   31,  2, 168, 0, 100, 0, 0, 0,   31,  0, 31,  1, 119, 0, 100, 254, 130, 0,   15,
    0, 31,  0, 141, 0,   100, 254, 105, 0, 0,   0, 31,  0, 0, 0,   0,   0, 4,   0, 3,   0, 1,   0,   5,   0,   4,
    0, 1,   0, 6,   0,   5,   0,   1,   0, 7,   0, 6,   0, 2, 0,   8,   0, 7,   0, 0,   0, 0,   0,   1,   0,   2,
    0, 3,   0, 4,   0,   5,   0,   6,   0, 7,   0, 8,   0, 0, 0,   3,   0, 4,   0, 5,   0, 6,   0,   7,   0,   8,
    0, 0,   0, 10,  0,   40,  0,   0,   0, 0,   0, 0,   0, 0, 0,   0};

void dll_7E_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, u32 unused,
                        f32* scaleOverride) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll7EEffectResourceData;
    f32 scale = 1.0f;
    f32 originOffset = 0.0f;
    ModgfxCommand* commands;
    ModgfxCommand* commandCursor;
    if (scaleOverride != NULL) {
        scale = *scaleOverride;
    }
    if ((u32)spawnParams != 0) {
        scale = spawnParams->scale;
    }
    commands = packet.entries;
    commandCursor = &commands[2];
    commands[0].stageIndex = 0;
    commands[0].parameter = 5;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, lastSixVertexIndices)];
    commands[0].flags = 0x4000;
    commands[0].valueX = originOffset;
    commands[0].valueY = -1.0f;
    commands[0].valueZ = originOffset;
    commands[1].stageIndex = 0;
    commands[1].parameter = 9;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, allVertexIndices)];
    commands[1].flags = 4;
    commands[1].valueX = originOffset;
    commands[1].valueY = originOffset;
    commands[1].valueZ = originOffset;
    if (variant == 1) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = -6.0f * scale;
        commandCursor->valueY = 1.0f;
        commandCursor->valueZ = 4.0f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 6.0f * scale;
        commandCursor->valueY = 1.0f;
        commandCursor->valueZ = 4.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 3;
    commandCursor[0].vertexIndices = (s16*)(gDll7EThreeVertexIndices);
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 255.0f;
    commandCursor[0].valueY = originOffset;
    commandCursor[0].valueZ = originOffset;
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 5;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, lastSixVertexIndices)];
    commandCursor[1].flags = 0x4000;
    commandCursor[1].valueX = -2.5f;
    commandCursor[1].valueY = -1.0f;
    commandCursor[1].valueZ = originOffset;
    commandCursor[2].stageIndex = 2;
    commandCursor[2].parameter = 5;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll7EEffectResourceView, lastSixVertexIndices)];
    commandCursor[2].flags = 0x4000;
    commandCursor[2].valueX = -2.5f;
    commandCursor[2].valueY = -1.0f;
    commandCursor[2].valueZ = originOffset;
    commandCursor[3].stageIndex = 2;
    commandCursor[3].parameter = 3;
    commandCursor[3].vertexIndices = (s16*)(gDll7EThreeVertexIndices);
    commandCursor[3].flags = 4;
    commandCursor[3].valueX = originOffset;
    commandCursor[3].valueY = originOffset;
    commandCursor[3].valueZ = originOffset;
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
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 9;
    packet.context.initialStateByte = 9;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xa;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commandCursor + sizeof(ModgfxCommand) * 4) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7EEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4010080;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            packet.context.position[0] = originOffset + sourceObj->anim.worldPosX;
            packet.context.position[1] = originOffset + sourceObj->anim.worldPosY;
            packet.context.position[2] = originOffset + sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = originOffset + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll7EEffectResourceData, 5,
                      (s16*)(&resourceData[offsetof(Dll7EEffectResourceView, triangles)]), 0x3c, 0);
}

void dll_7E_release(void) {
}

void dll_7E_initialise(void) {
}

Dll7EResourceDescriptor gDll7EResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_7E_initialise,
    dll_7E_release,
    NULL,
    dll_7E_spawnEffect,
    0x00000000,
};
