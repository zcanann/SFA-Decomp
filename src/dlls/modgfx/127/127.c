/*
 * DLL 127 / 0x7F - a three-variant foodbag modgfx effect spawner.
 */
#include "main/dll/dll_007F_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll7FEffectResourceView {
    ModgfxEffectVertex variantZeroVertices[9];
    u8 pad5A[2];
    ModgfxEffectVertex nonzeroVariantVertices[9];
    u8 padB6[2];
    s16 triangles[8][3];
    s16 allVertexIndices[10];
    s16 firstEightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7FEffectResourceView;

STATIC_ASSERT(offsetof(Dll7FEffectResourceView, variantZeroVertices) == 0x000);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, pad5A) == 0x05A);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, nonzeroVariantVertices) == 0x05C);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, padB6) == 0x0B6);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, triangles) == 0x0B8);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, allVertexIndices) == 0x0E8);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, firstEightVertexIndices) == 0x0FC);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, sequenceParams) == 0x10C);
STATIC_ASSERT(offsetof(Dll7FEffectResourceView, opaqueTail) == 0x11A);
STATIC_ASSERT(sizeof(Dll7FEffectResourceView) == 0x11C);

typedef struct Dll7FSingleVertexIndexData {
    s16 vertexIndex;
    s16 opaqueTail[3];
} Dll7FSingleVertexIndexData;

STATIC_ASSERT(offsetof(Dll7FSingleVertexIndexData, vertexIndex) == 0x00);
STATIC_ASSERT(offsetof(Dll7FSingleVertexIndexData, opaqueTail) == 0x02);
STATIC_ASSERT(sizeof(Dll7FSingleVertexIndexData) == 0x08);

Dll7FSingleVertexIndexData gDll7FSingleVertexIndexData = {8, {0, 0, 0}};

u8 gDll7FEffectResourceData[sizeof(Dll7FEffectResourceView)] = {
    1, 144, 0,   0,   1,   144, 0,   31,  0,   31,  4, 83,  251, 173, 1, 144, 0,   0,   0,   31,  0, 0,   254, 112,
    1, 144, 0,   31,  0,   31,  251, 173, 251, 173, 1, 144, 0,   0,   0, 31,  254, 112, 0,   0,   1, 144, 0,   31,
    0, 31,  251, 173, 4,   83,  1,   144, 0,   0,   0, 31,  0,   0,   1, 144, 1,   144, 0,   31,  0, 31,  4,   83,
    4, 83,  1,   144, 0,   0,   0,   31,  0,   0,   0, 0,   0,   0,   0, 15,  0,   0,   0,   0,   3, 232, 0,   0,
    1, 144, 0,   31,  0,   31,  2,   195, 253, 61,  1, 144, 0,   0,   0, 31,  0,   0,   252, 24,  1, 144, 0,   31,
    0, 31,  253, 61,  253, 61,  1,   144, 0,   0,   0, 31,  252, 24,  0, 0,   1,   144, 0,   31,  0, 31,  253, 61,
    2, 195, 1,   144, 0,   0,   0,   31,  0,   0,   3, 232, 1,   144, 0, 31,  0,   31,  2,   195, 2, 195, 1,   144,
    0, 0,   0,   31,  0,   0,   0,   0,   0,   0,   0, 15,  0,   0,   0, 0,   0,   0,   0,   1,   0, 8,   0,   1,
    0, 2,   0,   8,   0,   2,   0,   3,   0,   8,   0, 3,   0,   4,   0, 8,   0,   4,   0,   5,   0, 8,   0,   5,
    0, 6,   0,   8,   0,   6,   0,   7,   0,   8,   0, 7,   0,   0,   0, 8,   0,   0,   0,   1,   0, 2,   0,   3,
    0, 4,   0,   5,   0,   6,   0,   7,   0,   8,   0, 0,   0,   0,   0, 1,   0,   2,   0,   3,   0, 4,   0,   5,
    0, 6,   0,   7,   0,   0,   0,   60,  0,   30,  0, 1,   0,   1,   0, 0,   0,   0,   0,   0};

void dll_7F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = gDll7FEffectResourceData;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands = packet.entries;
    f32 originOffset = 0.0f;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x8c;
    commands[0].vertexIndices = NULL;
    commands[0].flags = 0x20000000;
    commands[0].valueX = 999.0f;
    commands[0].valueY = 94.0f;
    commands[0].valueZ = 95.0f;
    commandCursor = &commands[1];
    if (variant != 2) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x80;
        commandCursor->valueX = originOffset;
        commandCursor->valueY = originOffset;
        commandCursor->valueZ = 16383.0f;
        commandCursor++;
    }
    if (variant == 0) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 8;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, firstEightVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.7f;
        commandCursor->valueY = 0.7f;
        commandCursor->valueZ = 3.3333333f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 8;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, firstEightVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.36666667f;
        commandCursor->valueY = 0.36666667f;
        commandCursor->valueZ = 5.0f;
        commandCursor++;
    }
    if (variant == 0) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 8;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 3.0f;
        commandCursor->valueY = 3.0f;
        commandCursor->valueZ = 3.0f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 8;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 3.0f;
        commandCursor->valueY = 3.0f;
        commandCursor->valueZ = 3.0f;
        commandCursor++;
    }
    if (variant == 0) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x100;
        commandCursor->valueX = -400.0f;
        commandCursor->valueY = originOffset;
        commandCursor->valueZ = originOffset;
        commandCursor++;
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 1;
        commandCursor->vertexIndices = (s16*)&gDll7FSingleVertexIndexData.vertexIndex;
        commandCursor->flags = 0x4000;
        commandCursor->valueX = -4.0f;
        commandCursor->valueY = -4.0f;
        commandCursor->valueZ = originOffset;
    } else if (variant == 1) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x100;
        commandCursor->valueX = 400.0f;
        commandCursor->valueY = originOffset;
        commandCursor->valueZ = originOffset;
        commandCursor++;
    }
    if (variant == 0) {
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x100;
        commandCursor->valueX = -400.0f;
        commandCursor->valueY = originOffset;
        commandCursor->valueZ = originOffset;
        commandCursor++;
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 1;
        commandCursor->vertexIndices = (s16*)&gDll7FSingleVertexIndexData.vertexIndex;
        commandCursor->flags = 0x4000;
        commandCursor->valueX = -4.0f;
        commandCursor->valueY = -4.0f;
        commandCursor->valueZ = originOffset;
    } else if (variant == 1) {
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 9;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
        commandCursor->flags = 0x100;
        commandCursor->valueX = 400.0f;
        commandCursor->valueY = originOffset;
        commandCursor->valueZ = originOffset;
        commandCursor++;
    }
    commandCursor->stageIndex = 2;
    commandCursor->parameter = 9;
    commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll7FEffectResourceView, allVertexIndices)];
    commandCursor->flags = 4;
    commandCursor->valueX = originOffset;
    commandCursor->valueY = originOffset;
    commandCursor->valueZ = originOffset;
    commandCursor++;
    commandCursor->stageIndex = 3;
    commandCursor->parameter = 0;
    commandCursor->vertexIndices = NULL;
    commandCursor->flags = 0x20000000;
    commandCursor->valueX = 999.0f;
    commandCursor->valueY = 94.0f;
    commandCursor->valueZ = 95.0f;
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
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 9;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x20;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commandCursor + sizeof(ModgfxCommand)) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7FEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4000000;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += sourceObj->anim.worldPosY;
            packet.context.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    if (variant == 0) {
        packet.context.modeByte = 0;
        (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(resourceData), 8, (s16*)(&resourceData[offsetof(Dll7FEffectResourceView, triangles)]),
                          0x156, 0);
    } else {
        packet.context.modeByte = 0;
        (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(&resourceData[offsetof(Dll7FEffectResourceView, nonzeroVariantVertices)]), 8,
                          (s16*)(&resourceData[offsetof(Dll7FEffectResourceView, triangles)]), 0x8a, 0);
    }
}

void dll_7F_release(void) {
}

void dll_7F_initialise(void) {
}

Dll7FResourceDescriptor gDll7FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_7F_initialise,
    dll_7F_release,
    NULL,
    dll_7F_spawnEffect,
    0x00000000,
};
