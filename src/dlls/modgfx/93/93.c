/*
 * DLL 93 / 0x5D - a modgfx particle-sequence spawn DLL.
 */
#include "main/dll/dll_005D_modgfx.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll5DEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangleIndices[24][3];
    u8 opaque164[0x10];
    s16 partialIndices[30];
    s16 fullIndices[22];
    s16 sequenceParams[7];
    u8 pad1EA[2];
} Dll5DEffectResourceView;

STATIC_ASSERT(offsetof(Dll5DEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll5DEffectResourceView, triangleIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll5DEffectResourceView, partialIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll5DEffectResourceView, fullIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll5DEffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(sizeof(Dll5DEffectResourceView) == 0x1EC);

u8 gDll5DEffectResourceData[sizeof(Dll5DEffectResourceView)] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,   0,   3,   98,  0,   0,   1,   244, 0,   11,  0,   0,   3,   98,  0,
    0,   254, 12,  0,   22,  0,   0,   0,   0,   0,   0,   252, 24,  0,   32,  0,   0,   252, 158, 0,   0,   254, 12,
    0,   42,  0,   0,   252, 158, 0,   0,   1,   244, 0,   52,  0,   0,   0,   0,   0,   0,   3,   232, 0,   63,  0,
    0,   0,   0,   11,  184, 3,   232, 0,   0,   0,   31,  3,   98,  11,  184, 1,   244, 0,   11,  0,   31,  3,   98,
    11,  184, 254, 12,  0,   22,  0,   31,  0,   0,   11,  184, 252, 24,  0,   32,  0,   31,  252, 158, 11,  184, 254,
    12,  0,   42,  0,   31,  252, 158, 11,  184, 1,   244, 0,   52,  0,   31,  0,   0,   11,  184, 3,   232, 0,   63,
    0,   31,  0,   0,   23,  112, 3,   232, 0,   0,   0,   63,  3,   98,  23,  112, 1,   244, 0,   11,  0,   63,  3,
    98,  23,  112, 254, 12,  0,   22,  0,   63,  0,   0,   23,  112, 252, 24,  0,   32,  0,   63,  252, 158, 23,  112,
    254, 12,  0,   42,  0,   63,  252, 158, 23,  112, 1,   244, 0,   52,  0,   63,  0,   0,   23,  112, 3,   232, 0,
    63,  0,   63,  0,   0,   0,   0,   0,   1,   0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,   9,   0,   8,   0,   2,   0,   3,   0,   10,  0,   2,   0,   10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,   0,   11,  0,   10,  0,   4,   0,   5,   0,   12,  0,   4,   0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,   5,   0,   13,  0,   12,  0,   7,   0,   8,   0,   15,  0,   7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16,  0,   8,   0,   16,  0,   15,  0,   9,   0,   10,  0,   17,  0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,   18,  0,   10,  0,   18,  0,   17,  0,   11,  0,   12,  0,   19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13,  0,   20,  0,   12,  0,   20,  0,   19,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   30,  0,   80,  0,
    30,  0,   0,   0,   0,   0,   0,   0,   0};

void dll_5D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll5DEffectResourceData;
    ModgfxCommand* commands = packet.entries;
    GameObject* sourceContext;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.1f;
    commands[1].valueY = 1.3f;
    commands[1].valueZ = 0.1f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0x15;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[2].flags = 0x400000;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 100.0f;
    commands[2].valueZ = 0.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, partialIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 85.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0x15;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[4].flags = 0x4000;
    commands[4].valueX = -2.0f;
    commands[4].valueY = 2.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x15;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[5].flags = 0x400000;
    commands[5].valueX = 0.0f;
    commands[5].valueY = -100.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 2.0f;
    commands[6].valueY = -2.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x15;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[7].flags = 0x400000;
    commands[7].valueX = 0.0f;
    commands[7].valueY = 10.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x15;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[8].flags = 2;
    commands[8].valueX = 12.0f;
    commands[8].valueY = 1.3f;
    commands[8].valueZ = 12.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 7;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, partialIndices)];
    commands[9].flags = 4;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    commands[10].stageIndex = 3;
    commands[10].parameter = 0x15;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll5DEffectResourceView, fullIndices)];
    commands[10].flags = 0x4000;
    commands[10].valueX = 2.0f;
    commands[10].valueY = -2.0f;
    commands[10].valueZ = 0.0f;
    packet.context.modeByte = 0;
    sourceContext = sourceObj;
    packet.context.sourceObject = sourceContext;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = -10.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (commands + 11) - packet.entries;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll5DEffectResourceView, sequenceParams[6])];
    packet.context.commands = packet.entries;
    packet.context.flags = 0xc000040;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)sourceContext != NULL) {
            packet.context.position[0] += sourceContext->anim.worldPosX;
            packet.context.position[1] = -10.0f + sourceContext->anim.worldPosY;
            packet.context.position[2] += sourceContext->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] = -10.0f + spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll5DEffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll5DEffectResourceView, triangleIndices)]), 0x20B, 0);
}

void dll_5D_release(void) {
}

void dll_5D_initialise(void) {
}

Dll5DResourceDescriptor gDll5DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_5D_initialise, dll_5D_release, NULL, dll_5D_spawnEffect, 0,
};
