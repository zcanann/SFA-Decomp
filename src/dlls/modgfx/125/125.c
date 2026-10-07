/*
 * DLL 125 / 0x7D - a scaled foodbag modgfx effect spawner.
 */
#include "main/dll/dll_007D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll7DEffectResourceView {
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
} Dll7DEffectResourceView;

STATIC_ASSERT(offsetof(Dll7DEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, padD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll7DEffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll7DEffectResourceView) == 0x208);

u8 gDll7DEffectResourceData[sizeof(Dll7DEffectResourceView)] = {
    0,   0,   13, 72,  0,  0,   0,   0,  0,   0,  3,   98,  11, 84,  0,  0,   0,   8,  0,   0,  3,   98,  7,  108, 0,
    0,   0,   15, 0,   0,  0,   0,   5,  120, 0,  0,   0,   31, 0,   0,  252, 158, 7,  108, 0,  0,   0,   15, 0,   0,
    252, 158, 11, 84,  0,  0,   0,   8,  0,   0,  0,   0,   13, 72,  0,  0,   0,   0,  0,   0,  0,   0,   13, 72,  9,
    196, 0,   0,  0,   31, 3,   98,  11, 84,  9,  196, 0,   8,  0,   31, 3,   98,  7,  108, 9,  196, 0,   15, 0,   31,
    0,   0,   5,  120, 9,  196, 0,   31, 0,   31, 252, 158, 7,  108, 9,  196, 0,   15, 0,   31, 252, 158, 11, 84,  9,
    196, 0,   8,  0,   31, 0,   0,   13, 72,  9,  196, 0,   0,  0,   31, 0,   0,   13, 72,  23, 112, 0,   0,  0,   63,
    3,   98,  11, 84,  23, 112, 0,   8,  0,   63, 3,   98,  7,  108, 23, 112, 0,   15, 0,   63, 0,   0,   5,  120, 23,
    112, 0,   31, 0,   63, 252, 158, 7,  108, 23, 112, 0,   15, 0,   63, 252, 158, 11, 84,  23, 112, 0,   8,  0,   63,
    0,   0,   13, 72,  23, 112, 0,   0,  0,   63, 0,   0,   0,  0,   0,  8,   0,   1,  0,   0,  0,   7,   0,  8,   0,
    1,   0,   9,  0,   2,  0,   1,   0,  8,   0,  9,   0,   2,  0,   10, 0,   3,   0,  2,   0,  9,   0,   10, 0,   3,
    0,   11,  0,  4,   0,  3,   0,   10, 0,   11, 0,   4,   0,  12,  0,  5,   0,   4,  0,   11, 0,   12,  0,  5,   0,
    13,  0,   6,  0,   5,  0,   12,  0,  13,  0,  7,   0,   15, 0,   8,  0,   7,   0,  14,  0,  15,  0,   8,  0,   16,
    0,   9,   0,  8,   0,  15,  0,   16, 0,   9,  0,   17,  0,  10,  0,  9,   0,   16, 0,   17, 0,   10,  0,  18,  0,
    11,  0,   10, 0,   17, 0,   18,  0,  11,  0,  19,  0,   12, 0,   11, 0,   18,  0,  19,  0,  12,  0,   20, 0,   13,
    0,   12,  0,  19,  0,  20,  0,   0,  0,   1,  0,   2,   0,  3,   0,  4,   0,   5,  0,   6,  0,   0,   0,  7,   0,
    8,   0,   9,  0,   10, 0,   11,  0,  12,  0,  13,  0,   0,  0,   14, 0,   15,  0,  16,  0,  17,  0,   18, 0,   19,
    0,   20,  0,  0,   0,  0,   0,   1,  0,   2,  0,   3,   0,  4,   0,  5,   0,   6,  0,   14, 0,   15,  0,  16,  0,
    17,  0,   18, 0,   19, 0,   20,  0,  0,   0,  1,   0,   2,  0,   3,  0,   4,   0,  5,   0,  6,   0,   7,  0,   8,
    0,   9,   0,  10,  0,  11,  0,   12, 0,   13, 0,   14,  0,  15,  0,  16,  0,   17, 0,   18, 0,   19,  0,  20,  0,
    0,   0,   7,  0,   8,  0,   9,   0,  10,  0,  11,  0,   12, 0,   13, 0,   14,  0,  15,  0,  16,  0,   17, 0,   18,
    0,   19,  0,  20,  0,  0,   0,   0,  0,   15, 0,   45,  0,  0,   0,  0,   0,   0,  0,   0};
int gDll7DSpawnCounter;

s16 dll_7D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, u32 unused,
                       f32* scaleOverride) {
    s16 handle;
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll7DEffectResourceData;
    f32 scale = 1.0f;
    ModgfxCommand* commands;
    if (scaleOverride != NULL) {
        scale = *scaleOverride;
    }
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueY = commands[1].valueX = 0.15f * scale;
    commands[1].valueZ = 0.9f * scale;
    commands[2].stageIndex = 1;
    commands[2].parameter = 7;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, thirdSevenVertexIndices)];
    commands[2].flags = 2;
    commands[2].valueX = 3.0f;
    commands[2].valueY = 3.0f;
    commands[2].valueZ = 1.0f;
    commands[3].stageIndex = 2;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, firstSevenVertexIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 255.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 2;
    commands[4].parameter = 7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, secondSevenVertexIndices)];
    commands[4].flags = 4;
    commands[4].valueX = 255.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 2;
    commands[5].parameter = 7;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, secondSevenVertexIndices)];
    commands[5].flags = 2;
    commands[5].valueX = 2.0f;
    commands[5].valueY = 2.0f;
    commands[5].valueZ = 1.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 4.0f;
    commands[6].valueY = -6.0f;
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 3;
    commands[7].parameter = 0x15;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, allVertexIndices)];
    commands[7].flags = 0x4000;
    commands[7].valueX = 4.0f;
    commands[7].valueY = -6.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 7;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, firstSevenVertexIndices)];
    commands[8].flags = 4;
    commands[8].valueX = 0.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 0.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 7;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll7DEffectResourceView, secondSevenVertexIndices)];
    commands[9].flags = 4;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xa;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 10) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll7DEffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags = 0xc010080;
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
    handle = (*gModgfxInterface)
                 ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll7DEffectResourceData, 0x18,
                               (s16*)(&resourceData[offsetof(Dll7DEffectResourceView, triangles)]), 0x89, 0);
    gDll7DSpawnCounter += 1;
    if (gDll7DSpawnCounter == 5) {
        gDll7DSpawnCounter = 0;
    }
    return handle;
}

void dll_7D_release(void) {
}

void dll_7D_initialise(void) {
}

Dll7DResourceDescriptor gDll7DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_7D_initialise, dll_7D_release, NULL, dll_7D_spawnEffect,
};
