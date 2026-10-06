/*
 * DLL 136 / 0x88 - a nine-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0088_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll88EffectResourceView {
    ModgfxEffectVertex vertices[25];
    s16 opaque0FA;
    s16 triangles[32][3];
    s16 allVertexIndices[25];
    s16 opaque1EE;
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll88EffectResourceView;

STATIC_ASSERT(offsetof(Dll88EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, opaque0FA) == 0x0FA);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, triangles) == 0x0FC);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, allVertexIndices) == 0x1BC);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, opaque1EE) == 0x1EE);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, sequenceParams) == 0x1F0);
STATIC_ASSERT(offsetof(Dll88EffectResourceView, opaqueTail) == 0x1FE);
STATIC_ASSERT(sizeof(Dll88EffectResourceView) == 0x200);

u8 gDll88EffectResourceData[sizeof(Dll88EffectResourceView)] = {
    254, 12,  1,   244, 0,   0,   0,   0,   0,   31,  255, 6,   1,   244, 255, 176, 0,   7,   0,   31,  0,   0,   1,
    244, 255, 136, 0,   16,  0,   31,  0,   250, 1,   244, 255, 176, 0,   24,  0,   31,  1,   244, 1,   244, 0,   0,
    0,   31,  0,   31,  254, 12,  0,   250, 255, 176, 0,   0,   0,   24,  255, 6,   0,   250, 255, 96,  0,   7,   0,
    24,  0,   0,   0,   250, 255, 56,  0,   16,  0,   24,  0,   250, 0,   250, 255, 96,  0,   24,  0,   24,  1,   244,
    0,   250, 255, 176, 0,   31,  0,   24,  254, 12,  0,   0,   255, 136, 0,   0,   0,   16,  255, 6,   0,   0,   255,
    56,  0,   7,   0,   16,  0,   0,   0,   0,   255, 16,  0,   16,  0,   16,  0,   250, 0,   0,   255, 56,  0,   24,
    0,   16,  1,   244, 0,   0,   255, 136, 0,   31,  0,   16,  254, 12,  255, 6,   255, 176, 0,   0,   0,   7,   255,
    6,   255, 6,   255, 96,  0,   7,   0,   7,   0,   0,   255, 6,   255, 56,  0,   16,  0,   7,   0,   250, 255, 6,
    255, 96,  0,   24,  0,   7,   1,   244, 255, 6,   255, 176, 0,   31,  0,   7,   254, 12,  254, 12,  0,   0,   0,
    0,   0,   0,   255, 6,   254, 12,  255, 176, 0,   7,   0,   0,   0,   0,   254, 12,  255, 136, 0,   16,  0,   0,
    0,   250, 254, 12,  255, 176, 0,   24,  0,   0,   1,   244, 254, 12,  0,   0,   0,   31,  0,   0,   0,   0,   0,
    5,   0,   1,   0,   0,   0,   5,   0,   6,   0,   1,   0,   6,   0,   2,   0,   1,   0,   6,   0,   7,   0,   2,
    0,   7,   0,   3,   0,   2,   0,   7,   0,   8,   0,   3,   0,   8,   0,   4,   0,   3,   0,   8,   0,   9,   0,
    4,   0,   10,  0,   6,   0,   5,   0,   10,  0,   11,  0,   6,   0,   11,  0,   7,   0,   6,   0,   11,  0,   12,
    0,   7,   0,   12,  0,   8,   0,   7,   0,   12,  0,   13,  0,   8,   0,   13,  0,   9,   0,   8,   0,   13,  0,
    14,  0,   9,   0,   15,  0,   11,  0,   10,  0,   15,  0,   16,  0,   11,  0,   16,  0,   12,  0,   11,  0,   16,
    0,   17,  0,   12,  0,   17,  0,   13,  0,   12,  0,   17,  0,   18,  0,   13,  0,   18,  0,   14,  0,   13,  0,
    18,  0,   19,  0,   14,  0,   20,  0,   16,  0,   15,  0,   20,  0,   21,  0,   16,  0,   21,  0,   17,  0,   16,
    0,   21,  0,   22,  0,   17,  0,   22,  0,   18,  0,   17,  0,   22,  0,   23,  0,   18,  0,   23,  0,   19,  0,
    18,  0,   23,  0,   24,  0,   19,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,
    0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,
    19,  0,   20,  0,   21,  0,   22,  0,   23,  0,   24,  0,   0,   0,   0,   0,   30,  0,   30,  0,   80,  0,   0,
    0,   0,   0,   0,   0,   0};

void dll_88_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll88EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    f32 originOffset = 0.0f;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x19;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[0].flags = 2;
    commands[0].valueX = 20.7f;
    commands[0].valueY = 20.7f;
    commands[0].valueZ = 20.7f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x19;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[1].flags = 0x80;
    commands[1].valueX = originOffset;
    commands[1].valueY = originOffset;
    commands[1].valueZ = originOffset;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0x7a;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x10000;
    commands[2].valueX = originOffset;
    commands[2].valueY = originOffset;
    commands[2].valueZ = originOffset;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0x19;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[3].flags = 4;
    commands[3].valueX = originOffset;
    commands[3].valueY = originOffset;
    commands[3].valueZ = originOffset;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0x19;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[4].flags = 4;
    commands[4].valueX = 255.0f;
    commands[4].valueY = originOffset;
    commands[4].valueZ = originOffset;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x19;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[5].flags = 2;
    commands[5].valueX = 2.0f;
    commands[5].valueY = 2.0f;
    commands[5].valueZ = 1.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x19;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[6].flags = 2;
    commands[6].valueX = 1.5f;
    commands[6].valueY = 1.5f;
    commands[6].valueZ = 1.0f;
    commands[7].stageIndex = 3;
    commands[7].parameter = 0x19;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[7].flags = 2;
    commands[7].valueX = 1.5f;
    commands[7].valueY = 1.5f;
    commands[7].valueZ = 1.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 0x19;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll88EffectResourceView, allVertexIndices)];
    commands[8].flags = 4;
    commands[8].valueX = originOffset;
    commands[8].valueY = originOffset;
    commands[8].valueZ = originOffset;
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
    packet.context.drawGroupStride = 25;
    packet.context.initialStateByte = 0x19;
    packet.context.byte5A = 0xff;
    packet.context.textureFrameTimer = 16;
    packet.context.flags = 0x4000480;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 9) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll88EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (sourceObj != NULL) {
            GameObject* anchorObj = sourceObj;
            packet.context.position[0] += anchorObj->anim.worldPosX;
            packet.context.position[1] += anchorObj->anim.worldPosY;
            packet.context.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.context.position[0] += anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x19, (ModgfxEffectVertex*)(int)gDll88EffectResourceData, 0x20,
                      (s16*)(&resourceData[offsetof(Dll88EffectResourceView, triangles)]), 0x205, 0);
}

void dll_88_release(void) {
}

void dll_88_initialise(void) {
}

Dll88ResourceDescriptor gDll88ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_88_initialise, dll_88_release, NULL, dll_88_spawnEffect,
};
