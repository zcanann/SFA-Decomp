/*
 * DLL 138 / 0x8A - a single-command modgfx effect spawner.
 */
#include "main/dll/dll_008A_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll8AEffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[12][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8AEffectResourceView;

STATIC_ASSERT(offsetof(Dll8AEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll8AEffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(Dll8AEffectResourceView, allVertexIndices) == 0x98);
STATIC_ASSERT(offsetof(Dll8AEffectResourceView, sequenceParams) == 0xA8);
STATIC_ASSERT(offsetof(Dll8AEffectResourceView, opaqueTail) == 0xB6);
STATIC_ASSERT(sizeof(Dll8AEffectResourceView) == 0xB8);

u8 gDll8AEffectResourceData[sizeof(Dll8AEffectResourceView)] = {
    254, 12,  254, 12, 254, 12,  0,   0,   0,   0,   1,  244, 254, 12, 254, 12,  0,  32,  0,  32,  1,   244, 254,
    12,  1,   244, 0,  0,   0,   0,   254, 12,  254, 12, 1,   244, 0,  32,  0,   32, 254, 12, 1,   244, 254, 12,
    0,   0,   0,   0,  1,   244, 1,   244, 254, 12,  0,  32,  0,   32, 1,   244, 1,  244, 1,  244, 0,   0,   0,
    0,   254, 12,  1,  244, 1,   244, 0,   32,  0,   32, 0,   0,   0,  4,   0,   5,  0,   0,  0,   5,   0,   1,
    0,   1,   0,   5,  0,   6,   0,   1,   0,   6,   0,  2,   0,   2,  0,   6,   0,  7,   0,  2,   0,   7,   0,
    3,   0,   3,   0,  7,   0,   4,   0,   3,   0,   4,  0,   0,   0,  0,   0,   1,  0,   2,  0,   0,   0,   2,
    0,   3,   0,   4,  0,   7,   0,   6,   0,   4,   0,  6,   0,   5,  0,   0,   0,  1,   0,  2,   0,   3,   0,
    4,   0,   5,   0,  6,   0,   7,   0,   0,   0,   10, 0,   0,   0,  0,   0,   0,  0,   0,  0,   0,   0,   0};

void dll_8A_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll8AEffectResourceData;
    ModgfxCommand* commands = packet.entries;

    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8AEffectResourceView, allVertexIndices)];
    commands[0].flags = 2;
    commands[0].valueX = 0.5f;
    commands[0].valueY = 0.5f;
    commands[0].valueZ = 0.5f;
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
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 8;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.flags = 0x2000492;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand)) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll8AEffectResourceView, sequenceParams[6])];
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
        ->spawnEffect(&packet.context, 0, 8, (ModgfxEffectVertex*)(int)gDll8AEffectResourceData, 0xC,
                      (s16*)(&resourceData[offsetof(Dll8AEffectResourceView, triangles)]), 0x1FD, 0);
}

void dll_8A_release(void) {
}

void dll_8A_initialise(void) {
}

Dll8AResourceDescriptor gDll8AResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_8A_initialise, dll_8A_release, NULL, dll_8A_spawnEffect,
};
