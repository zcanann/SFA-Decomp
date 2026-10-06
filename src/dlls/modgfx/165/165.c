/*
 * DLL 165 / 0xA5 - a rotation-aware layered effect spawner.
 */
#include "main/dll/dll_00A5_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA5EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[4][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA5EffectResourceView;

STATIC_ASSERT(offsetof(DllA5EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(DllA5EffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(DllA5EffectResourceView, allVertexIndices) == 0x68);
STATIC_ASSERT(offsetof(DllA5EffectResourceView, sequenceParams) == 0x78);
STATIC_ASSERT(offsetof(DllA5EffectResourceView, opaqueTail) == 0x86);
STATIC_ASSERT(sizeof(DllA5EffectResourceView) == 0x88);

extern u8 gDllA5EffectResourceData[sizeof(DllA5EffectResourceView)];

s16 gDllA5FirstFourVertexIndices[4] = {0, 1, 2, 3};
s16 gDllA5LastFourVertexIndices[4] = {4, 5, 6, 7};

void dll_A5_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDllA5EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    u32 fl;

    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA5EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 4;
    commands[1].vertexIndices = (s16*)(gDllA5FirstFourVertexIndices);
    commands[1].flags = 2;
    commands[1].valueX = 1.0f;
    commands[1].valueY = 1.0f;
    commands[1].valueZ = 1.26f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 4;
    commands[2].vertexIndices = (s16*)(gDllA5LastFourVertexIndices);
    commands[2].flags = 2;
    commands[2].valueX = 1.9f;
    commands[2].valueY = 1.9f;
    commands[2].valueZ = 1.26f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x80;
    commands[3].valueX = 0.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = (f32)sourceObj->anim.rotX;
    commands[4].stageIndex = 0;
    commands[4].parameter = 0x7a;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x10000;
    commands[4].valueX = 0.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 8;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(DllA5EffectResourceView, allVertexIndices)];
    commands[5].flags = 4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x400000;
    commands[6].valueX = 0.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 1.0f;
    commands[7].stageIndex = 1;
    commands[7].parameter = 8;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(DllA5EffectResourceView, allVertexIndices)];
    commands[7].flags = 2;
    commands[7].valueX = 1.0f;
    commands[7].valueY = 1.0f;
    commands[7].valueZ = 3.0f;
    commands[8].stageIndex = 1;
    commands[8].parameter = 0x3a1;
    commands[8].vertexIndices = NULL;
    commands[8].flags = 0x1800000;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 2.0f;
    commands[9].stageIndex = 2;
    commands[9].parameter = 0x7a;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x10000;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 0.0f;
    commands[10].stageIndex = 2;
    commands[10].parameter = 8;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(DllA5EffectResourceView, allVertexIndices)];
    commands[10].flags = 4;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 0.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 2;
    commands[11].parameter = 0;
    commands[11].vertexIndices = NULL;
    commands[11].flags = 0x400000;
    commands[11].valueX = 0.0f;
    commands[11].valueY = 0.0f;
    commands[11].valueZ = 25.0f;
    commands[12].stageIndex = 2;
    commands[12].parameter = 0x3a0;
    commands[12].vertexIndices = NULL;
    commands[12].flags = 0x800000;
    commands[12].valueX = 1.0f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 0.0f;

    packet.context.modeByte = variant;
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
    packet.context.textureFrameTimer = 0x3c;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 13) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA5EffectResourceView, sequenceParams[6])];
    packet.context.commands = commands;
    packet.context.flags = 0x4040000;
    packet.context.flags |= (flags | 0x80);
    fl = packet.context.flags;
    if (fl & 1) {
        if (sourceObj != NULL) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += sourceObj->anim.worldPosY;
            packet.context.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 8, (ModgfxEffectVertex*)(int)gDllA5EffectResourceData, 4,
                      (s16*)(&resourceData[offsetof(DllA5EffectResourceView, triangles)]), 0x5e0, 0);
}

void dll_A5_release(void) {
}

void dll_A5_initialise(void) {
}

u8 gDllA5EffectResourceData[sizeof(DllA5EffectResourceView)] = {
    252, 24, 5, 120, 0,  0,  0,   0,   0,   0,   0,  0, 1, 144, 0,  0,   0, 0,   0,  0,   3,   232, 5,
    120, 0,  0, 0,   15, 0,  0,   0,   0,   9,   96, 0, 0, 0,   15, 0,   0, 252, 24, 5,   120, 15,  160,
    0,   0,  0, 31,  0,  0,  1,   144, 15,  160, 0,  0, 0, 31,  3,  232, 5, 120, 15, 160, 0,   15,  0,
    31,  0,  0, 9,   96, 15, 160, 0,   15,  0,   31, 0, 0, 0,   2,  0,   6, 0,   0,  0,   6,   0,   4,
    0,   1,  0, 3,   0,  7,  0,   1,   0,   7,   0,  5, 0, 0,   0,  1,   0, 2,   0,  3,   0,   4,   0,
    5,   0,  6, 0,   7,  0,  0,   0,   130, 0,   26, 0, 0, 0,   0,  0,   0, 0,   0,  0,   0};
DllA5ResourceDescriptor gDllA5ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A5_initialise, dll_A5_release, NULL, dll_A5_spawnEffect,
};
