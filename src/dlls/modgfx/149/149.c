/*
 * DLL 149 / 0x95 - a seven-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0095_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll95EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[8][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll95EffectResourceView;

STATIC_ASSERT(offsetof(Dll95EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, allVertexIndices) == 0x80);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, sequenceParams) == 0x90);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, opaqueTail) == 0x9E);
STATIC_ASSERT(sizeof(Dll95EffectResourceView) == 0xA0);

s16 gDll95VertexIndices[4] = {4, 5, 6, 7};

extern u16 gDll95EffectResourceData[sizeof(Dll95EffectResourceView) / sizeof(u16)];

void dll_95_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)gDll95EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    GameObject* anchorObj = sourceObj;
    PartFxSpawnParams* anchorParams = spawnParams;

    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[0].flags = 0x2;
    commands[0].valueX = 0.014f;
    commands[0].valueY = 0.03f;
    commands[0].valueZ = 0.014f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 4;
    commands[1].vertexIndices = (s16*)(gDll95VertexIndices);
    commands[1].flags = 0x8;
    commands[1].valueX = 255.0f;
    commands[1].valueY = 255.0f;
    commands[1].valueZ = 0.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 4;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[2].flags = 0x8;
    commands[2].valueX = 255.0f;
    commands[2].valueY = 85.0f;
    commands[2].valueZ = 0.0f;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x400000;
    commands[3].valueX = 0.0f;
    commands[3].valueY = 80.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 8;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[4].flags = 0x2;
    commands[4].valueX = 100.0f;
    commands[4].valueY = 100.0f;
    commands[4].valueZ = 100.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0;
    commands[5].vertexIndices = NULL;
    commands[5].flags = 0x400000;
    commands[5].valueX = 0.0f;
    commands[5].valueY = -80.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 8;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4;
    commands[6].valueX = 0.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 2.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 8;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x3C;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 7) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4002400;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0 && (u32)spawnParams != 0) {
            packet.context.position[0] += anchorObj->anim.worldPosX + anchorParams->posX;
            packet.context.position[1] += anchorObj->anim.worldPosY + anchorParams->posY;
            packet.context.position[2] += anchorObj->anim.worldPosZ + anchorParams->posZ;
        } else if ((u32)sourceObj != 0) {
            packet.context.position[0] += anchorObj->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else if ((u32)spawnParams != 0) {
            packet.context.position[0] += anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 8, (ModgfxEffectVertex*)(resourceData), 8, (s16*)(&resourceData[offsetof(Dll95EffectResourceView, triangles)]), 0x46,
                      0);
}

void dll_95_release(void) {
}

void dll_95_initialise(void) {
}

u16 gDll95EffectResourceData[sizeof(Dll95EffectResourceView) / sizeof(u16)] = {
    0xfce0, 0x01f4, 0xfce0, 0x0008, 0x001f, 0x0320, 0x01f4, 0xfce0, 0x0078,
    0x001f, 0x0320, 0x01f4, 0x0320, 0x0008, 0x001f, 0xfce0, 0x01f4, 0x0320,
    0x0078, 0x001f, 0xfc18, 0x0000, 0xfc18, 0x0008, 0x0000, 0x03e8, 0x0000,
    0xfc18, 0x0078, 0x0000, 0x03e8, 0x0000, 0x03e8, 0x0008, 0x0000, 0xfc18,
    0x0000, 0x03e8, 0x0078, 0x0000, 0x0000, 0x0001, 0x0005, 0x0000, 0x0005,
    0x0004, 0x0001, 0x0002, 0x0006, 0x0001, 0x0006, 0x0005, 0x0002, 0x0003,
    0x0007, 0x0002, 0x0007, 0x0006, 0x0003, 0x0000, 0x0004, 0x0003, 0x0004,
    0x0007, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0000, 0x0316, 0x000a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

Dll95ResourceDescriptor gDll95ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_95_initialise, dll_95_release, NULL, dll_95_spawnEffect,
};
