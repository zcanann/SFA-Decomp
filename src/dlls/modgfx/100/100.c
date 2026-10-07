/*
 * DLL 100 / 0x64 - particle/effect spawner front-end.
 *
 * dll_64_spawnEffect builds a fixed nine-command effect description and
 * submits it through the modgfx interface.
 */
#include "main/dll/dll_0064_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll64EffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll64EffectResourceView;

STATIC_ASSERT(offsetof(Dll64EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, triangleIndices) == 0x08C);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, allVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, firstGroupIndices) == 0x0F0);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, secondGroupIndices) == 0x100);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(sizeof(Dll64EffectResourceView) == 0x120);

u16 gDll64EffectResourceData[sizeof(Dll64EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x002c,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0058, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0080, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x00a8, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x00d0, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0100, 0x0000, 0x0000,
    0x0bb8, 0x03e8, 0x0000, 0x0040, 0x0362, 0x0bb8, 0x01f4, 0x002c, 0x0040,
    0x0362, 0x0bb8, 0xfe0c, 0x0058, 0x0040, 0x0000, 0x0bb8, 0xfc18, 0x0080,
    0x0040, 0xfc9e, 0x0bb8, 0xfe0c, 0x00a8, 0x0040, 0xfc9e, 0x0bb8, 0x01f4,
    0x00d0, 0x0040, 0x0000, 0x0bb8, 0x03e8, 0x0100, 0x0040, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x000d, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0000, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x0000, 0x0000, 0x0104, 0x003c, 0x0001, 0x0104, 0x0000, 0x0000, 0x0000,
};

void dll_64_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u32 effectScaleTenths;
    u8* resourceData = (u8*)(int)gDll64EffectResourceData;

    if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[1])] = 0;
    }
    effectScaleTenths = ((u8*)sourceObj->anim.placementData)[0x1a];
    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 7;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, firstGroupIndices)];
    packet.entries[0].flags = 2;
    packet.entries[0].valueX = 0.75f;
    packet.entries[0].valueY = 1.0f;
    packet.entries[0].valueZ = 0.75f;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 7;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[1].flags = 2;
    packet.entries[1].valueX = 0.45f;
    packet.entries[1].valueY = 0.6f;
    packet.entries[1].valueZ = 0.45f;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 0xe;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[2].flags = 4;
    packet.entries[2].valueX = 0.0f;
    packet.entries[2].valueY = 0.0f;
    packet.entries[2].valueZ = 0.0f;
    packet.entries[3].stageIndex = 1;
    packet.entries[3].parameter = 7;
    packet.entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[3].flags = 4;
    packet.entries[3].valueX = 200.0f;
    packet.entries[3].valueY = 0.0f;
    packet.entries[3].valueZ = 0.0f;
    packet.entries[4].stageIndex = 1;
    packet.entries[4].parameter = 0xe;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[4].flags = 0x100;
    packet.entries[4].valueX = 0.0f;
    packet.entries[4].valueY = 0.0f;
    packet.entries[4].valueZ = 20.0f;
    packet.entries[5].stageIndex = 2;
    packet.entries[5].parameter = 0xe;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[5].flags = 0x100;
    packet.entries[5].valueX = 0.0f;
    packet.entries[5].valueY = 0.0f;
    packet.entries[5].valueZ = 20.0f;
    packet.entries[6].stageIndex = 3;
    packet.entries[6].parameter = 1;
    packet.entries[6].vertexIndices = NULL;
    packet.entries[6].flags = 0x2000;
    packet.entries[6].valueX = 0.0f;
    packet.entries[6].valueY = 0.0f;
    packet.entries[6].valueZ = 0.0f;
    packet.entries[7].stageIndex = 4;
    packet.entries[7].parameter = 7;
    packet.entries[7].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[7].flags = 4;
    packet.entries[7].valueX = 0.0f;
    packet.entries[7].valueY = 0.0f;
    packet.entries[7].valueZ = 0.0f;
    packet.entries[8].stageIndex = 4;
    packet.entries[8].parameter = 0xe;
    packet.entries[8].vertexIndices = (s16*)&resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[8].flags = 0x100;
    packet.entries[8].valueX = 0.0f;
    packet.entries[8].valueY = 0.0f;
    packet.entries[8].valueZ = 20.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    if (effectScaleTenths != 0) {
        packet.context.scale = 0.1f * effectScaleTenths;
    } else {
        packet.context.scale = 1.0f;
    }
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = 9;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4040080;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.context.position[0] += params->posX;
            packet.context.position[1] += params->posY;
            packet.context.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll64EffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll64EffectResourceView, triangleIndices)]), 0x5e0, 0);
}

void dll_64_release(void) {
}

void dll_64_initialise(void) {
}

Dll64ResourceDescriptor gDll64ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_64_initialise, dll_64_release, NULL, dll_64_spawnEffect,
};
