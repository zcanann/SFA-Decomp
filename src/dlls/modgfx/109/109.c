/*
 * DLL 109 / 0x6D - a modgfx effect spawner.
 */
#include "main/dll/dll_006D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6DEffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll6DEffectResourceView;

STATIC_ASSERT(offsetof(Dll6DEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, triangleIndices) == 0x08C);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, allVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, firstGroupIndices) == 0x0F0);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, secondGroupIndices) == 0x100);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(sizeof(Dll6DEffectResourceView) == 0x120);

u16 gDll6DEffectResourceData[sizeof(Dll6DEffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x002a, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x0035, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0040, 0x0000, 0x0000,
    0x1770, 0x03e8, 0x0000, 0x001f, 0x0362, 0x1770, 0x01f4, 0x000b, 0x001f,
    0x0362, 0x1770, 0xfe0c, 0x0016, 0x001f, 0x0000, 0x1770, 0xfc18, 0x0020,
    0x001f, 0xfc9e, 0x1770, 0xfe0c, 0x002a, 0x001f, 0xfc9e, 0x1770, 0x01f4,
    0x0035, 0x001f, 0x0000, 0x1770, 0x03e8, 0x0040, 0x001f, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x000d, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0000, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x0000, 0x0000, 0x0028, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

void dll_6D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll6DEffectResourceData;
    GameObject* context;

    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 0xe;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, allVertexIndices)];
    packet.entries[0].flags = 0x80;
    packet.entries[0].valueX = 0.0f;
    packet.entries[0].valueY = -16000.0f;
    packet.entries[0].valueZ = 0.0f;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 7;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, secondGroupIndices)];
    packet.entries[1].flags = 4;
    packet.entries[1].valueX = 0.0f;
    packet.entries[1].valueY = 0.0f;
    packet.entries[1].valueZ = 0.0f;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 7;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, firstGroupIndices)];
    packet.entries[2].flags = 2;
    packet.entries[2].valueX = 0.3f;
    packet.entries[2].valueY = 0.7f;
    packet.entries[2].valueZ = 0.3f;
    packet.entries[3].stageIndex = 0;
    packet.entries[3].parameter = 7;
    packet.entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, secondGroupIndices)];
    packet.entries[3].flags = 2;
    packet.entries[3].valueX = 6.5f;
    packet.entries[3].valueY = 0.7f;
    packet.entries[3].valueZ = 6.5f;
    packet.entries[4].stageIndex = 1;
    packet.entries[4].parameter = 0xe;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, allVertexIndices)];
    packet.entries[4].flags = 0x4000;
    packet.entries[4].valueX = 0.0f;
    packet.entries[4].valueY = -3.0f;
    packet.entries[4].valueZ = 0.0f;
    packet.entries[5].stageIndex = 1;
    packet.entries[5].parameter = 7;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll6DEffectResourceView, firstGroupIndices)];
    packet.entries[5].flags = 4;
    packet.entries[5].valueX = 0.0f;
    packet.entries[5].valueY = 0.0f;
    packet.entries[5].valueZ = 0.0f;
    packet.context.modeByte = 0;
    context = sourceObj;
    packet.context.sourceObject = context;
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
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.commandCount = 6;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4000004;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (context != NULL) {
            packet.context.position[0] += context->anim.worldPosX;
            packet.context.position[1] += context->anim.worldPosY;
            packet.context.position[2] += context->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll6DEffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll6DEffectResourceView, triangleIndices)]), 0x34, 0);
}

void dll_6D_release(void) {
}

void dll_6D_initialise(void) {
}

Dll6DResourceDescriptor gDll6DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6D_initialise, dll_6D_release, NULL, dll_6D_spawnEffect,
};
