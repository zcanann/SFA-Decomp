/*
 * DLL 110 / 0x6E - a modgfx effect spawner.
 */
#include "main/dll/dll_006E_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6EEffectResourceView {
    ModgfxEffectVertex vertices[5];
    u8 pad32[2];
    s16 triangleIndices[4][3];
    u8 opaque4C[8];
    s16 allVertexIndices[6];
    s16 sequenceParams[7];
    u8 pad6E[2];
} Dll6EEffectResourceView;

STATIC_ASSERT(offsetof(Dll6EEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll6EEffectResourceView, triangleIndices) == 0x34);
STATIC_ASSERT(offsetof(Dll6EEffectResourceView, allVertexIndices) == 0x54);
STATIC_ASSERT(offsetof(Dll6EEffectResourceView, sequenceParams) == 0x60);
STATIC_ASSERT(sizeof(Dll6EEffectResourceView) == 0x70);

u16 gDll6EEffectResourceData[sizeof(Dll6EEffectResourceView) / sizeof(u16)] = {
    0xfc18, 0x0000, 0xfc18, 0x0000, 0x0000, 0x03e8, 0x0000, 0xfc18, 0x003f,
    0x0000, 0x03e8, 0x0000, 0x03e8, 0x003f, 0x003f, 0xfc18, 0x0000, 0x03e8,
    0x0000, 0x003f, 0x0000, 0x0000, 0x0000, 0x0020, 0x0020, 0x0000, 0x0000,
    0x0001, 0x0004, 0x0001, 0x0002, 0x0004, 0x0004, 0x0002, 0x0003, 0x0000,
    0x0004, 0x0003, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0000, 0x0000, 0x0050, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000,
};

void dll_6E_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll6EEffectResourceData;
    GameObject* context;
    f32 originOffset = 0.0f;

    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 5;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll6EEffectResourceView, allVertexIndices)];
    packet.entries[0].flags = 4;
    packet.entries[0].valueX = 255.0f;
    packet.entries[0].valueY = originOffset;
    packet.entries[0].valueZ = originOffset;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 5;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll6EEffectResourceView, allVertexIndices)];
    packet.entries[1].flags = 2;
    packet.entries[1].valueX = 0.01f;
    packet.entries[1].valueY = 0.01f;
    packet.entries[1].valueZ = 0.01f;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 5;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll6EEffectResourceView, allVertexIndices)];
    packet.entries[2].flags = 8;
    packet.entries[2].valueX = originOffset;
    packet.entries[2].valueY = 200.0f;
    packet.entries[2].valueZ = originOffset;
    packet.entries[3].stageIndex = 0;
    packet.entries[3].parameter = 0x7a;
    packet.entries[3].vertexIndices = NULL;
    packet.entries[3].flags = 0x10000;
    packet.entries[3].valueX = originOffset;
    packet.entries[3].valueY = originOffset;
    packet.entries[3].valueZ = originOffset;
    packet.entries[4].stageIndex = 1;
    packet.entries[4].parameter = 5;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll6EEffectResourceView, allVertexIndices)];
    packet.entries[4].flags = 4;
    packet.entries[4].valueX = originOffset;
    packet.entries[4].valueY = originOffset;
    packet.entries[4].valueZ = originOffset;
    packet.entries[5].stageIndex = 1;
    packet.entries[5].parameter = 5;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll6EEffectResourceView, allVertexIndices)];
    packet.entries[5].flags = 2;
    packet.entries[5].valueX = 4000.0f;
    packet.entries[5].valueY = 1.0f;
    packet.entries[5].valueZ = 4000.0f;
    packet.context.modeByte = 0;
    context = sourceObj;
    packet.context.sourceObject = context;
    packet.context.variant = variant;
    packet.context.position[0] = originOffset;
    packet.context.position[1] = 10.0f;
    packet.context.position[2] = originOffset;
    packet.context.velocity[0] = originOffset;
    packet.context.velocity[1] = originOffset;
    packet.context.velocity[2] = originOffset;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 5;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.commandCount = 6;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll6EEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4000010;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (context != NULL) {
            packet.context.position[0] = originOffset + context->anim.worldPosX;
            packet.context.position[1] = 10.0f + context->anim.worldPosY;
            packet.context.position[2] = originOffset + context->anim.worldPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = 10.0f + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 5, (ModgfxEffectVertex*)(int)gDll6EEffectResourceData, 4,
                      (s16*)(&resourceData[offsetof(Dll6EEffectResourceView, triangleIndices)]), 0x5e, 0);
}

void dll_6E_release(void) {
}

void dll_6E_initialise(void) {
}

Dll6EResourceDescriptor gDll6EResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6E_initialise, dll_6E_release, NULL, dll_6E_spawnEffect,
};
