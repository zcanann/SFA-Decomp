/*
 * DLL 107 / 0x6B - a modgfx effect spawner.
 */
#include "main/dll/dll_006B_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6BEffectResourceView {
    ModgfxEffectVertex vertices[5];
    u8 pad32[2];
    s16 colors[5][3];
    u8 pad52[2];
    s16 allVertexIndices[6];
    s16 sequenceParams[7];
    u8 pad6E[2];
} Dll6BEffectResourceView;

STATIC_ASSERT(offsetof(Dll6BEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll6BEffectResourceView, colors) == 0x34);
STATIC_ASSERT(offsetof(Dll6BEffectResourceView, allVertexIndices) == 0x54);
STATIC_ASSERT(offsetof(Dll6BEffectResourceView, sequenceParams) == 0x60);
STATIC_ASSERT(sizeof(Dll6BEffectResourceView) == 0x70);

u16 gDll6BEffectResourceData[sizeof(Dll6BEffectResourceView) / sizeof(u16)] = {
    0xfc18, 0x0000, 0xfc18, 0x0000, 0x0000, 0x03e8, 0x0000, 0xfc18, 0x003f,
    0x0000, 0x03e8, 0x0000, 0x03e8, 0x003f, 0x003f, 0xfc18, 0x0000, 0x03e8,
    0x0000, 0x003f, 0x0000, 0x0000, 0x0000, 0x0020, 0x0020, 0x0000, 0x0000,
    0x0001, 0x0004, 0x0001, 0x0002, 0x0004, 0x0004, 0x0002, 0x0003, 0x0000,
    0x0004, 0x0003, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0000, 0x0000, 0x0050, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000,
};

void dll_6B_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll6BEffectResourceData;
    GameObject* context;
    f32 originOffset = 0.0f;

    packet.entries[0].layer = 0;
    packet.entries[0].flags = 5;
    packet.entries[0].tex = &resourceData[offsetof(Dll6BEffectResourceView, allVertexIndices)];
    packet.entries[0].mode = 4;
    packet.entries[0].x = 255.0f;
    packet.entries[0].y = originOffset;
    packet.entries[0].z = originOffset;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 5;
    packet.entries[1].tex = &resourceData[offsetof(Dll6BEffectResourceView, allVertexIndices)];
    packet.entries[1].mode = 2;
    packet.entries[1].x = 0.01f;
    packet.entries[1].y = 0.01f;
    packet.entries[1].z = 0.01f;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 5;
    packet.entries[2].tex = &resourceData[offsetof(Dll6BEffectResourceView, allVertexIndices)];
    packet.entries[2].mode = 8;
    packet.entries[2].x = 200.0f;
    packet.entries[2].y = 200.0f;
    packet.entries[2].z = 200.0f;
    packet.entries[3].layer = 0;
    packet.entries[3].flags = 0x7a;
    packet.entries[3].tex = NULL;
    packet.entries[3].mode = 0x10000;
    packet.entries[3].x = originOffset;
    packet.entries[3].y = originOffset;
    packet.entries[3].z = originOffset;
    packet.entries[4].layer = 1;
    packet.entries[4].flags = 5;
    packet.entries[4].tex = &resourceData[offsetof(Dll6BEffectResourceView, allVertexIndices)];
    packet.entries[4].mode = 4;
    packet.entries[4].x = originOffset;
    packet.entries[4].y = originOffset;
    packet.entries[4].z = originOffset;
    packet.entries[5].layer = 1;
    packet.entries[5].flags = 5;
    packet.entries[5].tex = &resourceData[offsetof(Dll6BEffectResourceView, allVertexIndices)];
    packet.entries[5].mode = 2;
    packet.entries[5].x = 4000.0f;
    packet.entries[5].y = 1.0f;
    packet.entries[5].z = 4000.0f;
    packet.modeByte = 0;
    context = sourceObj;
    packet.sourceObj = context;
    packet.sourceMode = variant;
    packet.position[0] = originOffset;
    packet.position[1] = 10.0f;
    packet.position[2] = originOffset;
    packet.velocity[0] = originOffset;
    packet.velocity[1] = originOffset;
    packet.velocity[2] = originOffset;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 5;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.commandCount = 6;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll6BEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0x4000010;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (context != NULL) {
            packet.position[0] = originOffset + context->anim.worldPosX;
            packet.position[1] = 10.0f + context->anim.worldPosY;
            packet.position[2] = originOffset + context->anim.worldPosZ;
        } else {
            packet.position[0] = originOffset + spawnParams->posX;
            packet.position[1] = 10.0f + spawnParams->posY;
            packet.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 5, (u8*)(int)gDll6BEffectResourceData, 4,
                      &resourceData[offsetof(Dll6BEffectResourceView, colors)], 0x5e, 0);
}

void dll_6B_release(void) {
}

void dll_6B_initialise(void) {
}

Dll6BResourceDescriptor gDll6BResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6B_initialise, dll_6B_release, NULL, dll_6B_spawnEffect,
};
