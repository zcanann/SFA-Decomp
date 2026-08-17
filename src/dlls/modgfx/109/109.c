/*
 * DLL 109 / 0x6D - a modgfx effect spawner.
 */
#include "main/dll/dll_006D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6DEffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 colors[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll6DEffectResourceView;

STATIC_ASSERT(offsetof(Dll6DEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll6DEffectResourceView, colors) == 0x08C);
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

    packet.entries[0].layer = 0;
    packet.entries[0].flags = 0xe;
    packet.entries[0].tex = &resourceData[offsetof(Dll6DEffectResourceView, allVertexIndices)];
    packet.entries[0].mode = 0x80;
    packet.entries[0].x = 0.0f;
    packet.entries[0].y = -16000.0f;
    packet.entries[0].z = 0.0f;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 7;
    packet.entries[1].tex = &resourceData[offsetof(Dll6DEffectResourceView, secondGroupIndices)];
    packet.entries[1].mode = 4;
    packet.entries[1].x = 0.0f;
    packet.entries[1].y = 0.0f;
    packet.entries[1].z = 0.0f;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 7;
    packet.entries[2].tex = &resourceData[offsetof(Dll6DEffectResourceView, firstGroupIndices)];
    packet.entries[2].mode = 2;
    packet.entries[2].x = 0.3f;
    packet.entries[2].y = 0.7f;
    packet.entries[2].z = 0.3f;
    packet.entries[3].layer = 0;
    packet.entries[3].flags = 7;
    packet.entries[3].tex = &resourceData[offsetof(Dll6DEffectResourceView, secondGroupIndices)];
    packet.entries[3].mode = 2;
    packet.entries[3].x = 6.5f;
    packet.entries[3].y = 0.7f;
    packet.entries[3].z = 6.5f;
    packet.entries[4].layer = 1;
    packet.entries[4].flags = 0xe;
    packet.entries[4].tex = &resourceData[offsetof(Dll6DEffectResourceView, allVertexIndices)];
    packet.entries[4].mode = 0x4000;
    packet.entries[4].x = 0.0f;
    packet.entries[4].y = -3.0f;
    packet.entries[4].z = 0.0f;
    packet.entries[5].layer = 1;
    packet.entries[5].flags = 7;
    packet.entries[5].tex = &resourceData[offsetof(Dll6DEffectResourceView, firstGroupIndices)];
    packet.entries[5].mode = 4;
    packet.entries[5].x = 0.0f;
    packet.entries[5].y = 0.0f;
    packet.entries[5].z = 0.0f;
    packet.modeByte = 0;
    context = sourceObj;
    packet.sourceObj = context;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.commandCount = 6;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll6DEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0x4000004;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (context != NULL) {
            packet.position[0] += context->anim.worldPosX;
            packet.position[1] += context->anim.worldPosY;
            packet.position[2] += context->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0xe, (u8*)(int)gDll6DEffectResourceData, 0xc,
                      &resourceData[offsetof(Dll6DEffectResourceView, colors)], 0x34, 0);
}

void dll_6D_release(void) {
}

void dll_6D_initialise(void) {
}

Dll6DResourceDescriptor gDll6DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6D_initialise, dll_6D_release, NULL, dll_6D_spawnEffect,
};
