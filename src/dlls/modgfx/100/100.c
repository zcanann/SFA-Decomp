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
    s16 colors[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll64EffectResourceView;

STATIC_ASSERT(offsetof(Dll64EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll64EffectResourceView, colors) == 0x08C);
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
    packet.entries[0].layer = 0;
    packet.entries[0].flags = 7;
    packet.entries[0].tex = &resourceData[offsetof(Dll64EffectResourceView, firstGroupIndices)];
    packet.entries[0].mode = 2;
    packet.entries[0].x = 0.75f;
    packet.entries[0].y = 1.0f;
    packet.entries[0].z = 0.75f;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 7;
    packet.entries[1].tex = &resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[1].mode = 2;
    packet.entries[1].x = 0.45f;
    packet.entries[1].y = 0.6f;
    packet.entries[1].z = 0.45f;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 0xe;
    packet.entries[2].tex = &resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[2].mode = 4;
    packet.entries[2].x = 0.0f;
    packet.entries[2].y = 0.0f;
    packet.entries[2].z = 0.0f;
    packet.entries[3].layer = 1;
    packet.entries[3].flags = 7;
    packet.entries[3].tex = &resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[3].mode = 4;
    packet.entries[3].x = 200.0f;
    packet.entries[3].y = 0.0f;
    packet.entries[3].z = 0.0f;
    packet.entries[4].layer = 1;
    packet.entries[4].flags = 0xe;
    packet.entries[4].tex = &resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[4].mode = 0x100;
    packet.entries[4].x = 0.0f;
    packet.entries[4].y = 0.0f;
    packet.entries[4].z = 20.0f;
    packet.entries[5].layer = 2;
    packet.entries[5].flags = 0xe;
    packet.entries[5].tex = &resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[5].mode = 0x100;
    packet.entries[5].x = 0.0f;
    packet.entries[5].y = 0.0f;
    packet.entries[5].z = 20.0f;
    packet.entries[6].layer = 3;
    packet.entries[6].flags = 1;
    packet.entries[6].tex = NULL;
    packet.entries[6].mode = 0x2000;
    packet.entries[6].x = 0.0f;
    packet.entries[6].y = 0.0f;
    packet.entries[6].z = 0.0f;
    packet.entries[7].layer = 4;
    packet.entries[7].flags = 7;
    packet.entries[7].tex = &resourceData[offsetof(Dll64EffectResourceView, secondGroupIndices)];
    packet.entries[7].mode = 4;
    packet.entries[7].x = 0.0f;
    packet.entries[7].y = 0.0f;
    packet.entries[7].z = 0.0f;
    packet.entries[8].layer = 4;
    packet.entries[8].flags = 0xe;
    packet.entries[8].tex = &resourceData[offsetof(Dll64EffectResourceView, allVertexIndices)];
    packet.entries[8].mode = 0x100;
    packet.entries[8].x = 0.0f;
    packet.entries[8].y = 0.0f;
    packet.entries[8].z = 20.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    if (effectScaleTenths != 0) {
        packet.scale = 0.1f * effectScaleTenths;
    } else {
        packet.scale = 1.0f;
    }
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = 9;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll64EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0x4040080;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.position[0] += params->posX;
            packet.position[1] += params->posY;
            packet.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0xe, (u8*)(int)gDll64EffectResourceData, 0xc,
                      &resourceData[offsetof(Dll64EffectResourceView, colors)], 0x5e0, 0);
}

void dll_64_release(void) {
}

void dll_64_initialise(void) {
}

Dll64ResourceDescriptor gDll64ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_64_initialise, dll_64_release, NULL, dll_64_spawnEffect,
};
