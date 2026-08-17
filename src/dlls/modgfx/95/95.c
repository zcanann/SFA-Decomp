/*
 * DLL 95 / 0x5F - a modgfx effect spawner.
 */
#include "main/dll/dll_005F_modgfx.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll5FEffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 colors[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll5FEffectResourceView;

STATIC_ASSERT(offsetof(Dll5FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, colors) == 0x08C);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, allVertexIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, firstGroupIndices) == 0x0F0);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, secondGroupIndices) == 0x100);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, sequenceParams) == 0x110);
STATIC_ASSERT(sizeof(Dll5FEffectResourceView) == 0x120);

u16 gDll5FEffectResourceData[sizeof(Dll5FEffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x001f,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x003f, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x005f, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x007f, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x009f, 0x0000, 0x0000, 0x0000, 0x03e8, 0x00bf, 0x0000, 0x0000,
    0x1770, 0x03e8, 0x0000, 0x003f, 0x0362, 0x1770, 0x01f4, 0x001f, 0x003f,
    0x0362, 0x1770, 0xfe0c, 0x003f, 0x003f, 0x0000, 0x1770, 0xfc18, 0x005f,
    0x003f, 0xfc9e, 0x1770, 0xfe0c, 0x007f, 0x003f, 0xfc9e, 0x1770, 0x01f4,
    0x009f, 0x003f, 0x0000, 0x1770, 0x03e8, 0x00bf, 0x003f, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a,
    0x000b, 0x000c, 0x000d, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0000, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x0000, 0x0000, 0x0014, 0x00aa, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

void dll_5F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll5FEffectResourceData;
    GameObject* sourceContext;
    f32 originOffset = 0.0f;
    packet.entries[0].layer = 0;
    packet.entries[0].flags = 0x32;
    packet.entries[0].tex = NULL;
    packet.entries[0].mode = 0x800000;
    packet.entries[0].x = 1.0f;
    packet.entries[0].y = originOffset;
    packet.entries[0].z = originOffset;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 0x7a;
    packet.entries[1].tex = NULL;
    packet.entries[1].mode = 0x10000;
    packet.entries[1].x = originOffset;
    packet.entries[1].y = originOffset;
    packet.entries[1].z = originOffset;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 7;
    packet.entries[2].tex = &resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[2].mode = 4;
    packet.entries[2].x = originOffset;
    packet.entries[2].y = originOffset;
    packet.entries[2].z = originOffset;
    packet.entries[3].layer = 0;
    packet.entries[3].flags = 7;
    packet.entries[3].tex = &resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[3].mode = 2;
    packet.entries[3].x = 0.7f;
    packet.entries[3].y = 1.0f;
    packet.entries[3].z = 0.7f;
    packet.entries[4].layer = 0;
    packet.entries[4].flags = 7;
    packet.entries[4].tex = &resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[4].mode = 2;
    packet.entries[4].x = 1.2f;
    packet.entries[4].y = -1.0f;
    packet.entries[4].z = 1.2f;
    packet.entries[5].layer = 0;
    packet.entries[5].flags = 7;
    packet.entries[5].tex = &resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[5].mode = 8;
    packet.entries[5].x = originOffset;
    packet.entries[5].y = 160.0f;
    packet.entries[5].z = 115.0f;
    packet.entries[6].layer = 0;
    packet.entries[6].flags = 7;
    packet.entries[6].tex = &resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[6].mode = 8;
    packet.entries[6].x = 255.0f;
    packet.entries[6].y = 255.0f;
    packet.entries[6].z = 115.0f;
    packet.entries[7].layer = 0;
    packet.entries[7].flags = 1;
    packet.entries[7].tex = NULL;
    packet.entries[7].mode = 0x8000;
    packet.entries[7].x = originOffset;
    packet.entries[7].y = 255.0f;
    packet.entries[7].z = originOffset;
    packet.entries[8].layer = 0;
    packet.entries[8].flags = 1;
    packet.entries[8].tex = NULL;
    packet.entries[8].mode = 0x80000;
    packet.entries[8].x = originOffset;
    packet.entries[8].y = -130.0f;
    packet.entries[8].z = originOffset;
    packet.entries[9].layer = 1;
    packet.entries[9].flags = 1;
    packet.entries[9].tex = NULL;
    packet.entries[9].mode = 0x80000;
    packet.entries[9].x = originOffset;
    packet.entries[9].y = originOffset;
    packet.entries[9].z = originOffset;
    packet.entries[10].layer = 2;
    packet.entries[10].flags = 0xe;
    packet.entries[10].tex = &resourceData[offsetof(Dll5FEffectResourceView, allVertexIndices)];
    packet.entries[10].mode = 0x4000;
    packet.entries[10].x = originOffset;
    packet.entries[10].y = -4.0f;
    packet.entries[10].z = originOffset;
    packet.entries[11].layer = 2;
    packet.entries[11].flags = 7;
    packet.entries[11].tex = &resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[11].mode = 4;
    packet.entries[11].x = originOffset;
    packet.entries[11].y = originOffset;
    packet.entries[11].z = originOffset;
    packet.entries[12].layer = 2;
    packet.entries[12].flags = 1;
    packet.entries[12].tex = NULL;
    packet.entries[12].mode = 0x80000;
    packet.entries[12].x = originOffset;
    packet.entries[12].y = 90.0f;
    packet.entries[12].z = originOffset;
    packet.modeByte = 0;
    sourceContext = sourceObj;
    packet.ctx = (int)sourceContext;
    packet.sourceMode = variant;
    packet.position[0] = originOffset;
    packet.position[1] = originOffset;
    packet.position[2] = originOffset;
    packet.velocity[0] = originOffset;
    packet.velocity[1] = originOffset;
    packet.velocity[2] = originOffset;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.commandCount = 0;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4000002;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((void*)sourceContext != NULL) {
            packet.position[0] = originOffset + sourceContext->anim.worldPosX;
            packet.position[1] = originOffset + sourceContext->anim.worldPosY;
            packet.position[2] = originOffset + sourceContext->anim.worldPosZ;
        } else {
            packet.position[0] = originOffset + spawnParams->posX;
            packet.position[1] = originOffset + spawnParams->posY;
            packet.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0xe, (u8*)(int)gDll5FEffectResourceData, 0xc,
                      &resourceData[offsetof(Dll5FEffectResourceView, colors)], 0x48, 0);
}

void dll_5F_release(void) {
}

void dll_5F_initialise(void) {
}

Dll5FResourceDescriptor gDll5FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_5F_initialise, dll_5F_release, NULL, dll_5F_spawnEffect,
};
