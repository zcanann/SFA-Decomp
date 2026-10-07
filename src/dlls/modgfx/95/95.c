/*
 * DLL 95 / 0x5F - a modgfx effect spawner.
 */
#include "main/dll/dll_005F_modgfx.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll5FEffectResourceView {
    ModgfxEffectVertex vertices[14];
    s16 triangleIndices[12][3];
    s16 allVertexIndices[14];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 sequenceParams[7];
    u8 pad11E[2];
} Dll5FEffectResourceView;

STATIC_ASSERT(offsetof(Dll5FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll5FEffectResourceView, triangleIndices) == 0x08C);
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
    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 0x32;
    packet.entries[0].vertexIndices = NULL;
    packet.entries[0].flags = 0x800000;
    packet.entries[0].valueX = 1.0f;
    packet.entries[0].valueY = originOffset;
    packet.entries[0].valueZ = originOffset;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 0x7a;
    packet.entries[1].vertexIndices = NULL;
    packet.entries[1].flags = 0x10000;
    packet.entries[1].valueX = originOffset;
    packet.entries[1].valueY = originOffset;
    packet.entries[1].valueZ = originOffset;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 7;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[2].flags = 4;
    packet.entries[2].valueX = originOffset;
    packet.entries[2].valueY = originOffset;
    packet.entries[2].valueZ = originOffset;
    packet.entries[3].stageIndex = 0;
    packet.entries[3].parameter = 7;
    packet.entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[3].flags = 2;
    packet.entries[3].valueX = 0.7f;
    packet.entries[3].valueY = 1.0f;
    packet.entries[3].valueZ = 0.7f;
    packet.entries[4].stageIndex = 0;
    packet.entries[4].parameter = 7;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[4].flags = 2;
    packet.entries[4].valueX = 1.2f;
    packet.entries[4].valueY = -1.0f;
    packet.entries[4].valueZ = 1.2f;
    packet.entries[5].stageIndex = 0;
    packet.entries[5].parameter = 7;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[5].flags = 8;
    packet.entries[5].valueX = originOffset;
    packet.entries[5].valueY = 160.0f;
    packet.entries[5].valueZ = 115.0f;
    packet.entries[6].stageIndex = 0;
    packet.entries[6].parameter = 7;
    packet.entries[6].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, secondGroupIndices)];
    packet.entries[6].flags = 8;
    packet.entries[6].valueX = 255.0f;
    packet.entries[6].valueY = 255.0f;
    packet.entries[6].valueZ = 115.0f;
    packet.entries[7].stageIndex = 0;
    packet.entries[7].parameter = 1;
    packet.entries[7].vertexIndices = NULL;
    packet.entries[7].flags = 0x8000;
    packet.entries[7].valueX = originOffset;
    packet.entries[7].valueY = 255.0f;
    packet.entries[7].valueZ = originOffset;
    packet.entries[8].stageIndex = 0;
    packet.entries[8].parameter = 1;
    packet.entries[8].vertexIndices = NULL;
    packet.entries[8].flags = 0x80000;
    packet.entries[8].valueX = originOffset;
    packet.entries[8].valueY = -130.0f;
    packet.entries[8].valueZ = originOffset;
    packet.entries[9].stageIndex = 1;
    packet.entries[9].parameter = 1;
    packet.entries[9].vertexIndices = NULL;
    packet.entries[9].flags = 0x80000;
    packet.entries[9].valueX = originOffset;
    packet.entries[9].valueY = originOffset;
    packet.entries[9].valueZ = originOffset;
    packet.entries[10].stageIndex = 2;
    packet.entries[10].parameter = 0xe;
    packet.entries[10].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, allVertexIndices)];
    packet.entries[10].flags = 0x4000;
    packet.entries[10].valueX = originOffset;
    packet.entries[10].valueY = -4.0f;
    packet.entries[10].valueZ = originOffset;
    packet.entries[11].stageIndex = 2;
    packet.entries[11].parameter = 7;
    packet.entries[11].vertexIndices = (s16*)&resourceData[offsetof(Dll5FEffectResourceView, firstGroupIndices)];
    packet.entries[11].flags = 4;
    packet.entries[11].valueX = originOffset;
    packet.entries[11].valueY = originOffset;
    packet.entries[11].valueZ = originOffset;
    packet.entries[12].stageIndex = 2;
    packet.entries[12].parameter = 1;
    packet.entries[12].vertexIndices = NULL;
    packet.entries[12].flags = 0x80000;
    packet.entries[12].valueX = originOffset;
    packet.entries[12].valueY = 90.0f;
    packet.entries[12].valueZ = originOffset;
    packet.context.modeByte = 0;
    sourceContext = sourceObj;
    packet.context.sourceObject = sourceContext;
    packet.context.variant = variant;
    packet.context.position[0] = originOffset;
    packet.context.position[1] = originOffset;
    packet.context.position[2] = originOffset;
    packet.context.velocity[0] = originOffset;
    packet.context.velocity[1] = originOffset;
    packet.context.velocity[2] = originOffset;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.commandCount = 0;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll5FEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000002;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)sourceContext != NULL) {
            packet.context.position[0] = originOffset + sourceContext->anim.worldPosX;
            packet.context.position[1] = originOffset + sourceContext->anim.worldPosY;
            packet.context.position[2] = originOffset + sourceContext->anim.worldPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = originOffset + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0xe, (ModgfxEffectVertex*)(int)gDll5FEffectResourceData, 0xc,
                      (s16*)(&resourceData[offsetof(Dll5FEffectResourceView, triangleIndices)]), 0x48, 0);
}

void dll_5F_release(void) {
}

void dll_5F_initialise(void) {
}

Dll5FResourceDescriptor gDll5FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_5F_initialise, dll_5F_release, NULL, dll_5F_spawnEffect,
};
