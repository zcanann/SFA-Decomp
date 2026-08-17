/*
 * DLL 98 / 0x62 - a modgfx effect spawner.
 */
#include "main/dll/dll_0062_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll62EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 colors[24][3];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 thirdGroupIndices[8];
    s16 firstAndThirdGroupIndices[14];
    s16 allVertexIndices[22];
    s16 sequenceParams[7];
    u8 pad1EA[2];
} Dll62EffectResourceView;

STATIC_ASSERT(offsetof(Dll62EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, colors) == 0x0D4);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, firstGroupIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, secondGroupIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, thirdGroupIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, firstAndThirdGroupIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll62EffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(sizeof(Dll62EffectResourceView) == 0x1EC);

u16 gDll62EffectResourceData[sizeof(Dll62EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x002c,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0058, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0080, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x00a8, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x00d0, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0100, 0x0000, 0x0000,
    0x0640, 0x03e8, 0x0000, 0x0020, 0x0362, 0x0640, 0x01f4, 0x002c, 0x0020,
    0x0362, 0x0640, 0xfe0c, 0x0058, 0x0020, 0x0000, 0x0640, 0xfc18, 0x0080,
    0x0020, 0xfc9e, 0x0640, 0xfe0c, 0x00a8, 0x0020, 0xfc9e, 0x0640, 0x01f4,
    0x00d0, 0x0020, 0x0000, 0x0640, 0x03e8, 0x0100, 0x0020, 0x0000, 0x1770,
    0x03e8, 0x0000, 0x0040, 0x0362, 0x1770, 0x01f4, 0x002c, 0x0040, 0x0362,
    0x1770, 0xfe0c, 0x0058, 0x0040, 0x0000, 0x1770, 0xfc18, 0x0080, 0x0040,
    0xfc9e, 0x1770, 0xfe0c, 0x00a8, 0x0040, 0xfc9e, 0x1770, 0x01f4, 0x00d0,
    0x0040, 0x0000, 0x1770, 0x03e8, 0x0100, 0x0040, 0x0000, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0007, 0x0008,
    0x000f, 0x0007, 0x000f, 0x000e, 0x0008, 0x0009, 0x0010, 0x0008, 0x0010,
    0x000f, 0x0009, 0x000a, 0x0011, 0x0009, 0x0011, 0x0010, 0x000a, 0x000b,
    0x0012, 0x000a, 0x0012, 0x0011, 0x000b, 0x000c, 0x0013, 0x000b, 0x0013,
    0x0012, 0x000c, 0x000d, 0x0014, 0x000c, 0x0014, 0x0013, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0000, 0x0007, 0x0008, 0x0009,
    0x000a, 0x000b, 0x000c, 0x000d, 0x0000, 0x000e, 0x000f, 0x0010, 0x0011,
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004,
    0x0005, 0x0006, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014,
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
    0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011,
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0104, 0x003c, 0x003c, 0x0001,
    0x0104, 0x0000, 0x0000,
};

void dll_62_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    GfxCmd* commands = packet.entries;
    u8* resourceData = (u8*)(int)gDll62EffectResourceData;
    u8 effectScaleTenths;
    f32 layerPositionX;
    layerPositionX = 1.0f;
    effectScaleTenths = ((u8*)sourceObj->anim.placementData)[0x1a];
    if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[1])] = 0;
        layerPositionX = 4.0f;
    } else if (variant == 2) {
        layerPositionX = 0.0f;
        effectScaleTenths = 6;
    }
    commands[0].layer = 0;
    commands[0].flags = 0x15;
    commands[0].tex = &resourceData[offsetof(Dll62EffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 0xe;
    commands[1].tex = &resourceData[offsetof(Dll62EffectResourceView, firstAndThirdGroupIndices)];
    commands[1].mode = 2;
    commands[1].x = 0.95f;
    commands[1].y = 0.4f;
    commands[1].z = 0.95f;
    commands[2].layer = 0;
    commands[2].flags = 7;
    commands[2].tex = &resourceData[offsetof(Dll62EffectResourceView, secondGroupIndices)];
    commands[2].mode = 2;
    commands[2].x = 0.95f;
    commands[2].y = 0.4f;
    commands[2].z = 0.95f;
    commands[3].layer = 1;
    commands[3].flags = 7;
    commands[3].tex = &resourceData[offsetof(Dll62EffectResourceView, secondGroupIndices)];
    commands[3].mode = 4;
    commands[3].x = 255.0f;
    commands[3].y = 0.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 7;
    commands[4].tex = &resourceData[offsetof(Dll62EffectResourceView, thirdGroupIndices)];
    commands[4].mode = 4;
    commands[4].x = 255.0f;
    commands[4].y = 0.0f;
    commands[4].z = 0.0f;
    commands[5].layer = 1;
    commands[5].flags = 0x15;
    commands[5].tex = &resourceData[offsetof(Dll62EffectResourceView, allVertexIndices)];
    commands[5].mode = 0x100;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 10.0f;
    commands[6].layer = 2;
    commands[6].flags = 0x3a;
    commands[6].tex = NULL;
    commands[6].mode = 0x1800000;
    commands[6].x = layerPositionX;
    commands[6].y = 0.0f;
    commands[6].z = 5.0f;
    commands[7].layer = 2;
    commands[7].flags = 0x15;
    commands[7].tex = &resourceData[offsetof(Dll62EffectResourceView, allVertexIndices)];
    commands[7].mode = 0x100;
    commands[7].x = 0.0f;
    commands[7].y = 0.0f;
    commands[7].z = 10.0f;
    commands[8].layer = 3;
    commands[8].flags = 0x3a;
    commands[8].tex = NULL;
    commands[8].mode = 0x1800000;
    commands[8].x = layerPositionX;
    commands[8].y = 0.0f;
    commands[8].z = 5.0f;
    commands[9].layer = 3;
    commands[9].flags = 0x15;
    commands[9].tex = &resourceData[offsetof(Dll62EffectResourceView, allVertexIndices)];
    commands[9].mode = 0x100;
    commands[9].x = 0.0f;
    commands[9].y = 0.0f;
    commands[9].z = 10.0f;
    commands[10].layer = 4;
    commands[10].flags = 2;
    commands[10].tex = NULL;
    commands[10].mode = 0x2000;
    commands[10].x = 0.0f;
    commands[10].y = 0.0f;
    commands[10].z = 0.0f;
    commands[11].layer = 5;
    commands[11].flags = 7;
    commands[11].tex = &resourceData[offsetof(Dll62EffectResourceView, secondGroupIndices)];
    commands[11].mode = 4;
    commands[11].x = 0.0f;
    commands[11].y = 0.0f;
    commands[11].z = 0.0f;
    commands[12].layer = 5;
    commands[12].flags = 7;
    commands[12].tex = &resourceData[offsetof(Dll62EffectResourceView, thirdGroupIndices)];
    commands[12].mode = 4;
    commands[12].x = 0.0f;
    commands[12].y = 0.0f;
    commands[12].z = 0.0f;
    commands[13].layer = 5;
    commands[13].flags = 0x15;
    commands[13].tex = &resourceData[offsetof(Dll62EffectResourceView, allVertexIndices)];
    commands[13].mode = 0x100;
    commands[13].x = 0.0f;
    commands[13].y = 0.0f;
    commands[13].z = 10.0f;
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
        packet.scale = 0.1f * (f32)(u32)effectScaleTenths;
    } else {
        packet.scale = 1.0f;
    }
    packet.drawGroupCount = 2;
    packet.drawGroupStride = 7;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = 14;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll62EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0xc0400c0;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll62EffectResourceData, 0x18,
                      &resourceData[offsetof(Dll62EffectResourceView, colors)], 0x5e0, 0);
}

void dll_62_release(void) {
}

void dll_62_initialise(void) {
}

Dll62ResourceDescriptor gDll62ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_62_initialise, dll_62_release, NULL, dll_62_spawnEffect, 0,
};
