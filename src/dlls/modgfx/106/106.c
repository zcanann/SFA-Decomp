/*
 * DLL 106 / 0x6A - a modgfx effect spawner.
 */
#include "main/dll/dll_006A_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6AEffectResourceView {
    ModgfxEffectVertex vertices[18];
    s16 triangleIndices[16][3];
    s16 firstGroupIndices[10];
    s16 allVertexIndices[28];
    s16 sequenceParams[7];
    u8 pad16E[2];
    u8 variantColors[4][3];
} Dll6AEffectResourceView;

STATIC_ASSERT(offsetof(Dll6AEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll6AEffectResourceView, triangleIndices) == 0x0B4);
STATIC_ASSERT(offsetof(Dll6AEffectResourceView, firstGroupIndices) == 0x114);
STATIC_ASSERT(offsetof(Dll6AEffectResourceView, allVertexIndices) == 0x128);
STATIC_ASSERT(offsetof(Dll6AEffectResourceView, sequenceParams) == 0x160);
STATIC_ASSERT(offsetof(Dll6AEffectResourceView, variantColors) == 0x170);
STATIC_ASSERT(sizeof(Dll6AEffectResourceView) == 0x17C);

u32 gDll6AEffectResourceData[sizeof(Dll6AEffectResourceView) / sizeof(u32)] = {
    0x03e80000, 0x00000000, 0x000002c3, 0x0000fd3d, 0x000f0000, 0x00000000, 0xfc18001f, 0x0000fd3d, 0x0000fd3d,
    0x002f0000, 0xfc180000, 0x0000003f, 0x0000fd3d, 0x000002c3, 0x004f0000, 0x00000000, 0x03e8005f, 0x000002c3,
    0x000002c3, 0x006f0000, 0x03e80000, 0x0000007f, 0x000003e8, 0x07d00000, 0x0000000f, 0x02c307d0, 0xfd3d000f,
    0x000f0000, 0x07d0fc18, 0x001f000f, 0xfd3d07d0, 0xfd3d002f, 0x000ffc18, 0x07d00000, 0x003f000f, 0xfd3d07d0,
    0x02c3004f, 0x000f0000, 0x07d003e8, 0x005f000f, 0x02c307d0, 0x02c3006f, 0x000f03e8, 0x07d00000, 0x007f000f,
    0x00000001, 0x000a0000, 0x000a0009, 0x00010002, 0x000b0001, 0x000b000a, 0x00020003, 0x000c0002, 0x000c000b,
    0x00030004, 0x000d0003, 0x000d000c, 0x00040005, 0x000e0004, 0x000e000d, 0x00050006, 0x000f0005, 0x000f000e,
    0x00060007, 0x00100006, 0x0010000f, 0x00070008, 0x00110007, 0x00110010, 0x00000001, 0x00020003, 0x00040005,
    0x00060007, 0x00080000, 0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080009, 0x000a000b, 0x000c000d,
    0x000e000f, 0x00100011, 0x0009000a, 0x000b000c, 0x000d000e, 0x000f0010, 0x00110000, 0x00000032, 0x00000064,
    0x00000032, 0x00000000, 0x3296ff32, 0xff969b64, 0x0aff6482,
};

s16 dll_6A_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                       int unusedArg4, void* unusedArg5) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll6AEffectResourceData;
    GfxCmd* commands = packet.entries;

    commands[0].layer = 0;
    commands[0].flags = 0x12;
    commands[0].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 0x12;
    commands[1].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[1].mode = 2;
    commands[1].x = 0.2f;
    commands[1].y = 4.0f;
    commands[1].z = 0.2f;
    commands[2].layer = 0;
    commands[2].flags = 9;
    commands[2].tex = &resourceData[offsetof(Dll6AEffectResourceView, firstGroupIndices)];
    commands[2].mode = 8;
    commands[2].x = (f32)(u32)resourceData[offsetof(Dll6AEffectResourceView, variantColors) + variant * 3];
    commands[2].y = (f32)(u32)resourceData[offsetof(Dll6AEffectResourceView, variantColors) + variant * 3 + 1];
    commands[2].z = (f32)(u32)resourceData[offsetof(Dll6AEffectResourceView, variantColors) + variant * 3 + 2];
    commands[3].layer = 1;
    commands[3].flags = 0x12;
    commands[3].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[3].mode = 4;
    commands[3].x = 85.0f;
    commands[3].y = 0.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 0x12;
    commands[4].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[4].mode = 2;
    commands[4].x = 15.0f;
    commands[4].y = 0.15f;
    commands[4].z = 15.0f;
    commands[5].layer = 3;
    commands[5].flags = 0x12;
    commands[5].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[5].mode = 0x100;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 30.0f;
    commands[6].layer = 4;
    commands[6].flags = 2;
    commands[6].tex = NULL;
    commands[6].mode = 0x2000;
    commands[6].x = 0.0f;
    commands[6].y = 0.0f;
    commands[6].z = 0.0f;
    commands[7].layer = 5;
    commands[7].flags = 0x12;
    commands[7].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[7].mode = 4;
    commands[7].x = 0.0f;
    commands[7].y = 0.0f;
    commands[7].z = 0.0f;
    commands[8].layer = 5;
    commands[8].flags = 0x12;
    commands[8].tex = &resourceData[offsetof(Dll6AEffectResourceView, allVertexIndices)];
    commands[8].mode = 2;
    commands[8].x = 0.1f;
    commands[8].y = 10.0f;
    commands[8].z = 0.1f;
    commands[9].layer = 5;
    commands[9].flags = 0x7a;
    commands[9].tex = NULL;
    commands[9].mode = 0x10000;
    commands[9].x = 0.0f;
    commands[9].y = 0.0f;
    commands[9].z = 0.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
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
    packet.initialStateByte = 0x12;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.flags = 0x5000004;
    packet.commandCount = (commands + 10) - packet.entries;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll6AEffectResourceView, sequenceParams[6])];
    packet.commands = packet.entries;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.position[0] += sourceObj->anim.worldPosX;
            packet.position[1] += sourceObj->anim.worldPosY;
            packet.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    return (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x12, (u8*)(int)gDll6AEffectResourceData, 0x10,
                      &resourceData[offsetof(Dll6AEffectResourceView, triangleIndices)], 0x3e, 0);
}

void dll_6A_release(void) {
}

void dll_6A_initialise(void) {
}

Dll6AResourceDescriptor gDll6AResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6A_initialise, dll_6A_release, NULL, dll_6A_spawnEffect, 0,
};
