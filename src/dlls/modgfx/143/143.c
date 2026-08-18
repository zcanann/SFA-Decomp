/*
 * DLL 143 / 0x8F - a ten-command layered modgfx effect spawner.
 */
#include "main/dll/dll_008F_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll8FEffectResourceView {
    ModgfxEffectVertex vertices[18];
    s16 triangles[16][3];
    s16 firstNineVertexIndices[9];
    s16 opaque126;
    s16 allVertexIndices[18];
    s16 secondNineVertexIndices[9];
    s16 opaque15E;
    s16 sequenceParams[7];
    u8 opaque16E[0x0E];
} Dll8FEffectResourceView;

STATIC_ASSERT(offsetof(Dll8FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, triangles) == 0x0B4);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, firstNineVertexIndices) == 0x114);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque126) == 0x126);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, allVertexIndices) == 0x128);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, secondNineVertexIndices) == 0x14C);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque15E) == 0x15E);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, sequenceParams) == 0x160);
STATIC_ASSERT(offsetof(Dll8FEffectResourceView, opaque16E) == 0x16E);
STATIC_ASSERT(sizeof(Dll8FEffectResourceView) == 0x17C);

u16 gDll8FEffectResourceData[sizeof(Dll8FEffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0000, 0x0000, 0x0000, 0x02c3, 0x0000, 0xfd3d, 0x000f,
    0x0000, 0x0000, 0x0000, 0xfc18, 0x001f, 0x0000, 0xfd3d, 0x0000, 0xfd3d,
    0x002f, 0x0000, 0xfc18, 0x0000, 0x0000, 0x003f, 0x0000, 0xfd3d, 0x0000,
    0x02c3, 0x004f, 0x0000, 0x0000, 0x0000, 0x03e8, 0x005f, 0x0000, 0x02c3,
    0x0000, 0x02c3, 0x006f, 0x0000, 0x03e8, 0x0000, 0x0000, 0x007f, 0x0000,
    0x03e8, 0x07d0, 0x0000, 0x0000, 0x001f, 0x02c3, 0x07d0, 0xfd3d, 0x000f,
    0x001f, 0x0000, 0x07d0, 0xfc18, 0x001f, 0x001f, 0xfd3d, 0x07d0, 0xfd3d,
    0x002f, 0x001f, 0xfc18, 0x07d0, 0x0000, 0x003f, 0x001f, 0xfd3d, 0x07d0,
    0x02c3, 0x004f, 0x001f, 0x0000, 0x07d0, 0x03e8, 0x005f, 0x001f, 0x02c3,
    0x07d0, 0x02c3, 0x006f, 0x001f, 0x03e8, 0x07d0, 0x0000, 0x007f, 0x001f,
    0x0000, 0x0001, 0x000a, 0x0000, 0x000a, 0x0009, 0x0001, 0x0002, 0x000b,
    0x0001, 0x000b, 0x000a, 0x0002, 0x0003, 0x000c, 0x0002, 0x000c, 0x000b,
    0x0003, 0x0004, 0x000d, 0x0003, 0x000d, 0x000c, 0x0004, 0x0005, 0x000e,
    0x0004, 0x000e, 0x000d, 0x0005, 0x0006, 0x000f, 0x0005, 0x000f, 0x000e,
    0x0006, 0x0007, 0x0010, 0x0006, 0x0010, 0x000f, 0x0007, 0x0008, 0x0011,
    0x0007, 0x0011, 0x0010, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
    0x0006, 0x0007, 0x0008, 0x0000, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004,
    0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x000e, 0x000f, 0x0010, 0x0011, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d,
    0x000e, 0x000f, 0x0010, 0x0011, 0x0000, 0x0000, 0x0032, 0x0000, 0x0064,
    0x0000, 0x0032, 0x0000, 0x0000, 0x0032, 0xfa32, 0x0000, 0x0000, 0x0000,
    0x0000,
};

void dll_8F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll8FEffectResourceData;
    GfxCmd* commands = packet.entries;

    commands[0].layer = 0;
    commands[0].flags = 18;
    commands[0].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 18;
    commands[1].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[1].mode = 2;
    commands[1].x = 0.2f;
    commands[1].y = 2.0f;
    commands[1].z = 0.2f;
    commands[2].layer = 0;
    commands[2].flags = 18;
    commands[2].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[2].mode = 256;
    commands[2].x = 0.0f;
    commands[2].y = 0.0f;
    commands[2].z = 300.0f;
    commands[3].layer = 1;
    commands[3].flags = 18;
    commands[3].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[3].mode = 4;
    commands[3].x = 185.0f;
    commands[3].y = 0.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 18;
    commands[4].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[4].mode = 2;
    commands[4].x = 9.0f;
    commands[4].y = 0.3f;
    commands[4].z = 9.0f;
    commands[5].layer = 1;
    commands[5].flags = 18;
    commands[5].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[5].mode = 256;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 300.0f;
    commands[6].layer = 2;
    commands[6].flags = 18;
    commands[6].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[6].mode = 256;
    commands[6].x = 0.0f;
    commands[6].y = 0.0f;
    commands[6].z = 300.0f;
    commands[7].layer = 3;
    commands[7].flags = 18;
    commands[7].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[7].mode = 4;
    commands[7].x = 0.0f;
    commands[7].y = 0.0f;
    commands[7].z = 0.0f;
    commands[8].layer = 3;
    commands[8].flags = 18;
    commands[8].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[8].mode = 2;
    commands[8].x = 0.1f;
    commands[8].y = 7.0f;
    commands[8].z = 0.1f;
    commands[9].layer = 3;
    commands[9].flags = 18;
    commands[9].tex = &resourceData[offsetof(Dll8FEffectResourceView, allVertexIndices)];
    commands[9].mode = 256;
    commands[9].x = 0.0f;
    commands[9].y = 0.0f;
    commands[9].z = 300.0f;
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
    packet.initialStateByte = 18;
    packet.byte5A = 0;
    packet.textureFrameTimer = 16;
    packet.flags = 0x4000000;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 10) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll8FEffectResourceView, sequenceParams[6])];
    packet.commands = commands;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            GameObject* anchorObj = sourceObj;
            packet.position[0] += anchorObj->anim.worldPosX;
            packet.position[1] += anchorObj->anim.worldPosY;
            packet.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.position[0] += anchorParams->posX;
            packet.position[1] += anchorParams->posY;
            packet.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 18, (u8*)(int)gDll8FEffectResourceData, 16,
                      &resourceData[offsetof(Dll8FEffectResourceView, triangles)], 0x2E, 0);
}

void dll_8F_release(void) {
}

void dll_8F_initialise(void) {
}

Dll8FResourceDescriptor gDll8FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_8F_initialise,
    dll_8F_release,
    NULL,
    dll_8F_spawnEffect,
    0x00000000,
};
