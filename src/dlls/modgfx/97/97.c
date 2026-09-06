/*
 * DLL 97 / 0x61 - a modgfx effect spawner.
 */
#include "main/dll/dll_0061_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll61EffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangleIndices[8][3];
    s16 nineVertexIndices[10];
    s16 eightVertexIndices[8];
    s16 sequenceParams[7];
    u8 padBE[2];
} Dll61EffectResourceView;

STATIC_ASSERT(offsetof(Dll61EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, triangleIndices) == 0x5C);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, nineVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, eightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll61EffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(sizeof(Dll61EffectResourceView) == 0xC0);

s16 gDll61VertexEightIndices[4] = {8, 0, 0, 0};

u16 gDll61EffectResourceData[sizeof(Dll61EffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0190, 0x001f, 0x001f, 0x02c3, 0xfd3d, 0x0190, 0x0000,
    0x001f, 0x0000, 0xfc18, 0x0190, 0x001f, 0x001f, 0xfd3d, 0xfd3d, 0x0190,
    0x0000, 0x001f, 0xfc18, 0x0000, 0x0190, 0x001f, 0x001f, 0xfd3d, 0x02c3,
    0x0190, 0x0000, 0x001f, 0x0000, 0x03e8, 0x0190, 0x001f, 0x001f, 0x02c3,
    0x02c3, 0x0190, 0x0000, 0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000,
    0x0000, 0x0000, 0x0001, 0x0008, 0x0001, 0x0002, 0x0008, 0x0002, 0x0003,
    0x0008, 0x0003, 0x0004, 0x0008, 0x0004, 0x0005, 0x0008, 0x0005, 0x0006,
    0x0008, 0x0006, 0x0007, 0x0008, 0x0007, 0x0000, 0x0008, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0000, 0x0000,
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0000, 0x0050,
    0x001e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

void dll_61_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    f32 randomScale;
    u8* resourceData = (u8*)(int)gDll61EffectResourceData;
    GfxCmd* commands;
    commands = packet.entries;
    commands[0].layer = 0;
    commands[0].flags = 8;
    commands[0].tex = &resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 1;
    commands[1].tex = NULL;
    commands[1].mode = 0x2008000;
    commands[1].x = 125.0f;
    commands[1].y = 255.0f;
    commands[1].z = 125.0f;
    commands[2].layer = 0;
    commands[2].flags = 0;
    commands[2].tex = NULL;
    commands[2].mode = 0x2080000;
    commands[2].x = 0.0f;
    commands[2].y = 17.0f;
    commands[2].z = -17.0f;
    commands[3].layer = 0;
    commands[3].flags = 9;
    commands[3].tex = &resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[3].mode = 0x80;
    commands[3].x = 0.0f;
    commands[3].y = 0.0f;
    commands[3].z = (f32)sourceObj->anim.rotX;
    commands[4].layer = 0;
    commands[4].flags = 0x7a;
    commands[4].tex = NULL;
    commands[4].mode = 0x10000;
    commands[4].x = 0.0f;
    commands[4].y = 0.0f;
    commands[4].z = 0.0f;
    commands[5].layer = 0;
    commands[5].flags = 9;
    commands[5].tex = &resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[5].mode = 2;
    randomScale = 0.05f * randomGetRange(0, 0xc);
    randomScale = 2.6f + randomScale;
    commands[5].x = randomScale;
    commands[5].y = randomScale;
    commands[5].z = randomScale;
    commands[6].layer = 1;
    commands[6].flags = 0;
    commands[6].tex = NULL;
    commands[6].mode = 0x10000000;
    commands[6].x = 28.0f;
    commands[6].y = 2.0f;
    commands[6].z = 0.0f;
    commands[7].layer = 1;
    commands[7].flags = 8;
    commands[7].tex = &resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[7].mode = 0x4000;
    commands[7].x = 0.0f;
    commands[7].y = -4.0f;
    commands[7].z = 0.0f;
    commands[8].layer = 1;
    commands[8].flags = 9;
    commands[8].tex = &resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[8].mode = 0x100;
    commands[8].x = 600.0f;
    commands[8].y = 0.0f;
    commands[8].z = 0.0f;
    commands[9].layer = 1;
    commands[9].flags = 0;
    commands[9].tex = NULL;
    commands[9].mode = 0x400000;
    commands[9].x = 0.0f;
    commands[9].y = 0.0f;
    commands[9].z = -200.0f;
    commands[10].layer = 1;
    commands[10].flags = 0;
    commands[10].tex = NULL;
    commands[10].mode = 0x2080000;
    commands[10].x = 0.0f;
    commands[10].y = 17.0f;
    commands[10].z = -200.0f;
    commands[11].layer = 2;
    commands[11].flags = 8;
    commands[11].tex = &resourceData[offsetof(Dll61EffectResourceView, eightVertexIndices)];
    commands[11].mode = 0x4000;
    commands[11].x = 0.0f;
    commands[11].y = -4.0f;
    commands[11].z = 0.0f;
    commands[12].layer = 2;
    commands[12].flags = 9;
    commands[12].tex = &resourceData[offsetof(Dll61EffectResourceView, nineVertexIndices)];
    commands[12].mode = 0x100;
    commands[12].x = 600.0f;
    commands[12].y = 0.0f;
    commands[12].z = 0.0f;
    commands[13].layer = 2;
    commands[13].flags = 1;
    commands[13].tex = gDll61VertexEightIndices;
    commands[13].mode = 4;
    commands[13].x = 0.0f;
    commands[13].y = 0.0f;
    commands[13].z = 0.0f;
    commands[14].layer = 2;
    commands[14].flags = 0;
    commands[14].tex = NULL;
    commands[14].mode = 0x2008000;
    commands[14].x = 0.0f;
    commands[14].y = 0.0f;
    commands[14].z = 0.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 17.0f;
    packet.position[2] = -40.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 9;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 15) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll61EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4000010;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((void*)sourceObj != NULL) {
            packet.position[0] += sourceObj->anim.worldPosX;
            packet.position[1] += sourceObj->anim.worldPosY;
            packet.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll61EffectResourceData, 8,
                      &resourceData[offsetof(Dll61EffectResourceView, triangleIndices)], 0x90, 0);
}

void dll_61_release(void) {
}

void dll_61_initialise(void) {
}

Dll61ResourceDescriptor gDll61ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_61_initialise, dll_61_release, NULL, dll_61_spawnEffect,
};
