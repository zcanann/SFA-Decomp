/*
 * DLL 149 / 0x95 - a seven-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0095_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll95EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[8][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll95EffectResourceView;

STATIC_ASSERT(offsetof(Dll95EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, allVertexIndices) == 0x80);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, sequenceParams) == 0x90);
STATIC_ASSERT(offsetof(Dll95EffectResourceView, opaqueTail) == 0x9E);
STATIC_ASSERT(sizeof(Dll95EffectResourceView) == 0xA0);

s16 gDll95VertexIndices[4] = {4, 5, 6, 7};

extern u32 gDll95EffectResourceData[sizeof(Dll95EffectResourceView) / sizeof(u32)];

void dll_95_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)gDll95EffectResourceData;
    GfxCmd* commands = packet.entries;
    GameObject* anchorObj = sourceObj;
    PartFxSpawnParams* anchorParams = spawnParams;

    commands[0].layer = 0;
    commands[0].flags = 8;
    commands[0].tex = &resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[0].mode = 0x2;
    commands[0].x = 0.014f;
    commands[0].y = 0.03f;
    commands[0].z = 0.014f;
    commands[1].layer = 0;
    commands[1].flags = 4;
    commands[1].tex = gDll95VertexIndices;
    commands[1].mode = 0x8;
    commands[1].x = 255.0f;
    commands[1].y = 255.0f;
    commands[1].z = 0.0f;
    commands[2].layer = 0;
    commands[2].flags = 4;
    commands[2].tex = &resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[2].mode = 0x8;
    commands[2].x = 255.0f;
    commands[2].y = 85.0f;
    commands[2].z = 0.0f;
    commands[3].layer = 0;
    commands[3].flags = 0;
    commands[3].tex = NULL;
    commands[3].mode = 0x400000;
    commands[3].x = 0.0f;
    commands[3].y = 80.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 8;
    commands[4].tex = &resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[4].mode = 0x2;
    commands[4].x = 100.0f;
    commands[4].y = 100.0f;
    commands[4].z = 100.0f;
    commands[5].layer = 1;
    commands[5].flags = 0;
    commands[5].tex = NULL;
    commands[5].mode = 0x400000;
    commands[5].x = 0.0f;
    commands[5].y = -80.0f;
    commands[5].z = 0.0f;
    commands[6].layer = 2;
    commands[6].flags = 8;
    commands[6].tex = &resourceData[offsetof(Dll95EffectResourceView, allVertexIndices)];
    commands[6].mode = 0x4;
    commands[6].x = 0.0f;
    commands[6].y = 0.0f;
    commands[6].z = 0.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 2.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 8;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x3C;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 7) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll95EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4002400;
    if ((packet.flags & 1) != 0) {
        if ((u32)sourceObj != 0 && (u32)spawnParams != 0) {
            packet.position[0] += anchorObj->anim.worldPosX + anchorParams->posX;
            packet.position[1] += anchorObj->anim.worldPosY + anchorParams->posY;
            packet.position[2] += anchorObj->anim.worldPosZ + anchorParams->posZ;
        } else if ((u32)sourceObj != 0) {
            packet.position[0] += anchorObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else if ((u32)spawnParams != 0) {
            packet.position[0] += anchorParams->posX;
            packet.position[1] += anchorParams->posY;
            packet.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 8, resourceData, 8, &resourceData[offsetof(Dll95EffectResourceView, triangles)], 0x46,
                      0);
}

void dll_95_release(void) {
}

void dll_95_initialise(void) {
}

u32 gDll95EffectResourceData[sizeof(Dll95EffectResourceView) / sizeof(u32)] = {
    0xfce001f4, 0xfce00008, 0x001f0320, 0x01f4fce0, 0x0078001f, 0x032001f4, 0x03200008, 0x001ffce0,
    0x01f40320, 0x0078001f, 0xfc180000, 0xfc180008, 0x000003e8, 0x0000fc18, 0x00780000, 0x03e80000,
    0x03e80008, 0x0000fc18, 0x000003e8, 0x00780000, 0x00000001, 0x00050000, 0x00050004, 0x00010002,
    0x00060001, 0x00060005, 0x00020003, 0x00070002, 0x00070006, 0x00030000, 0x00040003, 0x00040007,
    0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00000316, 0x000a0000, 0x00000000, 0x00000000,
};

Dll95ResourceDescriptor gDll95ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_95_initialise, dll_95_release, NULL, dll_95_spawnEffect,
};
