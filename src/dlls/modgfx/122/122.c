/*
 * DLL 122 / 0x7A - a two-variant modgfx effect spawner.
 */
#include "main/dll/dll_007A_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll7AEffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangles[8][3];
    s16 allVertexIndices[10];
    s16 firstEightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll7AEffectResourceView;

STATIC_ASSERT(offsetof(Dll7AEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, pad5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, allVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, firstEightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(offsetof(Dll7AEffectResourceView, opaqueTail) == 0xBE);
STATIC_ASSERT(sizeof(Dll7AEffectResourceView) == 0xC0);

u16 gDll7AEffectResourceData[sizeof(Dll7AEffectResourceView) / sizeof(u16)] = {
    0x03e8, 0x0000, 0x0190, 0x001f, 0x001f, 0x02c3, 0xfd3d, 0x0190, 0x0000,
    0x001f, 0x0000, 0xfc18, 0x0190, 0x001f, 0x001f, 0xfd3d, 0xfd3d, 0x0190,
    0x0000, 0x001f, 0xfc18, 0x0000, 0x0190, 0x001f, 0x001f, 0xfd3d, 0x02c3,
    0x0190, 0x0000, 0x001f, 0x0000, 0x03e8, 0x0190, 0x001f, 0x001f, 0x02c3,
    0x02c3, 0x0190, 0x0000, 0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000,
    0x0000, 0x0000, 0x0001, 0x0008, 0x0001, 0x0002, 0x0008, 0x0002, 0x0003,
    0x0008, 0x0003, 0x0004, 0x0008, 0x0004, 0x0005, 0x0008, 0x0005, 0x0006,
    0x0008, 0x0006, 0x0007, 0x0008, 0x0007, 0x0000, 0x0008, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0000, 0x0000,
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0000, 0x0064,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

s16 dll_7A_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll7AEffectResourceData;
    GfxCmd* commands;
    GfxCmd* commandCursor;
    s16 handle;
    handle = 0;
    commands = packet.entries;
    commands[0].layer = 0;
    commands[0].flags = 8;
    commands[0].tex = &resourceData[offsetof(Dll7AEffectResourceView, firstEightVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 8;
    commands[1].tex = &resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[1].mode = 2;
    commands[1].x = 0.4f * randomGetRange(10, 15);
    commands[1].y = 0.4f * randomGetRange(10, 15);
    commands[1].z = 0.8f * randomGetRange(10, 15);
    commands[2].layer = 0;
    commands[2].flags = 9;
    commands[2].tex = &resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[2].mode = 0x80;
    commands[2].x = 0.0f;
    commands[2].y = 0.0f;
    commands[2].z = -16383.0f;
    commands[3].layer = 1;
    commands[3].flags = 0x9c;
    commands[3].tex = NULL;
    commands[3].mode = 0x800000;
    commands[3].x = 2.0f;
    commands[3].y = 1.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 0;
    commands[4].tex = NULL;
    commands[4].mode = 0x400000;
    commands[4].x = randomGetRange(-2000, 200);
    commands[4].y = randomGetRange(-200, 200);
    commands[4].z = randomGetRange(-200, 200);
    commands[5].layer = 1;
    commands[5].flags = 9;
    commands[5].tex = &resourceData[offsetof(Dll7AEffectResourceView, allVertexIndices)];
    commands[5].mode = 4;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 0.0f;
    commandCursor = &commands[6];
    if (variant == 0) {
        commandCursor->layer = 3;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x20000000;
        commandCursor->x = 999.0f;
        commandCursor->y = 94.0f;
        commandCursor->z = 95.0f;
        commandCursor++;
    }
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    if (variant == 0) {
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
        packet.position[2] = 0.0f;
    } else {
        packet.position[0] = 0.0f;
        packet.position[1] = 135.0f;
        packet.position[2] = 0.0f;
    }
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 9;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = commandCursor - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll7AEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0x4000000;
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
    if (variant == 0) {
        packet.modeByte = 0;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll7AEffectResourceData, 8,
                                   &resourceData[offsetof(Dll7AEffectResourceView, triangles)], 0x156, 0);
    } else if (variant == 1) {
        packet.modeByte = 0;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll7AEffectResourceData, 8,
                                   &resourceData[offsetof(Dll7AEffectResourceView, triangles)], 0xc0d, 0);
    }
    return handle;
}

void dll_7A_release(void) {
}

void dll_7A_initialise(void) {
}

Dll7AResourceDescriptor gDll7AResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_7A_initialise, dll_7A_release, NULL, dll_7A_spawnEffect,
};
