/*
 * DLL 121 / 0x79 - a three-variant modgfx effect spawner.
 */
#include "main/dll/dll_0079_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll79EffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 pad5A[2];
    s16 triangles[8][3];
    s16 allVertexIndices[10];
    s16 firstEightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll79EffectResourceView;

STATIC_ASSERT(offsetof(Dll79EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, pad5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, allVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, firstEightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(offsetof(Dll79EffectResourceView, opaqueTail) == 0xBE);
STATIC_ASSERT(sizeof(Dll79EffectResourceView) == 0xC0);

s16 gDll79EvenVertexIndices[4] = {0, 2, 4, 6};

extern u32 gDll79EffectResourceData[];

s16 dll_79_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll79EffectResourceData;
    GfxCmd* commandCursor;
    GfxCmd* commands;
    s16 handle;
    handle = 0;
    commands = packet.entries;
    commandCursor = commands;
    commandCursor = (GfxCmd*)((int)commandCursor | (int)commands);
    if (variant == 0) {
        commandCursor[0].layer = 0;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x80;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 16383.0f;
        commandCursor[1].layer = 0;
        commandCursor[1].flags = 8;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 2;
        commandCursor[1].x = 5.2f;
        commandCursor[1].y = 5.2f;
        commandCursor[1].z = 40.0f;
        commandCursor += 2;
    } else if (variant == 1) {
        f32 jitter;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])] = 0x118;
        commandCursor[0].layer = 0;
        commandCursor[0].flags = 0x69;
        commandCursor[0].tex = NULL;
        commandCursor[0].mode = 0x1800000;
        commandCursor[0].x = 1.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 0;
        commandCursor[1].flags = 8;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        commandCursor[1].x = 3.5f + jitter;
        commandCursor[1].y = 3.5f + jitter;
        commandCursor[1].z = 20.0f + jitter;
        commandCursor[2].layer = 0;
        commandCursor[2].flags = 9;
        commandCursor[2].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[2].mode = 0x80;
        commandCursor[2].x = 0.0f;
        commandCursor[2].y = 0.0f;
        commandCursor[2].z = 32676.0f;
        commandCursor[3].layer = 0;
        commandCursor[3].flags = 8;
        commandCursor[3].tex = &resourceData[offsetof(Dll79EffectResourceView, firstEightVertexIndices)];
        commandCursor[3].mode = 4;
        commandCursor[3].x = 100.0f;
        commandCursor[3].y = 0.0f;
        commandCursor[3].z = 0.0f;
        commandCursor += 4;
    } else if (variant == 2) {
        f32 jitter;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])] = 0x50;
        commandCursor[0].layer = 0;
        commandCursor[0].flags = 0x1fc;
        commandCursor[0].tex = NULL;
        commandCursor[0].mode = 0x1800000;
        commandCursor[0].x = 1.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 0;
        commandCursor[1].flags = 8;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        commandCursor[1].x = 1.2f + jitter;
        commandCursor[1].y = 1.2f + jitter;
        commandCursor[1].z = 12.0f + jitter;
        commandCursor[2].layer = 0;
        commandCursor[2].flags = 0x8c;
        commandCursor[2].tex = NULL;
        commandCursor[2].mode = 0x20000000;
        commandCursor[2].x = 999.0f;
        commandCursor[2].y = 96.0f;
        commandCursor[2].z = 97.0f;
        commandCursor[3].layer = 0;
        commandCursor[3].flags = 9;
        commandCursor[3].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[3].mode = 0x80;
        commandCursor[3].x = 0.0f;
        commandCursor[3].y = 0.0f;
        commandCursor[3].z = 32676.0f;
        commandCursor += 4;
    }
    if (variant == 0) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x4000;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 1;
        commandCursor[1].flags = 8;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 2;
        commandCursor[1].x = 0.5f;
        commandCursor[1].y = 0.5f;
        commandCursor[1].z = 0.5f;
        commandCursor += 2;
    } else if (variant == 1) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x4000;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = -2.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 1;
        commandCursor[1].flags = 0x8f;
        commandCursor[1].tex = NULL;
        commandCursor[1].mode = 0x1800000;
        commandCursor[1].x = 12.0f;
        commandCursor[1].y = 0.0f;
        commandCursor[1].z = 0.0f;
        commandCursor[2].layer = 0;
        commandCursor[2].flags = 4;
        commandCursor[2].tex = gDll79EvenVertexIndices;
        commandCursor[2].mode = 2;
        commandCursor[2].x = 1.0f;
        commandCursor[2].y = 1.0f;
        commandCursor[2].z = 2.0f;
        commandCursor += 3;
    } else if (variant == 2) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x4000;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 1;
        commandCursor[1].flags = 0x1fd;
        commandCursor[1].tex = NULL;
        commandCursor[1].mode = 0x1800000;
        commandCursor[1].x = 2.0f;
        commandCursor[1].y = 0.0f;
        commandCursor[1].z = 0.0f;
        commandCursor += 2;
    }
    if (variant == 0) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 400.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor += 1;
    } else if (variant == 1) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 800.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor += 1;
    } else if (variant == 2) {
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 800.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor += 1;
    }
    if (variant == 0) {
        commandCursor[0].layer = 2;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 400.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 2;
        commandCursor[1].flags = 9;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 4;
        commandCursor[1].x = 0.0f;
        commandCursor[1].y = 0.0f;
        commandCursor[1].z = 0.0f;
        commandCursor += 2;
    } else if (variant == 1) {
        commandCursor[0].layer = 2;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 800.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor += 1;
    } else if (variant == 2) {
        commandCursor[0].layer = 2;
        commandCursor[0].flags = 9;
        commandCursor[0].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].mode = 0x100;
        commandCursor[0].x = 800.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 2;
        commandCursor[1].flags = 9;
        commandCursor[1].tex = &resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].mode = 4;
        commandCursor[1].x = 0.0f;
        commandCursor[1].y = 0.0f;
        commandCursor[1].z = 0.0f;
        commandCursor += 2;
    }
    if (variant == 2) {
        commandCursor[0].layer = 3;
        commandCursor[0].flags = 0;
        commandCursor[0].tex = NULL;
        commandCursor[0].mode = 0x20000000;
        commandCursor[0].x = 999.0f;
        commandCursor[0].y = 96.0f;
        commandCursor[0].z = 97.0f;
        commandCursor += 1;
    }
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    if (variant == 0) {
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
        packet.position[2] = 0.0f;
    } else {
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
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
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[6])];
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
                     ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll79EffectResourceData, 8,
                                   &resourceData[offsetof(Dll79EffectResourceView, triangles)], 0x156, 0);
    } else if (variant == 1) {
        packet.modeByte = 0;
        packet.flags |= 4;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll79EffectResourceData, 8,
                                   &resourceData[offsetof(Dll79EffectResourceView, triangles)], 0x89, 0);
    } else if (variant == 2) {
        packet.modeByte = 0;
        packet.flags |= 4;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll79EffectResourceData, 8,
                                   &resourceData[offsetof(Dll79EffectResourceView, triangles)], 0x23b, 0);
    }
    return handle;
}

void dll_79_release(void) {
}

void dll_79_initialise(void) {
}

u32 gDll79EffectResourceData[sizeof(Dll79EffectResourceView) / sizeof(u32)] = {
    0x03e80000, 0x0190001f, 0x001f02c3, 0xfd3d0190, 0x0000001f, 0x0000fc18, 0x0190001f, 0x001ffd3d,
    0xfd3d0190, 0x0000001f, 0xfc180000, 0x0190001f, 0x001ffd3d, 0x02c30190, 0x0000001f, 0x000003e8,
    0x0190001f, 0x001f02c3, 0x02c30190, 0x0000001f, 0x00000000, 0xfbb4000f, 0x00000000, 0x00000001,
    0x00080001, 0x00020008, 0x00020003, 0x00080003, 0x00040008, 0x00040005, 0x00080005, 0x00060008,
    0x00060007, 0x00080007, 0x00000008, 0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080000,
    0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00000032, 0x001e0001, 0x00010000, 0x00000000,
};

Dll79ResourceDescriptor gDll79ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_79_initialise, dll_79_release, NULL, dll_79_spawnEffect,
};
