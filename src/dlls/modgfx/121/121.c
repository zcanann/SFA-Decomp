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
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;
    s16 handle;
    handle = 0;
    commands = packet.entries;
    commandCursor = commands;
    commandCursor = (ModgfxCommand*)((int)commandCursor | (int)commands);
    if (variant == 0) {
        commandCursor[0].stageIndex = 0;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x80;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 16383.0f;
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 8;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 2;
        commandCursor[1].valueX = 5.2f;
        commandCursor[1].valueY = 5.2f;
        commandCursor[1].valueZ = 40.0f;
        commandCursor += 2;
    } else if (variant == 1) {
        f32 jitter;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])] = 0x118;
        commandCursor[0].stageIndex = 0;
        commandCursor[0].parameter = 0x69;
        commandCursor[0].vertexIndices = NULL;
        commandCursor[0].flags = 0x1800000;
        commandCursor[0].valueX = 1.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 8;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        commandCursor[1].valueX = 3.5f + jitter;
        commandCursor[1].valueY = 3.5f + jitter;
        commandCursor[1].valueZ = 20.0f + jitter;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 9;
        commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[2].flags = 0x80;
        commandCursor[2].valueX = 0.0f;
        commandCursor[2].valueY = 0.0f;
        commandCursor[2].valueZ = 32676.0f;
        commandCursor[3].stageIndex = 0;
        commandCursor[3].parameter = 8;
        commandCursor[3].vertexIndices =
            (s16*)&resourceData[offsetof(Dll79EffectResourceView, firstEightVertexIndices)];
        commandCursor[3].flags = 4;
        commandCursor[3].valueX = 100.0f;
        commandCursor[3].valueY = 0.0f;
        commandCursor[3].valueZ = 0.0f;
        commandCursor += 4;
    } else if (variant == 2) {
        f32 jitter;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])] = 0x50;
        commandCursor[0].stageIndex = 0;
        commandCursor[0].parameter = 0x1fc;
        commandCursor[0].vertexIndices = NULL;
        commandCursor[0].flags = 0x1800000;
        commandCursor[0].valueX = 1.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 0;
        commandCursor[1].parameter = 8;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        commandCursor[1].valueX = 1.2f + jitter;
        commandCursor[1].valueY = 1.2f + jitter;
        commandCursor[1].valueZ = 12.0f + jitter;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 0x8c;
        commandCursor[2].vertexIndices = NULL;
        commandCursor[2].flags = 0x20000000;
        commandCursor[2].valueX = 999.0f;
        commandCursor[2].valueY = 96.0f;
        commandCursor[2].valueZ = 97.0f;
        commandCursor[3].stageIndex = 0;
        commandCursor[3].parameter = 9;
        commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[3].flags = 0x80;
        commandCursor[3].valueX = 0.0f;
        commandCursor[3].valueY = 0.0f;
        commandCursor[3].valueZ = 32676.0f;
        commandCursor += 4;
    }
    if (variant == 0) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x4000;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 1;
        commandCursor[1].parameter = 8;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 2;
        commandCursor[1].valueX = 0.5f;
        commandCursor[1].valueY = 0.5f;
        commandCursor[1].valueZ = 0.5f;
        commandCursor += 2;
    } else if (variant == 1) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x4000;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = -2.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 1;
        commandCursor[1].parameter = 0x8f;
        commandCursor[1].vertexIndices = NULL;
        commandCursor[1].flags = 0x1800000;
        commandCursor[1].valueX = 12.0f;
        commandCursor[1].valueY = 0.0f;
        commandCursor[1].valueZ = 0.0f;
        commandCursor[2].stageIndex = 0;
        commandCursor[2].parameter = 4;
        commandCursor[2].vertexIndices = (s16*)(gDll79EvenVertexIndices);
        commandCursor[2].flags = 2;
        commandCursor[2].valueX = 1.0f;
        commandCursor[2].valueY = 1.0f;
        commandCursor[2].valueZ = 2.0f;
        commandCursor += 3;
    } else if (variant == 2) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x4000;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 1;
        commandCursor[1].parameter = 0x1fd;
        commandCursor[1].vertexIndices = NULL;
        commandCursor[1].flags = 0x1800000;
        commandCursor[1].valueX = 2.0f;
        commandCursor[1].valueY = 0.0f;
        commandCursor[1].valueZ = 0.0f;
        commandCursor += 2;
    }
    if (variant == 0) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 400.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor += 1;
    } else if (variant == 1) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 800.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor += 1;
    } else if (variant == 2) {
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 800.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor += 1;
    }
    if (variant == 0) {
        commandCursor[0].stageIndex = 2;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 400.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 2;
        commandCursor[1].parameter = 9;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 4;
        commandCursor[1].valueX = 0.0f;
        commandCursor[1].valueY = 0.0f;
        commandCursor[1].valueZ = 0.0f;
        commandCursor += 2;
    } else if (variant == 1) {
        commandCursor[0].stageIndex = 2;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 800.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor += 1;
    } else if (variant == 2) {
        commandCursor[0].stageIndex = 2;
        commandCursor[0].parameter = 9;
        commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[0].flags = 0x100;
        commandCursor[0].valueX = 800.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 2;
        commandCursor[1].parameter = 9;
        commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll79EffectResourceView, allVertexIndices)];
        commandCursor[1].flags = 4;
        commandCursor[1].valueX = 0.0f;
        commandCursor[1].valueY = 0.0f;
        commandCursor[1].valueZ = 0.0f;
        commandCursor += 2;
    }
    if (variant == 2) {
        commandCursor[0].stageIndex = 3;
        commandCursor[0].parameter = 0;
        commandCursor[0].vertexIndices = NULL;
        commandCursor[0].flags = 0x20000000;
        commandCursor[0].valueX = 999.0f;
        commandCursor[0].valueY = 96.0f;
        commandCursor[0].valueZ = 97.0f;
        commandCursor += 1;
    }
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    if (variant == 0) {
        packet.context.position[0] = 0.0f;
        packet.context.position[1] = 0.0f;
        packet.context.position[2] = 0.0f;
    } else {
        packet.context.position[0] = 0.0f;
        packet.context.position[1] = 0.0f;
        packet.context.position[2] = 0.0f;
    }
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 9;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = commandCursor - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll79EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0x4000000;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    if (variant == 0) {
        packet.context.modeByte = 0;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll79EffectResourceData, 8,
                                   (s16*)(&resourceData[offsetof(Dll79EffectResourceView, triangles)]), 0x156, 0);
    } else if (variant == 1) {
        packet.context.modeByte = 0;
        packet.context.flags |= 4;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll79EffectResourceData, 8,
                                   (s16*)(&resourceData[offsetof(Dll79EffectResourceView, triangles)]), 0x89, 0);
    } else if (variant == 2) {
        packet.context.modeByte = 0;
        packet.context.flags |= 4;
        handle = (*gModgfxInterface)
                     ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll79EffectResourceData, 8,
                                   (s16*)(&resourceData[offsetof(Dll79EffectResourceView, triangles)]), 0x23b, 0);
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
