/*
 * DLL 156 / 0x9C - a variant-driven layered modgfx effect spawner.
 */
#include "main/dll/dll_009C_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll9CEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    u8 opaque164[0x4C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[2][7];
} Dll9CEffectResourceView;

STATIC_ASSERT(offsetof(Dll9CEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, opaque164) == 0x164);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll9CEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(sizeof(Dll9CEffectResourceView) == 0x214);

extern u32 gDll9CEffectResourceData[sizeof(Dll9CEffectResourceView) / sizeof(u32)];

void dll_9C_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commandCursor;
    u8* resourceData = (u8*)(int)gDll9CEffectResourceData;
    ModgfxCommand* commands = packet.entries;
    int idx;
    u8* q;

    commandCursor = commands;
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 0x15;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 0.01f;
    commandCursor[1].valueY = 2.0f;
    commandCursor[1].valueZ = 0.01f;
    commandCursor += 2;
    if (variant != 1) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x400000;
        commandCursor->valueX = 0.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    }
    if (variant == 1) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x80;
        commandCursor->valueX = (f32)spawnParams->arg2;
        commandCursor->valueY = (f32)spawnParams->arg1;
        commandCursor->valueZ = (f32)spawnParams->arg0;
        commandCursor++;
    }
    if (variant == 1) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 30.0f;
        commandCursor->valueY = spawnParams->posY / 30.0f;
        commandCursor->valueZ = 30.0f;
    } else {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 30.0f;
        commandCursor->valueY = 1.2f;
        commandCursor->valueZ = 30.0f;
    }
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 0xe;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, lastFourteenVertexIndices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 155.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 0x15;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 0x4000;
    commandCursor[2].valueX = 2.0f;
    commandCursor[2].valueY = -4.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor += 3;
    if (variant != 1) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x100;
        commandCursor->valueX = 0.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = -150.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 2;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 0x4000;
    commandCursor[0].valueX = 2.0f;
    commandCursor[0].valueY = -4.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 3;
    commandCursor[1].parameter = 0x15;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 0x4000;
    commandCursor[1].valueX = 2.0f;
    commandCursor[1].valueY = -4.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 3;
    commandCursor[2].parameter = 0xe;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll9CEffectResourceView, lastFourteenVertexIndices)];
    commandCursor[2].flags = 4;
    commandCursor[2].valueX = 0.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor[3].stageIndex = 1;

    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 4.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (s8)(((u8*)(commandCursor + 3) - (u8*)commands) / (int)sizeof(ModgfxCommand));
    idx = variant * 7;
    q = resourceData + idx * 2;
    packet.context.stageDurations[0] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 1) * 2;
    packet.context.stageDurations[1] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 2) * 2;
    packet.context.stageDurations[2] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 3) * 2;
    packet.context.stageDurations[3] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 4) * 2;
    packet.context.stageDurations[4] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 5) * 2;
    packet.context.stageDurations[5] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    q = resourceData + (idx + 6) * 2;
    packet.context.stageDurations[6] = *(s16*)&q[offsetof(Dll9CEffectResourceView, sequenceParams)];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0xc010480;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)sourceObj != NULL) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += sourceObj->anim.worldPosY;
            packet.context.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll9CEffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll9CEffectResourceView, triangles)]), 0x154, 0);
}

void dll_9C_release(void) {
}

void dll_9C_initialise(void) {
}

u32 gDll9CEffectResourceData[sizeof(Dll9CEffectResourceView) / sizeof(u32)] = {
    0x00000000, 0x03e80000, 0x00000362, 0x000001f4, 0x000b0000, 0x03620000, 0xfe0c0016, 0x00000000, 0x0000fc18,
    0x00200000, 0xfc9e0000, 0xfe0c0016, 0x0000fc9e, 0x000001f4, 0x000b0000, 0x00000000, 0x03e80000, 0x00000000,
    0x01f403e8, 0x0000000f, 0x036201f4, 0x01f4000b, 0x000f0362, 0x01f4fe0c, 0x0016000f, 0x000001f4, 0xfc180020,
    0x000ffc9e, 0x01f4fe0c, 0x0016000f, 0xfc9e01f4, 0x01f4000b, 0x000f0000, 0x01f403e8, 0x0000000f, 0x00001770,
    0x03e80000, 0x007f0362, 0x177001f4, 0x000b007f, 0x03621770, 0xfe0c0016, 0x007f0000, 0x1770fc18, 0x0020007f,
    0xfc9e1770, 0xfe0c0016, 0x007ffc9e, 0x177001f4, 0x000b007f, 0x00001770, 0x03e80000, 0x007f0000, 0x00000001,
    0x00080000, 0x00080007, 0x00010002, 0x00090001, 0x00090008, 0x00020003, 0x000a0002, 0x000a0009, 0x00030004,
    0x000b0003, 0x000b000a, 0x00040005, 0x000c0004, 0x000c000b, 0x00050006, 0x000d0005, 0x000d000c, 0x00070008,
    0x000f0007, 0x000f000e, 0x00080009, 0x00100008, 0x0010000f, 0x0009000a, 0x00110009, 0x00110010, 0x000a000b,
    0x0012000a, 0x00120011, 0x000b000c, 0x0013000b, 0x00130012, 0x000c000d, 0x0014000c, 0x00140013, 0x00000001,
    0x00020003, 0x00040005, 0x00060000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d0000, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00000001, 0x00020003, 0x00040005, 0x0006000e, 0x000f0010, 0x00110012, 0x00130014,
    0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080009, 0x000a000b, 0x000c000d, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d000e, 0x000f0010, 0x00110012, 0x00130014,
    0x00000096, 0x044c0032, 0x00000000, 0x00000000, 0x0028000a, 0x00140001, 0x00000000};
Dll9CResourceDescriptor gDll9CResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_9C_initialise,
    dll_9C_release,
    NULL,
    dll_9C_spawnEffect,
    0x00000000,
};
