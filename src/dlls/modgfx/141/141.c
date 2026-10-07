/*
 * DLL 141 / 0x8D - a three-variant layered modgfx effect spawner.
 */
#include "main/dll/dll_008D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll8DEffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 opaque5A[2];
    s16 triangles[8][3];
    s16 nineVertexIndices[10];
    s16 eightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8DEffectResourceView;

STATIC_ASSERT(offsetof(Dll8DEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, opaque5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, nineVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, eightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, opaqueTail) == 0xBE);
STATIC_ASSERT(sizeof(Dll8DEffectResourceView) == 0xC0);

extern u8 gDll8DEffectResourceData[sizeof(Dll8DEffectResourceView)];

s16 dll_8D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll8DEffectResourceData;
    ModgfxCommand* command;
    ModgfxCommand* commands;
    s16 ret = 0;
    f32 jitter;

    commands = packet.entries;
    command = (ModgfxCommand*)commands;

    if (variant == 0) {
        command->stageIndex = 0;
        command->parameter = 0x8c;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 94.0f;
        command->valueZ = 95.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->valueX = anchorParams->posX;
            command->valueY = anchorParams->posY;
            command->valueZ = anchorParams->posZ;
            command++;
        } else {
            command->valueX = 0.0f;
            command->valueY = 32640.0f;
            command->valueZ = 0.0f;
            command++;
        }
        command->stageIndex = 0;
        command->parameter = 8;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 2;
        command->valueX = 3.2f;
        command->valueY = 3.2f;
        command->valueZ = 30.0f;
        command++;
    } else if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])] = 0x50;
        command->stageIndex = 0;
        command->parameter = 2;
        command->vertexIndices = NULL;
        command->flags = 0x1800000;
        command->valueX = 1.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 0x69;
        command->vertexIndices = NULL;
        command->flags = 0x1800000;
        command->valueX = 1.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 8;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        command->valueY = command->valueX = 5.0f + jitter;
        command->valueZ = 28.0f + jitter;
        command++;
        command->stageIndex = 0;
        command->parameter = 0x8c;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 96.0f;
        command->valueZ = 97.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->valueX = anchorParams->posX;
            command->valueY = anchorParams->posY;
            command->valueZ = anchorParams->posZ;
            command++;
        } else {
            command->valueX = 0.0f;
            command->valueY = 32640.0f;
            command->valueZ = 0.0f;
            command++;
        }
    } else if (variant == 2) {
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])] = 0x50;
        command->stageIndex = 0;
        command->parameter = 0x1fc;
        command->vertexIndices = NULL;
        command->flags = 0x1800000;
        command->valueX = 1.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 8;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        command->valueY = command->valueX = 1.2f + jitter;
        command->valueZ = 12.0f + jitter;
        command++;
        command->stageIndex = 0;
        command->parameter = 0x8c;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 96.0f;
        command->valueZ = 97.0f;
        command++;
        command->stageIndex = 0;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->valueX = anchorParams->posX;
            command->valueY = anchorParams->posY;
            command->valueZ = anchorParams->posZ;
            command++;
        } else {
            command->valueX = 0.0f;
            command->valueY = 32640.0f;
            command->valueZ = 0.0f;
            command++;
        }
    }
    if (variant == 0) {
        command[0].stageIndex = 1;
        command[0].parameter = 9;
        command[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].flags = 0x4000;
        command[0].valueX = 0.0f;
        command[0].valueY = 0.0f;
        command[0].valueZ = 0.0f;
        command[1].stageIndex = 1;
        command[1].parameter = 0x68;
        command[1].vertexIndices = NULL;
        command[1].flags = 0x800000;
        command[1].valueX = 1.0f;
        command[1].valueY = 0.0f;
        command[1].valueZ = 0.0f;
        command[2].stageIndex = 1;
        command[2].parameter = 8;
        command[2].vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[2].flags = 2;
        command[2].valueX = 0.5f;
        command[2].valueY = 0.5f;
        command[2].valueZ = 0.5f;
        command += 3;
    } else if (variant == 1) {
        command[0].stageIndex = 1;
        command[0].parameter = 9;
        command[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].flags = 0x4000;
        command[0].valueX = 0.0f;
        command[0].valueY = 0.0f;
        command[0].valueZ = 0.0f;
        command[1].stageIndex = 1;
        command[1].parameter = 0x8f;
        command[1].vertexIndices = NULL;
        command[1].flags = 0x1800000;
        command[1].valueX = 2.0f;
        command[1].valueY = 0.0f;
        command[1].valueZ = 0.0f;
        command += 2;
    } else if (variant == 2) {
        command[0].stageIndex = 1;
        command[0].parameter = 9;
        command[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].flags = 0x4000;
        command[0].valueX = 0.0f;
        command[0].valueY = 0.0f;
        command[0].valueZ = 0.0f;
        command[1].stageIndex = 1;
        command[1].parameter = 0x1fd;
        command[1].vertexIndices = NULL;
        command[1].flags = 0x1800000;
        command[1].valueX = 2.0f;
        command[1].valueY = 0.0f;
        command[1].valueZ = 0.0f;
        command += 2;
    }
    if (variant == 0) {
        command->stageIndex = 1;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 400.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    } else if (variant == 1) {
        command->stageIndex = 1;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 800.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    } else if (variant == 2) {
        command->stageIndex = 1;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 800.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    }
    if (variant == 0) {
        command->stageIndex = 2;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 400.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    } else if (variant == 1) {
        command->stageIndex = 2;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 800.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    } else if (variant == 2) {
        command->stageIndex = 2;
        command->parameter = 9;
        command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->flags = 0x100;
        command->valueX = 800.0f;
        command->valueY = 0.0f;
        command->valueZ = 0.0f;
        command++;
    }
    command->stageIndex = 2;
    command->parameter = 9;
    command->vertexIndices = (s16*)&resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
    command->flags = 4;
    command->valueX = 0.0f;
    command->valueY = 0.0f;
    command->valueZ = 0.0f;
    command++;
    if (variant == 0) {
        command->stageIndex = 3;
        command->parameter = 0;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 94.0f;
        command->valueZ = 95.0f;
        command++;
    } else if (variant == 1) {
        command->stageIndex = 3;
        command->parameter = 0;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 96.0f;
        command->valueZ = 97.0f;
        command++;
    } else if (variant == 2) {
        command->stageIndex = 3;
        command->parameter = 0;
        command->vertexIndices = NULL;
        command->flags = 0x20000000;
        command->valueX = 999.0f;
        command->valueY = 96.0f;
        command->valueZ = 97.0f;
        command++;
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
    packet.context.commandCount = command - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000000;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)packet.context.sourceObject != 0) {
            GameObject* anchorObj = packet.context.sourceObject;
            packet.context.position[0] += anchorObj->anim.worldPosX;
            packet.context.position[1] += anchorObj->anim.worldPosY;
            packet.context.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.context.position[0] += anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    if (variant == 0) {
        packet.context.modeByte = 0;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll8DEffectResourceData, 8,
                                (s16*)(&resourceData[offsetof(Dll8DEffectResourceView, triangles)]), 0x156, 0);
    } else if (variant == 1) {
        packet.context.modeByte = 0;
        packet.context.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll8DEffectResourceData, 8,
                                (s16*)(&resourceData[offsetof(Dll8DEffectResourceView, triangles)]), 0xC0D, 0);
    } else if (variant == 2) {
        packet.context.modeByte = 0;
        packet.context.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet.context, 0, 9, (ModgfxEffectVertex*)(int)gDll8DEffectResourceData, 8,
                                (s16*)(&resourceData[offsetof(Dll8DEffectResourceView, triangles)]), 0x23B, 0);
    }
    return ret;
}

void dll_8D_release(void) {
}

void dll_8D_initialise(void) {
}

u8 gDll8DEffectResourceData[sizeof(Dll8DEffectResourceView)] = {
    0x03, 0xE8, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3, 0xFD, 0x3D, 0x01, 0x90, 0x00, 0x00,
    0x00, 0x1F, 0x00, 0x00, 0xFC, 0x18, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0xFD, 0x3D, 0x01, 0x90,
    0x00, 0x00, 0x00, 0x1F, 0xFC, 0x18, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0x02, 0xC3,
    0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x03, 0xE8, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3,
    0x02, 0xC3, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0xFB, 0xB4, 0x00, 0x0F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x05, 0x00, 0x06,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32,
    0x00, 0x1E, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

Dll8DResourceDescriptor gDll8DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_8D_initialise, dll_8D_release, NULL, dll_8D_spawnEffect,
};
