/*
 * DLL 129 / 0x81 - a multi-variant laser-beam modgfx effect spawner.
 */
#include "main/dll/dll_0081_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll81EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    u8 opaqueIndexData164[0x4C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    u8 opaqueIndexData1DC[0x1C];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll81EffectResourceView;

STATIC_ASSERT(offsetof(Dll81EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, padD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, opaqueIndexData164) == 0x164);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, opaqueIndexData1DC) == 0x1DC);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll81EffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll81EffectResourceView) == 0x208);

u8 gDll81EffectResourceData[sizeof(Dll81EffectResourceView)] = {
    0,   0,   3,   232, 0,   0,   0,   0,   0,   0,   3,   98,  1,  244, 0,   0,   0,   8,   0,   0,   3,   98,  254,
    12,  0,   0,   0,   15,  0,   0,   0,   0,   252, 24,  0,   0,  0,   31,  0,   0,   252, 158, 254, 12,  0,   0,
    0,   15,  0,   0,   252, 158, 1,   244, 0,   0,   0,   8,   0,  0,   0,   0,   3,   232, 0,   0,   0,   0,   0,
    0,   0,   0,   3,   232, 11,  184, 0,   0,   0,   127, 3,   98, 1,   244, 11,  184, 0,   8,   0,   127, 3,   98,
    254, 12,  11,  184, 0,   15,  0,   127, 0,   0,   252, 24,  11, 184, 0,   31,  0,   127, 252, 158, 254, 12,  11,
    184, 0,   15,  0,   127, 252, 158, 1,   244, 11,  184, 0,   8,  0,   127, 0,   0,   3,   232, 11,  184, 0,   0,
    0,   127, 0,   0,   3,   232, 23,  112, 0,   0,   0,   255, 3,  98,  1,   244, 23,  112, 0,   8,   0,   255, 3,
    98,  254, 12,  23,  112, 0,   15,  0,   255, 0,   0,   252, 24, 23,  112, 0,   31,  0,   255, 252, 158, 254, 12,
    23,  112, 0,   15,  0,   255, 252, 158, 1,   244, 23,  112, 0,  8,   0,   255, 0,   0,   3,   232, 23,  112, 0,
    0,   0,   255, 0,   0,   0,   0,   0,   8,   0,   1,   0,   0,  0,   7,   0,   8,   0,   1,   0,   9,   0,   2,
    0,   1,   0,   8,   0,   9,   0,   2,   0,   10,  0,   3,   0,  2,   0,   9,   0,   10,  0,   3,   0,   11,  0,
    4,   0,   3,   0,   10,  0,   11,  0,   4,   0,   12,  0,   5,  0,   4,   0,   11,  0,   12,  0,   5,   0,   13,
    0,   6,   0,   5,   0,   12,  0,   13,  0,   7,   0,   15,  0,  8,   0,   7,   0,   14,  0,   15,  0,   8,   0,
    16,  0,   9,   0,   8,   0,   15,  0,   16,  0,   9,   0,   17, 0,   10,  0,   9,   0,   16,  0,   17,  0,   10,
    0,   18,  0,   11,  0,   10,  0,   17,  0,   18,  0,   11,  0,  19,  0,   12,  0,   11,  0,   18,  0,   19,  0,
    12,  0,   20,  0,   13,  0,   12,  0,   19,  0,   20,  0,   0,  0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,  11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,  18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,  0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,  20,  0,   0,   0,   7,   0,   8,   0,   9,   0,
    10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16, 0,   17,  0,   18,  0,   19,  0,   20,  0,   0,
    0,   4,   0,   10,  0,   1,   0,   36,  0,   0,   0,   0,   0,  0};

s16 dll_81_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int owner,
                       int unused) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll81EffectResourceData;
    f32 verticalStep = -3.0f;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;
    if (variant == 0 || variant == 2 || variant == 0x1e) {
        *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[1])] = 0xc;
    } else if (variant == 1 || variant == 3) {
        verticalStep *= -1.0f;
        *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[1])] = 4;
        *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[4])] = 0x32;
    }
    commands = packet.entries;
    commandCursor = &commands[1];
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    if (variant == 0 || variant == 2) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.35f;
        commandCursor->valueY = 0.35f;
        commandCursor->valueZ = 0.01f;
        commandCursor++;
    } else if (variant == 0xe) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.2f;
        commandCursor->valueY = 0.2f;
        commandCursor->valueZ = 5.0f;
        commandCursor++;
    } else if (variant == 0x1e) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.45f;
        commandCursor->valueY = 0.45f;
        commandCursor->valueZ = 0.01f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 0.35f;
        commandCursor->valueY = 0.35f;
        commandCursor->valueZ = 3.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0x77;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x10000;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 0x79;
    commandCursor[1].vertexIndices = NULL;
    commandCursor[1].flags = 0x10000;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 1;
    commandCursor[2].parameter = 0x15;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 4;
    commandCursor[2].valueX = 255.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor += 3;
    if (variant == 0 || variant == 2) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 1.0f;
        commandCursor->valueY = 1.0f;
        commandCursor->valueZ = 300.0f;
        commandCursor++;
    } else if (variant == 0x1e) {
        commandCursor->stageIndex = 1;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 1.0f;
        commandCursor->valueY = 1.0f;
        commandCursor->valueZ = 460.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 1;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 0x4000;
    commandCursor[0].valueX = 1.0f;
    commandCursor[0].valueY = verticalStep;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 2;
    commandCursor[1].parameter = 0x15;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 255.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 2;
    commandCursor[2].parameter = 0x15;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 0x4000;
    commandCursor[2].valueX = 1.0f;
    commandCursor[2].valueY = verticalStep;
    commandCursor[2].valueZ = 0.0f;
    commandCursor[3].stageIndex = 3;
    commandCursor[3].parameter = 0x15;
    commandCursor[3].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[3].flags = 0x4000;
    commandCursor[3].valueX = 1.0f;
    commandCursor[3].valueY = verticalStep;
    commandCursor[3].valueZ = 0.0f;
    commandCursor[4].stageIndex = 4;
    commandCursor[4].parameter = 0x15;
    commandCursor[4].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[4].flags = 0x4000;
    commandCursor[4].valueX = 1.0f;
    commandCursor[4].valueY = verticalStep;
    commandCursor[4].valueZ = 0.0f;
    commandCursor += 5;
    if (variant == 0 || variant == 0x1e) {
        commandCursor->stageIndex = 4;
        commandCursor->parameter = 2;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x2000;
        commandCursor->valueX = 0.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 5;
    commandCursor[0].parameter = 0x15;
    commandCursor[0].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[0].flags = 0x4000;
    commandCursor[0].valueX = 1.0f;
    commandCursor[0].valueY = verticalStep;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 5;
    commandCursor[1].parameter = 0x15;
    commandCursor[1].vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor += 2;
    if (variant == 1 || variant == 3) {
        commandCursor->stageIndex = 5;
        commandCursor->parameter = 0x15;
        commandCursor->vertexIndices = (s16*)&resourceData[offsetof(Dll81EffectResourceView, allVertexIndices)];
        commandCursor->flags = 2;
        commandCursor->valueX = 1.0f;
        commandCursor->valueY = 1.0f;
        commandCursor->valueZ = 0.01f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 5;
    commandCursor[0].parameter = 0x78;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x10000;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 5;
    commandCursor[1].parameter = -1;
    commandCursor[1].vertexIndices = NULL;
    commandCursor[1].flags = 0x10000;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0xa;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commandCursor + sizeof(ModgfxCommand) * 2) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll81EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc0104c0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += sourceObj->anim.worldPosY;
            packet.context.position[2] += sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    if (variant == 0x1e) {
        return (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll81EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll81EffectResourceView, triangles)]), 0x3e9, 0);
    } else if (variant == 2 || variant == 3) {
        return (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll81EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll81EffectResourceView, triangles)]), 0x23d, 0);
    } else if ((u32)(variant - 10) <= 3 || variant == 0xe) {
        return (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll81EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll81EffectResourceView, triangles)]), 0x2e, 0);
    } else {
        return (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll81EffectResourceData, 0x18,
                          (s16*)(&resourceData[offsetof(Dll81EffectResourceView, triangles)]), 0xd9, 0);
    }
}

void dll_81_release(void) {
}

void dll_81_initialise(void) {
}

Dll81ResourceDescriptor gDll81ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_81_initialise, dll_81_release, NULL, dll_81_spawnEffect,
};
