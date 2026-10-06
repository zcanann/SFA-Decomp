/*
 * DLL 166 / 0xA6 - a randomised layered effect spawner.
 */
#include "main/dll/dll_00A6_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct DllA6ThreeIndexList {
    u8 indices[6];
    u8 opaqueTail[2];
} DllA6ThreeIndexList;

STATIC_ASSERT(offsetof(DllA6ThreeIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllA6ThreeIndexList, opaqueTail) == 0x06);
STATIC_ASSERT(sizeof(DllA6ThreeIndexList) == 0x08);

typedef struct DllA6EffectResourceView {
    ModgfxEffectVertex vertices[3];
    u8 opaque1E[2];
} DllA6EffectResourceView;

STATIC_ASSERT(offsetof(DllA6EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(DllA6EffectResourceView, opaque1E) == 0x1E);
STATIC_ASSERT(sizeof(DllA6EffectResourceView) == 0x20);

typedef struct DllA6SequenceParams {
    s16 values[7];
    s16 opaqueTail;
} DllA6SequenceParams;

STATIC_ASSERT(offsetof(DllA6SequenceParams, values) == 0x00);
STATIC_ASSERT(offsetof(DllA6SequenceParams, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllA6SequenceParams) == 0x10);

extern u8 gDllA6EffectResourceData[sizeof(DllA6EffectResourceView)];
extern DllA6SequenceParams gDllA6SequenceParams;

DllA6ThreeIndexList gDllA6TriangleIndices = {{0, 0, 0, 1, 0, 2}, {0, 0}};
DllA6ThreeIndexList gDllA6VertexIndices = {{0, 0, 0, 1, 0, 2}, {0, 0}};

void dll_A6_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands = packet.entries;
    f32 randomZ;
    f32 randomY;
    u32 fl;
    commandCursor = commands;

    if (variant == 0) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 3;
        commandCursor->vertexIndices = (s16*)(gDllA6VertexIndices.indices);
        commandCursor->flags = 8;
        commandCursor->valueX = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor->valueY = (f32)(int)(randomGetRange(0, 0x14) + 0x87);
        commandCursor->valueZ = (f32)(int)(randomGetRange(0, 0x14) + 0x41);
        commandCursor++;
    } else if (variant == 1) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 3;
        commandCursor->vertexIndices = (s16*)(gDllA6VertexIndices.indices);
        commandCursor->flags = 8;
        commandCursor->valueY = commandCursor->valueX = (f32)(int)(randomGetRange(0, 0x5a) + 0x87);
        commandCursor->valueZ = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor++;
    }
    randomZ = randomGetRange(0, 0xfffe);
    randomY = randomGetRange(-3000, -12000);
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x80;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = randomY;
    commandCursor[0].valueZ = randomZ;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 3;
    commandCursor[1].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 0;
    commandCursor[2].parameter = 3;
    commandCursor[2].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[2].flags = 2;
    commandCursor[2].valueX = 1.0f;
    commandCursor[2].valueY = 0.01f * randomGetRange(0, 0x19) + 0.25f;
    commandCursor[2].valueZ = 0.01f * randomGetRange(0, 10) + 0.4f;
    commandCursor[3].stageIndex = 1;
    commandCursor[3].parameter = 3;
    commandCursor[3].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[3].flags = 4;
    if (randomGetRange(0, 10) == 0) {
        commandCursor[3].valueX = 145.0f + randomGetRange(0, 0x1e);
    } else {
        commandCursor[3].valueX = 25.0f + randomGetRange(0, 10);
    }
    commandCursor[3].valueY = 0.0f;
    commandCursor[3].valueZ = 0.0f;
    commandCursor[4].stageIndex = 1;
    commandCursor[4].parameter = 0;
    commandCursor[4].vertexIndices = NULL;
    commandCursor[4].flags = 0x80;
    commandCursor[4].valueX = 0.0f;
    commandCursor[4].valueY = 0.0f;
    commandCursor[4].valueZ = randomGetRange(0, 0xfffe);
    commandCursor[5].stageIndex = 1;
    commandCursor[5].parameter = 3;
    commandCursor[5].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[5].flags = 2;
    commandCursor[5].valueX = 9.0f;
    commandCursor[5].valueY = 12.0f;
    commandCursor[5].valueZ = 21.0f;
    commandCursor[6].stageIndex = 2;
    commandCursor[6].parameter = 0;
    commandCursor[6].vertexIndices = NULL;
    commandCursor[6].flags = 0x80;
    commandCursor[6].valueX = 0.0f;
    commandCursor[6].valueY = 0.0f;
    commandCursor[6].valueZ = randomGetRange(0, 0xfffe);
    commandCursor[7].stageIndex = 2;
    commandCursor[7].parameter = 3;
    commandCursor[7].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[7].flags = 4;
    commandCursor[7].valueX = 0.0f;
    commandCursor[7].valueY = 0.0f;
    commandCursor[7].valueZ = 0.0f;
    commandCursor[8].stageIndex = 2;
    commandCursor[8].parameter = 3;
    commandCursor[8].vertexIndices = (s16*)(gDllA6VertexIndices.indices);
    commandCursor[8].flags = 2;
    commandCursor[8].valueX = 0.1f;
    commandCursor[8].valueY = 14.0f;
    commandCursor[8].valueZ = 0.05f;

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
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 3;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = &commandCursor[9] - commands;
    packet.context.stageDurations[0] = gDllA6SequenceParams.values[0];
    packet.context.stageDurations[1] = gDllA6SequenceParams.values[1];
    packet.context.stageDurations[2] = gDllA6SequenceParams.values[2];
    packet.context.stageDurations[3] = gDllA6SequenceParams.values[3];
    packet.context.stageDurations[4] = gDllA6SequenceParams.values[4];
    packet.context.stageDurations[5] = gDllA6SequenceParams.values[5];
    packet.context.stageDurations[6] = gDllA6SequenceParams.values[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    fl = 0x4000400;
    packet.context.flags = fl;
    fl |= flags;
    packet.context.flags = fl;
    if (fl & 1) {
        if (sourceObj != NULL && spawnParams != NULL) {
            packet.context.position[0] += sourceObj->anim.worldPosX + spawnParams->posX;
            packet.context.position[1] += sourceObj->anim.worldPosY + spawnParams->posY;
            packet.context.position[2] += sourceObj->anim.worldPosZ + spawnParams->posZ;
        } else if (sourceObj != NULL) {
            packet.context.position[0] += sourceObj->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else if (spawnParams != NULL) {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 3, (ModgfxEffectVertex*)(gDllA6EffectResourceData), 1,
                      (s16*)((s16*)gDllA6TriangleIndices.indices), 0x26a, 0);
}

void dll_A6_release(void) {
}

void dll_A6_initialise(void) {
}

u8 gDllA6EffectResourceData[sizeof(DllA6EffectResourceView)] = {
    0, 0, 0, 230, 5, 20, 0, 0, 0, 31, 0, 0, 255, 26, 5, 20, 0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15, 0, 16, 0, 0,
};

DllA6SequenceParams gDllA6SequenceParams = {{0, 0x46, 0x46, 0, 0, 0, 0}, 0};

DllA6ResourceDescriptor gDllA6ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A6_initialise, dll_A6_release, NULL, dll_A6_spawnEffect,
};
