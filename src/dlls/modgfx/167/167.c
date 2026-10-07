/*
 * DLL 167 / 0xA7 - a configurable layered effect spawner.
 */
#include "main/dll/dll_00A7_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA7EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[4][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA7EffectResourceView;

STATIC_ASSERT(offsetof(DllA7EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, allVertexIndices) == 0x68);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, sequenceParams) == 0x78);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, opaqueTail) == 0x86);
STATIC_ASSERT(sizeof(DllA7EffectResourceView) == 0x88);

extern u8 gDllA7EffectResourceData[sizeof(DllA7EffectResourceView)];

void dll_A7_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags, int unused,
                        DllA7CommandParams* commandParams) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDllA7EffectResourceData;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;
    u32 valueY;
    u32 valueZ;
    u32 valueX;
    s32 commandFlags;
    u32 fl;

    valueY = 0x30;
    valueZ = 0x31;
    valueX = 1;
    commandFlags = 0x50;
    commands = packet.entries;
    if (commandParams != NULL) {
        valueX = commandParams->valueX;
        valueY = commandParams->valueY;
        valueZ = commandParams->valueZ;
        commandFlags = commandParams->flags;
    }
    commands[0].stageIndex = 0;
    commands[0].parameter = 8;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 8;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    if (sourceObj != NULL) {
        commands[1].valueX = 7.0f * sourceObj->anim.rootMotionScale;
        commands[1].valueY = 6.0f * sourceObj->anim.rootMotionScale;
        commands[1].valueZ = 7.0f * sourceObj->anim.rootMotionScale;
    } else {
        commands[1].valueX = 7.0f;
        commands[1].valueY = 6.0f;
        commands[1].valueZ = 7.0f;
    }
    commands[2].stageIndex = 0;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x80;
    commands[2].valueX = 0.0f;
    commands[2].valueY = 0.0f;
    if (sourceObj != NULL) {
        commands[2].valueZ = (f32)sourceObj->anim.rotX;
    } else {
        commands[2].valueZ = 0.0f;
    }
    commands[3].stageIndex = 1;
    commands[3].parameter = 8;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 255.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = commandFlags;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x20000000;
    commands[4].valueX = (f32)(int)valueX;
    commands[4].valueY = (f32)(int)valueY;
    commands[4].valueZ = (f32)(int)valueZ;
    commandCursor = commands + 5;
    if (variant != 1) {
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 0x3b;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x1800000;
        commandCursor->valueX = 1.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = 10.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 2;
    commandCursor[0].parameter = 0;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x100;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 50.0f;
    commandCursor[1].stageIndex = 3;
    commandCursor[1].parameter = 1;
    commandCursor[1].vertexIndices = NULL;
    commandCursor[1].flags = 0x2000;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 4;
    commandCursor[2].parameter = 8;
    commandCursor[2].vertexIndices = (s16*)&resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commandCursor[2].flags = 4;
    commandCursor[2].valueX = 0.0f;
    commandCursor[2].valueY = 0.0f;
    commandCursor[2].valueZ = 0.0f;
    commandCursor[3].stageIndex = 4;
    commandCursor[3].parameter = 0;
    commandCursor[3].vertexIndices = NULL;
    commandCursor[3].flags = 0x20000000;
    commandCursor[3].valueX = (f32)(int)valueX;
    commandCursor[3].valueY = (f32)(int)valueY;
    commandCursor[3].valueZ = (f32)(int)valueZ;

    packet.context.modeByte = variant;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    if (spawnParams != NULL) {
        packet.context.position[1] = spawnParams->posY;
    } else {
        packet.context.position[1] = 0.0f;
    }
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 8;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = &commandCursor[4] - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4040000;
    packet.context.flags |= (flags | 0x80);
    fl = packet.context.flags;
    if (fl & 1) {
        GameObject* object = packet.context.sourceObject;
        if (object != NULL) {
            packet.context.position[0] += object->anim.worldPosX;
            packet.context.position[1] += object->anim.worldPosY;
            packet.context.position[2] += object->anim.worldPosZ;
        } else {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 8, (ModgfxEffectVertex*)(int)gDllA7EffectResourceData, 4,
                      (s16*)(&resourceData[offsetof(DllA7EffectResourceView, triangles)]), 0x5e0, 0);
}

void dll_A7_release(void) {
}

void dll_A7_initialise(void) {
}

u8 gDllA7EffectResourceData[sizeof(DllA7EffectResourceView)] = {
    252, 24, 0, 0,  0, 0,   0,  0,   0, 0,  0, 0,  0,   0,  252, 24,  0,  0,   0, 0,   3, 232, 0, 0,  0,  0,   0,   15,
    0,   0,  0, 0,  0, 0,   3,  232, 0, 15, 0, 0,  252, 24, 15,  160, 0,  0,   0, 0,   0, 31,  0, 0,  15, 160, 252, 24,
    0,   0,  0, 31, 3, 232, 15, 160, 0, 0,  0, 15, 0,   31, 0,   0,   15, 160, 3, 232, 0, 15,  0, 31, 0,  0,   0,   2,
    0,   6,  0, 0,  0, 6,   0,  4,   0, 1,  0, 3,  0,   7,  0,   1,   0,  7,   0, 5,   0, 0,   0, 1,  0,  2,   0,   3,
    0,   4,  0, 5,  0, 6,   0,  7,   0, 0,  1, 4,  0,   30, 0,   1,   1,  4,   0, 0,   0, 0,   0, 0};

DllA7ResourceDescriptor gDllA7ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A7_initialise, dll_A7_release, NULL, dll_A7_spawnEffect,
};
