/*
 * DLL 152 / 0x98 - an invertible nine-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0098_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

ModgfxEffectVertex gDll98PrimaryVertices[18] = {
    {0, 0, 1000, 0, 0},         {-707, 0, 707, 15, 0},    {-1000, 0, 0, 31, 0},      {-707, 0, -707, 47, 0},
    {0, 0, -1000, 63, 0},       {707, 0, -707, 79, 0},    {1000, 0, 0, 95, 0},       {707, 0, 707, 111, 0},
    {0, 0, 1000, 127, 0},       {0, 2000, 1000, 0, 31},   {-707, 2000, 707, 15, 31}, {-1000, 2000, 0, 31, 31},
    {-707, 2000, -707, 47, 31}, {0, 2000, -1000, 63, 31}, {707, 2000, -707, 79, 31}, {1000, 2000, 0, 95, 31},
    {707, 2000, 707, 111, 31},  {0, 2000, 1000, 127, 31},
};
ModgfxEffectVertex gDll98InvertedVertices[18] = {
    {0, 0, 1000, 0, 0},          {-707, 0, 707, 15, 0},     {-1000, 0, 0, 31, 0},       {-707, 0, -707, 47, 0},
    {0, 0, -1000, 63, 0},        {707, 0, -707, 79, 0},     {1000, 0, 0, 95, 0},        {707, 0, 707, 111, 0},
    {0, 0, 1000, 127, 0},        {0, -2000, 1000, 0, 31},   {-707, -2000, 707, 15, 31}, {-1000, -2000, 0, 31, 31},
    {-707, -2000, -707, 47, 31}, {0, -2000, -1000, 63, 31}, {707, -2000, -707, 79, 31}, {1000, -2000, 0, 95, 31},
    {707, -2000, 707, 111, 31},  {0, -2000, 1000, 127, 31},
};
s16 gDll98Triangles[16][3] = {
    {0, 1, 10}, {0, 10, 9},  {1, 2, 11}, {1, 11, 10}, {2, 3, 12}, {2, 12, 11}, {3, 4, 13}, {3, 13, 12},
    {4, 5, 14}, {4, 14, 13}, {5, 6, 15}, {5, 15, 14}, {6, 7, 16}, {6, 16, 15}, {7, 8, 17}, {7, 17, 16},
};
u8 gDll98Opaque1C8[0x14] = {0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 0};
s16 gDll98AllVertexIndices[18] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
u8 gDll98Opaque200[0x14] = {0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0};
s16 gDll98SequenceParams[7] = {0, 100, 100, 0, 0, 0, 0};

void dll_98_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int unused,
                        int invertY) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands;
    int effectId;
    gDll98SequenceParams[1] = randomGetRange(0, 0x1E) + 0x1E;
    gDll98SequenceParams[2] = gDll98SequenceParams[1];
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x12;
    commands[0].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[0].flags = 0x4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x12;
    commands[1].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[1].flags = 0x2;
    commands[1].valueZ = commands[1].valueX = 0.22f;
    commands[1].valueY = 0.3f;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0x12;
    commands[2].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[2].flags = 0x4;
    commands[2].valueX = 255.0f;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = 0.0f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 0x12;
    commands[3].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[3].flags = 0x400000;
    commands[3].valueX = 0.0f;
    if ((u32)invertY != 0) {
        commands[3].valueY = -7.0f;
    } else {
        commands[3].valueY = 7.0f;
    }
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0x12;
    commands[4].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[4].flags = 0x4000;
    commands[4].valueX = 0.0f;
    if ((u32)invertY != 0) {
        commands[4].valueY = 1.0f;
    } else {
        commands[4].valueY = -1.0f;
    }
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 2;
    commands[5].parameter = 0x12;
    commands[5].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[5].flags = 0x4;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x12;
    commands[6].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[6].flags = 0x400000;
    commands[6].valueX = 0.0f;
    if ((u32)invertY != 0) {
        commands[6].valueY = -7.0f;
    } else {
        commands[6].valueY = 7.0f;
    }
    commands[6].valueZ = 0.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x12;
    commands[7].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[7].flags = 0x4000;
    commands[7].valueX = 0.0f;
    if ((u32)invertY != 0) {
        commands[7].valueY = 1.0f;
    } else {
        commands[7].valueY = -1.0f;
    }
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x12;
    commands[8].vertexIndices = (s16*)(gDll98AllVertexIndices);
    commands[8].flags = 0x2;
    commands[8].valueX = 1.0f;
    commands[8].valueY = 1.0f;
    commands[8].valueZ = 1.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    if ((u32)invertY != 0) {
        packet.context.position[1] = -2.0f;
    } else {
        packet.context.position[1] = 2.0f;
    }
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0x12;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.flags = 0x4080400;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 9) - commands;
    packet.context.stageDurations[0] = gDll98SequenceParams[0];
    packet.context.stageDurations[1] = gDll98SequenceParams[1];
    packet.context.stageDurations[2] = gDll98SequenceParams[2];
    packet.context.stageDurations[3] = gDll98SequenceParams[3];
    packet.context.stageDurations[4] = gDll98SequenceParams[4];
    packet.context.stageDurations[5] = gDll98SequenceParams[5];
    packet.context.stageDurations[6] = gDll98SequenceParams[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)packet.context.sourceObject != 0) {
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
        effectId = 0x3E9;
    } else if (variant == 1) {
        effectId = 0x3F0;
    } else {
        effectId = 0x3F3;
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x12,
                      (ModgfxEffectVertex*)((u32)invertY != 0 ? gDll98InvertedVertices : gDll98PrimaryVertices), 0x10,
                      (s16*)(gDll98Triangles), effectId, 0);
}

void dll_98_release(void) {
}

void dll_98_initialise(void) {
}

Dll98ResourceDescriptor gDll98ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_98_initialise,
    dll_98_release,
    NULL,
    dll_98_spawnEffect,
    0x00000000,
};
