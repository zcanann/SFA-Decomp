/*
 * DLL 105 / 0x69 - a modgfx effect spawner.
 */
#include "main/dll/dll_0069_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll69EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangleIndices[4][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    u8 pad86[2];
} Dll69EffectResourceView;

STATIC_ASSERT(offsetof(Dll69EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll69EffectResourceView, triangleIndices) == 0x50);
STATIC_ASSERT(offsetof(Dll69EffectResourceView, allVertexIndices) == 0x68);
STATIC_ASSERT(offsetof(Dll69EffectResourceView, sequenceParams) == 0x78);
STATIC_ASSERT(sizeof(Dll69EffectResourceView) == 0x88);

u16 gDll69EffectResourceData[sizeof(Dll69EffectResourceView) / sizeof(u16)] = {
    0xfc18, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xfc18, 0x0000,
    0x0000, 0x03e8, 0x0000, 0x0000, 0x0040, 0x0000, 0x0000, 0x0000, 0x03e8,
    0x0040, 0x0000, 0xfc18, 0x0fa0, 0x0000, 0x0000, 0x0040, 0x0000, 0x0fa0,
    0xfc18, 0x0000, 0x0040, 0x03e8, 0x0fa0, 0x0000, 0x0040, 0x0040, 0x0000,
    0x0fa0, 0x03e8, 0x0040, 0x0040, 0x0000, 0x0002, 0x0006, 0x0000, 0x0006,
    0x0004, 0x0001, 0x0003, 0x0007, 0x0001, 0x0007, 0x0005, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0000, 0x0104, 0x001e,
    0x0001, 0x0104, 0x0000, 0x0000, 0x0000,
};

s16 dll_69_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags, int unusedArg4,
                       Dll69EffectParams* overrideParams) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* command;
    ModgfxCommand* entries;
    u8* resourceData = (u8*)(int)gDll69EffectResourceData;
    int param1 = 0x30;
    int param2 = 0x31;
    int param0 = 1;
    int param3 = 0x50;

    entries = packet.entries;
    if (overrideParams != NULL) {
        param0 = overrideParams->param0;
        param1 = overrideParams->param1;
        param2 = overrideParams->param2;
        param3 = overrideParams->param3;
    }
    entries[0].stageIndex = 0;
    entries[0].parameter = 8;
    entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[0].flags = 4;
    entries[0].valueX = 0.0f;
    entries[0].valueY = 0.0f;
    entries[0].valueZ = 0.0f;
    entries[1].stageIndex = 0;
    entries[1].parameter = 8;
    entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[1].flags = 2;
    if (sourceObj != NULL) {
        entries[1].valueX = 7.0f * sourceObj->anim.rootMotionScale;
        entries[1].valueY = 6.0f * sourceObj->anim.rootMotionScale;
        entries[1].valueZ = 7.0f * sourceObj->anim.rootMotionScale;
    } else {
        entries[1].valueX = 7.0f;
        entries[1].valueY = 6.0f;
        entries[1].valueZ = 7.0f;
    }
    entries[2].stageIndex = 0;
    entries[2].parameter = 0;
    entries[2].vertexIndices = NULL;
    entries[2].flags = 0x80;
    entries[2].valueX = 0.0f;
    entries[2].valueY = 0.0f;
    if (sourceObj != NULL) {
        entries[2].valueZ = (f32) * (s16*)sourceObj;
    } else {
        entries[2].valueZ = 0.0f;
    }
    entries[3].stageIndex = 1;
    entries[3].parameter = 8;
    entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[3].flags = 4;
    entries[3].valueX = 255.0f;
    entries[3].valueY = 0.0f;
    entries[3].valueZ = 0.0f;
    entries[4].stageIndex = 1;
    entries[4].parameter = param3;
    entries[4].vertexIndices = NULL;
    entries[4].flags = 0x20000000;
    entries[4].valueX = param0;
    entries[4].valueY = param1;
    entries[4].valueZ = param2;
    command = &entries[5];
    if (variant == 0) {
        command->stageIndex = 2;
        command->parameter = 0x3b;
        command->vertexIndices = NULL;
        command->flags = 0x1800000;
        command->valueX = 1.0f;
        command->valueY = 0.0f;
        command->valueZ = 10.0f;
        command++;
    }
    command[0].stageIndex = 2;
    command[0].parameter = 0;
    command[0].vertexIndices = NULL;
    command[0].flags = 0x100;
    command[0].valueX = 0.0f;
    command[0].valueY = 0.0f;
    command[0].valueZ = 50.0f;
    command[1].stageIndex = 3;
    command[1].parameter = 1;
    command[1].vertexIndices = NULL;
    command[1].flags = 0x2000;
    command[1].valueX = 0.0f;
    command[1].valueY = 0.0f;
    command[1].valueZ = 0.0f;
    command[2].stageIndex = 4;
    command[2].parameter = 8;
    command[2].vertexIndices = (s16*)&resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    command[2].flags = 4;
    command[2].valueX = 0.0f;
    command[2].valueY = 0.0f;
    command[2].valueZ = 0.0f;
    command[3].stageIndex = 4;
    command[3].parameter = 0;
    command[3].vertexIndices = NULL;
    command[3].flags = 0x20000000;
    command[3].valueX = param0;
    command[3].valueY = param1;
    command[3].valueZ = param2;
    packet.context.modeByte = variant;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    if (spawnParams != NULL) {
        packet.context.position[1] = ((PartFxSpawnParams*)spawnParams)->posY;
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
    packet.context.commandCount = (command + 4) - entries;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    {
        u32 packetFlags = 0x4000000;

        packet.context.flags = packetFlags;
        packetFlags |= spawnFlags | 0x80;
        packet.context.flags = packetFlags;
        if (variant == 2) {
            u32 mask = 0x40000;

            packet.context.flags = packetFlags ^ mask;
        } else {
            u32 mask = 0x40000;

            packet.context.flags = packetFlags | mask;
        }
    }
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.context.position[0] += params->posX;
            packet.context.position[1] += params->posY;
            packet.context.position[2] += params->posZ;
        }
    }
    return (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 8, (ModgfxEffectVertex*)(int)gDll69EffectResourceData, 4,
                      (s16*)(&resourceData[offsetof(Dll69EffectResourceView, triangleIndices)]),
                      variant == 2 ? 0xc11 : 0x5e0, 0);
}

void dll_69_release(void) {
}

void dll_69_initialise(void) {
}

Dll69ResourceDescriptor gDll69ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_69_initialise, dll_69_release, NULL, dll_69_spawnEffect,
};
