/*
 * DLL 134 / 0x86 - a randomised five-command modgfx effect spawner.
 */
#include "main/dll/dll_0086_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll86SequenceResource {
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll86SequenceResource;

STATIC_ASSERT(offsetof(Dll86SequenceResource, sequenceParams) == 0x00);
STATIC_ASSERT(offsetof(Dll86SequenceResource, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll86SequenceResource) == 0x10);

Dll86SequenceResource gDll86SequenceResource = {{0, 255, 0, 0, 0, 0, 0}, 0};

void dll_86_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands;
    s16* sequenceParams;
    f32 effectWidth = 81.0f;
    f32 effectHeight = 82.0f;
    int commandFlags = 0x64;
    f32 randomX;
    f32 copiedY;

    if (variant == 0) {
        effectWidth = 18.0f;
        effectHeight = 8.0f;
        commandFlags = 0x410;
    } else if (variant == 1) {
        effectWidth = 19.0f;
        effectHeight = 9.0f;
        commandFlags = 0x410;
    } else if (variant == 2) {
        effectWidth = 20.0f;
        effectHeight = 15.0f;
        commandFlags = 0x410;
    } else if (variant == 3) {
        effectWidth = 20.0f;
        effectHeight = 15.0f;
        commandFlags = 0x410;
    }
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = commandFlags;
    commands[0].vertexIndices = NULL;
    commands[0].flags = 0x20000000;
    commands[0].valueX = 999.0f;
    commands[0].valueY = effectWidth;
    commands[0].valueZ = effectHeight;
    commands[1].stageIndex = 1;
    commands[1].parameter = 0;
    commands[1].vertexIndices = NULL;
    commands[1].flags = 0x400000;
    commands[1].valueX = randomGetRange(-0x64, 0x64);
    commands[1].valueY = 0.0f;
    commands[1].valueZ = randomGetRange(-0x4b0, -0x320);
    randomX = commands[1].valueX;
    copiedY = commands[1].valueY;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x40000000;
    commands[2].valueX = randomX;
    commands[2].valueY = 0.0f;
    commands[2].valueZ = copiedY;
    commands[3].stageIndex = 1;
    commands[3].parameter = 0x65;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x800000;
    commands[3].valueX = 1.0f;
    commands[3].valueY = 1.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 2;
    commands[4].parameter = 0;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x20000000;
    commands[4].valueX = 999.0f;
    commands[4].valueY = effectWidth;
    commands[4].valueZ = effectHeight;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    randomX = randomGetRange(-0x64, 0x64);
    packet.context.position[0] = randomX;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 0;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 5) - commands;
    sequenceParams = gDll86SequenceResource.sequenceParams;
    packet.context.stageDurations[0] = sequenceParams[0];
    packet.context.stageDurations[1] = sequenceParams[1];
    packet.context.stageDurations[2] = sequenceParams[2];
    packet.context.stageDurations[3] = sequenceParams[3];
    packet.context.stageDurations[4] = sequenceParams[4];
    packet.context.stageDurations[5] = sequenceParams[5];
    packet.context.stageDurations[6] = sequenceParams[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x10400;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            GameObject* anchorObj = packet.context.sourceObject;
            packet.context.position[0] = randomX + anchorObj->anim.worldPosX;
            packet.context.position[1] += anchorObj->anim.worldPosY;
            packet.context.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.context.position[0] = randomX + anchorParams->posX;
            packet.context.position[1] += anchorParams->posY;
            packet.context.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet.context, 0, 0, 0, 0, 0, 0, 0);
}

void dll_86_release(void) {
}

void dll_86_initialise(void) {
}

Dll86ResourceDescriptor gDll86ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_86_initialise, dll_86_release, NULL, dll_86_spawnEffect,
};
