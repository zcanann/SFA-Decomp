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
    GfxCmd* commands;
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
    commands[0].layer = 0;
    commands[0].flags = commandFlags;
    commands[0].tex = NULL;
    commands[0].mode = 0x20000000;
    commands[0].x = 999.0f;
    commands[0].y = effectWidth;
    commands[0].z = effectHeight;
    commands[1].layer = 1;
    commands[1].flags = 0;
    commands[1].tex = NULL;
    commands[1].mode = 0x400000;
    commands[1].x = randomGetRange(-0x64, 0x64);
    commands[1].y = 0.0f;
    commands[1].z = randomGetRange(-0x4b0, -0x320);
    randomX = commands[1].x;
    copiedY = commands[1].y;
    commands[2].layer = 1;
    commands[2].flags = 0;
    commands[2].tex = NULL;
    commands[2].mode = 0x40000000;
    commands[2].x = randomX;
    commands[2].y = 0.0f;
    commands[2].z = copiedY;
    commands[3].layer = 1;
    commands[3].flags = 0x65;
    commands[3].tex = NULL;
    commands[3].mode = 0x800000;
    commands[3].x = 1.0f;
    commands[3].y = 1.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 2;
    commands[4].flags = 0;
    commands[4].tex = NULL;
    commands[4].mode = 0x20000000;
    commands[4].x = 999.0f;
    commands[4].y = effectWidth;
    commands[4].z = effectHeight;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    randomX = randomGetRange(-0x64, 0x64);
    packet.position[0] = randomX;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 0;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 5) - commands;
    sequenceParams = gDll86SequenceResource.sequenceParams;
    packet.sequenceParams[0] = sequenceParams[0];
    packet.sequenceParams[1] = sequenceParams[1];
    packet.sequenceParams[2] = sequenceParams[2];
    packet.sequenceParams[3] = sequenceParams[3];
    packet.sequenceParams[4] = sequenceParams[4];
    packet.sequenceParams[5] = sequenceParams[5];
    packet.sequenceParams[6] = sequenceParams[6];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x10400;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL) {
            GameObject* anchorObj = packet.sourceObj;
            packet.position[0] = randomX + anchorObj->anim.worldPosX;
            packet.position[1] += anchorObj->anim.worldPosY;
            packet.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.position[0] = randomX + anchorParams->posX;
            packet.position[1] += anchorParams->posY;
            packet.position[2] += anchorParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet, 0, 0, 0, 0, 0, 0, 0);
}

void dll_86_release(void) {
}

void dll_86_initialise(void) {
}

Dll86ResourceDescriptor gDll86ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_86_initialise, dll_86_release, NULL, dll_86_spawnEffect,
};
