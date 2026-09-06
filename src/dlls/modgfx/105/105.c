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
    GfxCmd* command;
    GfxCmd* entries;
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
    entries[0].layer = 0;
    entries[0].flags = 8;
    entries[0].tex = &resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[0].mode = 4;
    entries[0].x = 0.0f;
    entries[0].y = 0.0f;
    entries[0].z = 0.0f;
    entries[1].layer = 0;
    entries[1].flags = 8;
    entries[1].tex = &resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[1].mode = 2;
    if (sourceObj != NULL) {
        entries[1].x = 7.0f * sourceObj->anim.rootMotionScale;
        entries[1].y = 6.0f * sourceObj->anim.rootMotionScale;
        entries[1].z = 7.0f * sourceObj->anim.rootMotionScale;
    } else {
        entries[1].x = 7.0f;
        entries[1].y = 6.0f;
        entries[1].z = 7.0f;
    }
    entries[2].layer = 0;
    entries[2].flags = 0;
    entries[2].tex = NULL;
    entries[2].mode = 0x80;
    entries[2].x = 0.0f;
    entries[2].y = 0.0f;
    if (sourceObj != NULL) {
        entries[2].z = (f32) * (s16*)sourceObj;
    } else {
        entries[2].z = 0.0f;
    }
    entries[3].layer = 1;
    entries[3].flags = 8;
    entries[3].tex = &resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    entries[3].mode = 4;
    entries[3].x = 255.0f;
    entries[3].y = 0.0f;
    entries[3].z = 0.0f;
    entries[4].layer = 1;
    entries[4].flags = param3;
    entries[4].tex = NULL;
    entries[4].mode = 0x20000000;
    entries[4].x = param0;
    entries[4].y = param1;
    entries[4].z = param2;
    command = &entries[5];
    if (variant == 0) {
        command->layer = 2;
        command->flags = 0x3b;
        command->tex = NULL;
        command->mode = 0x1800000;
        command->x = 1.0f;
        command->y = 0.0f;
        command->z = 10.0f;
        command++;
    }
    command[0].layer = 2;
    command[0].flags = 0;
    command[0].tex = NULL;
    command[0].mode = 0x100;
    command[0].x = 0.0f;
    command[0].y = 0.0f;
    command[0].z = 50.0f;
    command[1].layer = 3;
    command[1].flags = 1;
    command[1].tex = NULL;
    command[1].mode = 0x2000;
    command[1].x = 0.0f;
    command[1].y = 0.0f;
    command[1].z = 0.0f;
    command[2].layer = 4;
    command[2].flags = 8;
    command[2].tex = &resourceData[offsetof(Dll69EffectResourceView, allVertexIndices)];
    command[2].mode = 4;
    command[2].x = 0.0f;
    command[2].y = 0.0f;
    command[2].z = 0.0f;
    command[3].layer = 4;
    command[3].flags = 0;
    command[3].tex = NULL;
    command[3].mode = 0x20000000;
    command[3].x = param0;
    command[3].y = param1;
    command[3].z = param2;
    packet.modeByte = variant;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    if (spawnParams != NULL) {
        packet.position[1] = ((PartFxSpawnParams*)spawnParams)->posY;
    } else {
        packet.position[1] = 0.0f;
    }
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 8;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = (command + 4) - entries;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll69EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    {
        u32 packetFlags = 0x4000000;

        packet.flags = packetFlags;
        packetFlags |= spawnFlags | 0x80;
        packet.flags = packetFlags;
        if (variant == 2) {
            u32 mask = 0x40000;

            packet.flags = packetFlags ^ mask;
        } else {
            u32 mask = 0x40000;

            packet.flags = packetFlags | mask;
        }
    }
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.position[0] += params->posX;
            packet.position[1] += params->posY;
            packet.position[2] += params->posZ;
        }
    }
    return (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 8, (u8*)(int)gDll69EffectResourceData, 4,
                      &resourceData[offsetof(Dll69EffectResourceView, triangleIndices)], variant == 2 ? 0xc11 : 0x5e0, 0);
}

void dll_69_release(void) {
}

void dll_69_initialise(void) {
}

Dll69ResourceDescriptor gDll69ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_69_initialise, dll_69_release, NULL, dll_69_spawnEffect,
};
