/*
 * DLL 146 / 0x92 - a scaled nine-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0092_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll92EffectResource {
    u8 opaque00[0x3C];
    u8 spawnData[0x18];
    u8 sharedTexture[0x0C];
    u8 primaryTexture[0x0C];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll92EffectResource;

STATIC_ASSERT(offsetof(Dll92EffectResource, opaque00) == 0x00);
STATIC_ASSERT(offsetof(Dll92EffectResource, spawnData) == 0x3C);
STATIC_ASSERT(offsetof(Dll92EffectResource, sharedTexture) == 0x54);
STATIC_ASSERT(offsetof(Dll92EffectResource, primaryTexture) == 0x60);
STATIC_ASSERT(offsetof(Dll92EffectResource, sequenceParams) == 0x6C);
STATIC_ASSERT(offsetof(Dll92EffectResource, opaqueTail) == 0x7A);
STATIC_ASSERT(sizeof(Dll92EffectResource) == 0x7C);

s16 gDll92VertexIndices[4] = {1, 0, 0, 0};

extern u16 gDll92EffectResourceData[sizeof(Dll92EffectResource) / sizeof(u16)];

void dll_92_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, u32 unused,
                        f32* scaleOverride) {
    Dll92EffectResource* resource[1];
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands;
    f32 scale;
    resource[0] = (Dll92EffectResource*)gDll92EffectResourceData;
    scale = 1.0f;
    if (scaleOverride != NULL) {
        scale = *scaleOverride;
    }
    commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 5;
    commands[0].vertexIndices = (s16*)(resource[0]->primaryTexture);
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 1;
    commands[1].vertexIndices = (s16*)(gDll92VertexIndices);
    commands[1].flags = 4;
    if (variant == 1) {
        commands[1].valueX = 155.0f;
    } else {
        commands[1].valueX = 55.0f;
    }
    commands[1].valueY = 0.0f;
    commands[1].valueZ = 0.0f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 6;
    commands[2].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[2].flags = 2;
    if (variant == 1) {
        commands[2].valueZ = commands[2].valueY = commands[2].valueX = 0.15f * scale;
    } else {
        commands[2].valueZ = commands[2].valueY = commands[2].valueX = 0.1f * scale;
    }
    commands[3].stageIndex = 1;
    commands[3].parameter = 6;
    commands[3].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[3].flags = 0x4000;
    commands[3].valueX = -0.5f;
    commands[3].valueY = 1.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 6;
    commands[4].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[4].flags = 2;
    commands[4].valueX = 4.0f;
    commands[4].valueY = 4.0f;
    commands[4].valueZ = 25.0f;
    commands[5].stageIndex = 2;
    commands[5].parameter = 6;
    commands[5].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[5].flags = 0x4000;
    commands[5].valueX = -0.5f;
    commands[5].valueY = 1.0f;
    commands[5].valueZ = 0.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 6;
    commands[6].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[6].flags = 2;
    commands[6].valueX = 8.0f;
    commands[6].valueY = 8.0f;
    commands[6].valueZ = 1.0f;
    commands[7].stageIndex = 3;
    commands[7].parameter = 6;
    commands[7].vertexIndices = (s16*)(resource[0]->sharedTexture);
    commands[7].flags = 0x4000;
    commands[7].valueX = -0.5f;
    commands[7].valueY = 1.0f;
    commands[7].valueZ = 0.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 1;
    commands[8].vertexIndices = (s16*)(gDll92VertexIndices);
    commands[8].flags = 4;
    commands[8].valueX = 0.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 2.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 6;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commands + sizeof(ModgfxCommand) * 9) - commands;
    packet.context.stageDurations[0] = resource[0]->sequenceParams[0];
    packet.context.stageDurations[1] = resource[0]->sequenceParams[1];
    packet.context.stageDurations[2] = resource[0]->sequenceParams[2];
    packet.context.stageDurations[3] = resource[0]->sequenceParams[3];
    packet.context.stageDurations[4] = resource[0]->sequenceParams[4];
    packet.context.stageDurations[5] = resource[0]->sequenceParams[5];
    packet.context.stageDurations[6] = resource[0]->sequenceParams[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000400;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
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
        ->spawnEffect(&packet.context, 0, 6, (ModgfxEffectVertex*)(resource[0]), 4, (s16*)(resource[0]->spawnData),
                      0x3C, 0);
}

void dll_92_release(void) {
}

void dll_92_initialise(void) {
}

u16 gDll92EffectResourceData[sizeof(Dll92EffectResource) / sizeof(u16)] = {
    0xff1a, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000, 0x0000, 0x0000, 0x007f,
    0x000f, 0x00e6, 0x0000, 0x0000, 0x00ff, 0x000f, 0xff1a, 0x0000, 0x03e8,
    0x0000, 0x0000, 0x0000, 0x0000, 0x03e8, 0x007f, 0x0000, 0x00e6, 0x0000,
    0x03e8, 0x00ff, 0x0000, 0x0000, 0x0004, 0x0003, 0x0000, 0x0001, 0x0004,
    0x0001, 0x0002, 0x0004, 0x0002, 0x0005, 0x0004, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0005, 0x0000, 0x0002, 0x0003, 0x0004, 0x0005, 0x0000,
    0x0000, 0x0006, 0x0014, 0x001a, 0x0000, 0x0000, 0x0000, 0x0000,
};

Dll92ResourceDescriptor gDll92ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_92_initialise,
    dll_92_release,
    NULL,
    dll_92_spawnEffect,
    0x00000000,
};
