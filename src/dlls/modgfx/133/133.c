/*
 * DLL 133 / 0x85 - a randomised multi-layer modgfx effect spawner.
 */
#include "main/dll/dll_0085_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef enum Dll85Variant {
    DLL85_VARIANT_BURST = 4,
} Dll85Variant;

typedef struct Dll85EffectResourceView {
    ModgfxEffectVertex vertices[4];
    s16 triangles[2][3];
    s16 sequenceParams[7];
    s16 opaqueTail;
    s16 textureAssetIds[5][2];
} Dll85EffectResourceView;

STATIC_ASSERT(offsetof(Dll85EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll85EffectResourceView, triangles) == 0x28);
STATIC_ASSERT(offsetof(Dll85EffectResourceView, sequenceParams) == 0x34);
STATIC_ASSERT(offsetof(Dll85EffectResourceView, opaqueTail) == 0x42);
STATIC_ASSERT(offsetof(Dll85EffectResourceView, textureAssetIds) == 0x44);
STATIC_ASSERT(sizeof(Dll85EffectResourceView) == 0x58);

s16 gDll85IndexPair01[2] = {0, 1};
s16 gDll85IndexSequence0123[4] = {0, 1, 2, 3};
s16 gDll85IndexPair23[2] = {2, 3};

extern u8 gDll85EffectResourceData[sizeof(Dll85EffectResourceView)];

void dll_85_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll85EffectResourceData;
    s16* resourceHalfwords = (s16*)resourceData;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands = packet.entries;
    f32 randomValue;

    if (variant == DLL85_VARIANT_BURST) {
        commands[0].stageIndex = 0;
        commands[0].parameter = 0;
        commands[0].vertexIndices = NULL;
        commands[0].flags = 0x400000;
        commands[0].valueX = 10.0f;
        commands[0].valueY = 0.0f;
        commands[0].valueZ = 0.0f;
        commands[1].stageIndex = 0;
        commands[1].parameter = 2;
        commands[1].vertexIndices = (s16*)(gDll85IndexPair23);
        commands[1].flags = 2;
        commands[1].valueX = 9.0f;
        commands[1].valueY = 2.0f;
        commands[1].valueZ = 9.0f;
        commands[2].stageIndex = 0;
        commands[2].parameter = 4;
        commands[2].vertexIndices = (s16*)(gDll85IndexPair23);
        commands[2].flags = 0x80;
        commands[2].valueX = randomGetRange(-0x7ff8, 0x7ff8);
        commands[2].valueY = 0.0f;
        commands[2].valueZ = 16383.0f;
        commandCursor = &commands[3];
    } else {
        GameObject* scaledSource = sourceObj;
        commands[0].stageIndex = 0;
        commands[0].parameter = 2;
        commands[0].vertexIndices = (s16*)(gDll85IndexPair01);
        commands[0].flags = 2;
        commands[0].valueX = 190.0f * scaledSource->anim.rootMotionScale;
        commands[0].valueY = 6.0f * scaledSource->anim.rootMotionScale;
        commands[0].valueZ = 1.0f;
        commands[1].stageIndex = 0;
        commands[1].parameter = 2;
        commands[1].vertexIndices = (s16*)(gDll85IndexPair23);
        commands[1].flags = 2;
        commands[1].valueX =
            40.0f * (scaledSource->anim.rootMotionScale / scaledSource->anim.modelInstance->rootMotionScaleBase);
        commands[1].valueY =
            6.0f * (scaledSource->anim.rootMotionScale / scaledSource->anim.modelInstance->rootMotionScaleBase);
        commands[1].valueZ = 1.0f;
        randomValue = randomGetRange(0, 0xfffe);
        commands[2].stageIndex = 0;
        commands[2].parameter = 0;
        commands[2].vertexIndices = NULL;
        commands[2].flags = 0x80;
        commands[2].valueX = randomValue;
        commands[2].valueY = 1000.0f;
        commands[2].valueZ = 0.0f;
        commandCursor = &commands[3];
    }
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 4;
    commandCursor[0].vertexIndices = (s16*)(gDll85IndexSequence0123);
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    randomValue = randomGetRange(0, 0xfffe);
    commandCursor[1].stageIndex = 1;
    commandCursor[1].parameter = 2;
    commandCursor[1].vertexIndices = (s16*)(gDll85IndexPair01);
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 255.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor[2].stageIndex = 2;
        commandCursor[2].parameter = 0;
        commandCursor[2].vertexIndices = NULL;
        commandCursor[2].flags = 0x100;
        commandCursor[2].valueX = 100.0f;
        commandCursor[2].valueY = 0.0f;
        commandCursor[2].valueZ = 0.0f;
        commandCursor += 3;
    } else {
        commandCursor[2].stageIndex = 1;
        commandCursor[2].parameter = 0;
        commandCursor[2].vertexIndices = NULL;
        commandCursor[2].flags = 0x80;
        commandCursor[2].valueX = randomValue;
        commandCursor[2].valueY = 1000.0f;
        commandCursor[2].valueZ = 0.0f;
        commandCursor += 3;
    }
    randomValue = randomGetRange(0, 0xfffe);
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x100;
        commandCursor->valueX = 100.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 2;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x80;
        commandCursor->valueX = randomValue;
        commandCursor->valueY = 1000.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    }
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor->stageIndex = 3;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x100;
        commandCursor->valueX = 100.0f;
        commandCursor->valueY = 0.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    } else {
        commandCursor->stageIndex = 3;
        commandCursor->parameter = 0;
        commandCursor->vertexIndices = NULL;
        commandCursor->flags = 0x80;
        commandCursor->valueX = randomValue;
        commandCursor->valueY = 1000.0f;
        commandCursor->valueZ = 0.0f;
        commandCursor++;
    }
    commandCursor[0].stageIndex = 3;
    commandCursor[0].parameter = 2;
    commandCursor[0].vertexIndices = (s16*)(gDll85IndexPair01);
    commandCursor[0].flags = 4;
    commandCursor[0].valueX = 100.0f;
    commandCursor[0].valueY = 0.0f;
    commandCursor[0].valueZ = 0.0f;
    commandCursor[1].stageIndex = 3;
    commandCursor[1].parameter = 4;
    commandCursor[1].vertexIndices = (s16*)(gDll85IndexSequence0123);
    commandCursor[1].flags = 2;
    commandCursor[1].valueX = 2.0f;
    commandCursor[1].valueY = 0.1f;
    commandCursor[1].valueZ = 1.0f;
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
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 4;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x20;
    packet.context.commandCount = (ModgfxCommand*)((u8*)commandCursor + sizeof(ModgfxCommand) * 2) - commands;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    if (variant == DLL85_VARIANT_BURST) {
        packet.context.flags = 0x4004400;
    } else {
        packet.context.flags = 0x4006410;
    }
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL && spawnParams != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX + spawnParams->posX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY + spawnParams->posY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ + spawnParams->posZ;
        } else if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else if (spawnParams != NULL) {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 4, (ModgfxEffectVertex*)(int)gDll85EffectResourceData, 2,
                      (s16*)(&resourceData[offsetof(Dll85EffectResourceView, triangles)]),
                      resourceHalfwords[variant * 2 + randomGetRange(0, 1) +
                                        offsetof(Dll85EffectResourceView, textureAssetIds) / sizeof(s16)],
                      0);
}

void dll_85_release(void) {
}

void dll_85_initialise(void) {
}

u8 gDll85EffectResourceData[sizeof(Dll85EffectResourceView)] = {
    0, 30, 0, 0,   0, 0, 0, 0, 0, 0,  255, 226, 0, 0,   0, 0,   0, 15,  0, 0, 255, 226, 3, 232, 0, 0,   0, 15, 0, 15,
    0, 30, 3, 232, 0, 0, 0, 0, 0, 15, 0,   0,   0, 1,   0, 2,   0, 0,   0, 2, 0,   3,   0, 0,   0, 10,  0, 15, 0, 80,
    0, 0,  0, 0,   0, 0, 0, 0, 5, 39, 5,   40,  0, 223, 0, 222, 0, 223, 2, 0, 1,   251, 1, 251, 0, 223, 0, 222};

Dll85ResourceDescriptor gDll85ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_85_initialise, dll_85_release, NULL, dll_85_spawnEffect,
};
