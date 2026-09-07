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
    GfxCmd* commandCursor;
    GfxCmd* commands = packet.entries;
    f32 randomValue;

    if (variant == DLL85_VARIANT_BURST) {
        commands[0].layer = 0;
        commands[0].flags = 0;
        commands[0].tex = NULL;
        commands[0].mode = 0x400000;
        commands[0].x = 10.0f;
        commands[0].y = 0.0f;
        commands[0].z = 0.0f;
        commands[1].layer = 0;
        commands[1].flags = 2;
        commands[1].tex = gDll85IndexPair23;
        commands[1].mode = 2;
        commands[1].x = 9.0f;
        commands[1].y = 2.0f;
        commands[1].z = 9.0f;
        commands[2].layer = 0;
        commands[2].flags = 4;
        commands[2].tex = gDll85IndexPair23;
        commands[2].mode = 0x80;
        commands[2].x = randomGetRange(-0x7ff8, 0x7ff8);
        commands[2].y = 0.0f;
        commands[2].z = 16383.0f;
        commandCursor = &commands[3];
    } else {
        GameObject* scaledSource = sourceObj;
        commands[0].layer = 0;
        commands[0].flags = 2;
        commands[0].tex = gDll85IndexPair01;
        commands[0].mode = 2;
        commands[0].x = 190.0f * scaledSource->anim.rootMotionScale;
        commands[0].y = 6.0f * scaledSource->anim.rootMotionScale;
        commands[0].z = 1.0f;
        commands[1].layer = 0;
        commands[1].flags = 2;
        commands[1].tex = gDll85IndexPair23;
        commands[1].mode = 2;
        commands[1].x =
            40.0f * (scaledSource->anim.rootMotionScale / scaledSource->anim.modelInstance->rootMotionScaleBase);
        commands[1].y =
            6.0f * (scaledSource->anim.rootMotionScale / scaledSource->anim.modelInstance->rootMotionScaleBase);
        commands[1].z = 1.0f;
        randomValue = randomGetRange(0, 0xfffe);
        commands[2].layer = 0;
        commands[2].flags = 0;
        commands[2].tex = NULL;
        commands[2].mode = 0x80;
        commands[2].x = randomValue;
        commands[2].y = 1000.0f;
        commands[2].z = 0.0f;
        commandCursor = &commands[3];
    }
    commandCursor[0].layer = 0;
    commandCursor[0].flags = 4;
    commandCursor[0].tex = gDll85IndexSequence0123;
    commandCursor[0].mode = 4;
    commandCursor[0].x = 0.0f;
    commandCursor[0].y = 0.0f;
    commandCursor[0].z = 0.0f;
    randomValue = randomGetRange(0, 0xfffe);
    commandCursor[1].layer = 1;
    commandCursor[1].flags = 2;
    commandCursor[1].tex = gDll85IndexPair01;
    commandCursor[1].mode = 4;
    commandCursor[1].x = 255.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor[2].layer = 2;
        commandCursor[2].flags = 0;
        commandCursor[2].tex = NULL;
        commandCursor[2].mode = 0x100;
        commandCursor[2].x = 100.0f;
        commandCursor[2].y = 0.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    } else {
        commandCursor[2].layer = 1;
        commandCursor[2].flags = 0;
        commandCursor[2].tex = NULL;
        commandCursor[2].mode = 0x80;
        commandCursor[2].x = randomValue;
        commandCursor[2].y = 1000.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    }
    randomValue = randomGetRange(0, 0xfffe);
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor->layer = 2;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x100;
        commandCursor->x = 100.0f;
        commandCursor->y = 0.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    } else {
        commandCursor->layer = 2;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x80;
        commandCursor->x = randomValue;
        commandCursor->y = 1000.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    }
    if (variant == DLL85_VARIANT_BURST) {
        commandCursor->layer = 3;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x100;
        commandCursor->x = 100.0f;
        commandCursor->y = 0.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    } else {
        commandCursor->layer = 3;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x80;
        commandCursor->x = randomValue;
        commandCursor->y = 1000.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    }
    commandCursor[0].layer = 3;
    commandCursor[0].flags = 2;
    commandCursor[0].tex = gDll85IndexPair01;
    commandCursor[0].mode = 4;
    commandCursor[0].x = 100.0f;
    commandCursor[0].y = 0.0f;
    commandCursor[0].z = 0.0f;
    commandCursor[1].layer = 3;
    commandCursor[1].flags = 4;
    commandCursor[1].tex = gDll85IndexSequence0123;
    commandCursor[1].mode = 2;
    commandCursor[1].x = 2.0f;
    commandCursor[1].y = 0.1f;
    commandCursor[1].z = 1.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 2;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 4;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x20;
    packet.commandCount = (GfxCmd*)((u8*)commandCursor + sizeof(GfxCmd) * 2) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll85EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    if (variant == DLL85_VARIANT_BURST) {
        packet.flags = 0x4004400;
    } else {
        packet.flags = 0x4006410;
    }
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (packet.sourceObj != NULL && spawnParams != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX + spawnParams->posX;
            packet.position[1] += packet.sourceObj->anim.worldPosY + spawnParams->posY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ + spawnParams->posZ;
        } else if (packet.sourceObj != NULL) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else if (spawnParams != NULL) {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 4, (u8*)(int)gDll85EffectResourceData, 2,
                      &resourceData[offsetof(Dll85EffectResourceView, triangles)],
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
