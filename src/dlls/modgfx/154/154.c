/*
 * DLL 154 / 0x9A - a randomized multi-layer modgfx effect spawner.
 */
#include "main/dll/dll_009A_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll9AEffectResourceView {
    ModgfxEffectVertex vertices[3];
    s16 opaqueTail;
} Dll9AEffectResourceView;

STATIC_ASSERT(offsetof(Dll9AEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll9AEffectResourceView, opaqueTail) == 0x1E);
STATIC_ASSERT(sizeof(Dll9AEffectResourceView) == 0x20);

typedef struct Dll9ASequence {
    s16 sequenceParams[7];
} Dll9ASequence;

STATIC_ASSERT(sizeof(Dll9ASequence) == 0x0E);

typedef struct Dll9ASequenceTemplate {
    Dll9ASequence sequence;
    s16 opaqueTail;
} Dll9ASequenceTemplate;

STATIC_ASSERT(offsetof(Dll9ASequenceTemplate, sequence) == 0x00);
STATIC_ASSERT(offsetof(Dll9ASequenceTemplate, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll9ASequenceTemplate) == 0x10);

typedef struct Dll9AThreeIndexList {
    s16 indices[3];
    s16 opaqueTail;
} Dll9AThreeIndexList;

STATIC_ASSERT(offsetof(Dll9AThreeIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(Dll9AThreeIndexList, opaqueTail) == 0x06);
STATIC_ASSERT(sizeof(Dll9AThreeIndexList) == 0x08);

typedef struct Dll9ASingleIndexList {
    s16 index;
    s16 opaqueTail;
} Dll9ASingleIndexList;

STATIC_ASSERT(offsetof(Dll9ASingleIndexList, index) == 0x00);
STATIC_ASSERT(offsetof(Dll9ASingleIndexList, opaqueTail) == 0x02);
STATIC_ASSERT(sizeof(Dll9ASingleIndexList) == 0x04);

Dll9AThreeIndexList gDll9ATriangleIndices = {{0, 1, 2}, 0};
Dll9ASingleIndexList gDll9ASingleVertexIndex = {2, 0};
Dll9AThreeIndexList gDll9AAllVertexIndices = {{0, 1, 2}, 0};

extern u16 gDll9AEffectVertexData[sizeof(Dll9AEffectResourceView) / sizeof(u16)];

const Dll9ASequenceTemplate gDll9ASequenceTemplate = {
    {{0, 10, 40, 60, 40, 0, 0}},
    0,
};

void dll_9A_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    Dll9ASequence sequence;
    ModgfxSpawnPacket packet;
    ModgfxCommand* commandCursor;
    ModgfxCommand* commands;
    f32 rotationZ;
    f32 rotationY;

    sequence = gDll9ASequenceTemplate.sequence;
    sequence.sequenceParams[1] += randomGetRange(0, 0x14);
    sequence.sequenceParams[2] += randomGetRange(-0x14, 0x14);
    sequence.sequenceParams[3] += randomGetRange(-0x14, 0x14);
    sequence.sequenceParams[4] += randomGetRange(-0x14, 0x14);
    commands = packet.entries;
    commandCursor = commands;
    if (variant == 0) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 3;
        commandCursor->vertexIndices = (s16*)(gDll9AAllVertexIndices.indices);
        commandCursor->flags = 8;
        commandCursor->valueX = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->valueY = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->valueZ = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor++;
    } else if (variant == 1) {
        commandCursor->stageIndex = 0;
        commandCursor->parameter = 3;
        commandCursor->vertexIndices = (s16*)(gDll9AAllVertexIndices.indices);
        commandCursor->flags = 8;
        commandCursor->valueX = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor->valueY = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->valueZ = (f32)(s32)(randomGetRange(0, 0x41) + 0x78);
        commandCursor++;
    }
    rotationZ = (f32)(s32)randomGetRange(-0x36b0, 0x36b0);
    rotationY = (f32)(s32)randomGetRange(-0x2ee0, 0x2ee0);
    commandCursor[0].stageIndex = 0;
    commandCursor[0].parameter = 0;
    commandCursor[0].vertexIndices = NULL;
    commandCursor[0].flags = 0x80;
    commandCursor[0].valueX = 0.0f;
    commandCursor[0].valueY = rotationY;
    commandCursor[0].valueZ = rotationZ;
    commandCursor[1].stageIndex = 0;
    commandCursor[1].parameter = 3;
    commandCursor[1].vertexIndices = (s16*)(gDll9AAllVertexIndices.indices);
    commandCursor[1].flags = 4;
    commandCursor[1].valueX = 0.0f;
    commandCursor[1].valueY = 0.0f;
    commandCursor[1].valueZ = 0.0f;
    commandCursor[2].stageIndex = 0;
    commandCursor[2].parameter = 3;
    commandCursor[2].vertexIndices = (s16*)(gDll9AAllVertexIndices.indices);
    commandCursor[2].flags = 2;
    commandCursor[2].valueX = 1.0f;
    commandCursor[2].valueY = 0.01f * (f32)(s32)randomGetRange(0, 0x32) + 0.2f;
    commandCursor[2].valueZ = 0.01f * (f32)(s32)randomGetRange(4, 6) + 0.8f;
    commandCursor[3].stageIndex = 1;
    commandCursor[3].parameter = 1;
    commandCursor[3].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[3].flags = 4;
    commandCursor[3].valueX = 255.0f;
    commandCursor[3].valueY = 0.0f;
    commandCursor[3].valueZ = 0.0f;
    commandCursor[4].stageIndex = 1;
    commandCursor[4].parameter = 0;
    commandCursor[4].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[4].flags = 0x4000;
    commandCursor[4].valueX = 1.8f;
    commandCursor[4].valueY = 0.0f;
    commandCursor[4].valueZ = 0.0f;
    commandCursor[5].stageIndex = 1;
    commandCursor[5].parameter = 3;
    commandCursor[5].vertexIndices = (s16*)(gDll9AAllVertexIndices.indices);
    commandCursor[5].flags = 2;
    commandCursor[5].valueX = 3.0f;
    commandCursor[5].valueY = 4.0f;
    commandCursor[5].valueZ = 4.0f;
    commandCursor[6].stageIndex = 1;
    commandCursor[6].parameter = 0;
    commandCursor[6].vertexIndices = NULL;
    commandCursor[6].flags = 0x80;
    commandCursor[6].valueX = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[6].valueY = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[6].valueZ = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[7].stageIndex = 2;
    commandCursor[7].parameter = 0;
    commandCursor[7].vertexIndices = NULL;
    commandCursor[7].flags = 0x80;
    commandCursor[7].valueX = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[7].valueY = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[7].valueZ = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[8].stageIndex = 2;
    commandCursor[8].parameter = 0;
    commandCursor[8].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[8].flags = 0x4000;
    commandCursor[8].valueX = 1.8f;
    commandCursor[8].valueY = 0.0f;
    commandCursor[8].valueZ = 0.0f;
    commandCursor[9].stageIndex = 3;
    commandCursor[9].parameter = 0;
    commandCursor[9].vertexIndices = NULL;
    commandCursor[9].flags = 0x80;
    commandCursor[9].valueX = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[9].valueY = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[9].valueZ = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[10].stageIndex = 3;
    commandCursor[10].parameter = 0;
    commandCursor[10].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[10].flags = 0x4000;
    commandCursor[10].valueX = 1.8f;
    commandCursor[10].valueY = 0.0f;
    commandCursor[10].valueZ = 0.0f;
    commandCursor[11].stageIndex = 4;
    commandCursor[11].parameter = 0;
    commandCursor[11].vertexIndices = NULL;
    commandCursor[11].flags = 0x80;
    commandCursor[11].valueX = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[11].valueY = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[11].valueZ = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[12].stageIndex = 4;
    commandCursor[12].parameter = 0;
    commandCursor[12].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[12].flags = 0x4000;
    commandCursor[12].valueX = 1.8f;
    commandCursor[12].valueY = 0.0f;
    commandCursor[12].valueZ = 0.0f;
    commandCursor[13].stageIndex = 4;
    commandCursor[13].parameter = 1;
    commandCursor[13].vertexIndices = (s16*)&gDll9ASingleVertexIndex.index;
    commandCursor[13].flags = 4;
    commandCursor[13].valueX = 0.0f;
    commandCursor[13].valueY = 0.0f;
    commandCursor[13].valueZ = 0.0f;

    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    if (variant == 0) {
        packet.context.position[1] = 0.0f;
    } else if (variant == 1) {
        packet.context.position[1] = 200.0f;
    }
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
    packet.context.commandCount = (s8)(((u8*)(commandCursor + 14) - (u8*)commands) / (int)sizeof(ModgfxCommand));
    packet.context.stageDurations[0] = sequence.sequenceParams[0];
    packet.context.stageDurations[1] = sequence.sequenceParams[1];
    packet.context.stageDurations[2] = sequence.sequenceParams[2];
    packet.context.stageDurations[3] = sequence.sequenceParams[3];
    packet.context.stageDurations[4] = sequence.sequenceParams[4];
    packet.context.stageDurations[5] = sequence.sequenceParams[5];
    packet.context.stageDurations[6] = sequence.sequenceParams[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000400;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((void*)packet.context.sourceObject != NULL && (void*)spawnParams != NULL) {
            packet.context.position[0] += (packet.context.sourceObject->anim.worldPosX + spawnParams->posX);
            packet.context.position[1] += (packet.context.sourceObject->anim.worldPosY + spawnParams->posY);
            packet.context.position[2] += (packet.context.sourceObject->anim.worldPosZ + spawnParams->posZ);
        } else if ((void*)packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else if ((void*)spawnParams != NULL) {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 3, (ModgfxEffectVertex*)gDll9AEffectVertexData, 1,
                      (s16*)(gDll9ATriangleIndices.indices), 0x31, 0);
}

void dll_9A_release(void) {
}

void dll_9A_initialise(void) {
}

u16 gDll9AEffectVertexData[sizeof(Dll9AEffectResourceView) / sizeof(u16)] = {
    0x0000, 0x00e6, 0x0708, 0x0000, 0x001f, 0x0000, 0xff1a, 0x0708, 0x001f,
    0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0010, 0x0000,
};

Dll9AResourceDescriptor gDll9AResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_9A_initialise, dll_9A_release, NULL, dll_9A_spawnEffect,
};
