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
    GfxCmd* commandCursor;
    GfxCmd* commands;
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
        commandCursor->layer = 0;
        commandCursor->flags = 3;
        commandCursor->tex = gDll9AAllVertexIndices.indices;
        commandCursor->mode = 8;
        commandCursor->x = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->z = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor++;
    } else if (variant == 1) {
        commandCursor->layer = 0;
        commandCursor->flags = 3;
        commandCursor->tex = gDll9AAllVertexIndices.indices;
        commandCursor->mode = 8;
        commandCursor->x = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        commandCursor->z = (f32)(s32)(randomGetRange(0, 0x41) + 0x78);
        commandCursor++;
    }
    rotationZ = (f32)(s32)randomGetRange(-0x36b0, 0x36b0);
    rotationY = (f32)(s32)randomGetRange(-0x2ee0, 0x2ee0);
    commandCursor[0].layer = 0;
    commandCursor[0].flags = 0;
    commandCursor[0].tex = NULL;
    commandCursor[0].mode = 0x80;
    commandCursor[0].x = 0.0f;
    commandCursor[0].y = rotationY;
    commandCursor[0].z = rotationZ;
    commandCursor[1].layer = 0;
    commandCursor[1].flags = 3;
    commandCursor[1].tex = gDll9AAllVertexIndices.indices;
    commandCursor[1].mode = 4;
    commandCursor[1].x = 0.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    commandCursor[2].layer = 0;
    commandCursor[2].flags = 3;
    commandCursor[2].tex = gDll9AAllVertexIndices.indices;
    commandCursor[2].mode = 2;
    commandCursor[2].x = 1.0f;
    commandCursor[2].y = 0.01f * (f32)(s32)randomGetRange(0, 0x32) + 0.2f;
    commandCursor[2].z = 0.01f * (f32)(s32)randomGetRange(4, 6) + 0.8f;
    commandCursor[3].layer = 1;
    commandCursor[3].flags = 1;
    commandCursor[3].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[3].mode = 4;
    commandCursor[3].x = 255.0f;
    commandCursor[3].y = 0.0f;
    commandCursor[3].z = 0.0f;
    commandCursor[4].layer = 1;
    commandCursor[4].flags = 0;
    commandCursor[4].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[4].mode = 0x4000;
    commandCursor[4].x = 1.8f;
    commandCursor[4].y = 0.0f;
    commandCursor[4].z = 0.0f;
    commandCursor[5].layer = 1;
    commandCursor[5].flags = 3;
    commandCursor[5].tex = gDll9AAllVertexIndices.indices;
    commandCursor[5].mode = 2;
    commandCursor[5].x = 3.0f;
    commandCursor[5].y = 4.0f;
    commandCursor[5].z = 4.0f;
    commandCursor[6].layer = 1;
    commandCursor[6].flags = 0;
    commandCursor[6].tex = NULL;
    commandCursor[6].mode = 0x80;
    commandCursor[6].x = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[6].y = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[6].z = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[7].layer = 2;
    commandCursor[7].flags = 0;
    commandCursor[7].tex = NULL;
    commandCursor[7].mode = 0x80;
    commandCursor[7].x = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[7].y = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[7].z = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[8].layer = 2;
    commandCursor[8].flags = 0;
    commandCursor[8].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[8].mode = 0x4000;
    commandCursor[8].x = 1.8f;
    commandCursor[8].y = 0.0f;
    commandCursor[8].z = 0.0f;
    commandCursor[9].layer = 3;
    commandCursor[9].flags = 0;
    commandCursor[9].tex = NULL;
    commandCursor[9].mode = 0x80;
    commandCursor[9].x = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[9].y = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[9].z = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[10].layer = 3;
    commandCursor[10].flags = 0;
    commandCursor[10].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[10].mode = 0x4000;
    commandCursor[10].x = 1.8f;
    commandCursor[10].y = 0.0f;
    commandCursor[10].z = 0.0f;
    commandCursor[11].layer = 4;
    commandCursor[11].flags = 0;
    commandCursor[11].tex = NULL;
    commandCursor[11].mode = 0x80;
    commandCursor[11].x = (f32)(s32)randomGetRange(-32000, 32000);
    commandCursor[11].y = rotationY * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[11].z = rotationZ * (f32)(s32)randomGetRange(-1, 1);
    commandCursor[12].layer = 4;
    commandCursor[12].flags = 0;
    commandCursor[12].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[12].mode = 0x4000;
    commandCursor[12].x = 1.8f;
    commandCursor[12].y = 0.0f;
    commandCursor[12].z = 0.0f;
    commandCursor[13].layer = 4;
    commandCursor[13].flags = 1;
    commandCursor[13].tex = &gDll9ASingleVertexIndex.index;
    commandCursor[13].mode = 4;
    commandCursor[13].x = 0.0f;
    commandCursor[13].y = 0.0f;
    commandCursor[13].z = 0.0f;

    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    if (variant == 0) {
        packet.position[1] = 0.0f;
    } else if (variant == 1) {
        packet.position[1] = 200.0f;
    }
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 4.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 3;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = (s8)(((u8*)(commandCursor + 14) - (u8*)commands) / (int)sizeof(GfxCmd));
    packet.sequenceParams[0] = sequence.sequenceParams[0];
    packet.sequenceParams[1] = sequence.sequenceParams[1];
    packet.sequenceParams[2] = sequence.sequenceParams[2];
    packet.sequenceParams[3] = sequence.sequenceParams[3];
    packet.sequenceParams[4] = sequence.sequenceParams[4];
    packet.sequenceParams[5] = sequence.sequenceParams[5];
    packet.sequenceParams[6] = sequence.sequenceParams[6];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4000400;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((void*)packet.sourceObj != NULL && (void*)spawnParams != NULL) {
            packet.position[0] = packet.position[0] + (packet.sourceObj->anim.worldPosX + spawnParams->posX);
            packet.position[1] = packet.position[1] + (packet.sourceObj->anim.worldPosY + spawnParams->posY);
            packet.position[2] = packet.position[2] + (packet.sourceObj->anim.worldPosZ + spawnParams->posZ);
        } else if ((void*)packet.sourceObj != NULL) {
            packet.position[0] = packet.position[0] + packet.sourceObj->anim.worldPosX;
            packet.position[1] = packet.position[1] + packet.sourceObj->anim.worldPosY;
            packet.position[2] = packet.position[2] + packet.sourceObj->anim.worldPosZ;
        } else if ((void*)spawnParams != NULL) {
            packet.position[0] = packet.position[0] + spawnParams->posX;
            packet.position[1] = packet.position[1] + spawnParams->posY;
            packet.position[2] = packet.position[2] + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 3, (u8*)gDll9AEffectVertexData, 1, gDll9ATriangleIndices.indices, 0x31, 0);
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
