/*
 * DLL 166 / 0xA6 - a randomised layered effect spawner.
 */
#include "main/dll/dll_00A6_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct DllA6ThreeIndexList {
    u8 indices[6];
    u8 opaqueTail[2];
} DllA6ThreeIndexList;

STATIC_ASSERT(offsetof(DllA6ThreeIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllA6ThreeIndexList, opaqueTail) == 0x06);
STATIC_ASSERT(sizeof(DllA6ThreeIndexList) == 0x08);

typedef struct DllA6EffectResourceView {
    ModgfxEffectVertex vertices[3];
    u8 opaque1E[2];
} DllA6EffectResourceView;

STATIC_ASSERT(offsetof(DllA6EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(DllA6EffectResourceView, opaque1E) == 0x1E);
STATIC_ASSERT(sizeof(DllA6EffectResourceView) == 0x20);

typedef struct DllA6SequenceParams {
    s16 values[7];
    s16 opaqueTail;
} DllA6SequenceParams;

STATIC_ASSERT(offsetof(DllA6SequenceParams, values) == 0x00);
STATIC_ASSERT(offsetof(DllA6SequenceParams, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllA6SequenceParams) == 0x10);

extern u8 gDllA6EffectResourceData[sizeof(DllA6EffectResourceView)];
extern DllA6SequenceParams gDllA6SequenceParams;

DllA6ThreeIndexList gDllA6TriangleIndices = {{0, 0, 0, 1, 0, 2}, {0, 0}};
DllA6ThreeIndexList gDllA6VertexIndices = {{0, 0, 0, 1, 0, 2}, {0, 0}};

void dll_A6_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags) {
    ModgfxSpawnPacket packet;
    GfxCmd* commandCursor;
    GfxCmd* commands = packet.entries;
    f32 randomZ;
    f32 randomY;
    u32 fl;
    commandCursor = commands;

    if (variant == 0) {
        commandCursor->layer = 0;
        commandCursor->flags = 3;
        commandCursor->tex = gDllA6VertexIndices.indices;
        commandCursor->mode = 8;
        commandCursor->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor->y = (f32)(int)(randomGetRange(0, 0x14) + 0x87);
        commandCursor->z = (f32)(int)(randomGetRange(0, 0x14) + 0x41);
        commandCursor++;
    } else if (variant == 1) {
        commandCursor->layer = 0;
        commandCursor->flags = 3;
        commandCursor->tex = gDllA6VertexIndices.indices;
        commandCursor->mode = 8;
        commandCursor->y = commandCursor->x = (f32)(int)(randomGetRange(0, 0x5a) + 0x87);
        commandCursor->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        commandCursor++;
    }
    randomZ = randomGetRange(0, 0xfffe);
    randomY = randomGetRange(-3000, -12000);
    commandCursor[0].layer = 0;
    commandCursor[0].flags = 0;
    commandCursor[0].tex = NULL;
    commandCursor[0].mode = 0x80;
    commandCursor[0].x = 0.0f;
    commandCursor[0].y = randomY;
    commandCursor[0].z = randomZ;
    commandCursor[1].layer = 0;
    commandCursor[1].flags = 3;
    commandCursor[1].tex = gDllA6VertexIndices.indices;
    commandCursor[1].mode = 4;
    commandCursor[1].x = 0.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    commandCursor[2].layer = 0;
    commandCursor[2].flags = 3;
    commandCursor[2].tex = gDllA6VertexIndices.indices;
    commandCursor[2].mode = 2;
    commandCursor[2].x = 1.0f;
    commandCursor[2].y = 0.01f * randomGetRange(0, 0x19) + 0.25f;
    commandCursor[2].z = 0.01f * randomGetRange(0, 10) + 0.4f;
    commandCursor[3].layer = 1;
    commandCursor[3].flags = 3;
    commandCursor[3].tex = gDllA6VertexIndices.indices;
    commandCursor[3].mode = 4;
    if (randomGetRange(0, 10) == 0) {
        commandCursor[3].x = 145.0f + randomGetRange(0, 0x1e);
    } else {
        commandCursor[3].x = 25.0f + randomGetRange(0, 10);
    }
    commandCursor[3].y = 0.0f;
    commandCursor[3].z = 0.0f;
    commandCursor[4].layer = 1;
    commandCursor[4].flags = 0;
    commandCursor[4].tex = NULL;
    commandCursor[4].mode = 0x80;
    commandCursor[4].x = 0.0f;
    commandCursor[4].y = 0.0f;
    commandCursor[4].z = randomGetRange(0, 0xfffe);
    commandCursor[5].layer = 1;
    commandCursor[5].flags = 3;
    commandCursor[5].tex = gDllA6VertexIndices.indices;
    commandCursor[5].mode = 2;
    commandCursor[5].x = 9.0f;
    commandCursor[5].y = 12.0f;
    commandCursor[5].z = 21.0f;
    commandCursor[6].layer = 2;
    commandCursor[6].flags = 0;
    commandCursor[6].tex = NULL;
    commandCursor[6].mode = 0x80;
    commandCursor[6].x = 0.0f;
    commandCursor[6].y = 0.0f;
    commandCursor[6].z = randomGetRange(0, 0xfffe);
    commandCursor[7].layer = 2;
    commandCursor[7].flags = 3;
    commandCursor[7].tex = gDllA6VertexIndices.indices;
    commandCursor[7].mode = 4;
    commandCursor[7].x = 0.0f;
    commandCursor[7].y = 0.0f;
    commandCursor[7].z = 0.0f;
    commandCursor[8].layer = 2;
    commandCursor[8].flags = 3;
    commandCursor[8].tex = gDllA6VertexIndices.indices;
    commandCursor[8].mode = 2;
    commandCursor[8].x = 0.1f;
    commandCursor[8].y = 14.0f;
    commandCursor[8].z = 0.05f;

    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
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
    packet.commandCount = &commandCursor[9] - commands;
    packet.sequenceParams[0] = gDllA6SequenceParams.values[0];
    packet.sequenceParams[1] = gDllA6SequenceParams.values[1];
    packet.sequenceParams[2] = gDllA6SequenceParams.values[2];
    packet.sequenceParams[3] = gDllA6SequenceParams.values[3];
    packet.sequenceParams[4] = gDllA6SequenceParams.values[4];
    packet.sequenceParams[5] = gDllA6SequenceParams.values[5];
    packet.sequenceParams[6] = gDllA6SequenceParams.values[6];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    fl = 0x4000400;
    packet.flags = fl;
    fl |= flags;
    packet.flags = fl;
    if (fl & 1) {
        if (sourceObj != NULL && spawnParams != NULL) {
            packet.position[0] += sourceObj->anim.worldPosX + spawnParams->posX;
            packet.position[1] += sourceObj->anim.worldPosY + spawnParams->posY;
            packet.position[2] += sourceObj->anim.worldPosZ + spawnParams->posZ;
        } else if (sourceObj != NULL) {
            packet.position[0] = packet.position[0] + sourceObj->anim.worldPosX;
            packet.position[1] = packet.position[1] + packet.sourceObj->anim.worldPosY;
            packet.position[2] = packet.position[2] + packet.sourceObj->anim.worldPosZ;
        } else if (spawnParams != NULL) {
            packet.position[0] = packet.position[0] + spawnParams->posX;
            packet.position[1] = packet.position[1] + spawnParams->posY;
            packet.position[2] = packet.position[2] + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 3, gDllA6EffectResourceData, 1, (s16*)gDllA6TriangleIndices.indices, 0x26a, 0);
}

void dll_A6_release(void) {
}

void dll_A6_initialise(void) {
}

u8 gDllA6EffectResourceData[sizeof(DllA6EffectResourceView)] = {
    0, 0, 0, 230, 5, 20, 0, 0, 0, 31, 0, 0, 255, 26, 5, 20, 0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15, 0, 16, 0, 0,
};

DllA6SequenceParams gDllA6SequenceParams = {{0, 0x46, 0x46, 0, 0, 0, 0}, 0};

DllA6ResourceDescriptor gDllA6ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A6_initialise, dll_A6_release, NULL, dll_A6_spawnEffect,
};
