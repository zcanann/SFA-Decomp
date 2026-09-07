/*
 * DLL 167 / 0xA7 - a configurable layered effect spawner.
 */
#include "main/dll/dll_00A7_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllA7EffectResourceView {
    ModgfxEffectVertex vertices[8];
    s16 triangles[4][3];
    s16 allVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllA7EffectResourceView;

STATIC_ASSERT(offsetof(DllA7EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, triangles) == 0x50);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, allVertexIndices) == 0x68);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, sequenceParams) == 0x78);
STATIC_ASSERT(offsetof(DllA7EffectResourceView, opaqueTail) == 0x86);
STATIC_ASSERT(sizeof(DllA7EffectResourceView) == 0x88);

extern u8 gDllA7EffectResourceData[sizeof(DllA7EffectResourceView)];

void dll_A7_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 flags, int unused,
                        DllA7CommandParams* commandParams) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDllA7EffectResourceData;
    GfxCmd* commandCursor;
    GfxCmd* commands;
    u32 valueY;
    u32 valueZ;
    u32 valueX;
    s32 commandFlags;
    u32 fl;

    valueY = 0x30;
    valueZ = 0x31;
    valueX = 1;
    commandFlags = 0x50;
    commands = packet.entries;
    if (commandParams != NULL) {
        valueX = commandParams->valueX;
        valueY = commandParams->valueY;
        valueZ = commandParams->valueZ;
        commandFlags = commandParams->flags;
    }
    commands[0].layer = 0;
    commands[0].flags = 8;
    commands[0].tex = &resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 8;
    commands[1].tex = &resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[1].mode = 2;
    if (sourceObj != NULL) {
        commands[1].x = 7.0f * sourceObj->anim.rootMotionScale;
        commands[1].y = 6.0f * sourceObj->anim.rootMotionScale;
        commands[1].z = 7.0f * sourceObj->anim.rootMotionScale;
    } else {
        commands[1].x = 7.0f;
        commands[1].y = 6.0f;
        commands[1].z = 7.0f;
    }
    commands[2].layer = 0;
    commands[2].flags = 0;
    commands[2].tex = NULL;
    commands[2].mode = 0x80;
    commands[2].x = 0.0f;
    commands[2].y = 0.0f;
    if (sourceObj != NULL) {
        commands[2].z = (f32)sourceObj->anim.rotX;
    } else {
        commands[2].z = 0.0f;
    }
    commands[3].layer = 1;
    commands[3].flags = 8;
    commands[3].tex = &resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commands[3].mode = 4;
    commands[3].x = 255.0f;
    commands[3].y = 0.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = commandFlags;
    commands[4].tex = NULL;
    commands[4].mode = 0x20000000;
    commands[4].x = (f32)(int)valueX;
    commands[4].y = (f32)(int)valueY;
    commands[4].z = (f32)(int)valueZ;
    commandCursor = commands + 5;
    if (variant != 1) {
        commandCursor->layer = 2;
        commandCursor->flags = 0x3b;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x1800000;
        commandCursor->x = 1.0f;
        commandCursor->y = 0.0f;
        commandCursor->z = 10.0f;
        commandCursor++;
    }
    commandCursor[0].layer = 2;
    commandCursor[0].flags = 0;
    commandCursor[0].tex = NULL;
    commandCursor[0].mode = 0x100;
    commandCursor[0].x = 0.0f;
    commandCursor[0].y = 0.0f;
    commandCursor[0].z = 50.0f;
    commandCursor[1].layer = 3;
    commandCursor[1].flags = 1;
    commandCursor[1].tex = NULL;
    commandCursor[1].mode = 0x2000;
    commandCursor[1].x = 0.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    commandCursor[2].layer = 4;
    commandCursor[2].flags = 8;
    commandCursor[2].tex = &resourceData[offsetof(DllA7EffectResourceView, allVertexIndices)];
    commandCursor[2].mode = 4;
    commandCursor[2].x = 0.0f;
    commandCursor[2].y = 0.0f;
    commandCursor[2].z = 0.0f;
    commandCursor[3].layer = 4;
    commandCursor[3].flags = 0;
    commandCursor[3].tex = NULL;
    commandCursor[3].mode = 0x20000000;
    commandCursor[3].x = (f32)(int)valueX;
    commandCursor[3].y = (f32)(int)valueY;
    commandCursor[3].z = (f32)(int)valueZ;

    packet.modeByte = variant;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    if (spawnParams != NULL) {
        packet.position[1] = spawnParams->posY;
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
    packet.commandCount = &commandCursor[4] - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(DllA7EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4040000;
    packet.flags |= (flags | 0x80);
    fl = packet.flags;
    if (fl & 1) {
        GameObject* object = packet.sourceObj;
        if (object != NULL) {
            packet.position[0] += object->anim.worldPosX;
            packet.position[1] += object->anim.worldPosY;
            packet.position[2] += object->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 8, (u8*)(int)gDllA7EffectResourceData, 4,
                      &resourceData[offsetof(DllA7EffectResourceView, triangles)], 0x5e0, 0);
}

void dll_A7_release(void) {
}

void dll_A7_initialise(void) {
}

u8 gDllA7EffectResourceData[sizeof(DllA7EffectResourceView)] = {
    252, 24, 0, 0,  0, 0,   0,  0,   0, 0,  0, 0,  0,   0,  252, 24,  0,  0,   0, 0,   3, 232, 0, 0,  0,  0,   0,   15,
    0,   0,  0, 0,  0, 0,   3,  232, 0, 15, 0, 0,  252, 24, 15,  160, 0,  0,   0, 0,   0, 31,  0, 0,  15, 160, 252, 24,
    0,   0,  0, 31, 3, 232, 15, 160, 0, 0,  0, 15, 0,   31, 0,   0,   15, 160, 3, 232, 0, 15,  0, 31, 0,  0,   0,   2,
    0,   6,  0, 0,  0, 6,   0,  4,   0, 1,  0, 3,  0,   7,  0,   1,   0,  7,   0, 5,   0, 0,   0, 1,  0,  2,   0,   3,
    0,   4,  0, 5,  0, 6,   0,  7,   0, 0,  1, 4,  0,   30, 0,   1,   1,  4,   0, 0,   0, 0,   0, 0};

DllA7ResourceDescriptor gDllA7ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A7_initialise, dll_A7_release, NULL, dll_A7_spawnEffect,
};
