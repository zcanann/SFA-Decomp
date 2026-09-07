/*
 * DLL 152 / 0x98 - an invertible nine-command layered modgfx effect spawner.
 */
#include "main/dll/dll_0098_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

ModgfxEffectVertex gDll98PrimaryVertices[18] = {
    {0, 0, 1000, 0, 0},
    {-707, 0, 707, 15, 0},
    {-1000, 0, 0, 31, 0},
    {-707, 0, -707, 47, 0},
    {0, 0, -1000, 63, 0},
    {707, 0, -707, 79, 0},
    {1000, 0, 0, 95, 0},
    {707, 0, 707, 111, 0},
    {0, 0, 1000, 127, 0},
    {0, 2000, 1000, 0, 31},
    {-707, 2000, 707, 15, 31},
    {-1000, 2000, 0, 31, 31},
    {-707, 2000, -707, 47, 31},
    {0, 2000, -1000, 63, 31},
    {707, 2000, -707, 79, 31},
    {1000, 2000, 0, 95, 31},
    {707, 2000, 707, 111, 31},
    {0, 2000, 1000, 127, 31},
};
ModgfxEffectVertex gDll98InvertedVertices[18] = {
    {0, 0, 1000, 0, 0},
    {-707, 0, 707, 15, 0},
    {-1000, 0, 0, 31, 0},
    {-707, 0, -707, 47, 0},
    {0, 0, -1000, 63, 0},
    {707, 0, -707, 79, 0},
    {1000, 0, 0, 95, 0},
    {707, 0, 707, 111, 0},
    {0, 0, 1000, 127, 0},
    {0, -2000, 1000, 0, 31},
    {-707, -2000, 707, 15, 31},
    {-1000, -2000, 0, 31, 31},
    {-707, -2000, -707, 47, 31},
    {0, -2000, -1000, 63, 31},
    {707, -2000, -707, 79, 31},
    {1000, -2000, 0, 95, 31},
    {707, -2000, 707, 111, 31},
    {0, -2000, 1000, 127, 31},
};
s16 gDll98Triangles[16][3] = {
    {0, 1, 10},
    {0, 10, 9},
    {1, 2, 11},
    {1, 11, 10},
    {2, 3, 12},
    {2, 12, 11},
    {3, 4, 13},
    {3, 13, 12},
    {4, 5, 14},
    {4, 14, 13},
    {5, 6, 15},
    {5, 15, 14},
    {6, 7, 16},
    {6, 16, 15},
    {7, 8, 17},
    {7, 17, 16},
};
u8 gDll98Opaque1C8[0x14] = {0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 0};
s16 gDll98AllVertexIndices[18] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
u8 gDll98Opaque200[0x14] = {0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0};
s16 gDll98SequenceParams[7] = {0, 100, 100, 0, 0, 0, 0};

void dll_98_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int unused,
                        int invertY) {
    ModgfxSpawnPacket packet;
    GfxCmd* commands;
    int effectId;
    gDll98SequenceParams[1] = randomGetRange(0, 0x1E) + 0x1E;
    gDll98SequenceParams[2] = gDll98SequenceParams[1];
    commands = packet.entries;
    commands[0].layer = 0;
    commands[0].flags = 0x12;
    commands[0].tex = gDll98AllVertexIndices;
    commands[0].mode = 0x4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 0x12;
    commands[1].tex = gDll98AllVertexIndices;
    commands[1].mode = 0x2;
    commands[1].z = commands[1].x = 0.22f;
    commands[1].y = 0.3f;
    commands[2].layer = 1;
    commands[2].flags = 0x12;
    commands[2].tex = gDll98AllVertexIndices;
    commands[2].mode = 0x4;
    commands[2].x = 255.0f;
    commands[2].y = 0.0f;
    commands[2].z = 0.0f;
    commands[3].layer = 1;
    commands[3].flags = 0x12;
    commands[3].tex = gDll98AllVertexIndices;
    commands[3].mode = 0x400000;
    commands[3].x = 0.0f;
    if ((u32)invertY != 0) {
        commands[3].y = -7.0f;
    } else {
        commands[3].y = 7.0f;
    }
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 0x12;
    commands[4].tex = gDll98AllVertexIndices;
    commands[4].mode = 0x4000;
    commands[4].x = 0.0f;
    if ((u32)invertY != 0) {
        commands[4].y = 1.0f;
    } else {
        commands[4].y = -1.0f;
    }
    commands[4].z = 0.0f;
    commands[5].layer = 2;
    commands[5].flags = 0x12;
    commands[5].tex = gDll98AllVertexIndices;
    commands[5].mode = 0x4;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 0.0f;
    commands[6].layer = 2;
    commands[6].flags = 0x12;
    commands[6].tex = gDll98AllVertexIndices;
    commands[6].mode = 0x400000;
    commands[6].x = 0.0f;
    if ((u32)invertY != 0) {
        commands[6].y = -7.0f;
    } else {
        commands[6].y = 7.0f;
    }
    commands[6].z = 0.0f;
    commands[7].layer = 2;
    commands[7].flags = 0x12;
    commands[7].tex = gDll98AllVertexIndices;
    commands[7].mode = 0x4000;
    commands[7].x = 0.0f;
    if ((u32)invertY != 0) {
        commands[7].y = 1.0f;
    } else {
        commands[7].y = -1.0f;
    }
    commands[7].z = 0.0f;
    commands[8].layer = 2;
    commands[8].flags = 0x12;
    commands[8].tex = gDll98AllVertexIndices;
    commands[8].mode = 0x2;
    commands[8].x = 1.0f;
    commands[8].y = 1.0f;
    commands[8].z = 1.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    if ((u32)invertY != 0) {
        packet.position[1] = -2.0f;
    } else {
        packet.position[1] = 2.0f;
    }
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0x12;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.flags = 0x4080400;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 9) - commands;
    packet.sequenceParams[0] = gDll98SequenceParams[0];
    packet.sequenceParams[1] = gDll98SequenceParams[1];
    packet.sequenceParams[2] = gDll98SequenceParams[2];
    packet.sequenceParams[3] = gDll98SequenceParams[3];
    packet.sequenceParams[4] = gDll98SequenceParams[4];
    packet.sequenceParams[5] = gDll98SequenceParams[5];
    packet.sequenceParams[6] = gDll98SequenceParams[6];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((u32)packet.sourceObj != 0) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    if (variant == 0) {
        effectId = 0x3E9;
    } else if (variant == 1) {
        effectId = 0x3F0;
    } else {
        effectId = 0x3F3;
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x12,
                      (u32)invertY != 0 ? gDll98InvertedVertices
                                        : gDll98PrimaryVertices,
                      0x10, gDll98Triangles, effectId, 0);
}

void dll_98_release(void) {
}

void dll_98_initialise(void) {
}

Dll98ResourceDescriptor gDll98ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000},
    dll_98_initialise,
    dll_98_release,
    NULL,
    dll_98_spawnEffect,
    0x00000000,
};
