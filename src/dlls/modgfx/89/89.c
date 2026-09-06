/*
 * DLL 89 / 0x59 - a modgfx particle-sequence spawn DLL.
 */
#include "main/dll/dll_0059_dll59func0.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

#define DLL59_EFFECT_ID 0xC0D

typedef struct Dll59EffectResourceView {
    ModgfxEffectVertex vertices[17];
    u8 padAA[2];
    s16 triangleIndices[8][3];
    s16 indicesWithVertexZero[18];
    s16 indicesWithoutVertexZero[16];
    s16 sequenceParams[7];
    u8 pad12E[2];
} Dll59EffectResourceView;

STATIC_ASSERT(offsetof(Dll59EffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, triangleIndices) == 0xAC);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, indicesWithVertexZero) == 0xDC);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, indicesWithoutVertexZero) == 0x100);
STATIC_ASSERT(offsetof(Dll59EffectResourceView, sequenceParams) == 0x120);
STATIC_ASSERT(sizeof(Dll59EffectResourceView) == 0x130);

void dll_59_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resource = (u8*)(int)gDll59EffectResourceData;
    GfxCmd* commands = packet.entries;
    GameObject* sourceContext;
    f32 one;
    f32 zero;
    commands[0].layer = 1;
    commands[0].flags = 0x11;
    commands[0].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[0].mode = 0x4000;
    commands[0].x = (zero = 0.0f);
    commands[0].y = -3.0f;
    commands[0].z = zero;
    commands[1].layer = 1;
    commands[1].flags = 0x10;
    commands[1].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithoutVertexZero)];
    commands[1].mode = 2;
    commands[1].x = 35.0f;
    commands[1].y = 35.0f;
    commands[1].z = 35.0f;
    commands[2].layer = 1;
    commands[2].flags = 0x11;
    commands[2].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[2].mode = 0x100;
    commands[2].x = zero;
    commands[2].y = zero;
    commands[2].z = 1500.0f;
    commands[3].layer = 1;
    commands[3].flags = 2;
    commands[3].tex = NULL;
    commands[3].mode = 0x04000000;
    commands[3].x = (one = 1.0f);
    commands[3].y = zero;
    commands[3].z = zero;
    commands[4].layer = 2;
    commands[4].flags = 2;
    commands[4].tex = NULL;
    commands[4].mode = 0x04000000;
    commands[4].x = one;
    commands[4].y = zero;
    commands[4].z = zero;
    commands[5].layer = 2;
    commands[5].flags = 0x11;
    commands[5].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[5].mode = 0x4000;
    commands[5].x = zero;
    commands[5].y = -3.0f;
    commands[5].z = zero;
    commands[6].layer = 2;
    commands[6].flags = 0x11;
    commands[6].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[6].mode = 4;
    commands[6].x = zero;
    commands[6].y = zero;
    commands[6].z = zero;
    commands[7].layer = 2;
    commands[7].flags = 0x11;
    commands[7].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithVertexZero)];
    commands[7].mode = 0x100;
    commands[7].x = zero;
    commands[7].y = zero;
    commands[7].z = -1000.0f;
    commands[8].layer = 2;
    commands[8].flags = 0x10;
    commands[8].tex = &resource[offsetof(Dll59EffectResourceView, indicesWithoutVertexZero)];
    commands[8].mode = 2;
    commands[8].x = 2.0f;
    commands[8].y = 2.0f;
    commands[8].z = 2.0f;
    packet.v58 = 0;
    sourceContext = sourceObj;
    packet.ctx = (int)sourceContext;
    packet.v44 = variant;
    packet.pos[0] = zero;
    packet.pos[1] = 135.0f;
    packet.pos[2] = zero;
    packet.col[0] = zero;
    packet.col[1] = zero;
    packet.col[2] = zero;
    packet.scale = one;
    packet.v40 = 1;
    packet.v3c = 0;
    packet.v59 = 0x11;
    packet.v5a = 0;
    packet.v5b = 0x10;
    packet.count = (commands + 9) - packet.entries;
    packet.hw[0] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x0];
    packet.hw[1] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x2];
    packet.hw[2] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x4];
    packet.hw[3] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x6];
    packet.hw[4] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0x8];
    packet.hw[5] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0xA];
    packet.hw[6] = *(s16*)&resource[offsetof(Dll59EffectResourceView, sequenceParams) + 0xC];
    packet.cmds = packet.entries;
    packet.flags = 0x04000000;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((void*)sourceContext != NULL) {
            packet.pos[0] = zero + sourceContext->anim.worldPosX;
            packet.pos[1] = 135.0f + sourceContext->anim.worldPosY;
            packet.pos[2] = zero + sourceContext->anim.worldPosZ;
        } else {
            packet.pos[0] = zero + spawnParams->posX;
            packet.pos[1] = 135.0f + spawnParams->posY;
            packet.pos[2] = zero + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x11, (u8*)(int)gDll59EffectResourceData, 8,
                      &resource[offsetof(Dll59EffectResourceView, triangleIndices)], DLL59_EFFECT_ID, 0);
}

void dll_59_release(void) {
}

void dll_59_initialise(void) {
}

u8 gDll59EffectResourceData[0x130] = {
    0,   0,   0, 0,   0, 0,   0,   15,  0,   0,   0,   150, 1,   144, 3,   132, 0,   0,   0, 127, 255, 206, 1,   144,
    3,   232, 0, 31,  0, 127, 0,   50,  2,   18,  252, 24,  0,   0,   0,   127, 255, 106, 2, 18,  252, 174, 0,   31,
    0,   127, 3, 232, 0, 100, 0,   150, 0,   0,   0,   127, 4,   176, 0,   100, 255, 206, 0, 31,  0,   127, 252, 24,
    1,   14,  0, 50,  0, 0,   0,   127, 252, 24,  1,   14,  255, 206, 0,   31,  0,   127, 2, 108, 2,   38,  3,   12,
    0,   0,   0, 127, 3, 12,  2,   38,  3,   152, 0,   31,  0,   127, 252, 204, 0,   210, 3, 12,  0,   0,   0,   127,
    253, 188, 0, 210, 3, 52,  0,   31,  0,   127, 3,   52,  0,   100, 252, 244, 0,   0,   0, 127, 3,   12,  0,   100,
    253, 148, 0, 31,  0, 127, 252, 104, 1,   214, 252, 244, 0,   0,   0,   127, 252, 244, 1, 214, 252, 204, 0,   31,
    0,   127, 0, 0,   0, 0,   0,   1,   0,   2,   0,   0,   0,   3,   0,   4,   0,   0,   0, 5,   0,   6,   0,   0,
    0,   7,   0, 8,   0, 0,   0,   9,   0,   10,  0,   0,   0,   11,  0,   12,  0,   0,   0, 13,  0,   14,  0,   0,
    0,   15,  0, 16,  0, 0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0, 7,   0,   8,   0,   9,
    0,   10,  0, 11,  0, 12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   0,   0,   1,   0, 2,   0,   3,   0,   4,
    0,   5,   0, 6,   0, 7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0, 14,  0,   15,  0,   16,
    0,   0,   0, 90,  0, 50,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

Dll59ResourceDescriptor gDll59ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_59_initialise, dll_59_release, NULL, dll_59_spawnEffect,
};
