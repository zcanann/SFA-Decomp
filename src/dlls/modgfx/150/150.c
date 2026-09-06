/*
 * DLL 150 / 0x96 - a game-bit-gated seven-command modgfx effect spawner.
 */
#include "main/dll/dll_0096_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/gamebits.h"
#include "main/vecmath.h"

typedef struct Dll96EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[7];
    s16 opaque172;
    u8 opaque174[0x3C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    u8 opaque1DC[0x1C];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll96EffectResourceView;

STATIC_ASSERT(offsetof(Dll96EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, padD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, opaque172) == 0x172);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, opaque174) == 0x174);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, opaque1DC) == 0x1DC);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll96EffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll96EffectResourceView) == 0x208);

extern u32 gDll96EffectResourceData[sizeof(Dll96EffectResourceView) / sizeof(u32)];

s16 dll_96_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll96EffectResourceData;
    GfxCmd* commands;

    if (mainGetBit(GAMEBIT_ITEM_SpellStone3_Got) != 0) {
        return -1;
    }
    commands = packet.entries;
    commands[0].layer = 0;
    commands[0].flags = 0x15;
    commands[0].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[0].mode = 0x4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    commands[1].layer = 0;
    commands[1].flags = 0x15;
    commands[1].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[1].mode = 0x2;
    if (mainGetBit(GAMEBIT_ITEM_SpellStone1_Used) != 0) {
        commands[1].x = 0.15f;
    } else {
        commands[1].x = 0.03f * randomGetRange(5, 10);
    }
    commands[1].y = 10.5f;
    commands[1].z = commands[1].x;
    commands[2].layer = 1;
    commands[2].flags = 7;
    commands[2].tex = &resourceData[offsetof(Dll96EffectResourceView, firstSevenVertexIndices)];
    commands[2].mode = 0x2;
    commands[2].x = 4.0f;
    commands[2].y = 1.0f;
    commands[2].z = 4.0f;
    commands[3].layer = 1;
    commands[3].flags = 0x15;
    commands[3].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[3].mode = 0x4;
    commands[3].x = 255.0f;
    commands[3].y = 0.0f;
    commands[3].z = 0.0f;
    commands[4].layer = 1;
    commands[4].flags = 0x15;
    commands[4].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[4].mode = 0x4000;
    commands[4].x = 0.0f;
    commands[4].y = 4.0f;
    commands[4].z = 0.0f;
    commands[5].layer = 2;
    commands[5].flags = 0x15;
    commands[5].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[5].mode = 0x4;
    commands[5].x = 0.0f;
    commands[5].y = 0.0f;
    commands[5].z = 0.0f;
    commands[6].layer = 2;
    commands[6].flags = 0x15;
    commands[6].tex = &resourceData[offsetof(Dll96EffectResourceView, allVertexIndices)];
    commands[6].mode = 0x4000;
    commands[6].x = 0.0f;
    commands[6].y = 4.0f;
    commands[6].z = 0.0f;
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
    packet.drawGroupCount = 2;
    packet.drawGroupStride = 7;
    packet.initialStateByte = 0xE;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = (GfxCmd*)((u8*)commands + sizeof(GfxCmd) * 7) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll96EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0xc0104c0;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((u32)sourceObj != 0) {
            packet.position[0] += sourceObj->anim.localPosX;
            packet.position[1] += sourceObj->anim.localPosY;
            packet.position[2] += sourceObj->anim.localPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    return (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll96EffectResourceData, 0x18,
                      &resourceData[offsetof(Dll96EffectResourceView, triangles)], 0x89, 0);
}

void dll_96_release(void) {
}

void dll_96_initialise(void) {
}

u32 gDll96EffectResourceData[sizeof(Dll96EffectResourceView) / sizeof(u32)] = {
    0x00000000, 0x03e80000, 0x00ff0362, 0x000001f4, 0x000b00ff, 0x03620000, 0xfe0c0016, 0x00ff0000, 0x0000fc18,
    0x002000ff, 0xfc9e0000, 0xfe0c0016, 0x00fffc9e, 0x000001f4, 0x000b00ff, 0x00000000, 0x03e80000, 0x00ff0000,
    0x0bb803e8, 0x0000007f, 0x03620bb8, 0x01f4000b, 0x007f0362, 0x0bb8fe0c, 0x0016007f, 0x00000bb8, 0xfc180020,
    0x007ffc9e, 0x0bb8fe0c, 0x0016007f, 0xfc9e0bb8, 0x01f4000b, 0x007f0000, 0x0bb803e8, 0x0000007f, 0x00001770,
    0x03e80000, 0x00000362, 0x177001f4, 0x000b0000, 0x03621770, 0xfe0c0016, 0x00000000, 0x1770fc18, 0x00200000,
    0xfc9e1770, 0xfe0c0016, 0x0000fc9e, 0x177001f4, 0x000b0000, 0x00001770, 0x03e80000, 0x00000000, 0x00000001,
    0x00080000, 0x00080007, 0x00010002, 0x00090001, 0x00090008, 0x00020003, 0x000a0002, 0x000a0009, 0x00030004,
    0x000b0003, 0x000b000a, 0x00040005, 0x000c0004, 0x000c000b, 0x00050006, 0x000d0005, 0x000d000c, 0x00070008,
    0x000f0007, 0x000f000e, 0x00080009, 0x00100008, 0x0010000f, 0x0009000a, 0x00110009, 0x00110010, 0x000a000b,
    0x0012000a, 0x00120011, 0x000b000c, 0x0013000b, 0x00130012, 0x000c000d, 0x0014000c, 0x00140013, 0x00000001,
    0x00020003, 0x00040005, 0x00060000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d0000, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00000001, 0x00020003, 0x00040005, 0x0006000e, 0x000f0010, 0x00110012, 0x00130014,
    0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080009, 0x000a000b, 0x000c000d, 0x000e000f, 0x00100011,
    0x00120013, 0x00140000, 0x00070008, 0x0009000a, 0x000b000c, 0x000d000e, 0x000f0010, 0x00110012, 0x00130014,
    0x00000032, 0x00320000, 0x00000000, 0x00000000};
Dll96ResourceDescriptor gDll96ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_96_initialise, dll_96_release, NULL, dll_96_spawnEffect,
};
