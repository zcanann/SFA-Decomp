/*
 * DLL 115 / 0x73 - a modgfx effect spawner.
 */
#include "main/dll/dll_0073_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll73EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[8];
    s16 secondSevenVertexIndices[8];
    s16 thirdSevenVertexIndices[8];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[22];
    s16 lastFourteenVertexIndices[14];
    s16 sequenceParams[7];
    u8 pad206[2];
} Dll73EffectResourceView;

STATIC_ASSERT(offsetof(Dll73EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll73EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(sizeof(Dll73EffectResourceView) == 0x208);

u16 gDll73EffectResourceData[sizeof(Dll73EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x0016, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x000b, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0000,
    0x01f4, 0x03e8, 0x0000, 0x0004, 0x0362, 0x01f4, 0x01f4, 0x000b, 0x0004,
    0x0362, 0x01f4, 0xfe0c, 0x0016, 0x0004, 0x0000, 0x01f4, 0xfc18, 0x0020,
    0x0004, 0xfc9e, 0x01f4, 0xfe0c, 0x0016, 0x0004, 0xfc9e, 0x01f4, 0x01f4,
    0x000b, 0x0004, 0x0000, 0x01f4, 0x03e8, 0x0000, 0x0004, 0x0000, 0x1770,
    0x03e8, 0x0000, 0x003f, 0x0362, 0x1770, 0x01f4, 0x000b, 0x003f, 0x0362,
    0x1770, 0xfe0c, 0x0016, 0x003f, 0x0000, 0x1770, 0xfc18, 0x0020, 0x003f,
    0xfc9e, 0x1770, 0xfe0c, 0x0016, 0x003f, 0xfc9e, 0x1770, 0x01f4, 0x000b,
    0x003f, 0x0000, 0x1770, 0x03e8, 0x0000, 0x003f, 0x0000, 0x0000, 0x0001,
    0x0008, 0x0000, 0x0008, 0x0007, 0x0001, 0x0002, 0x0009, 0x0001, 0x0009,
    0x0008, 0x0002, 0x0003, 0x000a, 0x0002, 0x000a, 0x0009, 0x0003, 0x0004,
    0x000b, 0x0003, 0x000b, 0x000a, 0x0004, 0x0005, 0x000c, 0x0004, 0x000c,
    0x000b, 0x0005, 0x0006, 0x000d, 0x0005, 0x000d, 0x000c, 0x0007, 0x0008,
    0x000f, 0x0007, 0x000f, 0x000e, 0x0008, 0x0009, 0x0010, 0x0008, 0x0010,
    0x000f, 0x0009, 0x000a, 0x0011, 0x0009, 0x0011, 0x0010, 0x000a, 0x000b,
    0x0012, 0x000a, 0x0012, 0x0011, 0x000b, 0x000c, 0x0013, 0x000b, 0x0013,
    0x0012, 0x000c, 0x000d, 0x0014, 0x000c, 0x0014, 0x0013, 0x0000, 0x0001,
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0000, 0x0007, 0x0008, 0x0009,
    0x000a, 0x000b, 0x000c, 0x000d, 0x0000, 0x000e, 0x000f, 0x0010, 0x0011,
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0001, 0x0002, 0x0003, 0x0004,
    0x0005, 0x0006, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014,
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
    0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011,
    0x0012, 0x0013, 0x0014, 0x0000, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b,
    0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014,
    0x0000, 0x0032, 0x0096, 0x0032, 0x0001, 0x0000, 0x0000, 0x0000,
};

void dll_73_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll73EffectResourceData;
    GfxCmd* commands;
    GfxCmd* entries;
    f32 originOffset = 0.0f;
    entries = packet.entries;
    commands = entries;
    commands = (GfxCmd*)((int)commands | (int)entries);
    commands[0].layer = 0;
    commands[0].flags = 0x15;
    commands[0].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = originOffset;
    commands[0].y = originOffset;
    commands[0].z = originOffset;
    commands[1].layer = 0;
    commands[1].flags = 0x15;
    commands[1].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[1].mode = 2;
    commands[1].x = 0.01f;
    commands[1].y = 3.0f;
    commands[1].z = 0.01f;
    commands[2].layer = 0;
    commands[2].flags = 0;
    commands[2].tex = NULL;
    commands[2].mode = 0x400000;
    commands[2].x = originOffset;
    commands[2].y = 100.0f;
    commands[2].z = originOffset;
    commands[3].layer = 0;
    commands[3].flags = 0x124;
    commands[3].tex = NULL;
    commands[3].mode = 0x20000;
    commands[3].x = originOffset;
    commands[3].y = originOffset;
    commands[3].z = originOffset;
    commands[4].layer = 1;
    commands[4].flags = 0x15;
    commands[4].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[4].mode = 2;
    commands[4].x = 200.0f;
    commands[4].y = 1.5f;
    commands[4].z = 200.0f;
    commands[5].layer = 1;
    commands[5].flags = 0xe;
    commands[5].tex = &resourceData[offsetof(Dll73EffectResourceView, lastFourteenVertexIndices)];
    commands[5].mode = 4;
    commands[5].x = 255.0f;
    commands[5].y = originOffset;
    commands[5].z = originOffset;
    commands[6].layer = 1;
    commands[6].flags = 0x15;
    commands[6].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[6].mode = 0x4000;
    commands[6].x = 2.0f;
    commands[6].y = 4.0f;
    commands[6].z = originOffset;
    commands[7].layer = 1;
    commands[7].flags = 0;
    commands[7].tex = NULL;
    commands[7].mode = 0x400000;
    commands[7].x = originOffset;
    commands[7].y = -100.0f;
    commands[7].z = originOffset;
    commands[8].layer = 1;
    commands[8].flags = 0x15;
    commands[8].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[8].mode = 8;
    commands[8].x = (f32)randomGetRange(0x64, 0xff);
    commands[8].y = 255.0f;
    commands[8].z = 255.0f;
    commands[9].layer = 2;
    commands[9].flags = 0x15;
    commands[9].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[9].mode = 0x4000;
    commands[9].x = 2.0f;
    commands[9].y = 4.0f;
    commands[9].z = originOffset;
    commands[10].layer = 2;
    commands[10].flags = 0x15;
    commands[10].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[10].mode = 8;
    commands[10].x = (f32)randomGetRange(0x64, 0xff);
    commands[10].y = 255.0f;
    commands[10].z = 255.0f;
    commands[11].layer = 3;
    commands[11].flags = 0x124;
    commands[11].tex = NULL;
    commands[11].mode = 0x20000;
    commands[11].x = originOffset;
    commands[11].y = originOffset;
    commands[11].z = originOffset;
    commands[12].layer = 3;
    commands[12].flags = 0xe;
    commands[12].tex = &resourceData[offsetof(Dll73EffectResourceView, lastFourteenVertexIndices)];
    commands[12].mode = 4;
    commands[12].x = originOffset;
    commands[12].y = originOffset;
    commands[12].z = originOffset;
    commands[13].layer = 3;
    commands[13].flags = 0x15;
    commands[13].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[13].mode = 0x4000;
    commands[13].x = 2.0f;
    commands[13].y = 4.0f;
    commands[13].z = originOffset;
    commands[14].layer = 3;
    commands[14].flags = 0x15;
    commands[14].tex = &resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[14].mode = 2;
    commands[14].x = 0.01f;
    commands[14].y = 1.0f;
    commands[14].z = 0.01f;
    commands[15].layer = 3;
    commands[15].flags = 0;
    commands[15].tex = NULL;
    commands[15].mode = 0x400000;
    commands[15].x = originOffset;
    commands[15].y = 100.0f;
    commands[15].z = originOffset;
    commands[16].layer = 3;
    commands[16].flags = 0;
    commands[16].tex = NULL;
    commands[16].mode = 0x80000;
    commands[16].x = originOffset;
    commands[16].y = 400.0f;
    commands[16].z = originOffset;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = originOffset;
    packet.position[1] = originOffset;
    packet.position[2] = originOffset;
    packet.velocity[0] = originOffset;
    packet.velocity[1] = originOffset;
    packet.velocity[2] = originOffset;
    packet.scale = 1.0f;
    packet.drawGroupCount = 2;
    packet.drawGroupStride = 7;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = (commands + 17) - entries;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0xc0104c0;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.position[0] = originOffset + sourceObj->anim.localPosX;
            packet.position[1] = originOffset + sourceObj->anim.localPosY;
            packet.position[2] = originOffset + sourceObj->anim.localPosZ;
        } else {
            packet.position[0] = originOffset + spawnParams->posX;
            packet.position[1] = originOffset + spawnParams->posY;
            packet.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll73EffectResourceData, 0x18,
                      &resourceData[offsetof(Dll73EffectResourceView, triangles)], 0xd9, 0);
}

void dll_73_release(void) {
}

void dll_73_initialise(void) {
}

Dll73ResourceDescriptor gDll73ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_73_initialise, dll_73_release, NULL, dll_73_spawnEffect,
};
