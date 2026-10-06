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
    ModgfxCommand* commands;
    ModgfxCommand* entries;
    f32 originOffset = 0.0f;
    entries = packet.entries;
    commands = entries;
    commands = (ModgfxCommand*)((int)commands | (int)entries);
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = originOffset;
    commands[0].valueY = originOffset;
    commands[0].valueZ = originOffset;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.01f;
    commands[1].valueY = 3.0f;
    commands[1].valueZ = 0.01f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x400000;
    commands[2].valueX = originOffset;
    commands[2].valueY = 100.0f;
    commands[2].valueZ = originOffset;
    commands[3].stageIndex = 0;
    commands[3].parameter = 0x124;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x20000;
    commands[3].valueX = originOffset;
    commands[3].valueY = originOffset;
    commands[3].valueZ = originOffset;
    commands[4].stageIndex = 1;
    commands[4].parameter = 0x15;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[4].flags = 2;
    commands[4].valueX = 200.0f;
    commands[4].valueY = 1.5f;
    commands[4].valueZ = 200.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0xe;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, lastFourteenVertexIndices)];
    commands[5].flags = 4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = originOffset;
    commands[5].valueZ = originOffset;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 2.0f;
    commands[6].valueY = 4.0f;
    commands[6].valueZ = originOffset;
    commands[7].stageIndex = 1;
    commands[7].parameter = 0;
    commands[7].vertexIndices = NULL;
    commands[7].flags = 0x400000;
    commands[7].valueX = originOffset;
    commands[7].valueY = -100.0f;
    commands[7].valueZ = originOffset;
    commands[8].stageIndex = 1;
    commands[8].parameter = 0x15;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[8].flags = 8;
    commands[8].valueX = randomGetRange(0x64, 0xff);
    commands[8].valueY = 255.0f;
    commands[8].valueZ = 255.0f;
    commands[9].stageIndex = 2;
    commands[9].parameter = 0x15;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[9].flags = 0x4000;
    commands[9].valueX = 2.0f;
    commands[9].valueY = 4.0f;
    commands[9].valueZ = originOffset;
    commands[10].stageIndex = 2;
    commands[10].parameter = 0x15;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[10].flags = 8;
    commands[10].valueX = randomGetRange(0x64, 0xff);
    commands[10].valueY = 255.0f;
    commands[10].valueZ = 255.0f;
    commands[11].stageIndex = 3;
    commands[11].parameter = 0x124;
    commands[11].vertexIndices = NULL;
    commands[11].flags = 0x20000;
    commands[11].valueX = originOffset;
    commands[11].valueY = originOffset;
    commands[11].valueZ = originOffset;
    commands[12].stageIndex = 3;
    commands[12].parameter = 0xe;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, lastFourteenVertexIndices)];
    commands[12].flags = 4;
    commands[12].valueX = originOffset;
    commands[12].valueY = originOffset;
    commands[12].valueZ = originOffset;
    commands[13].stageIndex = 3;
    commands[13].parameter = 0x15;
    commands[13].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[13].flags = 0x4000;
    commands[13].valueX = 2.0f;
    commands[13].valueY = 4.0f;
    commands[13].valueZ = originOffset;
    commands[14].stageIndex = 3;
    commands[14].parameter = 0x15;
    commands[14].vertexIndices = (s16*)&resourceData[offsetof(Dll73EffectResourceView, allVertexIndices)];
    commands[14].flags = 2;
    commands[14].valueX = 0.01f;
    commands[14].valueY = 1.0f;
    commands[14].valueZ = 0.01f;
    commands[15].stageIndex = 3;
    commands[15].parameter = 0;
    commands[15].vertexIndices = NULL;
    commands[15].flags = 0x400000;
    commands[15].valueX = originOffset;
    commands[15].valueY = 100.0f;
    commands[15].valueZ = originOffset;
    commands[16].stageIndex = 3;
    commands[16].parameter = 0;
    commands[16].vertexIndices = NULL;
    commands[16].flags = 0x80000;
    commands[16].valueX = originOffset;
    commands[16].valueY = 400.0f;
    commands[16].valueZ = originOffset;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = originOffset;
    packet.context.position[1] = originOffset;
    packet.context.position[2] = originOffset;
    packet.context.velocity[0] = originOffset;
    packet.context.velocity[1] = originOffset;
    packet.context.velocity[2] = originOffset;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = (commands + 17) - entries;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll73EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc0104c0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.context.position[0] = originOffset + sourceObj->anim.localPosX;
            packet.context.position[1] = originOffset + sourceObj->anim.localPosY;
            packet.context.position[2] = originOffset + sourceObj->anim.localPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = originOffset + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll73EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll73EffectResourceView, triangles)]), 0xd9, 0);
}

void dll_73_release(void) {
}

void dll_73_initialise(void) {
}

Dll73ResourceDescriptor gDll73ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_73_initialise, dll_73_release, NULL, dll_73_spawnEffect,
};
