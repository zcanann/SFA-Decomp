/*
 * DLL 113 / 0x71 - a modgfx effect spawner.
 */
#include "main/dll/dll_0071_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll71EffectResourceView {
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
} Dll71EffectResourceView;

STATIC_ASSERT(offsetof(Dll71EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll71EffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(sizeof(Dll71EffectResourceView) == 0x208);

u16 gDll71EffectResourceData[sizeof(Dll71EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x0016, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x000b, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0000,
    0x01f4, 0x03e8, 0x0000, 0x000f, 0x0362, 0x01f4, 0x01f4, 0x000b, 0x000f,
    0x0362, 0x01f4, 0xfe0c, 0x0016, 0x000f, 0x0000, 0x01f4, 0xfc18, 0x0020,
    0x000f, 0xfc9e, 0x01f4, 0xfe0c, 0x0016, 0x000f, 0xfc9e, 0x01f4, 0x01f4,
    0x000b, 0x000f, 0x0000, 0x01f4, 0x03e8, 0x0000, 0x000f, 0x0000, 0x1770,
    0x03e8, 0x0000, 0x007f, 0x0362, 0x1770, 0x01f4, 0x000b, 0x007f, 0x0362,
    0x1770, 0xfe0c, 0x0016, 0x007f, 0x0000, 0x1770, 0xfc18, 0x0020, 0x007f,
    0xfc9e, 0x1770, 0xfe0c, 0x0016, 0x007f, 0xfc9e, 0x1770, 0x01f4, 0x000b,
    0x007f, 0x0000, 0x1770, 0x03e8, 0x0000, 0x007f, 0x0000, 0x0000, 0x0001,
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
    0x0000, 0x0096, 0x00fa, 0x0032, 0x0001, 0x0000, 0x0000, 0x0000,
};

void dll_71_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll71EffectResourceData;
    ModgfxCommand* commands = packet.entries;
    GameObject* context;
    f32 originOffset = 0.0f;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = originOffset;
    commands[0].valueY = originOffset;
    commands[0].valueZ = originOffset;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0x15;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.01f;
    commands[1].valueY = 2.0f;
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
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[4].flags = 2;
    commands[4].valueX = 200.0f;
    commands[4].valueY = 1.3f;
    commands[4].valueZ = 200.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0xe;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, lastFourteenVertexIndices)];
    commands[5].flags = 4;
    commands[5].valueX = 255.0f;
    commands[5].valueY = originOffset;
    commands[5].valueZ = originOffset;
    commands[6].stageIndex = 1;
    commands[6].parameter = 0x15;
    commands[6].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[6].flags = 0x4000;
    commands[6].valueX = 2.0f;
    commands[6].valueY = 2.0f;
    commands[6].valueZ = originOffset;
    commands[7].stageIndex = 1;
    commands[7].parameter = 0;
    commands[7].vertexIndices = NULL;
    commands[7].flags = 0x400000;
    commands[7].valueX = originOffset;
    commands[7].valueY = -100.0f;
    commands[7].valueZ = originOffset;
    commands[8].stageIndex = 2;
    commands[8].parameter = 0x15;
    commands[8].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[8].flags = 0x4000;
    commands[8].valueX = 2.0f;
    commands[8].valueY = 2.0f;
    commands[8].valueZ = originOffset;
    commands[9].stageIndex = 3;
    commands[9].parameter = 0x124;
    commands[9].vertexIndices = NULL;
    commands[9].flags = 0x20000;
    commands[9].valueX = originOffset;
    commands[9].valueY = originOffset;
    commands[9].valueZ = originOffset;
    commands[10].stageIndex = 3;
    commands[10].parameter = 0xe;
    commands[10].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, lastFourteenVertexIndices)];
    commands[10].flags = 4;
    commands[10].valueX = originOffset;
    commands[10].valueY = originOffset;
    commands[10].valueZ = originOffset;
    commands[11].stageIndex = 3;
    commands[11].parameter = 0x15;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[11].flags = 0x4000;
    commands[11].valueX = 2.0f;
    commands[11].valueY = 2.0f;
    commands[11].valueZ = originOffset;
    commands[12].stageIndex = 3;
    commands[12].parameter = 0x15;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(Dll71EffectResourceView, allVertexIndices)];
    commands[12].flags = 2;
    commands[12].valueX = 0.01f;
    commands[12].valueY = 1.0f;
    commands[12].valueZ = 0.01f;
    commands[13].stageIndex = 3;
    commands[13].parameter = 0;
    commands[13].vertexIndices = NULL;
    commands[13].flags = 0x400000;
    commands[13].valueX = originOffset;
    commands[13].valueY = 100.0f;
    commands[13].valueZ = originOffset;
    packet.context.modeByte = 0;
    context = sourceObj;
    packet.context.sourceObject = context;
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
    packet.context.commandCount = (commands + 14) - packet.entries;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll71EffectResourceView, sequenceParams[6])];
    packet.context.commands = packet.entries;
    packet.context.flags = 0xc0100c0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (context != NULL) {
            packet.context.position[0] = originOffset + context->anim.worldPosX;
            packet.context.position[1] = originOffset + context->anim.worldPosY;
            packet.context.position[2] = originOffset + context->anim.worldPosZ;
        } else {
            packet.context.position[0] = originOffset + spawnParams->posX;
            packet.context.position[1] = originOffset + spawnParams->posY;
            packet.context.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll71EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll71EffectResourceView, triangles)]), 0x154, 0);
}

void dll_71_release(void) {
}

void dll_71_initialise(void) {
}

Dll71ResourceDescriptor gDll71ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_71_initialise, dll_71_release, NULL, dll_71_spawnEffect,
};
