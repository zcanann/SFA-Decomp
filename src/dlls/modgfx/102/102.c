/*
 * DLL 102 / 0x66 - a modgfx effect spawner.
 */
#include "main/dll/dll_0066_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll66EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangleIndices[24][3];
    s16 firstGroupIndices[8];
    s16 secondGroupIndices[8];
    s16 thirdGroupIndices[8];
    s16 firstAndThirdGroupIndices[14];
    s16 allVertexIndices[22];
    s16 sequenceParams[7];
    u8 pad1EA[2];
} Dll66EffectResourceView;

STATIC_ASSERT(offsetof(Dll66EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, triangleIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, firstGroupIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, secondGroupIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, thirdGroupIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, firstAndThirdGroupIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll66EffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(sizeof(Dll66EffectResourceView) == 0x1EC);

u16 gDll66EffectResourceData[sizeof(Dll66EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x0016, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x000b, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0000,
    0x0bb8, 0x03e8, 0x0000, 0x003f, 0x0362, 0x0bb8, 0x01f4, 0x000b, 0x003f,
    0x0362, 0x0bb8, 0xfe0c, 0x0016, 0x003f, 0x0000, 0x0bb8, 0xfc18, 0x0020,
    0x003f, 0xfc9e, 0x0bb8, 0xfe0c, 0x0016, 0x003f, 0xfc9e, 0x0bb8, 0x01f4,
    0x000b, 0x003f, 0x0000, 0x0bb8, 0x03e8, 0x0000, 0x003f, 0x0000, 0x1770,
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
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0032, 0x00c8, 0x0032, 0x0001,
    0x0000, 0x0000, 0x0000,
};

void dll_66_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll66EffectResourceData;
    GameObject* context;

    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 0x15;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[0].flags = 4;
    packet.entries[0].valueX = 0.0f;
    packet.entries[0].valueY = 0.0f;
    packet.entries[0].valueZ = 0.0f;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 0x15;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[1].flags = 2;
    packet.entries[1].valueX = 0.01f;
    packet.entries[1].valueY = 2.0f;
    packet.entries[1].valueZ = 0.01f;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 0x50;
    packet.entries[2].vertexIndices = NULL;
    packet.entries[2].flags = 0x20000000;
    packet.entries[2].valueX = 999.0f;
    packet.entries[2].valueY = 18.0f;
    packet.entries[2].valueZ = 19.0f;
    packet.entries[3].stageIndex = 0;
    packet.entries[3].parameter = 0;
    packet.entries[3].vertexIndices = NULL;
    packet.entries[3].flags = 0x80000;
    packet.entries[3].valueX = 0.0f;
    packet.entries[3].valueY = 450.0f;
    packet.entries[3].valueZ = 0.0f;
    packet.entries[4].stageIndex = 0;
    packet.entries[4].parameter = 0;
    packet.entries[4].vertexIndices = NULL;
    packet.entries[4].flags = 0x400000;
    packet.entries[4].valueX = 0.0f;
    packet.entries[4].valueY = 100.0f;
    packet.entries[4].valueZ = 0.0f;
    packet.entries[5].stageIndex = 1;
    packet.entries[5].parameter = 0x15;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[5].flags = 2;
    packet.entries[5].valueX = 200.0f;
    packet.entries[5].valueY = 1.0f;
    packet.entries[5].valueZ = 200.0f;
    packet.entries[6].stageIndex = 1;
    packet.entries[6].parameter = 7;
    packet.entries[6].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, secondGroupIndices)];
    packet.entries[6].flags = 4;
    packet.entries[6].valueX = 255.0f;
    packet.entries[6].valueY = 0.0f;
    packet.entries[6].valueZ = 0.0f;
    packet.entries[7].stageIndex = 1;
    packet.entries[7].parameter = 0x15;
    packet.entries[7].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[7].flags = 0x4000;
    packet.entries[7].valueX = 0.0f;
    packet.entries[7].valueY = 2.0f;
    packet.entries[7].valueZ = 0.0f;
    packet.entries[8].stageIndex = 1;
    packet.entries[8].parameter = 0;
    packet.entries[8].vertexIndices = NULL;
    packet.entries[8].flags = 0x100;
    packet.entries[8].valueX = 0.0f;
    packet.entries[8].valueY = 0.0f;
    packet.entries[8].valueZ = -150.0f;
    packet.entries[9].stageIndex = 1;
    packet.entries[9].parameter = 0;
    packet.entries[9].vertexIndices = NULL;
    packet.entries[9].flags = 0x80000;
    packet.entries[9].valueX = 0.0f;
    packet.entries[9].valueY = 100.0f;
    packet.entries[9].valueZ = 0.0f;
    packet.entries[10].stageIndex = 1;
    packet.entries[10].parameter = 0;
    packet.entries[10].vertexIndices = NULL;
    packet.entries[10].flags = 0x400000;
    packet.entries[10].valueX = 0.0f;
    packet.entries[10].valueY = 0.0f;
    packet.entries[10].valueZ = 0.0f;
    packet.entries[11].stageIndex = 2;
    packet.entries[11].parameter = 0x15;
    packet.entries[11].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[11].flags = 0x4000;
    packet.entries[11].valueX = 0.0f;
    packet.entries[11].valueY = 2.0f;
    packet.entries[11].valueZ = 0.0f;
    packet.entries[12].stageIndex = 2;
    packet.entries[12].parameter = 0;
    packet.entries[12].vertexIndices = NULL;
    packet.entries[12].flags = 0x100;
    packet.entries[12].valueX = 0.0f;
    packet.entries[12].valueY = 0.0f;
    packet.entries[12].valueZ = -150.0f;
    packet.entries[13].stageIndex = 3;
    packet.entries[13].parameter = 0;
    packet.entries[13].vertexIndices = NULL;
    packet.entries[13].flags = 0x80000;
    packet.entries[13].valueX = 0.0f;
    packet.entries[13].valueY = -450.0f;
    packet.entries[13].valueZ = 0.0f;
    packet.entries[14].stageIndex = 3;
    packet.entries[14].parameter = 7;
    packet.entries[14].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, secondGroupIndices)];
    packet.entries[14].flags = 4;
    packet.entries[14].valueX = 0.0f;
    packet.entries[14].valueY = 0.0f;
    packet.entries[14].valueZ = 0.0f;
    packet.entries[15].stageIndex = 3;
    packet.entries[15].parameter = 0x15;
    packet.entries[15].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[15].flags = 0x4000;
    packet.entries[15].valueX = 0.0f;
    packet.entries[15].valueY = 2.0f;
    packet.entries[15].valueZ = 0.0f;
    packet.entries[16].stageIndex = 3;
    packet.entries[16].parameter = 0;
    packet.entries[16].vertexIndices = NULL;
    packet.entries[16].flags = 0x100;
    packet.entries[16].valueX = 0.0f;
    packet.entries[16].valueY = 0.0f;
    packet.entries[16].valueZ = -150.0f;
    packet.entries[17].stageIndex = 3;
    packet.entries[17].parameter = 0x15;
    packet.entries[17].vertexIndices = (s16*)&resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[17].flags = 2;
    packet.entries[17].valueX = 0.01f;
    packet.entries[17].valueY = 1.0f;
    packet.entries[17].valueZ = 0.01f;
    packet.entries[18].stageIndex = 3;
    packet.entries[18].parameter = 0;
    packet.entries[18].vertexIndices = NULL;
    packet.entries[18].flags = 0x400000;
    packet.entries[18].valueX = 0.0f;
    packet.entries[18].valueY = 200.0f;
    packet.entries[18].valueZ = 0.0f;
    packet.entries[18].stageIndex = 4;
    packet.entries[18].parameter = 0;
    packet.entries[18].vertexIndices = NULL;
    packet.entries[18].flags = 0x20000000;
    packet.entries[18].valueX = 999.0f;
    packet.entries[18].valueY = 18.0f;
    packet.entries[18].valueZ = 19.0f;
    packet.context.modeByte = 0;
    context = sourceObj;
    packet.context.sourceObject = context;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = 20;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc010080;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (context != NULL) {
            packet.context.position[0] += context->anim.worldPosX;
            packet.context.position[1] += context->anim.worldPosY;
            packet.context.position[2] += context->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.context.position[0] += params->posX;
            packet.context.position[1] += params->posY;
            packet.context.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll66EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll66EffectResourceView, triangleIndices)]), 0x155, 0);
}

void dll_66_release(void) {
}

void dll_66_initialise(void) {
}

Dll66ResourceDescriptor gDll66ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_66_initialise, dll_66_release, NULL, dll_66_spawnEffect, 0,
};
