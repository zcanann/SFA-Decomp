/*
 * dll_00A3 (DLL 163 / 0xA3) - bone-particle effect spawner.
 *
 * dll_A3_spawnEffect builds a 14-command effect description and submits it
 * through the modgfx interface.
 */
#include "main/dll/dll_00A3_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct DllA3EffectResourceView {
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
} DllA3EffectResourceView;

STATIC_ASSERT(offsetof(DllA3EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, triangleIndices) == 0x0D4);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, firstGroupIndices) == 0x164);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, secondGroupIndices) == 0x174);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, thirdGroupIndices) == 0x184);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, firstAndThirdGroupIndices) == 0x194);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(DllA3EffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(sizeof(DllA3EffectResourceView) == 0x1EC);

u16 gDllA3EffectResourceData[sizeof(DllA3EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x002a, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x0034, 0x0000, 0x0000, 0x0000, 0x03e8, 0x003f, 0x0000, 0x0000,
    0x0640, 0x03e8, 0x0000, 0x000f, 0x0362, 0x0640, 0x01f4, 0x000b, 0x000f,
    0x0362, 0x0640, 0xfe0c, 0x0016, 0x000f, 0x0000, 0x0640, 0xfc18, 0x0020,
    0x000f, 0xfc9e, 0x0640, 0xfe0c, 0x002a, 0x000f, 0xfc9e, 0x0640, 0x01f4,
    0x0034, 0x000f, 0x0000, 0x0640, 0x03e8, 0x003f, 0x000f, 0x0000, 0x1770,
    0x03e8, 0x0000, 0x001f, 0x0362, 0x1770, 0x01f4, 0x000b, 0x001f, 0x0362,
    0x1770, 0xfe0c, 0x0016, 0x001f, 0x0000, 0x1770, 0xfc18, 0x0020, 0x001f,
    0xfc9e, 0x1770, 0xfe0c, 0x002a, 0x001f, 0xfc9e, 0x1770, 0x01f4, 0x0034,
    0x001f, 0x0000, 0x1770, 0x03e8, 0x003f, 0x001f, 0x0000, 0x0000, 0x0001,
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
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0104, 0x003c, 0x003c, 0x0001,
    0x0104, 0x0000, 0x0000,
};

void dll_A3_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands = packet.entries;
    u8* resourceData = (u8*)(int)gDllA3EffectResourceData;
    u32 variantByte = (u8)variant;

    commands[0].stageIndex = 0;
    commands[0].parameter = 0x15;
    commands[0].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, allVertexIndices)];
    commands[0].flags = 4;
    commands[0].valueX = 0.0f;
    commands[0].valueY = 0.0f;
    commands[0].valueZ = 0.0f;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0xe;
    commands[1].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, firstAndThirdGroupIndices)];
    commands[1].flags = 2;
    commands[1].valueX = 0.95f;
    commands[1].valueY = 0.4f;
    commands[1].valueZ = 0.95f;
    commands[2].stageIndex = 0;
    commands[2].parameter = 7;
    commands[2].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, secondGroupIndices)];
    commands[2].flags = 2;
    commands[2].valueX = 0.95f;
    commands[2].valueY = 0.4f;
    commands[2].valueZ = 0.95f;
    commands[3].stageIndex = 1;
    commands[3].parameter = 7;
    commands[3].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, secondGroupIndices)];
    commands[3].flags = 4;
    commands[3].valueX = 255.0f;
    commands[3].valueY = 0.0f;
    commands[3].valueZ = 0.0f;
    commands[4].stageIndex = 1;
    commands[4].parameter = 7;
    commands[4].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, thirdGroupIndices)];
    commands[4].flags = 4;
    commands[4].valueX = 255.0f;
    commands[4].valueY = 0.0f;
    commands[4].valueZ = 0.0f;
    commands[5].stageIndex = 1;
    commands[5].parameter = 0x15;
    commands[5].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, allVertexIndices)];
    commands[5].flags = 0x100;
    commands[5].valueX = 0.0f;
    commands[5].valueY = 0.0f;
    commands[5].valueZ = 10.0f;
    commands[6].stageIndex = 2;
    commands[6].parameter = 0x3a;
    commands[6].vertexIndices = NULL;
    commands[6].flags = 0x1800000;
    commands[6].valueX = 0.0f;
    commands[6].valueY = 0.0f;
    commands[6].valueZ = 5.0f;
    commands[7].stageIndex = 2;
    commands[7].parameter = 0x15;
    commands[7].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, allVertexIndices)];
    commands[7].flags = 0x100;
    commands[7].valueX = 0.0f;
    commands[7].valueY = 0.0f;
    commands[7].valueZ = 10.0f;
    commands[8].stageIndex = 3;
    commands[8].parameter = 0x3a;
    commands[8].vertexIndices = NULL;
    commands[8].flags = 0x1800000;
    commands[8].valueX = 0.0f;
    commands[8].valueY = 0.0f;
    commands[8].valueZ = 5.0f;
    commands[9].stageIndex = 3;
    commands[9].parameter = 0x15;
    commands[9].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, allVertexIndices)];
    commands[9].flags = 0x100;
    commands[9].valueX = 0.0f;
    commands[9].valueY = 0.0f;
    commands[9].valueZ = 10.0f;
    commands[10].stageIndex = 4;
    commands[10].parameter = 2;
    commands[10].vertexIndices = NULL;
    commands[10].flags = 0x2000;
    commands[10].valueX = 0.0f;
    commands[10].valueY = 0.0f;
    commands[10].valueZ = 0.0f;
    commands[11].stageIndex = 5;
    commands[11].parameter = 7;
    commands[11].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, secondGroupIndices)];
    commands[11].flags = 4;
    commands[11].valueX = 0.0f;
    commands[11].valueY = 0.0f;
    commands[11].valueZ = 0.0f;
    commands[12].stageIndex = 5;
    commands[12].parameter = 7;
    commands[12].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, thirdGroupIndices)];
    commands[12].flags = 4;
    commands[12].valueX = 0.0f;
    commands[12].valueY = 0.0f;
    commands[12].valueZ = 0.0f;
    commands[13].stageIndex = 5;
    commands[13].parameter = 0x15;
    commands[13].vertexIndices = (s16*)&resourceData[offsetof(DllA3EffectResourceView, allVertexIndices)];
    commands[13].flags = 0x100;
    commands[13].valueX = 0.0f;
    commands[13].valueY = 0.0f;
    commands[13].valueZ = 10.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    if (variantByte != 0) {
        packet.context.scale = 0.1f * variantByte;
    } else {
        packet.context.scale = 1.0f;
    }
    packet.context.drawGroupCount = 2;
    packet.context.drawGroupStride = 7;
    packet.context.initialStateByte = 0xe;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x1e;
    packet.context.commandCount = 14;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(DllA3EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc0400c0;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (packet.context.sourceObject != NULL) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.context.position[0] += params->posX;
            packet.context.position[1] += params->posY;
            packet.context.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDllA3EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(DllA3EffectResourceView, triangleIndices)]), 0x5e0, 0);
}

void dll_A3_release(void) {
}

void dll_A3_initialise(void) {
}

DllA3ResourceDescriptor gDllA3ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_A3_initialise, dll_A3_release, NULL, dll_A3_spawnEffect, 0,
};
