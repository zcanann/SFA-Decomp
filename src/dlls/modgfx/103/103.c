/*
 * DLL 103 / 0x67 - a gameplay-preview effect spawner.
 *
 * dll_67_spawnEffect builds a seven-command effect description and submits
 * it through the modgfx interface.
 */
#include "main/dll/dll_0067_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll67EffectResourceView {
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
} Dll67EffectResourceView;

STATIC_ASSERT(offsetof(Dll67EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, triangleIndices) == 0x0D4);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, firstGroupIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, secondGroupIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, thirdGroupIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, firstAndThirdGroupIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll67EffectResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(sizeof(Dll67EffectResourceView) == 0x1EC);

u16 gDll67EffectResourceData[sizeof(Dll67EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x002a, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x0034, 0x0000, 0x0000, 0x0000, 0x03e8, 0x003f, 0x0000, 0x0000,
    0x0bb8, 0x03e8, 0x0000, 0x003f, 0x0362, 0x0bb8, 0x01f4, 0x000b, 0x003f,
    0x0362, 0x0bb8, 0xfe0c, 0x0016, 0x003f, 0x0000, 0x0bb8, 0xfc18, 0x0020,
    0x003f, 0xfc9e, 0x0bb8, 0xfe0c, 0x002a, 0x003f, 0xfc9e, 0x0bb8, 0x01f4,
    0x0034, 0x003f, 0x0000, 0x0bb8, 0x03e8, 0x003f, 0x003f, 0x0000, 0x1770,
    0x03e8, 0x0000, 0x007f, 0x0362, 0x1770, 0x01f4, 0x000b, 0x007f, 0x0362,
    0x1770, 0xfe0c, 0x0016, 0x007f, 0x0000, 0x1770, 0xfc18, 0x0020, 0x007f,
    0xfc9e, 0x1770, 0xfe0c, 0x002a, 0x007f, 0xfc9e, 0x1770, 0x01f4, 0x0034,
    0x007f, 0x0000, 0x1770, 0x03e8, 0x003f, 0x007f, 0x0000, 0x0000, 0x0001,
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
    0x0012, 0x0013, 0x0014, 0x0000, 0x0000, 0x0032, 0x0064, 0x0032, 0x0000,
    0x0000, 0x0000, 0x0000,
};

void dll_67_spawnEffect(GameObject* sourceObj, int variant, void* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll67EffectResourceData;

    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 0x15;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, allVertexIndices)];
    packet.entries[0].flags = 4;
    packet.entries[0].valueX = 0.0f;
    packet.entries[0].valueY = 0.0f;
    packet.entries[0].valueZ = 0.0f;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 0x15;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, allVertexIndices)];
    packet.entries[1].flags = 2;
    packet.entries[1].valueX = 1.8f;
    packet.entries[1].valueY = 2.0f;
    packet.entries[1].valueZ = 1.8f;
    packet.entries[2].stageIndex = 1;
    packet.entries[2].parameter = 7;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, secondGroupIndices)];
    packet.entries[2].flags = 4;
    packet.entries[2].valueX = 255.0f;
    packet.entries[2].valueY = 0.0f;
    packet.entries[2].valueZ = 0.0f;
    packet.entries[3].stageIndex = 1;
    packet.entries[3].parameter = 0x15;
    packet.entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, allVertexIndices)];
    packet.entries[3].flags = 0x4000;
    packet.entries[3].valueX = 0.0f;
    packet.entries[3].valueY = -8.0f;
    packet.entries[3].valueZ = 0.0f;
    packet.entries[4].stageIndex = 2;
    packet.entries[4].parameter = 0x15;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, allVertexIndices)];
    packet.entries[4].flags = 0x4000;
    packet.entries[4].valueX = 0.0f;
    packet.entries[4].valueY = -8.0f;
    packet.entries[4].valueZ = 0.0f;
    packet.entries[5].stageIndex = 3;
    packet.entries[5].parameter = 7;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, secondGroupIndices)];
    packet.entries[5].flags = 4;
    packet.entries[5].valueX = 0.0f;
    packet.entries[5].valueY = 0.0f;
    packet.entries[5].valueZ = 0.0f;
    packet.entries[6].stageIndex = 3;
    packet.entries[6].parameter = 0x15;
    packet.entries[6].vertexIndices = (s16*)&resourceData[offsetof(Dll67EffectResourceView, allVertexIndices)];
    packet.entries[6].flags = 0x4000;
    packet.entries[6].valueX = 0.0f;
    packet.entries[6].valueY = -8.0f;
    packet.entries[6].valueZ = 0.0f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
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
    packet.context.commandCount = 7;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll67EffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
    packet.context.flags = 0xc010040;
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
        ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(int)gDll67EffectResourceData, 0x18,
                      (s16*)(&resourceData[offsetof(Dll67EffectResourceView, triangleIndices)]), 0xe3, 0);
}

void dll_67_release(void) {
}

void dll_67_initialise(void) {
}

Dll67ResourceDescriptor gDll67ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_67_initialise, dll_67_release, NULL, dll_67_spawnEffect, 0,
};
