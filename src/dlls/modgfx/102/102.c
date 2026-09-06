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

    packet.entries[0].layer = 0;
    packet.entries[0].flags = 0x15;
    packet.entries[0].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[0].mode = 4;
    packet.entries[0].x = 0.0f;
    packet.entries[0].y = 0.0f;
    packet.entries[0].z = 0.0f;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 0x15;
    packet.entries[1].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[1].mode = 2;
    packet.entries[1].x = 0.01f;
    packet.entries[1].y = 2.0f;
    packet.entries[1].z = 0.01f;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 0x50;
    packet.entries[2].tex = NULL;
    packet.entries[2].mode = 0x20000000;
    packet.entries[2].x = 999.0f;
    packet.entries[2].y = 18.0f;
    packet.entries[2].z = 19.0f;
    packet.entries[3].layer = 0;
    packet.entries[3].flags = 0;
    packet.entries[3].tex = NULL;
    packet.entries[3].mode = 0x80000;
    packet.entries[3].x = 0.0f;
    packet.entries[3].y = 450.0f;
    packet.entries[3].z = 0.0f;
    packet.entries[4].layer = 0;
    packet.entries[4].flags = 0;
    packet.entries[4].tex = NULL;
    packet.entries[4].mode = 0x400000;
    packet.entries[4].x = 0.0f;
    packet.entries[4].y = 100.0f;
    packet.entries[4].z = 0.0f;
    packet.entries[5].layer = 1;
    packet.entries[5].flags = 0x15;
    packet.entries[5].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[5].mode = 2;
    packet.entries[5].x = 200.0f;
    packet.entries[5].y = 1.0f;
    packet.entries[5].z = 200.0f;
    packet.entries[6].layer = 1;
    packet.entries[6].flags = 7;
    packet.entries[6].tex = &resourceData[offsetof(Dll66EffectResourceView, secondGroupIndices)];
    packet.entries[6].mode = 4;
    packet.entries[6].x = 255.0f;
    packet.entries[6].y = 0.0f;
    packet.entries[6].z = 0.0f;
    packet.entries[7].layer = 1;
    packet.entries[7].flags = 0x15;
    packet.entries[7].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[7].mode = 0x4000;
    packet.entries[7].x = 0.0f;
    packet.entries[7].y = 2.0f;
    packet.entries[7].z = 0.0f;
    packet.entries[8].layer = 1;
    packet.entries[8].flags = 0;
    packet.entries[8].tex = NULL;
    packet.entries[8].mode = 0x100;
    packet.entries[8].x = 0.0f;
    packet.entries[8].y = 0.0f;
    packet.entries[8].z = -150.0f;
    packet.entries[9].layer = 1;
    packet.entries[9].flags = 0;
    packet.entries[9].tex = NULL;
    packet.entries[9].mode = 0x80000;
    packet.entries[9].x = 0.0f;
    packet.entries[9].y = 100.0f;
    packet.entries[9].z = 0.0f;
    packet.entries[10].layer = 1;
    packet.entries[10].flags = 0;
    packet.entries[10].tex = NULL;
    packet.entries[10].mode = 0x400000;
    packet.entries[10].x = 0.0f;
    packet.entries[10].y = 0.0f;
    packet.entries[10].z = 0.0f;
    packet.entries[11].layer = 2;
    packet.entries[11].flags = 0x15;
    packet.entries[11].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[11].mode = 0x4000;
    packet.entries[11].x = 0.0f;
    packet.entries[11].y = 2.0f;
    packet.entries[11].z = 0.0f;
    packet.entries[12].layer = 2;
    packet.entries[12].flags = 0;
    packet.entries[12].tex = NULL;
    packet.entries[12].mode = 0x100;
    packet.entries[12].x = 0.0f;
    packet.entries[12].y = 0.0f;
    packet.entries[12].z = -150.0f;
    packet.entries[13].layer = 3;
    packet.entries[13].flags = 0;
    packet.entries[13].tex = NULL;
    packet.entries[13].mode = 0x80000;
    packet.entries[13].x = 0.0f;
    packet.entries[13].y = -450.0f;
    packet.entries[13].z = 0.0f;
    packet.entries[14].layer = 3;
    packet.entries[14].flags = 7;
    packet.entries[14].tex = &resourceData[offsetof(Dll66EffectResourceView, secondGroupIndices)];
    packet.entries[14].mode = 4;
    packet.entries[14].x = 0.0f;
    packet.entries[14].y = 0.0f;
    packet.entries[14].z = 0.0f;
    packet.entries[15].layer = 3;
    packet.entries[15].flags = 0x15;
    packet.entries[15].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[15].mode = 0x4000;
    packet.entries[15].x = 0.0f;
    packet.entries[15].y = 2.0f;
    packet.entries[15].z = 0.0f;
    packet.entries[16].layer = 3;
    packet.entries[16].flags = 0;
    packet.entries[16].tex = NULL;
    packet.entries[16].mode = 0x100;
    packet.entries[16].x = 0.0f;
    packet.entries[16].y = 0.0f;
    packet.entries[16].z = -150.0f;
    packet.entries[17].layer = 3;
    packet.entries[17].flags = 0x15;
    packet.entries[17].tex = &resourceData[offsetof(Dll66EffectResourceView, allVertexIndices)];
    packet.entries[17].mode = 2;
    packet.entries[17].x = 0.01f;
    packet.entries[17].y = 1.0f;
    packet.entries[17].z = 0.01f;
    packet.entries[18].layer = 3;
    packet.entries[18].flags = 0;
    packet.entries[18].tex = NULL;
    packet.entries[18].mode = 0x400000;
    packet.entries[18].x = 0.0f;
    packet.entries[18].y = 200.0f;
    packet.entries[18].z = 0.0f;
    packet.entries[18].layer = 4;
    packet.entries[18].flags = 0;
    packet.entries[18].tex = NULL;
    packet.entries[18].mode = 0x20000000;
    packet.entries[18].x = 999.0f;
    packet.entries[18].y = 18.0f;
    packet.entries[18].z = 19.0f;
    packet.modeByte = 0;
    context = sourceObj;
    packet.sourceObj = context;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 2;
    packet.drawGroupStride = 7;
    packet.initialStateByte = 0xe;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x1e;
    packet.commandCount = 20;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll66EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0xc010080;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (context != NULL) {
            packet.position[0] += context->anim.worldPosX;
            packet.position[1] += context->anim.worldPosY;
            packet.position[2] += context->anim.worldPosZ;
        } else {
            PartFxSpawnParams* params = (PartFxSpawnParams*)spawnParams;

            packet.position[0] += params->posX;
            packet.position[1] += params->posY;
            packet.position[2] += params->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll66EffectResourceData, 0x18,
                      &resourceData[offsetof(Dll66EffectResourceView, triangleIndices)], 0x155, 0);
}

void dll_66_release(void) {
}

void dll_66_initialise(void) {
}

Dll66ResourceDescriptor gDll66ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_66_initialise, dll_66_release, NULL, dll_66_spawnEffect, 0,
};
