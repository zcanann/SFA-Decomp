/*
 * DLL 111 / 0x6F - a modgfx effect spawner.
 */
#include "main/dll/dll_006F_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll6FEffectResourceView {
    ModgfxEffectVertex vertices[24];
    s16 triangles[16][3];
    s16 allVertexIndices[24];
    s16 eightVertexIndices[8];
    s16 twelveVertexIndices[12];
    s16 sequenceParams[7];
    u8 pad1B6[2];
} Dll6FEffectResourceView;

STATIC_ASSERT(offsetof(Dll6FEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll6FEffectResourceView, triangles) == 0x0F0);
STATIC_ASSERT(offsetof(Dll6FEffectResourceView, allVertexIndices) == 0x150);
STATIC_ASSERT(offsetof(Dll6FEffectResourceView, eightVertexIndices) == 0x180);
STATIC_ASSERT(offsetof(Dll6FEffectResourceView, twelveVertexIndices) == 0x190);
STATIC_ASSERT(offsetof(Dll6FEffectResourceView, sequenceParams) == 0x1A8);
STATIC_ASSERT(sizeof(Dll6FEffectResourceView) == 0x1B8);

s16 gDll6FFourVertexIndices[4] = {0, 6, 12, 18};

u16 gDll6FEffectResourceData[sizeof(Dll6FEffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x0000, 0x000f, 0x0000, 0x014d, 0x0028, 0x0000, 0x0000,
    0x000b, 0x00eb, 0x0028, 0xff15, 0x001f, 0x000b, 0x03e8, 0x0000, 0x0000,
    0x0000, 0x001f, 0x0355, 0x0000, 0xfe9f, 0x000f, 0x001f, 0x02c3, 0x0000,
    0xfd3d, 0x001f, 0x001f, 0x0000, 0x0000, 0x0000, 0x000f, 0x0000, 0x0000,
    0x0028, 0xfeb3, 0x0000, 0x000b, 0xff16, 0x0028, 0xff15, 0x001f, 0x000b,
    0x0000, 0x0000, 0xfc18, 0x0000, 0x001f, 0xfea0, 0x0000, 0xfcab, 0x000f,
    0x001f, 0xfd3e, 0x0000, 0xfd3d, 0x001f, 0x001f, 0x0000, 0x0000, 0x0000,
    0x000f, 0x0000, 0xfeb3, 0x0028, 0x0000, 0x0000, 0x000b, 0xff15, 0x0028,
    0x00ea, 0x001f, 0x000b, 0xfc18, 0x0000, 0x0000, 0x0000, 0x001f, 0xfcab,
    0x0000, 0x0160, 0x000f, 0x001f, 0xfd3d, 0x0000, 0x02c2, 0x001f, 0x001f,
    0x0000, 0x0000, 0x0000, 0x000f, 0x0000, 0x0000, 0x0028, 0x014d, 0x0000,
    0x000b, 0x00ea, 0x0028, 0x00eb, 0x001f, 0x000b, 0x0000, 0x0000, 0x03e8,
    0x0000, 0x001f, 0x0160, 0x0000, 0x0355, 0x000f, 0x001f, 0x02c2, 0x0000,
    0x02c3, 0x001f, 0x001f, 0x0000, 0x0002, 0x0001, 0x0001, 0x0004, 0x0003,
    0x0001, 0x0002, 0x0004, 0x0002, 0x0005, 0x0004, 0x0006, 0x0008, 0x0007,
    0x0007, 0x000a, 0x0009, 0x0007, 0x0008, 0x000a, 0x0008, 0x000b, 0x000a,
    0x000c, 0x000e, 0x000d, 0x000d, 0x0010, 0x000f, 0x000d, 0x000e, 0x0010,
    0x000e, 0x0011, 0x0010, 0x0012, 0x0013, 0x0014, 0x0013, 0x0016, 0x0015,
    0x0013, 0x0014, 0x0016, 0x0014, 0x0017, 0x0016, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b,
    0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014,
    0x0015, 0x0016, 0x0017, 0x0001, 0x0002, 0x0007, 0x0008, 0x000d, 0x000e,
    0x0013, 0x0014, 0x0003, 0x0004, 0x0005, 0x0009, 0x000a, 0x000b, 0x000f,
    0x0010, 0x0011, 0x0015, 0x0016, 0x0017, 0x0000, 0x0018, 0x0018, 0x0018,
    0x0018, 0x0000, 0x0000, 0x0000,
};

void dll_6F_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll6FEffectResourceData;
    GameObject* context;
    f32 originOffset = 0.0f;

    packet.entries[0].layer = 0;
    packet.entries[0].flags = 0x18;
    packet.entries[0].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[0].mode = 2;
    packet.entries[0].x = 3.0f;
    packet.entries[0].y = 16.0f;
    packet.entries[0].z = 3.0f;
    packet.entries[1].layer = 0;
    packet.entries[1].flags = 0x18;
    packet.entries[1].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[1].mode = 4;
    packet.entries[1].x = originOffset;
    packet.entries[1].y = originOffset;
    packet.entries[1].z = originOffset;
    packet.entries[2].layer = 0;
    packet.entries[2].flags = 0x18;
    packet.entries[2].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[2].mode = 8;
    packet.entries[2].x = 255.0f;
    packet.entries[2].y = 255.0f;
    packet.entries[2].z = originOffset;
    packet.entries[3].layer = 0;
    packet.entries[3].flags = 0x18;
    packet.entries[3].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[3].mode = 8;
    packet.entries[3].x = 255.0f;
    packet.entries[3].y = 255.0f;
    packet.entries[3].z = originOffset;
    packet.entries[4].layer = 0;
    packet.entries[4].flags = 8;
    packet.entries[4].tex = &resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[4].mode = 8;
    packet.entries[4].x = 255.0f;
    packet.entries[4].y = 155.0f;
    packet.entries[4].z = originOffset;
    packet.entries[5].layer = 0;
    packet.entries[5].flags = 0xc;
    packet.entries[5].tex = &resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[5].mode = 8;
    packet.entries[5].x = 235.0f;
    packet.entries[5].y = originOffset;
    packet.entries[5].z = originOffset;
    packet.entries[6].layer = 0;
    packet.entries[6].flags = 0x7a;
    packet.entries[6].tex = NULL;
    packet.entries[6].mode = 0x10000;
    packet.entries[6].x = originOffset;
    packet.entries[6].y = originOffset;
    packet.entries[6].z = originOffset;
    packet.entries[7].layer = 0;
    packet.entries[7].flags = 0x14;
    packet.entries[7].tex = NULL;
    packet.entries[7].mode = 0x800000;
    packet.entries[7].x = 1.0f;
    packet.entries[7].y = originOffset;
    packet.entries[7].z = originOffset;
    packet.entries[8].layer = 0;
    packet.entries[8].flags = 0x11;
    packet.entries[8].tex = NULL;
    packet.entries[8].mode = 0x800000;
    packet.entries[8].x = 40.0f;
    packet.entries[8].y = originOffset;
    packet.entries[8].z = originOffset;
    packet.entries[9].layer = 0;
    packet.entries[9].flags = 1;
    packet.entries[9].tex = NULL;
    packet.entries[9].mode = 0x2008000;
    packet.entries[9].x = 255.0f;
    packet.entries[9].y = 155.0f;
    packet.entries[9].z = originOffset;
    packet.entries[10].layer = 0;
    packet.entries[10].flags = 0;
    packet.entries[10].tex = NULL;
    packet.entries[10].mode = 0x80000;
    packet.entries[10].x = originOffset;
    packet.entries[10].y = 10.0f;
    packet.entries[10].z = originOffset;
    packet.entries[11].layer = 0;
    packet.entries[11].flags = 0;
    packet.entries[11].tex = NULL;
    packet.entries[11].mode = 0x100;
    packet.entries[11].x = originOffset;
    packet.entries[11].y = originOffset;
    packet.entries[11].z = 200.0f;
    packet.entries[12].layer = 1;
    packet.entries[12].flags = 4;
    packet.entries[12].tex = gDll6FFourVertexIndices;
    packet.entries[12].mode = 4;
    packet.entries[12].x = 85.0f;
    packet.entries[12].y = originOffset;
    packet.entries[12].z = originOffset;
    packet.entries[13].layer = 1;
    packet.entries[13].flags = 8;
    packet.entries[13].tex = &resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[13].mode = 4;
    packet.entries[13].x = 25.0f;
    packet.entries[13].y = originOffset;
    packet.entries[13].z = originOffset;
    packet.entries[14].layer = 1;
    packet.entries[14].flags = 0x18;
    packet.entries[14].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[14].mode = 0x4000;
    packet.entries[14].x = originOffset;
    packet.entries[14].y = -0.6f;
    packet.entries[14].z = originOffset;
    packet.entries[15].layer = 1;
    packet.entries[15].flags = 0x7a;
    packet.entries[15].tex = NULL;
    packet.entries[15].mode = 0x10000;
    packet.entries[15].x = 1.0f;
    packet.entries[15].y = originOffset;
    packet.entries[15].z = originOffset;
    packet.entries[16].layer = 1;
    packet.entries[16].flags = 0;
    packet.entries[16].tex = NULL;
    packet.entries[16].mode = 0x100;
    packet.entries[16].x = originOffset;
    packet.entries[16].y = originOffset;
    packet.entries[16].z = 200.0f;
    packet.entries[17].layer = 2;
    packet.entries[17].flags = 4;
    packet.entries[17].tex = gDll6FFourVertexIndices;
    packet.entries[17].mode = 4;
    packet.entries[17].x = originOffset;
    packet.entries[17].y = originOffset;
    packet.entries[17].z = originOffset;
    packet.entries[18].layer = 2;
    packet.entries[18].flags = 8;
    packet.entries[18].tex = &resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[18].mode = 4;
    packet.entries[18].x = 155.0f;
    packet.entries[18].y = originOffset;
    packet.entries[18].z = originOffset;
    packet.entries[19].layer = 2;
    packet.entries[19].flags = 0x18;
    packet.entries[19].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[19].mode = 0x4000;
    packet.entries[19].x = originOffset;
    packet.entries[19].y = -0.6f;
    packet.entries[19].z = originOffset;
    packet.entries[20].layer = 2;
    packet.entries[20].flags = 0;
    packet.entries[20].tex = NULL;
    packet.entries[20].mode = 0x80000;
    packet.entries[20].x = originOffset;
    packet.entries[20].y = 30.0f;
    packet.entries[20].z = originOffset;
    packet.entries[21].layer = 2;
    packet.entries[21].flags = 0;
    packet.entries[21].tex = NULL;
    packet.entries[21].mode = 0x100;
    packet.entries[21].x = originOffset;
    packet.entries[21].y = originOffset;
    packet.entries[21].z = 200.0f;
    packet.entries[22].layer = 3;
    packet.entries[22].flags = 8;
    packet.entries[22].tex = &resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[22].mode = 4;
    packet.entries[22].x = originOffset;
    packet.entries[22].y = originOffset;
    packet.entries[22].z = originOffset;
    packet.entries[23].layer = 3;
    packet.entries[23].flags = 0xc;
    packet.entries[23].tex = &resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[23].mode = 4;
    packet.entries[23].x = 115.0f;
    packet.entries[23].y = originOffset;
    packet.entries[23].z = originOffset;
    packet.entries[24].layer = 3;
    packet.entries[24].flags = 0x18;
    packet.entries[24].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[24].mode = 0x4000;
    packet.entries[24].x = originOffset;
    packet.entries[24].y = -0.6f;
    packet.entries[24].z = originOffset;
    packet.entries[25].layer = 3;
    packet.entries[25].flags = 0;
    packet.entries[25].tex = NULL;
    packet.entries[25].mode = 0x100;
    packet.entries[25].x = originOffset;
    packet.entries[25].y = originOffset;
    packet.entries[25].z = 200.0f;
    packet.entries[26].layer = 4;
    packet.entries[26].flags = 0xc;
    packet.entries[26].tex = &resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[26].mode = 4;
    packet.entries[26].x = originOffset;
    packet.entries[26].y = originOffset;
    packet.entries[26].z = originOffset;
    packet.entries[27].layer = 4;
    packet.entries[27].flags = 0x18;
    packet.entries[27].tex = &resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[27].mode = 0x4000;
    packet.entries[27].x = originOffset;
    packet.entries[27].y = -0.6f;
    packet.entries[27].z = originOffset;
    packet.entries[28].layer = 4;
    packet.entries[28].flags = 0;
    packet.entries[28].tex = NULL;
    packet.entries[28].mode = 0x2008000;
    packet.entries[28].x = 255.0f;
    packet.entries[28].y = 155.0f;
    packet.entries[28].z = originOffset;
    packet.entries[29].layer = 4;
    packet.entries[29].flags = 0;
    packet.entries[29].tex = NULL;
    packet.entries[29].mode = 0x100;
    packet.entries[29].x = originOffset;
    packet.entries[29].y = originOffset;
    packet.entries[29].z = 200.0f;
    packet.modeByte = 0;
    context = sourceObj;
    packet.sourceObj = context;
    packet.sourceMode = variant;
    packet.position[0] = originOffset;
    packet.position[1] = originOffset;
    packet.position[2] = originOffset;
    packet.velocity[0] = originOffset;
    packet.velocity[1] = originOffset;
    packet.velocity[2] = originOffset;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 0x18;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0x10;
    packet.flags = 0x4000084;
    packet.commandCount = 0x14;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (context != NULL) {
            packet.position[0] = originOffset + context->anim.worldPosX;
            packet.position[1] = originOffset + context->anim.worldPosY;
            packet.position[2] = originOffset + context->anim.worldPosZ;
        } else {
            packet.position[0] = originOffset + spawnParams->posX;
            packet.position[1] = originOffset + spawnParams->posY;
            packet.position[2] = originOffset + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&packet, 0, 0x18, (u8*)(int)gDll6FEffectResourceData, 0x10,
                      &resourceData[offsetof(Dll6FEffectResourceView, triangles)], 0x48, 0);
}

void dll_6F_release(void) {
}

void dll_6F_initialise(void) {
}

Dll6FResourceDescriptor gDll6FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6F_initialise, dll_6F_release, NULL, dll_6F_spawnEffect,
};
