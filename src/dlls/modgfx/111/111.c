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

    packet.entries[0].stageIndex = 0;
    packet.entries[0].parameter = 0x18;
    packet.entries[0].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[0].flags = 2;
    packet.entries[0].valueX = 3.0f;
    packet.entries[0].valueY = 16.0f;
    packet.entries[0].valueZ = 3.0f;
    packet.entries[1].stageIndex = 0;
    packet.entries[1].parameter = 0x18;
    packet.entries[1].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[1].flags = 4;
    packet.entries[1].valueX = originOffset;
    packet.entries[1].valueY = originOffset;
    packet.entries[1].valueZ = originOffset;
    packet.entries[2].stageIndex = 0;
    packet.entries[2].parameter = 0x18;
    packet.entries[2].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[2].flags = 8;
    packet.entries[2].valueX = 255.0f;
    packet.entries[2].valueY = 255.0f;
    packet.entries[2].valueZ = originOffset;
    packet.entries[3].stageIndex = 0;
    packet.entries[3].parameter = 0x18;
    packet.entries[3].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[3].flags = 8;
    packet.entries[3].valueX = 255.0f;
    packet.entries[3].valueY = 255.0f;
    packet.entries[3].valueZ = originOffset;
    packet.entries[4].stageIndex = 0;
    packet.entries[4].parameter = 8;
    packet.entries[4].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[4].flags = 8;
    packet.entries[4].valueX = 255.0f;
    packet.entries[4].valueY = 155.0f;
    packet.entries[4].valueZ = originOffset;
    packet.entries[5].stageIndex = 0;
    packet.entries[5].parameter = 0xc;
    packet.entries[5].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[5].flags = 8;
    packet.entries[5].valueX = 235.0f;
    packet.entries[5].valueY = originOffset;
    packet.entries[5].valueZ = originOffset;
    packet.entries[6].stageIndex = 0;
    packet.entries[6].parameter = 0x7a;
    packet.entries[6].vertexIndices = NULL;
    packet.entries[6].flags = 0x10000;
    packet.entries[6].valueX = originOffset;
    packet.entries[6].valueY = originOffset;
    packet.entries[6].valueZ = originOffset;
    packet.entries[7].stageIndex = 0;
    packet.entries[7].parameter = 0x14;
    packet.entries[7].vertexIndices = NULL;
    packet.entries[7].flags = 0x800000;
    packet.entries[7].valueX = 1.0f;
    packet.entries[7].valueY = originOffset;
    packet.entries[7].valueZ = originOffset;
    packet.entries[8].stageIndex = 0;
    packet.entries[8].parameter = 0x11;
    packet.entries[8].vertexIndices = NULL;
    packet.entries[8].flags = 0x800000;
    packet.entries[8].valueX = 40.0f;
    packet.entries[8].valueY = originOffset;
    packet.entries[8].valueZ = originOffset;
    packet.entries[9].stageIndex = 0;
    packet.entries[9].parameter = 1;
    packet.entries[9].vertexIndices = NULL;
    packet.entries[9].flags = 0x2008000;
    packet.entries[9].valueX = 255.0f;
    packet.entries[9].valueY = 155.0f;
    packet.entries[9].valueZ = originOffset;
    packet.entries[10].stageIndex = 0;
    packet.entries[10].parameter = 0;
    packet.entries[10].vertexIndices = NULL;
    packet.entries[10].flags = 0x80000;
    packet.entries[10].valueX = originOffset;
    packet.entries[10].valueY = 10.0f;
    packet.entries[10].valueZ = originOffset;
    packet.entries[11].stageIndex = 0;
    packet.entries[11].parameter = 0;
    packet.entries[11].vertexIndices = NULL;
    packet.entries[11].flags = 0x100;
    packet.entries[11].valueX = originOffset;
    packet.entries[11].valueY = originOffset;
    packet.entries[11].valueZ = 200.0f;
    packet.entries[12].stageIndex = 1;
    packet.entries[12].parameter = 4;
    packet.entries[12].vertexIndices = (s16*)(gDll6FFourVertexIndices);
    packet.entries[12].flags = 4;
    packet.entries[12].valueX = 85.0f;
    packet.entries[12].valueY = originOffset;
    packet.entries[12].valueZ = originOffset;
    packet.entries[13].stageIndex = 1;
    packet.entries[13].parameter = 8;
    packet.entries[13].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[13].flags = 4;
    packet.entries[13].valueX = 25.0f;
    packet.entries[13].valueY = originOffset;
    packet.entries[13].valueZ = originOffset;
    packet.entries[14].stageIndex = 1;
    packet.entries[14].parameter = 0x18;
    packet.entries[14].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[14].flags = 0x4000;
    packet.entries[14].valueX = originOffset;
    packet.entries[14].valueY = -0.6f;
    packet.entries[14].valueZ = originOffset;
    packet.entries[15].stageIndex = 1;
    packet.entries[15].parameter = 0x7a;
    packet.entries[15].vertexIndices = NULL;
    packet.entries[15].flags = 0x10000;
    packet.entries[15].valueX = 1.0f;
    packet.entries[15].valueY = originOffset;
    packet.entries[15].valueZ = originOffset;
    packet.entries[16].stageIndex = 1;
    packet.entries[16].parameter = 0;
    packet.entries[16].vertexIndices = NULL;
    packet.entries[16].flags = 0x100;
    packet.entries[16].valueX = originOffset;
    packet.entries[16].valueY = originOffset;
    packet.entries[16].valueZ = 200.0f;
    packet.entries[17].stageIndex = 2;
    packet.entries[17].parameter = 4;
    packet.entries[17].vertexIndices = (s16*)(gDll6FFourVertexIndices);
    packet.entries[17].flags = 4;
    packet.entries[17].valueX = originOffset;
    packet.entries[17].valueY = originOffset;
    packet.entries[17].valueZ = originOffset;
    packet.entries[18].stageIndex = 2;
    packet.entries[18].parameter = 8;
    packet.entries[18].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[18].flags = 4;
    packet.entries[18].valueX = 155.0f;
    packet.entries[18].valueY = originOffset;
    packet.entries[18].valueZ = originOffset;
    packet.entries[19].stageIndex = 2;
    packet.entries[19].parameter = 0x18;
    packet.entries[19].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[19].flags = 0x4000;
    packet.entries[19].valueX = originOffset;
    packet.entries[19].valueY = -0.6f;
    packet.entries[19].valueZ = originOffset;
    packet.entries[20].stageIndex = 2;
    packet.entries[20].parameter = 0;
    packet.entries[20].vertexIndices = NULL;
    packet.entries[20].flags = 0x80000;
    packet.entries[20].valueX = originOffset;
    packet.entries[20].valueY = 30.0f;
    packet.entries[20].valueZ = originOffset;
    packet.entries[21].stageIndex = 2;
    packet.entries[21].parameter = 0;
    packet.entries[21].vertexIndices = NULL;
    packet.entries[21].flags = 0x100;
    packet.entries[21].valueX = originOffset;
    packet.entries[21].valueY = originOffset;
    packet.entries[21].valueZ = 200.0f;
    packet.entries[22].stageIndex = 3;
    packet.entries[22].parameter = 8;
    packet.entries[22].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, eightVertexIndices)];
    packet.entries[22].flags = 4;
    packet.entries[22].valueX = originOffset;
    packet.entries[22].valueY = originOffset;
    packet.entries[22].valueZ = originOffset;
    packet.entries[23].stageIndex = 3;
    packet.entries[23].parameter = 0xc;
    packet.entries[23].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[23].flags = 4;
    packet.entries[23].valueX = 115.0f;
    packet.entries[23].valueY = originOffset;
    packet.entries[23].valueZ = originOffset;
    packet.entries[24].stageIndex = 3;
    packet.entries[24].parameter = 0x18;
    packet.entries[24].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[24].flags = 0x4000;
    packet.entries[24].valueX = originOffset;
    packet.entries[24].valueY = -0.6f;
    packet.entries[24].valueZ = originOffset;
    packet.entries[25].stageIndex = 3;
    packet.entries[25].parameter = 0;
    packet.entries[25].vertexIndices = NULL;
    packet.entries[25].flags = 0x100;
    packet.entries[25].valueX = originOffset;
    packet.entries[25].valueY = originOffset;
    packet.entries[25].valueZ = 200.0f;
    packet.entries[26].stageIndex = 4;
    packet.entries[26].parameter = 0xc;
    packet.entries[26].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, twelveVertexIndices)];
    packet.entries[26].flags = 4;
    packet.entries[26].valueX = originOffset;
    packet.entries[26].valueY = originOffset;
    packet.entries[26].valueZ = originOffset;
    packet.entries[27].stageIndex = 4;
    packet.entries[27].parameter = 0x18;
    packet.entries[27].vertexIndices = (s16*)&resourceData[offsetof(Dll6FEffectResourceView, allVertexIndices)];
    packet.entries[27].flags = 0x4000;
    packet.entries[27].valueX = originOffset;
    packet.entries[27].valueY = -0.6f;
    packet.entries[27].valueZ = originOffset;
    packet.entries[28].stageIndex = 4;
    packet.entries[28].parameter = 0;
    packet.entries[28].vertexIndices = NULL;
    packet.entries[28].flags = 0x2008000;
    packet.entries[28].valueX = 255.0f;
    packet.entries[28].valueY = 155.0f;
    packet.entries[28].valueZ = originOffset;
    packet.entries[29].stageIndex = 4;
    packet.entries[29].parameter = 0;
    packet.entries[29].vertexIndices = NULL;
    packet.entries[29].flags = 0x100;
    packet.entries[29].valueX = originOffset;
    packet.entries[29].valueY = originOffset;
    packet.entries[29].valueZ = 200.0f;
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
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0x18;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0x10;
    packet.context.flags = 0x4000084;
    packet.context.commandCount = 0x14;
    packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[0])];
    packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[1])];
    packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[2])];
    packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[3])];
    packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[4])];
    packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[5])];
    packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll6FEffectResourceView, sequenceParams[6])];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + 0x60);
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
        ->spawnEffect(&packet.context, 0, 0x18, (ModgfxEffectVertex*)(int)gDll6FEffectResourceData, 0x10,
                      (s16*)(&resourceData[offsetof(Dll6FEffectResourceView, triangles)]), 0x48, 0);
}

void dll_6F_release(void) {
}

void dll_6F_initialise(void) {
}

Dll6FResourceDescriptor gDll6FResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_6F_initialise, dll_6F_release, NULL, dll_6F_spawnEffect,
};
