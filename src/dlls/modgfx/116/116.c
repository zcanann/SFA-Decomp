/*
 * DLL 116 / 0x74 - a two-variant modgfx effect spawner.
 */
#include "main/dll/dll_0074_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll74EffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 padD2[2];
    s16 triangles[24][3];
    s16 firstSevenVertexIndices[8];
    s16 secondSevenVertexIndices[8];
    s16 thirdSevenVertexIndices[8];
    s16 firstAndThirdVertexIndices[14];
    s16 allVertexIndices[22];
    s16 lastFourteenVertexIndices[14];
    s16 firstFourteenVertexIndices[14];
    s16 sequenceParams[7];
    u8 pad222[2];
} Dll74EffectResourceView;

STATIC_ASSERT(offsetof(Dll74EffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, firstSevenVertexIndices) == 0x164);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, secondSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, thirdSevenVertexIndices) == 0x184);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, firstAndThirdVertexIndices) == 0x194);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, lastFourteenVertexIndices) == 0x1DC);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, firstFourteenVertexIndices) == 0x1F8);
STATIC_ASSERT(offsetof(Dll74EffectResourceView, sequenceParams) == 0x214);
STATIC_ASSERT(sizeof(Dll74EffectResourceView) == 0x224);

u16 gDll74EffectResourceData[sizeof(Dll74EffectResourceView) / sizeof(u16)] = {
    0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0362, 0x0000, 0x01f4, 0x000b,
    0x0000, 0x0362, 0x0000, 0xfe0c, 0x0016, 0x0000, 0x0000, 0x0000, 0xfc18,
    0x0020, 0x0000, 0xfc9e, 0x0000, 0xfe0c, 0x0016, 0x0000, 0xfc9e, 0x0000,
    0x01f4, 0x000b, 0x0000, 0x0000, 0x0000, 0x03e8, 0x0000, 0x0000, 0x0000,
    0x157c, 0x03e8, 0x0000, 0x003b, 0x0362, 0x157c, 0x01f4, 0x000b, 0x003b,
    0x0362, 0x157c, 0xfe0c, 0x0016, 0x003b, 0x0000, 0x157c, 0xfc18, 0x0020,
    0x003b, 0xfc9e, 0x157c, 0xfe0c, 0x0016, 0x003b, 0xfc9e, 0x157c, 0x01f4,
    0x000b, 0x003b, 0x0000, 0x157c, 0x03e8, 0x0000, 0x003b, 0x0000, 0x1770,
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
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
    0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0000, 0x000a, 0x00b4, 0x0028,
    0x0000, 0x0000, 0x0000, 0x0000,
};

void dll_74_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    GfxCmd* commandCursor;
    u8* resourceData = (u8*)(int)gDll74EffectResourceData;
    GfxCmd* commands = packet.entries;
    commands[0].layer = 0;
    commands[0].flags = 0x15;
    commands[0].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
    commands[0].mode = 4;
    commands[0].x = 0.0f;
    commands[0].y = 0.0f;
    commands[0].z = 0.0f;
    if (variant == 0) {
        commands[1].layer = 0;
        commands[1].flags = 0x15;
        commands[1].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commands[1].mode = 2;
        commands[1].x = 0.01f;
        commands[1].y = 1.0f;
        commands[1].z = 0.01f;
        commandCursor = &commands[2];
    } else {
        commands[1].layer = 0;
        commands[1].flags = 0x15;
        commands[1].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commands[1].mode = 2;
        commands[1].x = 0.01f;
        commands[1].y = 3.0f;
        commands[1].z = 0.01f;
        commandCursor = &commands[2];
    }
    if (variant == 0) {
        commandCursor->layer = 0;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x400000;
        commandCursor->x = 0.0f;
        commandCursor->y = -90.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    } else {
        commandCursor->layer = 0;
        commandCursor->flags = 0;
        commandCursor->tex = NULL;
        commandCursor->mode = 0x400000;
        commandCursor->x = 0.0f;
        commandCursor->y = -290.0f;
        commandCursor->z = 0.0f;
        commandCursor++;
    }
    commandCursor[0].layer = 1;
    commandCursor[0].flags = 0x15;
    commandCursor[0].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
    commandCursor[0].mode = 2;
    commandCursor[0].x = 70.0f;
    commandCursor[0].y = 1.5f;
    commandCursor[0].z = 70.0f;
    commandCursor[1].layer = 1;
    commandCursor[1].flags = 0xe;
    commandCursor[1].tex = &resourceData[offsetof(Dll74EffectResourceView, firstFourteenVertexIndices)];
    commandCursor[1].mode = 4;
    commandCursor[1].x = 255.0f;
    commandCursor[1].y = 0.0f;
    commandCursor[1].z = 0.0f;
    if (variant == 0) {
        commandCursor[2].layer = 1;
        commandCursor[2].flags = 0x15;
        commandCursor[2].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commandCursor[2].mode = 0x4000;
        commandCursor[2].x = 0.0f;
        commandCursor[2].y = 4.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    } else {
        commandCursor[2].layer = 1;
        commandCursor[2].flags = 0x15;
        commandCursor[2].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commandCursor[2].mode = 0x4000;
        commandCursor[2].x = 0.0f;
        commandCursor[2].y = -4.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    }
    commandCursor[0].layer = 2;
    commandCursor[0].flags = 7;
    commandCursor[0].tex = &resourceData[offsetof(Dll74EffectResourceView, firstSevenVertexIndices)];
    commandCursor[0].mode = 2;
    commandCursor[0].x = 17.0f;
    commandCursor[0].y = 1.0f;
    commandCursor[0].z = 17.0f;
    commandCursor[1].layer = 2;
    commandCursor[1].flags = 7;
    commandCursor[1].tex = &resourceData[offsetof(Dll74EffectResourceView, secondSevenVertexIndices)];
    commandCursor[1].mode = 2;
    commandCursor[1].x = 1.5f;
    commandCursor[1].y = 1.0f;
    commandCursor[1].z = 1.5f;
    if (variant == 0) {
        commandCursor[2].layer = 2;
        commandCursor[2].flags = 0x15;
        commandCursor[2].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commandCursor[2].mode = 0x4000;
        commandCursor[2].x = 0.0f;
        commandCursor[2].y = 4.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    } else {
        commandCursor[2].layer = 2;
        commandCursor[2].flags = 0x15;
        commandCursor[2].tex = &resourceData[offsetof(Dll74EffectResourceView, allVertexIndices)];
        commandCursor[2].mode = 0x4000;
        commandCursor[2].x = 0.0f;
        commandCursor[2].y = -4.0f;
        commandCursor[2].z = 0.0f;
        commandCursor += 3;
    }
    commandCursor[0].layer = 2;
    commandCursor[0].flags = 0xe;
    commandCursor[0].tex = &resourceData[offsetof(Dll74EffectResourceView, firstFourteenVertexIndices)];
    commandCursor[0].mode = 4;
    commandCursor[0].x = 0.0f;
    commandCursor[0].y = 0.0f;
    commandCursor[0].z = 0.0f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
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
    packet.commandCount = (commandCursor + 1) - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll74EffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + 0x60);
    packet.flags = 0xc0104c0;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.position[0] += sourceObj->anim.localPosX;
            packet.position[1] += sourceObj->anim.localPosY;
            packet.position[2] += sourceObj->anim.localPosZ;
        } else {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    if (variant == 0) {
        (*gModgfxInterface)
            ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll74EffectResourceData, 0x18,
                          &resourceData[offsetof(Dll74EffectResourceView, triangles)], 0x2e, 0);
    } else {
        (*gModgfxInterface)
            ->spawnEffect(&packet, 0, 0x15, (u8*)(int)gDll74EffectResourceData, 0x18,
                          &resourceData[offsetof(Dll74EffectResourceView, triangles)], 0xd9, 0);
    }
}

void dll_74_release(void) {
}

void dll_74_initialise(void) {
}

Dll74ResourceDescriptor gDll74ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_74_initialise, dll_74_release, NULL, dll_74_spawnEffect, 0,
};
