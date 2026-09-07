/*
 * DLL 141 / 0x8D - a three-variant layered modgfx effect spawner.
 */
#include "main/dll/dll_008D_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll8DEffectResourceView {
    ModgfxEffectVertex vertices[9];
    u8 opaque5A[2];
    s16 triangles[8][3];
    s16 nineVertexIndices[10];
    s16 eightVertexIndices[8];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8DEffectResourceView;

STATIC_ASSERT(offsetof(Dll8DEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, opaque5A) == 0x5A);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, triangles) == 0x5C);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, nineVertexIndices) == 0x8C);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, eightVertexIndices) == 0xA0);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, sequenceParams) == 0xB0);
STATIC_ASSERT(offsetof(Dll8DEffectResourceView, opaqueTail) == 0xBE);
STATIC_ASSERT(sizeof(Dll8DEffectResourceView) == 0xC0);

extern u8 gDll8DEffectResourceData[sizeof(Dll8DEffectResourceView)];

s16 dll_8D_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)(int)gDll8DEffectResourceData;
    GfxCmd* command;
    GfxCmd* commands;
    s16 ret = 0;
    f32 jitter;

    commands = packet.entries;
    command = (GfxCmd*)commands;

    if (variant == 0) {
        command->layer = 0;
        command->flags = 0x8c;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 94.0f;
        command->z = 95.0f;
        command++;
        command->layer = 0;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->x = anchorParams->posX;
            command->y = anchorParams->posY;
            command->z = anchorParams->posZ;
            command++;
        } else {
            command->x = 0.0f;
            command->y = 32640.0f;
            command->z = 0.0f;
            command++;
        }
        command->layer = 0;
        command->flags = 8;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 2;
        command->x = 3.2f;
        command->y = 3.2f;
        command->z = 30.0f;
        command++;
    } else if (variant == 1) {
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])] = 0x50;
        command->layer = 0;
        command->flags = 2;
        command->tex = NULL;
        command->mode = 0x1800000;
        command->x = 1.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
        command->layer = 0;
        command->flags = 0x69;
        command->tex = NULL;
        command->mode = 0x1800000;
        command->x = 1.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
        command->layer = 0;
        command->flags = 8;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        command->y = command->x = 5.0f + jitter;
        command->z = 28.0f + jitter;
        command++;
        command->layer = 0;
        command->flags = 0x8c;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 96.0f;
        command->z = 97.0f;
        command++;
        command->layer = 0;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->x = anchorParams->posX;
            command->y = anchorParams->posY;
            command->z = anchorParams->posZ;
            command++;
        } else {
            command->x = 0.0f;
            command->y = 32640.0f;
            command->z = 0.0f;
            command++;
        }
    } else if (variant == 2) {
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])] = 0x50;
        *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])] = 0x50;
        command->layer = 0;
        command->flags = 0x1fc;
        command->tex = NULL;
        command->mode = 0x1800000;
        command->x = 1.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
        command->layer = 0;
        command->flags = 8;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 2;
        jitter = 0.05f * randomGetRange(0, 0xc);
        command->y = command->x = 1.2f + jitter;
        command->z = 12.0f + jitter;
        command++;
        command->layer = 0;
        command->flags = 0x8c;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 96.0f;
        command->z = 97.0f;
        command++;
        command->layer = 0;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x80;
        if ((u32)spawnParams != 0) {
            PartFxSpawnParams* anchorParams = spawnParams;
            command->x = anchorParams->posX;
            command->y = anchorParams->posY;
            command->z = anchorParams->posZ;
            command++;
        } else {
            command->x = 0.0f;
            command->y = 32640.0f;
            command->z = 0.0f;
            command++;
        }
    }
    if (variant == 0) {
        command[0].layer = 1;
        command[0].flags = 9;
        command[0].tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].mode = 0x4000;
        command[0].x = 0.0f;
        command[0].y = 0.0f;
        command[0].z = 0.0f;
        command[1].layer = 1;
        command[1].flags = 0x68;
        command[1].tex = NULL;
        command[1].mode = 0x800000;
        command[1].x = 1.0f;
        command[1].y = 0.0f;
        command[1].z = 0.0f;
        command[2].layer = 1;
        command[2].flags = 8;
        command[2].tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[2].mode = 2;
        command[2].x = 0.5f;
        command[2].y = 0.5f;
        command[2].z = 0.5f;
        command += 3;
    } else if (variant == 1) {
        command[0].layer = 1;
        command[0].flags = 9;
        command[0].tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].mode = 0x4000;
        command[0].x = 0.0f;
        command[0].y = 0.0f;
        command[0].z = 0.0f;
        command[1].layer = 1;
        command[1].flags = 0x8f;
        command[1].tex = NULL;
        command[1].mode = 0x1800000;
        command[1].x = 2.0f;
        command[1].y = 0.0f;
        command[1].z = 0.0f;
        command += 2;
    } else if (variant == 2) {
        command[0].layer = 1;
        command[0].flags = 9;
        command[0].tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command[0].mode = 0x4000;
        command[0].x = 0.0f;
        command[0].y = 0.0f;
        command[0].z = 0.0f;
        command[1].layer = 1;
        command[1].flags = 0x1fd;
        command[1].tex = NULL;
        command[1].mode = 0x1800000;
        command[1].x = 2.0f;
        command[1].y = 0.0f;
        command[1].z = 0.0f;
        command += 2;
    }
    if (variant == 0) {
        command->layer = 1;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 400.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    } else if (variant == 1) {
        command->layer = 1;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 800.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    } else if (variant == 2) {
        command->layer = 1;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 800.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    }
    if (variant == 0) {
        command->layer = 2;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 400.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    } else if (variant == 1) {
        command->layer = 2;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 800.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    } else if (variant == 2) {
        command->layer = 2;
        command->flags = 9;
        command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
        command->mode = 0x100;
        command->x = 800.0f;
        command->y = 0.0f;
        command->z = 0.0f;
        command++;
    }
    command->layer = 2;
    command->flags = 9;
    command->tex = &resourceData[offsetof(Dll8DEffectResourceView, nineVertexIndices)];
    command->mode = 4;
    command->x = 0.0f;
    command->y = 0.0f;
    command->z = 0.0f;
    command++;
    if (variant == 0) {
        command->layer = 3;
        command->flags = 0;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 94.0f;
        command->z = 95.0f;
        command++;
    } else if (variant == 1) {
        command->layer = 3;
        command->flags = 0;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 96.0f;
        command->z = 97.0f;
        command++;
    } else if (variant == 2) {
        command->layer = 3;
        command->flags = 0;
        command->tex = NULL;
        command->mode = 0x20000000;
        command->x = 999.0f;
        command->y = 96.0f;
        command->z = 97.0f;
        command++;
    }
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    if (variant == 0) {
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
        packet.position[2] = 0.0f;
    } else {
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
        packet.position[2] = 0.0f;
    }
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 9;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = command - commands;
    packet.sequenceParams[0] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[0])];
    packet.sequenceParams[1] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[1])];
    packet.sequenceParams[2] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[2])];
    packet.sequenceParams[3] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[3])];
    packet.sequenceParams[4] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[4])];
    packet.sequenceParams[5] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[5])];
    packet.sequenceParams[6] = *(s16*)&resourceData[offsetof(Dll8DEffectResourceView, sequenceParams[6])];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4000000;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((u32)packet.sourceObj != 0) {
            GameObject* anchorObj = packet.sourceObj;
            packet.position[0] += anchorObj->anim.worldPosX;
            packet.position[1] += anchorObj->anim.worldPosY;
            packet.position[2] += anchorObj->anim.worldPosZ;
        } else {
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.position[0] += anchorParams->posX;
            packet.position[1] += anchorParams->posY;
            packet.position[2] += anchorParams->posZ;
        }
    }
    if (variant == 0) {
        packet.modeByte = 0;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll8DEffectResourceData, 8,
                                &resourceData[offsetof(Dll8DEffectResourceView, triangles)], 0x156, 0);
    } else if (variant == 1) {
        packet.modeByte = 0;
        packet.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll8DEffectResourceData, 8,
                                &resourceData[offsetof(Dll8DEffectResourceView, triangles)], 0xC0D, 0);
    } else if (variant == 2) {
        packet.modeByte = 0;
        packet.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&packet, 0, 9, (u8*)(int)gDll8DEffectResourceData, 8,
                                &resourceData[offsetof(Dll8DEffectResourceView, triangles)], 0x23B, 0);
    }
    return ret;
}

void dll_8D_release(void) {
}

void dll_8D_initialise(void) {
}

u8 gDll8DEffectResourceData[sizeof(Dll8DEffectResourceView)] = {
    0x03, 0xE8, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3, 0xFD, 0x3D, 0x01, 0x90, 0x00, 0x00,
    0x00, 0x1F, 0x00, 0x00, 0xFC, 0x18, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0xFD, 0x3D, 0x01, 0x90,
    0x00, 0x00, 0x00, 0x1F, 0xFC, 0x18, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0x02, 0xC3,
    0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x03, 0xE8, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3,
    0x02, 0xC3, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0xFB, 0xB4, 0x00, 0x0F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x05, 0x00, 0x06,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32,
    0x00, 0x1E, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

Dll8DResourceDescriptor gDll8DResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_8D_initialise, dll_8D_release, NULL, dll_8D_spawnEffect,
};
