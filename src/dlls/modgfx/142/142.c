/*
 * DLL 142 / 0x8E - a randomized layered modgfx effect spawner.
 */
#include "main/dll/dll_008E_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct Dll8EVertexResourceView {
    ModgfxEffectVertex vertices[3];
    s16 opaqueTail;
} Dll8EVertexResourceView;

STATIC_ASSERT(offsetof(Dll8EVertexResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll8EVertexResourceView, opaqueTail) == 0x1E);
STATIC_ASSERT(sizeof(Dll8EVertexResourceView) == 0x20);

typedef struct Dll8ESequenceResource {
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8ESequenceResource;

STATIC_ASSERT(offsetof(Dll8ESequenceResource, sequenceParams) == 0x00);
STATIC_ASSERT(offsetof(Dll8ESequenceResource, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll8ESequenceResource) == 0x10);

extern u8 gDll8EEffectVtxColorTable[sizeof(Dll8EVertexResourceView)];
extern Dll8ESequenceResource gDll8ESequenceResource;

u8 gDll8EEffectSpawnResource[8] = {0, 0, 0, 1, 0, 2, 0, 0};
u8 gDll8EEffectTexture[8] = {0, 0, 0, 1, 0, 2, 0, 0};

void dll_8E_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    GfxCmd* command;
    GfxCmd* commands = packet.entries;
    s16* sequenceParams;
    f32 rz;
    f32 ry;

    command = commands;
    if (variant == 0) {
        command->layer = 0;
        command->flags = 3;
        command->tex = gDll8EEffectTexture;
        command->mode = 8;
        command->x = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        command++;
    } else if (variant == 1) {
        command->layer = 0;
        command->flags = 3;
        command->tex = gDll8EEffectTexture;
        command->mode = 8;
        command->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        command->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->z = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
        command++;
    }
    rz = randomGetRange(0, 0xfffe);
    ry = randomGetRange(-0xbb8, -0x2ee0);
    command[0].layer = 0;
    command[0].flags = 0;
    command[0].tex = NULL;
    command[0].mode = 0x80;
    command[0].x = 0.0f;
    command[0].y = ry;
    command[0].z = rz;
    command[1].layer = 0;
    command[1].flags = 3;
    command[1].tex = gDll8EEffectTexture;
    command[1].mode = 4;
    command[1].x = 0.0f;
    command[1].y = 0.0f;
    command[1].z = 0.0f;
    command[2].layer = 0;
    command[2].flags = 3;
    command[2].tex = gDll8EEffectTexture;
    command[2].mode = 2;
    command[2].x = 1.0f;
    command[2].y = 0.01f * randomGetRange(0, 0x32) + 0.5f;
    command[2].z = 0.01f * randomGetRange(0, 0x14) + 0.8f;
    command[3].layer = 1;
    command[3].flags = 3;
    command[3].tex = gDll8EEffectTexture;
    command[3].mode = 4;
    if (randomGetRange(0, 0xa) == 0) {
        command[3].x = 145.0f + randomGetRange(0, 0x1e);
    } else {
        command[3].x = 25.0f + randomGetRange(0, 0xa);
    }
    command[3].y = 0.0f;
    command[3].z = 0.0f;
    command[4].layer = 2;
    command[4].flags = 0;
    command[4].tex = NULL;
    command[4].mode = 0x80;
    command[4].x = 0.0f;
    command[4].y = 0.0f;
    command[4].z = randomGetRange(0, 0xfffe);
    command[5].layer = 1;
    command[5].flags = 3;
    command[5].tex = gDll8EEffectTexture;
    command[5].mode = 2;
    command[5].x = 10.0f;
    command[5].y = 12.0f;
    command[5].z = 21.0f;
    command[6].layer = 2;
    command[6].flags = 0;
    command[6].tex = NULL;
    command[6].mode = 0x80;
    command[6].x = 0.0f;
    command[6].y = 0.0f;
    command[6].z = randomGetRange(0, 0xfffe);
    command[7].layer = 2;
    command[7].flags = 3;
    command[7].tex = gDll8EEffectTexture;
    command[7].mode = 4;
    command[7].x = 0.0f;
    command[7].y = 0.0f;
    command[7].z = 0.0f;
    command[8].layer = 2;
    command[8].flags = 3;
    command[8].tex = gDll8EEffectTexture;
    command[8].mode = 2;
    command[8].x = 0.1f;
    command[8].y = 4.0f;
    command[8].z = 0.05f;
    packet.modeByte = 0;
    packet.sourceObj = sourceObj;
    packet.sourceMode = variant;
    packet.position[0] = 0.0f;
    if (variant == 0) {
        packet.position[1] = 0.0f;
    } else if (variant == 1) {
        packet.position[1] = 200.0f;
    }
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 4.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 3;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.commandCount = (GfxCmd*)((u8*)command + sizeof(GfxCmd) * 9) - commands;
    sequenceParams = gDll8ESequenceResource.sequenceParams;
    packet.sequenceParams[0] = sequenceParams[0];
    packet.sequenceParams[1] = sequenceParams[1];
    packet.sequenceParams[2] = sequenceParams[2];
    packet.sequenceParams[3] = sequenceParams[3];
    packet.sequenceParams[4] = sequenceParams[4];
    packet.sequenceParams[5] = sequenceParams[5];
    packet.sequenceParams[6] = sequenceParams[6];
    packet.commands = (GfxCmd*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.flags = 0x4000410;
    packet.flags |= spawnFlags;
    if ((packet.flags & 1) != 0) {
        if ((u32)packet.sourceObj != 0 && (u32)spawnParams != 0) {
            GameObject* anchorObj = packet.sourceObj;
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.position[0] += anchorObj->anim.worldPosX + anchorParams->posX;
            packet.position[1] += anchorObj->anim.worldPosY + anchorParams->posY;
            packet.position[2] += anchorObj->anim.worldPosZ + anchorParams->posZ;
        } else if ((u32)packet.sourceObj != 0) {
            packet.position[0] += packet.sourceObj->anim.worldPosX;
            packet.position[1] += packet.sourceObj->anim.worldPosY;
            packet.position[2] += packet.sourceObj->anim.worldPosZ;
        } else if ((u32)spawnParams != 0) {
            packet.position[0] += spawnParams->posX;
            packet.position[1] += spawnParams->posY;
            packet.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet, 0, 3, gDll8EEffectVtxColorTable, 1, &gDll8EEffectSpawnResource, 0x26A, 0);
}

void dll_8E_release(void) {
}

void dll_8E_initialise(void) {
}

u8 gDll8EEffectVtxColorTable[sizeof(Dll8EVertexResourceView)] = {
    0, 0, 0, 230, 5, 20, 0, 0, 0, 31, 0, 0, 255, 26, 5, 20, 0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15, 0, 16, 0, 0,
};

Dll8ESequenceResource gDll8ESequenceResource = {{0, 140, 140, 0, 0, 0, 0}, 0};

Dll8EResourceDescriptor gDll8EResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_8E_initialise, dll_8E_release, NULL, dll_8E_spawnEffect,
};
