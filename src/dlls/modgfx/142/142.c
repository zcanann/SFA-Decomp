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
    ModgfxCommand* command;
    ModgfxCommand* commands = packet.entries;
    s16* sequenceParams;
    f32 rz;
    f32 ry;

    command = commands;
    if (variant == 0) {
        command->stageIndex = 0;
        command->parameter = 3;
        command->vertexIndices = (s16*)(gDll8EEffectTexture);
        command->flags = 8;
        command->valueX = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->valueY = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->valueZ = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        command++;
    } else if (variant == 1) {
        command->stageIndex = 0;
        command->parameter = 3;
        command->vertexIndices = (s16*)(gDll8EEffectTexture);
        command->flags = 8;
        command->valueX = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        command->valueY = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        command->valueZ = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
        command++;
    }
    rz = randomGetRange(0, 0xfffe);
    ry = randomGetRange(-0xbb8, -0x2ee0);
    command[0].stageIndex = 0;
    command[0].parameter = 0;
    command[0].vertexIndices = NULL;
    command[0].flags = 0x80;
    command[0].valueX = 0.0f;
    command[0].valueY = ry;
    command[0].valueZ = rz;
    command[1].stageIndex = 0;
    command[1].parameter = 3;
    command[1].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[1].flags = 4;
    command[1].valueX = 0.0f;
    command[1].valueY = 0.0f;
    command[1].valueZ = 0.0f;
    command[2].stageIndex = 0;
    command[2].parameter = 3;
    command[2].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[2].flags = 2;
    command[2].valueX = 1.0f;
    command[2].valueY = 0.01f * randomGetRange(0, 0x32) + 0.5f;
    command[2].valueZ = 0.01f * randomGetRange(0, 0x14) + 0.8f;
    command[3].stageIndex = 1;
    command[3].parameter = 3;
    command[3].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[3].flags = 4;
    if (randomGetRange(0, 0xa) == 0) {
        command[3].valueX = 145.0f + randomGetRange(0, 0x1e);
    } else {
        command[3].valueX = 25.0f + randomGetRange(0, 0xa);
    }
    command[3].valueY = 0.0f;
    command[3].valueZ = 0.0f;
    command[4].stageIndex = 2;
    command[4].parameter = 0;
    command[4].vertexIndices = NULL;
    command[4].flags = 0x80;
    command[4].valueX = 0.0f;
    command[4].valueY = 0.0f;
    command[4].valueZ = randomGetRange(0, 0xfffe);
    command[5].stageIndex = 1;
    command[5].parameter = 3;
    command[5].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[5].flags = 2;
    command[5].valueX = 10.0f;
    command[5].valueY = 12.0f;
    command[5].valueZ = 21.0f;
    command[6].stageIndex = 2;
    command[6].parameter = 0;
    command[6].vertexIndices = NULL;
    command[6].flags = 0x80;
    command[6].valueX = 0.0f;
    command[6].valueY = 0.0f;
    command[6].valueZ = randomGetRange(0, 0xfffe);
    command[7].stageIndex = 2;
    command[7].parameter = 3;
    command[7].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[7].flags = 4;
    command[7].valueX = 0.0f;
    command[7].valueY = 0.0f;
    command[7].valueZ = 0.0f;
    command[8].stageIndex = 2;
    command[8].parameter = 3;
    command[8].vertexIndices = (s16*)(gDll8EEffectTexture);
    command[8].flags = 2;
    command[8].valueX = 0.1f;
    command[8].valueY = 4.0f;
    command[8].valueZ = 0.05f;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = 0.0f;
    if (variant == 0) {
        packet.context.position[1] = 0.0f;
    } else if (variant == 1) {
        packet.context.position[1] = 200.0f;
    }
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 4.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 3;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (ModgfxCommand*)((u8*)command + sizeof(ModgfxCommand) * 9) - commands;
    sequenceParams = gDll8ESequenceResource.sequenceParams;
    packet.context.stageDurations[0] = sequenceParams[0];
    packet.context.stageDurations[1] = sequenceParams[1];
    packet.context.stageDurations[2] = sequenceParams[2];
    packet.context.stageDurations[3] = sequenceParams[3];
    packet.context.stageDurations[4] = sequenceParams[4];
    packet.context.stageDurations[5] = sequenceParams[5];
    packet.context.stageDurations[6] = sequenceParams[6];
    packet.context.commands = (ModgfxCommand*)((u8*)&packet + offsetof(ModgfxSpawnPacket, entries));
    packet.context.flags = 0x4000410;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)packet.context.sourceObject != 0 && (u32)spawnParams != 0) {
            GameObject* anchorObj = packet.context.sourceObject;
            PartFxSpawnParams* anchorParams = spawnParams;
            packet.context.position[0] += anchorObj->anim.worldPosX + anchorParams->posX;
            packet.context.position[1] += anchorObj->anim.worldPosY + anchorParams->posY;
            packet.context.position[2] += anchorObj->anim.worldPosZ + anchorParams->posZ;
        } else if ((u32)packet.context.sourceObject != 0) {
            packet.context.position[0] += packet.context.sourceObject->anim.worldPosX;
            packet.context.position[1] += packet.context.sourceObject->anim.worldPosY;
            packet.context.position[2] += packet.context.sourceObject->anim.worldPosZ;
        } else if ((u32)spawnParams != 0) {
            packet.context.position[0] += spawnParams->posX;
            packet.context.position[1] += spawnParams->posY;
            packet.context.position[2] += spawnParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet.context, 0, 3, (ModgfxEffectVertex*)(gDll8EEffectVtxColorTable), 1, (s16*)(&gDll8EEffectSpawnResource), 0x26A, 0);
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
