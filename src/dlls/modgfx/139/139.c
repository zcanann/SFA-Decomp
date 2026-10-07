/*
 * DLL 139 / 0x8B - a two-pass layered modgfx effect spawner.
 */
#include "main/dll/dll_008B_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll8BEffectResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    u8 opaque164[0x4C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    u8 opaque1DC[0x1C];
    s16 sequenceParams[7];
    s16 opaqueTail;
} Dll8BEffectResourceView;

STATIC_ASSERT(offsetof(Dll8BEffectResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, opaque164) == 0x164);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, opaque1DC) == 0x1DC);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, sequenceParams) == 0x1F8);
STATIC_ASSERT(offsetof(Dll8BEffectResourceView, opaqueTail) == 0x206);
STATIC_ASSERT(sizeof(Dll8BEffectResourceView) == 0x208);

u8 gDll8BEffectResourceData[sizeof(Dll8BEffectResourceView)] = {
    0,   0,   3,   232, 0,   0,   0,   0,   0,   0,   3,   98,  1,  244, 0,   0,   0,   16,  0,   0,   3,   98,  254,
    12,  0,   0,   0,   31,  0,   0,   0,   0,   252, 24,  0,   0,  0,   47,  0,   0,   252, 158, 254, 12,  0,   0,
    0,   31,  0,   0,   252, 158, 1,   244, 0,   0,   0,   16,  0,  0,   0,   0,   3,   232, 0,   0,   0,   0,   0,
    0,   0,   0,   3,   232, 11,  184, 0,   0,   0,   127, 3,   98, 1,   244, 11,  184, 0,   16,  0,   127, 3,   98,
    254, 12,  11,  184, 0,   31,  0,   127, 0,   0,   252, 24,  11, 184, 0,   47,  0,   127, 252, 158, 254, 12,  11,
    184, 0,   31,  0,   127, 252, 158, 1,   244, 11,  184, 0,   16, 0,   127, 0,   0,   3,   232, 11,  184, 0,   0,
    0,   127, 0,   0,   3,   232, 23,  112, 0,   0,   0,   255, 3,  98,  1,   244, 23,  112, 0,   16,  0,   255, 3,
    98,  254, 12,  23,  112, 0,   31,  0,   255, 0,   0,   252, 24, 23,  112, 0,   47,  0,   255, 252, 158, 254, 12,
    23,  112, 0,   31,  0,   255, 252, 158, 1,   244, 23,  112, 0,  16,  0,   255, 0,   0,   3,   232, 23,  112, 0,
    0,   0,   255, 0,   0,   0,   0,   0,   8,   0,   1,   0,   0,  0,   7,   0,   8,   0,   1,   0,   9,   0,   2,
    0,   1,   0,   8,   0,   9,   0,   2,   0,   10,  0,   3,   0,  2,   0,   9,   0,   10,  0,   3,   0,   11,  0,
    4,   0,   3,   0,   10,  0,   11,  0,   4,   0,   12,  0,   5,  0,   4,   0,   11,  0,   12,  0,   5,   0,   13,
    0,   6,   0,   5,   0,   12,  0,   13,  0,   7,   0,   15,  0,  8,   0,   7,   0,   14,  0,   15,  0,   8,   0,
    16,  0,   9,   0,   8,   0,   15,  0,   16,  0,   9,   0,   17, 0,   10,  0,   9,   0,   16,  0,   17,  0,   10,
    0,   18,  0,   11,  0,   10,  0,   17,  0,   18,  0,   11,  0,  19,  0,   12,  0,   11,  0,   18,  0,   19,  0,
    12,  0,   20,  0,   13,  0,   12,  0,   19,  0,   20,  0,   0,  0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,  11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,  18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,  0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,  20,  0,   0,   0,   7,   0,   8,   0,   9,   0,
    10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16, 0,   17,  0,   18,  0,   19,  0,   20,  0,   0,
    0,   46,  0,   100, 0,   16,  0,   0,   0,   0,   0,   0,   0,  0};

void dll_8B_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, u32 unused,
                        f32* scalePtr) {
    ModgfxSpawnPacket packet;
    u8* resourceData = (u8*)gDll8BEffectResourceData;
    void* modelData = resourceData;
    f32 zero;
    f32 scaledZ;
    f32 velX = 2.0f;
    f32 velY = -1.7f;
    f32 scale = 1.0f;
    ModgfxCommand* commands;
    ModgfxCommand* command;
    GameObject* anchorObj = sourceObj;
    PartFxSpawnParams* anchorParams = spawnParams;
    int pass;

    if (scalePtr != NULL) {
        scale = *scalePtr;
    }
    pass = 0;
    scaledZ = 0.01f + scale;
    commands = packet.entries;
    zero = 0.0f;
    for (; pass < 2; pass++) {
        if (pass == 1) {
            velX = 2.0f;
            velY = -4.2f;
        }
        commands[0].stageIndex = 0;
        commands[0].parameter = 0x15;
        commands[0].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        commands[0].flags = 4;
        commands[0].valueX = zero;
        commands[0].valueY = zero;
        commands[0].valueZ = zero;
        commands[1].stageIndex = 0;
        commands[1].parameter = 0x15;
        commands[1].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        commands[1].flags = 0x80;
        commands[1].valueX = zero;
        commands[1].valueY = (f32)sourceObj->anim.rotY;
        commands[1].valueZ = 16383.0f + ((f32)sourceObj->anim.rotX - 16128.0f);
        command = &commands[2];
        if (pass == 0) {
            command->stageIndex = 0;
            command->parameter = 0x15;
            command->vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
            command->flags = 2;
            if (variant == 4) {
                command->valueX = 0.0375f;
                command->valueY = 0.0375f;
                command->valueZ = scaledZ;
            } else {
                command->valueX = 0.0125f;
                command->valueY = 0.0125f;
                command->valueZ = scaledZ;
            }
            command++;
        } else {
            command->stageIndex = 0;
            command->parameter = 0x15;
            command->vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
            command->flags = 2;
            if (variant == 4) {
                command->valueX = 0.03f;
                command->valueY = 0.03f;
                command->valueZ = scaledZ;
            } else {
                command->valueX = 0.01f;
                command->valueY = 0.01f;
                command->valueZ = scaledZ;
            }
            command++;
        }
        command[0].stageIndex = 0;
        command[0].parameter = 0;
        command[0].vertexIndices = NULL;
        command[0].flags = 0x400000;
        switch (variant) {
        case 0:
            command[0].valueX = 0.0f;
            command[0].valueY = 30.0f;
            command[0].valueZ = 0.0f;
            break;
        case 1:
            command[0].valueX = 0.0f;
            command[0].valueY = -30.0f;
            command[0].valueZ = 0.0f;
            break;
        case 2:
            command[0].valueX = 30.0f;
            command[0].valueY = 0.0f;
            command[0].valueZ = 0.0f;
            break;
        case 3:
            command[0].valueX = -30.0f;
            command[0].valueY = 0.0f;
            command[0].valueZ = 0.0f;
            break;
        case 4:
            command[0].valueX = 0.0f;
            command[0].valueY = 0.1f;
            command[0].valueZ = 0.0f;
            break;
        }
        command[1].stageIndex = 1;
        command[1].parameter = 0x15;
        command[1].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[1].flags = 4;
        command[1].valueX = 255.0f;
        command[1].valueY = zero;
        command[1].valueZ = zero;
        command[2].stageIndex = 1;
        command[2].parameter = 0x15;
        command[2].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[2].flags = 2;
        command[2].valueX = 6.0f;
        command[2].valueY = 6.0f;
        command[2].valueZ = 300.0f;
        command[3].stageIndex = 1;
        command[3].parameter = 0x15;
        command[3].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[3].flags = 0x4000;
        command[3].valueX = velX;
        command[3].valueY = velY;
        command[3].valueZ = zero;
        command[4].stageIndex = 2;
        command[4].parameter = 0x15;
        command[4].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[4].flags = 4;
        command[4].valueX = 255.0f;
        command[4].valueY = zero;
        command[4].valueZ = zero;
        command[5].stageIndex = 2;
        command[5].parameter = 0x15;
        command[5].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[5].flags = 0x4000;
        command[5].valueX = velX;
        command[5].valueY = velY;
        command[5].valueZ = zero;
        command[6].stageIndex = 3;
        command[6].parameter = 0x15;
        command[6].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[6].flags = 0x4000;
        command[6].valueX = velX;
        command[6].valueY = velY;
        command[6].valueZ = zero;
        command[7].stageIndex = 3;
        command[7].parameter = 0x15;
        command[7].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[7].flags = 4;
        command[7].valueX = zero;
        command[7].valueY = zero;
        command[7].valueZ = zero;
        command[8].stageIndex = 3;
        command[8].parameter = 0x15;
        command[8].vertexIndices = (s16*)&resourceData[offsetof(Dll8BEffectResourceView, allVertexIndices)];
        command[8].flags = 2;
        command[8].valueX = 0.1f;
        command[8].valueY = 0.1f;
        command[8].valueZ = 0.1f;
        packet.context.modeByte = 0;
        packet.context.sourceObject = sourceObj;
        packet.context.variant = variant;
        packet.context.position[0] = zero;
        packet.context.position[1] = zero;
        packet.context.position[2] = zero;
        packet.context.velocity[0] = zero;
        packet.context.velocity[1] = zero;
        packet.context.velocity[2] = zero;
        packet.context.scale = 6.4f;
        packet.context.drawGroupCount = 2;
        packet.context.drawGroupStride = 7;
        packet.context.initialStateByte = 0xE;
        packet.context.byte5A = 0;
        packet.context.textureFrameTimer = 0x28;
        packet.context.commandCount = (ModgfxCommand*)((u8*)command + sizeof(ModgfxCommand) * 9) - commands;
        packet.context.stageDurations[0] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[0])];
        packet.context.stageDurations[1] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[1])];
        packet.context.stageDurations[2] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[2])];
        packet.context.stageDurations[3] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[3])];
        packet.context.stageDurations[4] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[4])];
        packet.context.stageDurations[5] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[5])];
        packet.context.stageDurations[6] = *(s16*)&resourceData[offsetof(Dll8BEffectResourceView, sequenceParams[6])];
        packet.context.commands = commands;
        packet.context.flags = 0xC0104C0;
        packet.context.flags |= spawnFlags;
        if ((packet.context.flags & 1) != 0) {
            if (sourceObj != NULL) {
                packet.context.position[0] = zero + anchorObj->anim.worldPosX;
                packet.context.position[1] = zero + anchorObj->anim.worldPosY;
                packet.context.position[2] = zero + anchorObj->anim.worldPosZ;
            } else {
                packet.context.position[0] = zero + anchorParams->posX;
                packet.context.position[1] = zero + anchorParams->posY;
                packet.context.position[2] = zero + anchorParams->posZ;
            }
        }
        (*gModgfxInterface)
            ->spawnEffect(&packet.context, 0, 0x15, (ModgfxEffectVertex*)(modelData), 0x18,
                          (s16*)(&resourceData[offsetof(Dll8BEffectResourceView, triangles)]), 0xD9, 0);
    }
}

void dll_8B_release(void) {
}

void dll_8B_initialise(void) {
}

Dll8BResourceDescriptor gDll8BResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_8B_initialise, dll_8B_release, NULL, dll_8B_spawnEffect,
};
