/*
 * DLL 91 / 0x5B - an impact and debris effect spawner.
 */
#include "main/dll/dll_005B_modgfx.h"
#include "game/objects/object.h"
#include "main/debug.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/model.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"
#include "main/dll/partfx_interface.h"

typedef struct Dll5BEffectResourceView {
    ModgfxEffectVertex vertices[4];
    s16 triangleIndices[4][3];
    s16 sequenceParams[7];
    u8 pad4E[2];
} Dll5BEffectResourceView;

STATIC_ASSERT(offsetof(Dll5BEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll5BEffectResourceView, triangleIndices) == 0x28);
STATIC_ASSERT(offsetof(Dll5BEffectResourceView, sequenceParams) == 0x40);
STATIC_ASSERT(sizeof(Dll5BEffectResourceView) == 0x50);


u8 gDll5BZeroIndices[4] = {0};
u8 gDll5BQuadIndices[8] = {0, 0, 0, 1, 0, 2, 0, 3};

const Dll5BSpawnCountRange gDll5BDefaultSpawnCountRange = {5, 20};

u8 gDll5BEffectResourceData[0x50] = {0,   0,   2, 88, 0, 0,  0, 15, 0, 31, 2,   88,  0, 0, 0,   0,   0, 0,  0, 0,
                                     253, 168, 0, 0,  2, 88, 0, 15, 0, 0,  253, 168, 0, 0, 253, 168, 0, 31, 0, 0,
                                     0,   0,   0, 1,  0, 2,  0, 0,  0, 2,  0,   3,   0, 0, 0,   3,   0, 1,  0, 1,
                                     0,   3,   0, 2,  0, 0,  0, 70, 0, 0,  0,   0,   0, 0, 0,   0,   0, 0,  0, 0};

Dll5BResourceDescriptor gDll5BResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, NULL, NULL, NULL, dll_5B_spawnModelEffects,
    "!!!! This modgfx needs an owner object\n",
};

s16 dll_5B_spawnModelEffects(GameObject* sourceObj, int effectId, PartFxSpawnParams* unusedSpawnParams, u32 spawnFlags,
                             int unusedModelId, const Dll5BSpawnCountRange* countRange) {
    Dll5BSpawnCountRange spawnCountRange;
    PartFxSpawnParams partFxParams;
    ModgfxSpawnPacket packet;
    Dll5BEffectResourceView* resources[1];
    ModgfxCommand* commandCursor;
    ObjModel* model;
    int partFxSpawnCount;
    ModgfxCommand* commands;
    int effectCount;
    void* texture;
    s16 spawnHandle;
    ModelFileHeader* modelFile;
    resources[0] = (Dll5BEffectResourceView*)gDll5BEffectResourceData;
    spawnHandle = 0;
    /* Retail resolves the model before checking for a missing owner. */
    model = (ObjModel*)sourceObj->anim.banks[sourceObj->anim.bankIndex];
    spawnCountRange = gDll5BDefaultSpawnCountRange;
    if (countRange != NULL) {
        spawnCountRange.min = countRange->min;
        spawnCountRange.max = countRange->max;
    }
    if (sourceObj == NULL) {
        debugPrintf((char*)resources[0] + sizeof(*resources[0]) +
                    offsetof(Dll5BResourceDescriptor, missingOwnerMessage));
        return -1;
    }
    partFxParams.position[0] = 0.0f;
    partFxParams.position[1] = 0.0f;
    partFxParams.position[2] = 0.0f;
    partFxParams.scale = 1.0f;
    partFxParams.arg2 = 0;
    modelFile = model->file;
    if (modelFile->textureCount == 0) {
        return -1;
    }
    packet.context.modeByte = effectId;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = effectId;
    packet.context.position[0] = 0.0f;
    packet.context.position[1] = 0.0f;
    packet.context.position[2] = 0.0f;
    packet.context.velocity[0] = 0.0f;
    packet.context.velocity[1] = 0.0f;
    packet.context.velocity[2] = 0.0f;
    packet.context.scale = 1.0f;
    packet.context.drawGroupCount = 1;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 4;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.stageDurations[0] = resources[0]->sequenceParams[0];
    packet.context.stageDurations[1] = resources[0]->sequenceParams[1];
    packet.context.stageDurations[2] = resources[0]->sequenceParams[2];
    packet.context.stageDurations[3] = resources[0]->sequenceParams[3];
    packet.context.stageDurations[4] = resources[0]->sequenceParams[4];
    packet.context.stageDurations[5] = resources[0]->sequenceParams[5];
    packet.context.stageDurations[6] = resources[0]->sequenceParams[6];
    effectCount = randomGetRange(spawnCountRange.min, spawnCountRange.max);
    if (effectId == 0xc) {
        effectCount = randomGetRange(2, 6);
    } else if (effectId == 0xd) {
        effectCount = randomGetRange(2, 6);
    } else if (effectId == 0x11) {
        effectCount = 5;
    }
    commands = packet.entries;
    for (; effectCount != 0; effectCount--) {
        texture = textureIdxToPtr(modelFile->textureEntries[0].reference);
        commands[0].stageIndex = 0;
        commands[0].parameter = 1;
        commands[0].vertexIndices = (s16*)(gDll5BZeroIndices);
        commands[0].flags = 8;
        commands[0].valueX = 0.0f;
        commands[0].valueY = 0.0f;
        commands[0].valueZ = 0.0f;
        if (effectId == 0xc || effectId == 5) {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 2;
            commands[1].valueX = 0.15f * randomGetRange(1, 6);
            commands[1].valueY = 0.15f * randomGetRange(1, 6);
            commands[1].valueZ = 0.15f * randomGetRange(1, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0xd) {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 2;
            commands[1].valueX = 0.15f * randomGetRange(1, 6);
            commands[1].valueY = 0.15f * randomGetRange(1, 6);
            commands[1].valueZ = 0.15f * randomGetRange(1, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x14) {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 2;
            commands[1].valueX = 0.25f * randomGetRange(3, 6);
            commands[1].valueY = 0.25f * randomGetRange(3, 6);
            commands[1].valueZ = 0.25f * randomGetRange(3, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x11) {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 2;
            commands[1].valueX = 0.25f * randomGetRange(3, 6);
            commands[1].valueY = 0.25f * randomGetRange(3, 6);
            commands[1].valueZ = 0.25f * randomGetRange(3, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x10) {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 8;
            commands[1].valueX = 255.0f;
            commands[1].valueY = 0.0f;
            commands[1].valueZ = 255.0f;
            commands[2].stageIndex = 0;
            commands[2].parameter = 4;
            commands[2].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[2].flags = 2;
            commands[2].valueX = 2.5f * randomGetRange(3, 6);
            commands[2].valueY = 2.5f * randomGetRange(3, 6);
            commands[2].valueZ = 2.5f * randomGetRange(3, 6);
            commandCursor = &commands[3];
        } else {
            commands[1].stageIndex = 0;
            commands[1].parameter = 4;
            commands[1].vertexIndices = (s16*)(gDll5BQuadIndices);
            commands[1].flags = 2;
            commands[1].valueX = 0.15f * randomGetRange(1, 6);
            commands[1].valueY = 0.15f * randomGetRange(1, 6);
            commands[1].valueZ = 0.15f * randomGetRange(1, 6);
            commandCursor = &commands[2];
        }
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 0;
        commandCursor[0].vertexIndices = NULL;
        commandCursor[0].flags = 0x80000000;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = -0.07f;
        commandCursor[0].valueZ = 0.0f;
        commandCursor[1].stageIndex = 1;
        commandCursor[1].parameter = 0;
        commandCursor[1].vertexIndices = NULL;
        commandCursor[1].flags = 0x100;
        commandCursor[1].valueX = 0.0f;
        commandCursor[1].valueY = 300.0f * randomGetRange(-10, 10);
        commandCursor[1].valueZ = 300.0f * randomGetRange(-10, 10);
        if (effectId == 0x10) {
            commandCursor[2].stageIndex = 1;
            commandCursor[2].parameter = 0;
            commandCursor[2].vertexIndices = NULL;
            commandCursor[2].flags = 0x400000;
            commandCursor[2].valueX = 0.0f;
            commandCursor[2].valueY = 0.0f;
            commandCursor[2].valueZ = 300.0f + randomGetRange(0, 300);
            partFxParams.rotY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotX, &commandCursor[2].valueX);
            commandCursor += 3;
        } else if (effectId == 0x11) {
            commandCursor[2].stageIndex = 1;
            commandCursor[2].parameter = 0;
            commandCursor[2].vertexIndices = NULL;
            commandCursor[2].flags = 0x400000;
            commandCursor[2].valueX = 0.0f;
            commandCursor[2].valueY = 0.0f;
            commandCursor[2].valueZ = 300.0f + randomGetRange(0, 300);
            partFxParams.rotY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotX, &commandCursor[2].valueX);
            commandCursor += 3;
        } else {
            commandCursor[2].stageIndex = 1;
            commandCursor[2].parameter = 0;
            commandCursor[2].vertexIndices = NULL;
            commandCursor[2].flags = 0x400000;
            commandCursor[2].valueX = 0.0f;
            commandCursor[2].valueY = 0.0f;
            commandCursor[2].valueZ = 100.0f + randomGetRange(0, 100);
            partFxParams.rotY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotX, &commandCursor[2].valueX);
            commandCursor += 3;
        }
        commandCursor[0].stageIndex = 1;
        commandCursor[0].parameter = 4;
        commandCursor[0].vertexIndices = (s16*)(gDll5BQuadIndices);
        commandCursor[0].flags = 4;
        commandCursor[0].valueX = 0.0f;
        commandCursor[0].valueY = 0.0f;
        commandCursor[0].valueZ = 0.0f;
        packet.context.commands = commands;
        packet.context.commandCount = (commandCursor + 1) - commands;
        packet.context.flags = 0x4000000;
        packet.context.flags |= spawnFlags;
        spawnHandle = (*gModgfxInterface)
                          ->spawnEffect(&packet.context, 0, 4, (ModgfxEffectVertex*)(resources[0]->vertices), 4,
                                        (s16*)(resources[0]->triangleIndices), 0, texture);
    }
    partFxSpawnCount = randomGetRange(2, 6);
    if (effectId == 7) {
        effectId = randomGetRange(4, 6);
    }
    if (effectId == 0xb) {
        effectId = randomGetRange(8, 10);
    }
    if (effectId == 0xc) {
        partFxSpawnCount = randomGetRange(1, 3);
    }
    switch (effectId) {
    case 0:
    case 0x14:
        partFxParams.arg2 = 0x2a;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 1:
        partFxParams.arg2 = 0x2b;
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    case 2:
        partFxParams.arg2 = 0x184;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 3:
        partFxParams.arg2 = 0x1a1;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 4:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.arg2 = 0x159;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 5:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.arg2 = 0x91;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 6:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.arg2 = 0x74;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 8:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.arg2 = 0xdf;
        do {
            (*gPartfxInterface)->spawnEffect(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.arg2 = 0x159;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 9:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.arg2 = 0xde;
        do {
            (*gPartfxInterface)->spawnEffect(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.arg2 = 0x91;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 10:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.arg2 = 0x160;
        do {
            (*gPartfxInterface)->spawnEffect(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.arg2 = 0x74;
        (*gPartfxInterface)->spawnEffect(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 0xc:
        partFxParams.arg2 = 0x2a;
        break;
    case 0xd:
        partFxParams.arg2 = 0x4c;
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    case 0xe:
        partFxParams.arg2 = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnEffect(sourceObj, 0x135, &partFxParams, 1, -1, NULL);
        }
        break;
    case 0xf:
        (*gPartfxInterface)->spawnEffect(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 0x51b, NULL, 2, -1, NULL);
        break;
    case 0x10:
    case 0x11:
        partFxParams.arg2 = 0x4c;
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    default:
        partFxParams.arg2 = 0x2a;
        effectCount = 5;
        do {
            (*gPartfxInterface)->spawnEffect(sourceObj, 5, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        break;
    }
    return spawnHandle;
}
