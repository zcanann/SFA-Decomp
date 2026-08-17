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
    s16 colors[4][3];
    s16 sequenceParams[7];
    u8 pad4E[2];
} Dll5BEffectResourceView;

STATIC_ASSERT(offsetof(Dll5BEffectResourceView, vertices) == 0x00);
STATIC_ASSERT(offsetof(Dll5BEffectResourceView, colors) == 0x28);
STATIC_ASSERT(offsetof(Dll5BEffectResourceView, sequenceParams) == 0x40);
STATIC_ASSERT(sizeof(Dll5BEffectResourceView) == 0x50);

typedef struct Dll5BPartFxSpawnParams {
    s16 rotationX;
    s16 rotationY;
    s16 rotationZOrEffectId;
    u8 pad06[2];
    f32 scale;
    f32 position[3];
} Dll5BPartFxSpawnParams;

STATIC_ASSERT(offsetof(Dll5BPartFxSpawnParams, rotationX) == 0x00);
STATIC_ASSERT(offsetof(Dll5BPartFxSpawnParams, rotationY) == 0x02);
STATIC_ASSERT(offsetof(Dll5BPartFxSpawnParams, rotationZOrEffectId) == 0x04);
STATIC_ASSERT(offsetof(Dll5BPartFxSpawnParams, scale) == 0x08);
STATIC_ASSERT(offsetof(Dll5BPartFxSpawnParams, position) == 0x0C);
STATIC_ASSERT(sizeof(Dll5BPartFxSpawnParams) == 0x18);

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
    Dll5BPartFxSpawnParams partFxParams;
    ModgfxSpawnPacket packet;
    Dll5BEffectResourceView* resources[1];
    GfxCmd* commandCursor;
    ObjModel* model;
    int partFxSpawnCount;
    GfxCmd* commands;
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
    partFxParams.rotationZOrEffectId = 0;
    modelFile = model->file;
    if (modelFile->textureCount == 0) {
        return -1;
    }
    packet.modeByte = effectId;
    packet.sourceObj = sourceObj;
    packet.sourceMode = effectId;
    packet.position[0] = 0.0f;
    packet.position[1] = 0.0f;
    packet.position[2] = 0.0f;
    packet.velocity[0] = 0.0f;
    packet.velocity[1] = 0.0f;
    packet.velocity[2] = 0.0f;
    packet.scale = 1.0f;
    packet.drawGroupCount = 1;
    packet.drawGroupStride = 0;
    packet.initialStateByte = 4;
    packet.byte5A = 0;
    packet.textureFrameTimer = 0;
    packet.sequenceParams[0] = resources[0]->sequenceParams[0];
    packet.sequenceParams[1] = resources[0]->sequenceParams[1];
    packet.sequenceParams[2] = resources[0]->sequenceParams[2];
    packet.sequenceParams[3] = resources[0]->sequenceParams[3];
    packet.sequenceParams[4] = resources[0]->sequenceParams[4];
    packet.sequenceParams[5] = resources[0]->sequenceParams[5];
    packet.sequenceParams[6] = resources[0]->sequenceParams[6];
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
        texture = textureIdxToPtr(modelFile->textureIds[0]);
        commands[0].layer = 0;
        commands[0].flags = 1;
        commands[0].tex = gDll5BZeroIndices;
        commands[0].mode = 8;
        commands[0].x = 0.0f;
        commands[0].y = 0.0f;
        commands[0].z = 0.0f;
        if (effectId == 0xc || effectId == 5) {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 2;
            commands[1].x = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].y = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].z = 0.15f * (f32)randomGetRange(1, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0xd) {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 2;
            commands[1].x = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].y = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].z = 0.15f * (f32)randomGetRange(1, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x14) {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 2;
            commands[1].x = 0.25f * (f32)randomGetRange(3, 6);
            commands[1].y = 0.25f * (f32)randomGetRange(3, 6);
            commands[1].z = 0.25f * (f32)randomGetRange(3, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x11) {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 2;
            commands[1].x = 0.25f * (f32)randomGetRange(3, 6);
            commands[1].y = 0.25f * (f32)randomGetRange(3, 6);
            commands[1].z = 0.25f * (f32)randomGetRange(3, 6);
            commandCursor = &commands[2];
        } else if (effectId == 0x10) {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 8;
            commands[1].x = 255.0f;
            commands[1].y = 0.0f;
            commands[1].z = 255.0f;
            commands[2].layer = 0;
            commands[2].flags = 4;
            commands[2].tex = gDll5BQuadIndices;
            commands[2].mode = 2;
            commands[2].x = 2.5f * (f32)randomGetRange(3, 6);
            commands[2].y = 2.5f * (f32)randomGetRange(3, 6);
            commands[2].z = 2.5f * (f32)randomGetRange(3, 6);
            commandCursor = &commands[3];
        } else {
            commands[1].layer = 0;
            commands[1].flags = 4;
            commands[1].tex = gDll5BQuadIndices;
            commands[1].mode = 2;
            commands[1].x = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].y = 0.15f * (f32)randomGetRange(1, 6);
            commands[1].z = 0.15f * (f32)randomGetRange(1, 6);
            commandCursor = &commands[2];
        }
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 0;
        commandCursor[0].tex = NULL;
        commandCursor[0].mode = 0x80000000;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = -0.07f;
        commandCursor[0].z = 0.0f;
        commandCursor[1].layer = 1;
        commandCursor[1].flags = 0;
        commandCursor[1].tex = NULL;
        commandCursor[1].mode = 0x100;
        commandCursor[1].x = 0.0f;
        commandCursor[1].y = 300.0f * (f32)randomGetRange(-10, 10);
        commandCursor[1].z = 300.0f * (f32)randomGetRange(-10, 10);
        if (effectId == 0x10) {
            commandCursor[2].layer = 1;
            commandCursor[2].flags = 0;
            commandCursor[2].tex = NULL;
            commandCursor[2].mode = 0x400000;
            commandCursor[2].x = 0.0f;
            commandCursor[2].y = 0.0f;
            commandCursor[2].z = 300.0f + (f32)randomGetRange(0, 300);
            partFxParams.rotationY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotationX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotationX, &commandCursor[2].x);
            commandCursor += 3;
        } else if (effectId == 0x11) {
            commandCursor[2].layer = 1;
            commandCursor[2].flags = 0;
            commandCursor[2].tex = NULL;
            commandCursor[2].mode = 0x400000;
            commandCursor[2].x = 0.0f;
            commandCursor[2].y = 0.0f;
            commandCursor[2].z = 300.0f + (f32)randomGetRange(0, 300);
            partFxParams.rotationY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotationX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotationX, &commandCursor[2].x);
            commandCursor += 3;
        } else {
            commandCursor[2].layer = 1;
            commandCursor[2].flags = 0;
            commandCursor[2].tex = NULL;
            commandCursor[2].mode = 0x400000;
            commandCursor[2].x = 0.0f;
            commandCursor[2].y = 0.0f;
            commandCursor[2].z = 100.0f + (f32)randomGetRange(0, 100);
            partFxParams.rotationY = randomGetRange(-0x7fff, -0xfa0);
            partFxParams.rotationX = randomGetRange(0, 0xffff);
            vecRotateZXY(&partFxParams.rotationX, &commandCursor[2].x);
            commandCursor += 3;
        }
        commandCursor[0].layer = 1;
        commandCursor[0].flags = 4;
        commandCursor[0].tex = gDll5BQuadIndices;
        commandCursor[0].mode = 4;
        commandCursor[0].x = 0.0f;
        commandCursor[0].y = 0.0f;
        commandCursor[0].z = 0.0f;
        packet.commands = commands;
        packet.commandCount = (commandCursor + 1) - commands;
        packet.flags = 0x4000000;
        packet.flags |= spawnFlags;
        spawnHandle = (*gModgfxInterface)
                          ->spawnEffect(&packet, 0, 4, resources[0]->vertices, 4, resources[0]->colors, 0, texture);
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
        partFxParams.rotationZOrEffectId = 0x2a;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 1:
        partFxParams.rotationZOrEffectId = 0x2b;
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    case 2:
        partFxParams.rotationZOrEffectId = 0x184;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 3:
        partFxParams.rotationZOrEffectId = 0x1a1;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        break;
    case 4:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.rotationZOrEffectId = 0x159;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 5:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.rotationZOrEffectId = 0x91;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 6:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        partFxParams.rotationZOrEffectId = 0x74;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 8:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.rotationZOrEffectId = 0xdf;
        do {
            (*gPartfxInterface)->spawnObject(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.rotationZOrEffectId = 0x159;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 9:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.rotationZOrEffectId = 0xde;
        do {
            (*gPartfxInterface)->spawnObject(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.rotationZOrEffectId = 0x91;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 10:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        }
        effectCount = 0x14;
        partFxParams.rotationZOrEffectId = 0x160;
        do {
            (*gPartfxInterface)->spawnObject(sourceObj, 7, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        partFxParams.rotationZOrEffectId = 0x74;
        (*gPartfxInterface)->spawnObject(sourceObj, 3, &partFxParams, 1, -1, NULL);
        break;
    case 0xc:
        partFxParams.rotationZOrEffectId = 0x2a;
        break;
    case 0xd:
        partFxParams.rotationZOrEffectId = 0x4c;
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    case 0xe:
        partFxParams.rotationZOrEffectId = 0x60;
        for (; partFxSpawnCount != 0; partFxSpawnCount--) {
            (*gPartfxInterface)->spawnObject(sourceObj, 0x135, &partFxParams, 1, -1, NULL);
        }
        break;
    case 0xf:
        (*gPartfxInterface)->spawnObject(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 0x51b, NULL, 2, -1, NULL);
        break;
    case 0x10:
    case 0x11:
        partFxParams.rotationZOrEffectId = 0x4c;
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
        break;
    default:
        partFxParams.rotationZOrEffectId = 0x2a;
        effectCount = 5;
        do {
            (*gPartfxInterface)->spawnObject(sourceObj, 5, &partFxParams, 1, -1, NULL);
            effectCount--;
        } while (effectCount != 0);
        break;
    }
    return spawnHandle;
}
