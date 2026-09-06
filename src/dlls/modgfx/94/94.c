/*
 * DLL 94 / 0x5E - a modgfx particle-sequence spawner.
 */
#include "main/dll/dll_005E_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll5ESequenceResourceView {
    ModgfxEffectVertex vertices[36];
    s16 triangleIndices[16][3];
    s16 nineVertexIndices[4][10];
    u8 opaque218[0x48];
    s16 allVertexIndices[36];
    s16 subsetIndices[18];
    s16 sequenceParams[7];
    u8 opaque2DA[0x12];
} Dll5ESequenceResourceView;

STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, triangleIndices) == 0x168);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, nineVertexIndices) == 0x1C8);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, opaque218) == 0x218);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, allVertexIndices) == 0x260);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, subsetIndices) == 0x2A8);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, sequenceParams) == 0x2CC);
STATIC_ASSERT(offsetof(Dll5ESequenceResourceView, opaque2DA) == 0x2DA);
STATIC_ASSERT(sizeof(Dll5ESequenceResourceView) == 0x2EC);

extern u8 gDll5ESequenceResourceData[];

void dll_5E_spawnSequence(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    u8* resourceData = (u8*)(int)gDll5ESequenceResourceData;
    (*gModgfxInterface)->beginSequence(sourceObj, (u8)variant, 0x12, 3, 9);
    (*gModgfxInterface)->setSequenceParams(&resourceData[offsetof(Dll5ESequenceResourceView, sequenceParams)]);
    (*gModgfxInterface)->addSequenceFlags(spawnFlags | 0x4004484);
    (*gModgfxInterface)->resetSequenceSpawns();
    (*gModgfxInterface)
        ->addSequenceSpawn(2, 0.01f, 0.02f, 0.01f, 9,
                           &resourceData[offsetof(Dll5ESequenceResourceView, nineVertexIndices[0])]);
    (*gModgfxInterface)
        ->addSequenceSpawn(2, 0.015f, 0.02f, 0.014f, 9,
                           &resourceData[offsetof(Dll5ESequenceResourceView, nineVertexIndices[1])]);
    (*gModgfxInterface)
        ->addSequenceSpawn(2, 0.015f, 0.02f, 0.015f, 9,
                           &resourceData[offsetof(Dll5ESequenceResourceView, nineVertexIndices[2])]);
    (*gModgfxInterface)
        ->addSequenceSpawn(2, 0.015f, 0.02f, 0.015f, 9,
                           &resourceData[offsetof(Dll5ESequenceResourceView, nineVertexIndices[3])]);
    (*gModgfxInterface)
        ->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)
        ->addSequenceSpawn(8, 175.0f, 165.0f, 40.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(2, 37.0f, 11.0f, 37.0f, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x4000, 0.0f, -4.0f, 0.0f, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, 1.0f, 1.0f, 3.0f, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)
        ->addSequenceSpawn(4, 254.0f, 0.0f, 0.0f, 0x12,
                           &resourceData[offsetof(Dll5ESequenceResourceView, subsetIndices)]);
    (*gModgfxInterface)
        ->addSequenceSpawn(0x4000, 0.0f, -4.0f, 0.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, 0.0f, 0.0f, 1800.0f, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, 1.0f, 1.0f, 3.0f, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)
        ->addSequenceSpawn(0x4000, 0.0f, -4.0f, 0.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, 0.0f, 0.0f, 1800.0f, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, 1.0f, 1.0f, 3.0f, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)
        ->addSequenceSpawn(0x4000, 0.0f, -4.0f, 0.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, 0.0f, 0.0f, 1800.0f, 0, NULL);
    (*gModgfxInterface)
        ->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24,
                           &resourceData[offsetof(Dll5ESequenceResourceView, allVertexIndices)]);
    (*gModgfxInterface)
        ->spawnSequence(spawnParams, (u8*)(int)gDll5ESequenceResourceData, 0x24,
                        &resourceData[offsetof(Dll5ESequenceResourceView, triangleIndices)], 0x10, 0x120, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

void dll_5E_release(void) {
}

void dll_5E_initialise(void) {
}

u8 gDll5ESequenceResourceData[sizeof(Dll5ESequenceResourceView)] = {
    4,   76,  0,   0,   0,   0,   0,   0,   0,   0,   3,   39,  0,   0,   253, 61,  0,   15,  0,   0,   0,   0,   0,
    0,   252, 24,  0,   31,  0,   0,   253, 161, 0,   0,   253, 61,  0,   47,  0,   0,   252, 124, 0,   0,   0,   0,
    0,   63,  0,   0,   253, 161, 0,   0,   2,   195, 0,   79,  0,   0,   0,   0,   0,   0,   3,   232, 0,   95,  0,
    0,   3,   39,  0,   0,   2,   195, 0,   111, 0,   0,   4,   76,  0,   0,   0,   0,   0,   127, 0,   0,   4,   176,
    7,   208, 0,   100, 0,   0,   0,   31,  3,   39,  7,   208, 253, 161, 0,   15,  0,   31,  0,   100, 7,   208, 252,
    124, 0,   31,  0,   31,  253, 161, 7,   208, 253, 161, 0,   47,  0,   31,  252, 124, 7,   208, 0,   100, 0,   63,
    0,   31,  253, 161, 7,   208, 3,   39,  0,   79,  0,   31,  0,   0,   7,   208, 4,   76,  0,   95,  0,   31,  3,
    39,  7,   208, 3,   39,  0,   111, 0,   31,  4,   176, 7,   208, 0,   100, 0,   127, 0,   31,  3,   132, 15,  160,
    0,   100, 0,   0,   0,   63,  2,   95,  15,  160, 253, 161, 0,   15,  0,   63,  255, 156, 15,  160, 252, 124, 0,
    31,  0,   63,  252, 217, 15,  160, 253, 161, 0,   47,  0,   63,  251, 180, 15,  160, 0,   100, 0,   63,  0,   63,
    252, 217, 15,  160, 3,   39,  0,   79,  0,   63,  0,   100, 15,  160, 4,   76,  0,   95,  0,   63,  2,   95,  15,
    160, 3,   39,  0,   111, 0,   63,  3,   132, 15,  160, 0,   100, 0,   127, 0,   63,  3,   232, 23,  112, 255, 156,
    0,   0,   0,   94,  2,   195, 23,  112, 252, 217, 0,   15,  0,   94,  0,   0,   23,  112, 251, 180, 0,   31,  0,
    94,  253, 61,  23,  112, 252, 217, 0,   47,  0,   94,  252, 24,  23,  112, 255, 156, 0,   63,  0,   94,  253, 61,
    23,  112, 2,   95,  0,   79,  0,   94,  0,   0,   23,  112, 3,   132, 0,   95,  0,   94,  2,   195, 23,  112, 2,
    95,  0,   111, 0,   94,  3,   232, 23,  112, 255, 156, 0,   127, 0,   94,  0,   0,   0,   1,   0,   10,  0,   0,
    0,   10,  0,   9,   0,   1,   0,   2,   0,   11,  0,   1,   0,   11,  0,   10,  0,   2,   0,   3,   0,   12,  0,
    2,   0,   12,  0,   11,  0,   3,   0,   4,   0,   13,  0,   3,   0,   13,  0,   12,  0,   4,   0,   5,   0,   14,
    0,   4,   0,   14,  0,   13,  0,   5,   0,   6,   0,   15,  0,   5,   0,   15,  0,   14,  0,   6,   0,   7,   0,
    16,  0,   6,   0,   16,  0,   15,  0,   7,   0,   8,   0,   17,  0,   7,   0,   17,  0,   16,  0,   0,   0,   1,
    0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   0,   0,   9,   0,   10,  0,   11,  0,
    12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,  0,   0,   0,   18,  0,   19,  0,   20,  0,   21,  0,   22,
    0,   23,  0,   24,  0,   25,  0,   26,  0,   0,   0,   27,  0,   28,  0,   29,  0,   30,  0,   31,  0,   32,  0,
    33,  0,   34,  0,   35,  0,   0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,
    0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,
    19,  0,   20,  0,   21,  0,   22,  0,   23,  0,   24,  0,   25,  0,   26,  0,   27,  0,   28,  0,   29,  0,   30,
    0,   31,  0,   32,  0,   33,  0,   34,  0,   35,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,   0,
    6,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   14,  0,   15,  0,   16,  0,   17,
    0,   18,  0,   19,  0,   20,  0,   21,  0,   22,  0,   23,  0,   24,  0,   25,  0,   26,  0,   27,  0,   28,  0,
    29,  0,   30,  0,   31,  0,   32,  0,   33,  0,   34,  0,   35,  0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   21,  0,   22,  0,   23,  0,   24,  0,
    25,  0,   26,  0,   0,   0,   10,  0,   120, 0,   80,  0,   10,  0,   0,   0,   0,   0,   0,   0,   0,   1,   217,
    0,   0,   1,   253, 0,   0,   2,   1,   0,   0,   2,   3,
};

Dll5EResourceDescriptor gDll5EResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_5E_initialise, dll_5E_release, NULL, dll_5E_spawnSequence, 0,
};
