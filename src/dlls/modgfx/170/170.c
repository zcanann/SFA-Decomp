/*
 * DLL 170 / 0xAA - a multi-spawn modgfx sequence.
 */
#include "main/dll/dll_00AA_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct DllAASevenIndexList {
    s16 indices[7];
    s16 opaqueTail;
} DllAASevenIndexList;

STATIC_ASSERT(offsetof(DllAASevenIndexList, indices) == 0x00);
STATIC_ASSERT(offsetof(DllAASevenIndexList, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(DllAASevenIndexList) == 0x10);

typedef struct DllAASequenceResourceView {
    ModgfxEffectVertex vertices[21];
    u8 opaqueD2[2];
    s16 triangles[24][3];
    u8 opaqueIndexData164[0x10];
    DllAASevenIndexList middleSevenVertexIndices;
    u8 opaqueIndexData184[0x2C];
    s16 allVertexIndices[21];
    s16 opaque1DA;
    s16 sequenceParams[7];
    s16 opaqueTail;
} DllAASequenceResourceView;

STATIC_ASSERT(offsetof(DllAASequenceResourceView, vertices) == 0x000);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, opaqueD2) == 0x0D2);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, triangles) == 0x0D4);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, opaqueIndexData164) == 0x164);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, middleSevenVertexIndices) == 0x174);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, opaqueIndexData184) == 0x184);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, allVertexIndices) == 0x1B0);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, opaque1DA) == 0x1DA);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, sequenceParams) == 0x1DC);
STATIC_ASSERT(offsetof(DllAASequenceResourceView, opaqueTail) == 0x1EA);
STATIC_ASSERT(sizeof(DllAASequenceResourceView) == 0x1EC);

extern u8 gDllAASequenceResourceData[sizeof(DllAASequenceResourceView)];

void dll_AA_spawnSequence(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 sequenceFlags) {
    u8* resourceData = (u8*)(int)gDllAASequenceResourceData;
    f32 scale;

    scale = 8.0f;
    if (spawnParams != NULL) {
        scale = spawnParams->scale / 5.0f;
    }
    (*gModgfxInterface)->beginSequence(sourceObj, (u8)variant, 0x15, 1, 0);
    (*gModgfxInterface)->setStageDurations((s16*)(&resourceData[offsetof(DllAASequenceResourceView, sequenceParams)]));
    (*gModgfxInterface)->addSequenceFlags(sequenceFlags);
    (*gModgfxInterface)->resetSequenceCommands();
    (*gModgfxInterface)
        ->addSequenceCommand(4, 0.65f, 0.0f, 0.0f, 0x15,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, allVertexIndices)]));
    (*gModgfxInterface)
        ->addSequenceCommand(2, 0.5f, 1.0f, 0.5f, 0x15,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, allVertexIndices)]));
    (*gModgfxInterface)->addSequenceCommand(0x400000, 0.0f, -100.0f, 0.0f, 0, NULL);
    (*gModgfxInterface)->nextStage();
    (*gModgfxInterface)
        ->addSequenceCommand(4, 160.0f, 0.0f, 0.0f, 7,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, middleSevenVertexIndices.indices)]));
    (*gModgfxInterface)->nextStage();
    (*gModgfxInterface)
        ->addSequenceCommand(4, 255.0f, 0.0f, 0.0f, 7,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, middleSevenVertexIndices.indices)]));
    (*gModgfxInterface)
        ->addSequenceCommand(2, scale, 3.0f, scale, 0x15,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, allVertexIndices)]));
    (*gModgfxInterface)->nextStage();
    (*gModgfxInterface)
        ->addSequenceCommand(4, 0.0f, 0.0f, 0.0f, 7,
                           (s16*)(&resourceData[offsetof(DllAASequenceResourceView, middleSevenVertexIndices.indices)]));
    (*gModgfxInterface)
        ->spawnSequence(spawnParams, (ModgfxEffectVertex*)(int)gDllAASequenceResourceData, 0x15,
                        (s16*)(&resourceData[offsetof(DllAASequenceResourceView, triangles)]), 0x18, 0x3e9, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

void dll_AA_release(void) {
}

void dll_AA_initialise(void) {
}

u8 gDllAASequenceResourceData[sizeof(DllAASequenceResourceView)] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,   0,   3,   98,  0,   0,   1,   244, 0,   11,  0,   0,   3,   98,  0,
    0,   254, 12,  0,   22,  0,   0,   0,   0,   0,   0,   252, 24,  0,   32,  0,   0,   252, 158, 0,   0,   254, 12,
    0,   42,  0,   0,   252, 158, 0,   0,   1,   244, 0,   52,  0,   0,   0,   0,   0,   0,   3,   232, 0,   63,  0,
    0,   0,   0,   11,  184, 3,   232, 0,   0,   0,   31,  3,   98,  11,  184, 1,   244, 0,   11,  0,   31,  3,   98,
    11,  184, 254, 12,  0,   22,  0,   31,  0,   0,   11,  184, 252, 24,  0,   32,  0,   31,  252, 158, 11,  184, 254,
    12,  0,   42,  0,   31,  252, 158, 11,  184, 1,   244, 0,   52,  0,   31,  0,   0,   11,  184, 3,   232, 0,   63,
    0,   31,  0,   0,   23,  112, 3,   232, 0,   0,   0,   63,  3,   98,  23,  112, 1,   244, 0,   11,  0,   63,  3,
    98,  23,  112, 254, 12,  0,   22,  0,   63,  0,   0,   23,  112, 252, 24,  0,   32,  0,   63,  252, 158, 23,  112,
    254, 12,  0,   42,  0,   63,  252, 158, 23,  112, 1,   244, 0,   52,  0,   63,  0,   0,   23,  112, 3,   232, 0,
    63,  0,   63,  0,   0,   0,   0,   0,   1,   0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,   9,   0,   8,   0,   2,   0,   3,   0,   10,  0,   2,   0,   10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,   0,   11,  0,   10,  0,   4,   0,   5,   0,   12,  0,   4,   0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,   5,   0,   13,  0,   12,  0,   7,   0,   8,   0,   15,  0,   7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16,  0,   8,   0,   16,  0,   15,  0,   9,   0,   10,  0,   17,  0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,   18,  0,   10,  0,   18,  0,   17,  0,   11,  0,   12,  0,   19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13,  0,   20,  0,   12,  0,   20,  0,   19,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   5,   0,   30,  0,
    40,  0,   0,   0,   0,   0,   0,   0,   0};
DllAAResourceDescriptor gDllAAResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_AA_initialise, dll_AA_release, NULL, dll_AA_spawnSequence, 0,
};
