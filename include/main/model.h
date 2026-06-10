#ifndef MAIN_MODEL_H_
#define MAIN_MODEL_H_

#include "global.h"

/*
 * ModelFileHeader - in-place header of a loaded .MOD model file. Offset
 * fields are patched to pointers by ObjModel_RelocateModelData /
 * ObjModel_RelocateAnimData (the u32-vs-pointer launders in model.c keep
 * the original load widths). Only fields with read/write evidence in
 * model.c are named; everything else is padded.
 */
typedef struct ModelFileHeader {
    u8 refCount;
    u8 unk01;
    u16 flags; /* 0x10 = dynamic vertex buffers, 0x40 = vertex anim area */
    u8 unk04[8];
    s32 dataSize; /* anim data appended at header + dataSize */
    u8 unk10[8];
    u8 *unk18;
    u8 *unk1C;
    s32 *textureIds; /* file texture ids, patched to texture ptrs on load */
    u8 flags24; /* bit 8 = 9-byte (else 3-byte) entries at normals */
    u8 unk25[3];
    u8 *vertices; /* 6 bytes each, vertexCount */
    u8 *normals;  /* 3 or 9 bytes each, normalCount */
    u8 *unk30;
    u8 *unk34;
    u8 *renderOps; /* 0x44 each, renderOpCount */
    u8 *unk3C;
    u8 *unk40;
    u8 unk44[0x10];
    u8 *unk54;
    u8 *unk58;
    u8 *unk5C;
    u8 *unk60;
    u8 *unk64;
    u8 *unk68;
    u8 *unk6C; /* per-joint s16 table */
    u8 unk70[0x10];
    s32 unk80;
    s16 unk84;
    u8 unk86[4];
    u16 unk8A; /* count of 0x74-stride entries at unkA4 */
    u8 unk8C[8];
    u8 *unk94;
    u8 unk98[0xC];
    u8 *unkA4; /* 0x74-stride entries */
    u8 *unkA8;
    u8 unkAC[2];
    u16 unkAE; /* count of 0x74-stride entries at unkC8 */
    u8 unkB0[8];
    u8 *unkB8;
    u8 unkBC[0xC];
    u8 *unkC8; /* 0x74-stride entries */
    u8 *unkCC;
    u8 *displayLists; /* 0x1c-stride entries, unkF5 + unkF6 */
    u8 *unkD4;
    u8 unkD8[4];
    u8 *unkDC; /* pointer table, unkF9 entries */
    u16 cullDistance;
    u16 unkE2;
    u16 vertexCount;
    u16 normalCount;
    u8 unkE8[4];
    u16 countEC; /* nonzero = per-joint matrix buffers */
    u8 unkEE[4];
    u8 textureCount;
    u8 jointCount;
    u8 extraJointCount;
    u8 unkF5;
    u8 unkF6;
    u8 unkF7;
    u8 renderOpCount;
    u8 unkF9;
} ModelFileHeader;

STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20);
STATIC_ASSERT(offsetof(ModelFileHeader, unkC8) == 0xC8);
STATIC_ASSERT(offsetof(ModelFileHeader, textureCount) == 0xF2);
STATIC_ASSERT(offsetof(ModelFileHeader, unkF9) == 0xF9);

typedef struct ObjModelJointMatrix {
    f32 row0[3];
    f32 translationX;
    f32 row1[3];
    f32 translationY;
    f32 row2[3];
    f32 translationZ;
    f32 row3[4];
} ObjModelJointMatrix;

STATIC_ASSERT(sizeof(ObjModelJointMatrix) == 0x40);
STATIC_ASSERT(offsetof(ObjModelJointMatrix, translationX) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelJointMatrix, translationY) == 0x1C);
STATIC_ASSERT(offsetof(ObjModelJointMatrix, translationZ) == 0x2C);

typedef struct ObjModelBlendChannel {
    f32 weight;
    f32 targetWeight;
    f32 unk08;
    s8 unk0C;
    s8 unk0D;
    u8 flags0E;
    u8 unk0F;
} ObjModelBlendChannel;

STATIC_ASSERT(sizeof(ObjModelBlendChannel) == 0x10);

/*
 * ObjModel - per-object model working set built by modelLoad_layoutBuffers
 * (all buffers carved from one allocation). Double-buffered matrix/vertex
 * buffers are selected by flags bits 0/1.
 */
typedef struct ObjModel {
    ModelFileHeader *file;
    u8 unk04[8];
    u8 *jointMatrices[2];
    u8 *unk14; /* joint workspace, 0x1c header + per-joint tables */
    u16 bufferFlags; /* 1 = mtx buffer select, 2 = vtx buffer select, 0x40 = textures loaded */
    u8 unk1A[2];
    u8 *vtxBuf0;
    u8 *vtxBuf1;
    u8 *normalBuf;
    struct ObjModelBlendChannel *blendChannels; /* 3 channels */
    void *animStateA;  /* ObjAnimState */
    void *animStateB;  /* ObjAnimState, only with load flag 0x80 */
    u8 *textureRefs;   /* 0xc each, renderOpCount */
    void *renderCallback;
    void *postRenderCallback;
    s32 *unk40; /* per-entry ints, file->unk8A */
    s32 *unk44; /* per-entry ints, file->unkAE */
    u8 *unk48;
    u8 *unk4C;
    u8 *unk50;
    u8 *unk54;
    void *renderAttachment;
    u8 *curMtxBuf;
    u8 bool60;
    u8 unk61[3];
} ObjModel;

STATIC_ASSERT(offsetof(ObjModel, bufferFlags) == 0x18);
STATIC_ASSERT(offsetof(ObjModel, renderCallback) == 0x38);
STATIC_ASSERT(offsetof(ObjModel, bool60) == 0x60);

ObjModelJointMatrix *ObjModel_GetJointMatrix(u8 *modelBytes, int jointIndex);

#endif
