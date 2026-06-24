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
    u8 *jointData;
    u8 *unk40;
    u8 unk44[0x10];
    u8 *unk54;
    u8 *unk58;
    u8 *collisionTriangles; /* 0x5c: 8-byte triangle vertex-index records (hit-detect mesh) */
    u8 *collisionBlocks;    /* 0x60: 0x14-byte spatial blocks (AABB + triangle range), count at +0xf0 */
    u8 *animationModelPtrs;
    u8 *animationDataSection;
    u8 *animationHeaderBuffer; /* per-joint s16 table */
    u8 unk70[0x10];
    s32 animationDataFileOffset;
    s16 unk84;
    u8 unk86[4];
    u16 vertexAnimCount; /* count of 0x74-stride entries at vertexAnimEntries */
    u8 unk8C[8];
    u8 *vertexAnimEntriesRaw;
    u8 unk98[0xC];
    u8 *vertexAnimEntries; /* 0x74-stride entries */
    u8 *vertexAnimBase;
    u8 unkAC[2];
    u16 blendAnimCount; /* count of 0x74-stride entries at blendAnimEntries */
    u8 unkB0[8];
    u8 *blendAnimEntriesRaw;
    u8 unkBC[0xC];
    u8 *blendAnimEntries; /* 0x74-stride entries */
    u8 *blendAnimBase;
    u8 *displayLists; /* 0x1c-stride entries, unkF5 + shadowDisplayListCount */
    u8 *instrs;
    u8 unkD8[4];
    u8 *morphTargetPtrs; /* pointer table, morphTargetCount entries */
    u16 cullDistance;
    u16 shaderFlags;
    u16 vertexCount;
    u16 normalCount;
    u8 unkE8[4];
    u16 animationCount; /* nonzero = per-joint matrix buffers */
    u8 unkEE[4];
    u8 textureCount;
    u8 jointCount;
    u8 extraJointCount;
    u8 unkF5;
    u8 shadowDisplayListCount; /* count of the 2nd display-list group (shadow), indexed at base unkF5 */
    u8 unkF7;
    u8 renderOpCount;
    u8 morphTargetCount;
} ModelFileHeader;

/* ModelFileHeader.flags bits */
#define MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS 0x10
#define MODEL_FLAG_VERTEX_ANIM_AREA 0x40

/* ModelFileHeader.flags24 bit: set = 9-byte (else 3-byte) entries at normals */
#define MODEL_FLAGS24_NORMALS_9BYTE 0x8

/* ObjModel.bufferFlags bit */
#define OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED 0x40

STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20);
STATIC_ASSERT(offsetof(ModelFileHeader, blendAnimEntries) == 0xC8);
STATIC_ASSERT(offsetof(ModelFileHeader, textureCount) == 0xF2);
STATIC_ASSERT(offsetof(ModelFileHeader, morphTargetCount) == 0xF9);

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
    f32 weightRate;   /* 0x08: per-dt weight delta (weight += weightRate * dt) */
    s8 morphTargetA;  /* 0x0C: index into morphTargetPtrs[] for blend source A (-1 = none) */
    s8 morphTargetB;  /* 0x0D: index into morphTargetPtrs[] for blend source B (-1 = none) */
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
    u8 *jointWorkspace; /* 0x1c header + per-joint tables */
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
    s32 *vertexAnimData; /* 0x40: per-entry s32 array (file->vertexAnimCount), filled from vertexAnimEntries[i]+0x60 */
    s32 *blendAnimData;  /* 0x44: per-entry s32 array (file->blendAnimCount), filled from normalBuf + blendAnimEntries[i]+0x60 */
    u8 *unk48;
    u8 *unk4C;
    u8 *unk50;
    u8 *unk54;
    void *renderAttachment;
    u8 *curMtxBuf;
    u8 unk60;
    u8 unk61[3];
} ObjModel;

STATIC_ASSERT(offsetof(ObjModel, bufferFlags) == 0x18);
STATIC_ASSERT(offsetof(ObjModel, renderCallback) == 0x38);
STATIC_ASSERT(offsetof(ObjModel, unk60) == 0x60);

typedef struct ObjModelChainEntry {
    void *frameBuffer;
    void *model;
    s32 frameCount;
} ObjModelChainEntry;

typedef struct ObjModelChain {
    ObjModelChainEntry *entries;
    s32 count;
    f32 originX;
    f32 originY;
    f32 originZ;
    f32 phase;
    u8 updateFlag;
    u8 unk19;
    u8 enabled;
} ObjModelChain;

STATIC_ASSERT(sizeof(ObjModelChainEntry) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelChainEntry, frameBuffer) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChainEntry, model) == 0x04);
STATIC_ASSERT(offsetof(ObjModelChainEntry, frameCount) == 0x08);
STATIC_ASSERT(offsetof(ObjModelChain, entries) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChain, count) == 0x04);
STATIC_ASSERT(offsetof(ObjModelChain, originX) == 0x08);
STATIC_ASSERT(offsetof(ObjModelChain, originY) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelChain, originZ) == 0x10);
STATIC_ASSERT(offsetof(ObjModelChain, phase) == 0x14);
STATIC_ASSERT(offsetof(ObjModelChain, updateFlag) == 0x18);
STATIC_ASSERT(offsetof(ObjModelChain, unk19) == 0x19);
STATIC_ASSERT(offsetof(ObjModelChain, enabled) == 0x1A);

ObjModelJointMatrix *ObjModel_GetJointMatrix(u8 *modelBytes, int jointIndex);
ObjModelChain *ObjModelChain_Alloc(void *models, int count);
void ObjModelChain_SetOrigin(ObjModelChain *chain, f32 x, f32 y, f32 z);
void ObjModelChain_SetEnabled(ObjModelChain *chain, u8 enabled);
void ObjModelChain_AdvancePhase(ObjModelChain *chain);
void ObjModelChain_Free(ObjModelChain *chain);


/* extern-cleanup: defining-file public prototypes */
void setGQR6_2(int a, int b, int c, int d);
void modelApplyBoneTransforms(int a, int b, u16 c, void* d, void* e, int f);
void* modelLoad_layoutBuffers(u8* p, int b, int isType1, int c);
void modelAnimResetState(void* m, void* data);
int modelLoadAnimations(void* model, int id, void* animBase);

#endif
