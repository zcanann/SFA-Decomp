#ifndef MAIN_MODEL_H_
#define MAIN_MODEL_H_

#include "global.h"
#include "main/texture.h"

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
    u8 *colors;   /* GX_VA_CLR0 array, stride 2 */
    u8 *texCoords; /* GX_VA_TEX0/TEX1 array, stride 4 */
    u8 *renderOps; /* 0x44 each, renderOpCount */
    u8 *jointData;
    u8 *jointBlendData; /* 0x40: per-joint blend/pivot table (stride joff); [+0..8]=pivot XYZ (PSMTXTrans to/from origin for scale-fuzz), [+0xc]=scale divisor; passed to ObjModel_BlendVertexStream; offset->ptr relocated on load */
    u8 unk44[0x10];
    u8 *unk54;
    u8 *hitVolumes;
    u8 *collisionTriangles; /* 0x5c: 8-byte triangle vertex-index records (hit-detect mesh) */
    u8 *collisionBlocks;    /* 0x60: 0x14-byte spatial blocks (AABB + triangle range), count at +0xf0 */
    u8 *animationModelPtrs;
    u8 *animationDataSection;
    u8 *animationHeaderBuffer; /* per-joint s16 table */
    s16 animGroupBaseIndices[8]; /* 0x70: wiki Idx0..Idx7; group-base indices from modelLoadAnimations scanning for -1 markers */
    s32 animationDataFileOffset;
    s16 headerSize; /* roundUpTo8(loaded header size) + 0xb0; read back into size table */
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
    u8 *displayLists; /* 0x1c-stride entries, displayListCount + shadowDisplayListCount */
    u8 *instrs;
    u16 instrsBitLenWords; /* 0xD8: render-instruction stream length; *8 gives bit length (see objprint_dolphin render-instr readers) */
    u8 unkDA[2];
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
    u8 displayListCount; /* 0xF5: count of the primary (non-shadow) 0x1c-stride display-list group; base index for the shadow group */
    u8 shadowDisplayListCount; /* count of the 2nd display-list group (shadow), indexed at base displayListCount */
    u8 hitSphereCount; /* 0xF7: count of 0x10-byte hit-sphere records (double-buffered: pos += hitSphereCount*0x10 twice) */
    u8 renderOpCount;
    u8 morphTargetCount;
    u8 texMtxCount; /* 0xFA: texture-matrix descriptor count (GX_VA_TEXnMTXIDX loop bound) */
} ModelFileHeader;

/* ModelFileHeader.flags bits */
#define MODEL_FLAG_NO_ANIMATIONS 0x2
#define MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS 0x10
#define MODEL_FLAG_VERTEX_ANIM_AREA 0x40
#define MODEL_FLAG_NO_DEPTH_TEST 0x400
#define MODEL_FLAG_ALPHA_Z_UPDATE 0x2000
#define MODEL_FLAG_ALT_POINTER_LAYOUT 0x8000

/* ModelFileHeader.flags24 bits */
#define MODEL_FLAGS24_VERY_BRIGHT 0x02
/* set = 9-byte (else 3-byte) entries at normals */
#define MODEL_FLAGS24_NORMALS_9BYTE 0x8

/* ModelFileHeader.shaderFlags bit: set = use object color override (gObjOverrideColor) */
#define MODEL_SHADERFLAGS_USE_OBJ_COLOR 0x2

/* ObjModel.bufferFlags bit */
#define OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED 0x40

STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20);
STATIC_ASSERT(offsetof(ModelFileHeader, blendAnimEntries) == 0xC8);
STATIC_ASSERT(offsetof(ModelFileHeader, textureCount) == 0xF2);
STATIC_ASSERT(offsetof(ModelFileHeader, morphTargetCount) == 0xF9);
STATIC_ASSERT(offsetof(ModelFileHeader, texMtxCount) == 0xFA);

/* ModelFileHeader.jointData entry (wiki: Bone). tail is the inverse bind-pose
 * translation, negated into PSMTXTrans every frame by modelInitBoneMtxs. */
typedef struct ModelBone {
    s8 parent;   /* parent bone index, -1 = none */
    u8 idx[3];   /* matrix indices to write; high bit is a flag */
    f32 head[3]; /* translation */
    f32 tail[3]; /* bind translation */
} ModelBone;

STATIC_ASSERT(sizeof(ModelBone) == 0x1C);

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

/* ObjModelBlendChannel.flags0E fade/state bits */
#define BLENDCHAN_FLAG_MANUAL 0x01    /* weight is manual; skip auto-advance */
#define BLENDCHAN_FLAG_RESET_WEIGHT 0x02 /* reset weight to base pending */
#define BLENDCHAN_FLAG_FADING 0x04    /* fade in progress */
#define BLENDCHAN_FLAG_FADED 0x08     /* fade processed/settled */
#define BLENDCHAN_FLAG_CLAMP_TARGET 0x20 /* clamp low weight to targetWeight floor */

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
    u8 *hitSphereBuf0; /* 0x48: hit-sphere workspace buffer 0 (file->hitSphereCount * 0x10) */
    u8 *hitSphereBuf1; /* 0x4C: hit-sphere workspace buffer 1 (double-buffered) */
    u8 *hitSphereBufActive; /* 0x50: current hit-sphere buffer, initialized to hitSphereBuf0 */
    u8 *unk54;
    void *renderAttachment;
    u8 *curMtxBuf;
    u8 unk60;
    u8 unk61[3];
} ObjModel;

s16* ObjModel_GetBaseVertexCoords(ModelFileHeader* modelFile, int vertexIndex);
s16* ObjModel_GetCurrentVertexCoords(ObjModel* model, int vertexIndex);
void ObjModel_SetPostRenderCallback(ObjModel* model, void* callback);
Texture* ObjModel_GetTexture(ModelFileHeader* modelFile, int textureIndex);

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
void Model_GetVertexPosition(ModelFileHeader* model, int vertexIndex, f32* out);

int loadModelAndAnimTabs(void);
void postRenderSetAlphaBlendState(void);
void playerTailFn_80026b3c();

#endif
