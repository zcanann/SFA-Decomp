#ifndef MAIN_MODEL_H_
#define MAIN_MODEL_H_

#include "global.h"
#include "main/texture.h"
#include "main/collision_polygon.h"
#include "main/ground_shadow.h"
#include "dolphin/mtx.h"

typedef struct GameObject GameObject;
typedef struct ObjAnimState ObjAnimState;
struct ObjAnimCachedMove;
struct ObjAnimMoveData;

typedef struct ShaderLayer {
    union {
        s32 textureIndex;
        Texture* texture;
    };
    u8 typeBits;
    u8 materialId;
    u8 scrollMtx;
    u8 unk7;
} ShaderLayer;

STATIC_ASSERT(sizeof(ShaderLayer) == 0x08);
STATIC_ASSERT(offsetof(ShaderLayer, typeBits) == 0x04);
STATIC_ASSERT(offsetof(ShaderLayer, materialId) == 0x05);
STATIC_ASSERT(offsetof(ShaderLayer, scrollMtx) == 0x06);

typedef struct Shader {
    u8 pad00[0x08];
    void* reg1Texture;
    u8 alpha;
    u8 pad0D[0x14 - 0x0D];
    void* reg2Texture;
    s32 textureId;
    u32 unk1C;
    u8 reg2TexSlot;
    u8 pad21;
    u8 reg2Alpha;
    u8 pad23;
    ShaderLayer layers[2];
    union {
        u32 auxTextureIndex;
        Texture* auxTexture;
    };
    union {
        s32 indTextureId;
        Texture* indTexture;
    };
    u32 flags;
    u8 vtxAttrFlags;
    u8 layerCount;
    u8 envMapParams;
    u8 alphaOverride;
} Shader;

STATIC_ASSERT(sizeof(Shader) == 0x44);
STATIC_ASSERT(offsetof(Shader, reg1Texture) == 0x08);
STATIC_ASSERT(offsetof(Shader, alpha) == 0x0C);
STATIC_ASSERT(offsetof(Shader, reg2Texture) == 0x14);
STATIC_ASSERT(offsetof(Shader, textureId) == 0x18);
STATIC_ASSERT(offsetof(Shader, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(Shader, reg2TexSlot) == 0x20);
STATIC_ASSERT(offsetof(Shader, reg2Alpha) == 0x22);
STATIC_ASSERT(offsetof(Shader, layers) == 0x24);
STATIC_ASSERT(offsetof(Shader, auxTextureIndex) == 0x34);
STATIC_ASSERT(offsetof(Shader, indTextureId) == 0x38);
STATIC_ASSERT(offsetof(Shader, flags) == 0x3C);
STATIC_ASSERT(offsetof(Shader, vtxAttrFlags) == 0x40);
STATIC_ASSERT(offsetof(Shader, layerCount) == 0x41);
STATIC_ASSERT(offsetof(Shader, envMapParams) == 0x42);
STATIC_ASSERT(offsetof(Shader, alphaOverride) == 0x43);

/* Shader.flags bits */
#define SHADER_FLAG_BACKFACE_CULL      0x8
#define SHADER_FLAG_PROJECTED_TEX_PASS 0x100
#define SHADER_FLAG_ALPHA_TEST_OPAQUE  0x400
#define SHADER_FLAG_WATER_CAUSTIC      0x20000
#define SHADER_FLAG_DECAL_LAYER        0x100000
#define SHADER_FLAG_FORCE_BLEND        0x40000000

/* A model render callback normally returns zero for the standard material
 * setup or one after supplying its own GX state. This third result suppresses
 * the display list associated with the current render op. */
#define OBJMODEL_RENDER_CALLBACK_SKIP_DRAW 2

typedef struct ModelRenderOpTextureRefs {
    void* texture0;
    void* texture1;
    u8 swapSelector;
    u8 pad09[3];
} ModelRenderOpTextureRefs;

STATIC_ASSERT(sizeof(ModelRenderOpTextureRefs) == 0x0C);
STATIC_ASSERT(offsetof(ModelRenderOpTextureRefs, texture1) == 0x04);
STATIC_ASSERT(offsetof(ModelRenderOpTextureRefs, swapSelector) == 0x08);

/* Quantized normal and two-matrix weight records used by the skinning streams. */
typedef struct ModelPackedNormal {
    s8 x;
    s8 y;
    s8 z;
} ModelPackedNormal;

typedef struct ModelNormalTriplet {
    ModelPackedNormal vectors[3];
} ModelNormalTriplet;

typedef struct ModelSkinWeightPair {
    u8 matrixA;
    u8 matrixB;
} ModelSkinWeightPair;

STATIC_ASSERT(sizeof(ModelPackedNormal) == 3);
STATIC_ASSERT(offsetof(ModelPackedNormal, x) == 0);
STATIC_ASSERT(offsetof(ModelPackedNormal, y) == 1);
STATIC_ASSERT(offsetof(ModelPackedNormal, z) == 2);
STATIC_ASSERT(sizeof(ModelNormalTriplet) == 9);
STATIC_ASSERT(offsetof(ModelNormalTriplet, vectors) == 0);
STATIC_ASSERT(sizeof(ModelSkinWeightPair) == 2);
STATIC_ASSERT(offsetof(ModelSkinWeightPair, matrixA) == 0);
STATIC_ASSERT(offsetof(ModelSkinWeightPair, matrixB) == 1);

/* Jobs and chunk records for the cached vertex and normal blend streams. */
typedef struct ModelVtxAnimJob {
    u8 unk00[2];
    u16 chunkCount; /* 0x02 */
    u8 unk04[2];
    u8 quantShift; /* 0x06: low six bits: signed GQR7 scale for s16/s8 streams */
    u8 unk07[5];
    struct ModelVtxAnimChunk* chunks; /* 0x0C */
} ModelVtxAnimJob;

typedef struct ModelVtxAnimChunk {
    u8 unk00[0x60];
    s32 srcDataOffset; /* 0x60: into the anim data */
    u8* weightStream;  /* 0x64 */
    u8 unk68[4];
    u8 mtxIdxA; /* 0x6C: * 0x30 into the reordered matrix array */
    u8 mtxIdxB; /* 0x6D */
    u8 unk6E;
    u8 weightBlocks;  /* 0x6F */
    u16 vtxCount;     /* 0x70 */
    u8 dstByteOffset; /* 0x72 */
    u8 vtxBlocks;     /* 0x73 */
} ModelVtxAnimChunk;  /* 0x74 */

STATIC_ASSERT(sizeof(ModelVtxAnimChunk) == 0x74);
STATIC_ASSERT(sizeof(ModelVtxAnimJob) == 0x10);
STATIC_ASSERT(offsetof(ModelVtxAnimJob, quantShift) == 0x06);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, weightStream) == 0x64);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, mtxIdxA) == 0x6c);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, mtxIdxB) == 0x6d);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, weightBlocks) == 0x6f);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, dstByteOffset) == 0x72);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, vtxBlocks) == 0x73);
STATIC_ASSERT(offsetof(ModelVtxAnimJob, chunkCount) == 0x02);
STATIC_ASSERT(offsetof(ModelVtxAnimJob, chunks) == 0x0C);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, srcDataOffset) == 0x60);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, vtxCount) == 0x70);

/* Each extra joint blends two inverse-bind-adjusted joint matrices. */
typedef struct ModelExtraJointDef {
    u8 jointA;
    u8 jointB;
    u8 weightA; /* quarter units; the second weight is 1 - weightA / 4 */
    u8 unk03;
} ModelExtraJointDef;

STATIC_ASSERT(sizeof(ModelExtraJointDef) == 4);
STATIC_ASSERT(offsetof(ModelExtraJointDef, jointA) == 0);
STATIC_ASSERT(offsetof(ModelExtraJointDef, jointB) == 1);
STATIC_ASSERT(offsetof(ModelExtraJointDef, weightA) == 2);

/* Fuzz shell expansion about a pivot, for a joint or the vertex-animation path. */
typedef struct ModelFuzzScaleDef {
    f32 pivot[3];
    f32 scaleDivisor;
} ModelFuzzScaleDef;

STATIC_ASSERT(sizeof(ModelFuzzScaleDef) == 0x10);
STATIC_ASSERT(offsetof(ModelFuzzScaleDef, pivot) == 0);
STATIC_ASSERT(offsetof(ModelFuzzScaleDef, scaleDivisor) == 0x0C);

typedef struct ModelCollisionTriangle {
    u16 vertexIndices[3];
    u8 unk06[2];
} ModelCollisionTriangle;

STATIC_ASSERT(sizeof(ModelCollisionTriangle) == 8);
STATIC_ASSERT(offsetof(ModelCollisionTriangle, vertexIndices) == 0);

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
    u16 flags; /* 0x8 = single-pass anim-eval path, 0x10 = dynamic vertex buffers, 0x40 = vertex anim area */
    union {
        u16 modelId; /* MODELS.TAB index */
        u16 modNo;   /* animation-bank model number */
    };
    u8 unk06[6];
    s32 dataSize; /* anim data appended at header + dataSize */
    u8 unk10[8];
    u8* unk18;
    u8* unk1C;
    s32* textureIds; /* file texture ids, patched to texture ptrs on load */
    u8 flags24;      /* 0x08 = NBT triplets instead of single packed normals */
    u8 unk25[3];
    u8* vertices;  /* vertexCount s16 XYZ records; scale selected by MODEL_FLAG_INTEGER_VERTEX_COORDS */
    u8* normals;   /* 3 or 9 bytes each, normalCount */
    u8* colors;    /* GX_VA_CLR0 array, stride 2 */
    u8* texCoords; /* GX_VA_TEX0/TEX1 array, stride 4 */
    Shader* renderOps;
    u8* jointData;
    ModelFuzzScaleDef* jointFuzzScales; /* one record per joint */
    ModelFuzzScaleDef vertexFuzzScale;
    ModelExtraJointDef* extraJointDefs;
    union {
        u8* hitVolumes;      /* 0x18-byte ModelHitSphereDef records */
        void* hitReactTable; /* animation-bank hit-reaction rows */
    };
    ModelCollisionTriangle* collisionTriangles;
    CollisionPolygonGroup* collisionBlocks;
    struct ObjAnimMoveData** moveData;
    u8* animationDataSection;
    union {
        u8* animationHeaderBuffer; /* per-joint s16 table */
        s16* cachedAnimIds;
    };
    union {
        s16 animGroupBaseIndices[8]; /* group bases from modelLoadAnimations */
        s16 moveGroupBaseIndices[8];
    };
    s32 animationDataFileOffset;
    s16 animationCacheSize; /* Per-cache allocation size, including the joint-slot prefix. */
    u8 unk86[2];
    ModelVtxAnimJob vertexAnimJob;
    u8 unk98[0xC];
    ModelVtxAnimChunk* vertexAnimEntries;
    u8* vertexWeightData;
    ModelVtxAnimJob normalAnimJob;
    u8 unkBC[0xC];
    ModelVtxAnimChunk* normalAnimEntries;
    u8* normalWeightData;
    struct ModelDisplayListEntry* displayLists; /* primary group followed by shadow group */
    u8* instrs;
    u16 instrsBitLenWords; /* 0xD8: render-instruction stream length; *8 gives bit length (see objprint_dolphin render-instr readers) */
    u8 unkDA[2];
    u16** morphTargetPtrs; /* morphTargetCount streams: index/flags, then signed component words */
    u16 cullDistance;
    u16 shaderFlags;
    u16 vertexCount;
    u16 normalCount;
    u16 colorCount;
    u16 texCoordCount;
    union {
        u16 animationCount; /* nonzero = per-joint matrix buffers */
        u16 moveCount;
    };
    u8 unkEE[2];
    u16 collisionBlockCount; /* 0xF0: number of 0x14-byte collisionBlocks entries */
    u8 textureCount;
    u8 jointCount;
    u8 extraJointCount;
    u8 displayListCount; /* 0xF5: count of the primary (non-shadow) 0x1c-stride display-list group; base index for the shadow group */
    u8 shadowDisplayListCount; /* count of the 2nd display-list group (shadow), indexed at base displayListCount */
    u8 hitVolumeCount;         /* 0xF7: count of 0x10-byte runtime hit-sphere records */
    u8 renderOpCount;
    u8 morphTargetCount;
    u8 texMtxCount; /* 0xFA: texture-matrix descriptor count (GX_VA_TEXnMTXIDX loop bound) */
} ModelFileHeader;

/* ModelFileHeader.flags bits */
#define MODEL_FLAG_NO_ANIMATIONS          0x2
#define MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS 0x10
#define MODEL_FLAG_CACHED_ANIMATIONS      0x40
#define MODEL_FLAG_NO_DEPTH_TEST          0x400
/* Set: integer s16 XYZ; clear: signed s16 XYZ with eight fractional bits. */
#define MODEL_FLAG_INTEGER_VERTEX_COORDS  0x800
#define MODEL_FLAG_ALPHA_Z_UPDATE         0x2000
#define MODEL_FLAG_ALT_POINTER_LAYOUT     0x8000

/* ModelFileHeader.flags24 bits */
#define MODEL_FLAGS24_VERY_BRIGHT 0x02
/* Selects GX_VA_NBT and ModelNormalTriplet entries instead of single normals. */
#define MODEL_FLAGS24_NBT_NORMALS 0x8

/* ModelFileHeader.shaderFlags bit: set = use object color override (gObjOverrideColor) */
#define MODEL_SHADERFLAGS_USE_OBJ_COLOR 0x2

/* ObjModel.bufferFlags bits */
#define OBJMODEL_BUFFER_FLAG_HITSPHERE_SELECT 0x4 /* selects a hitVolumeSphereBuffers entry */
#define OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED  0x40

STATIC_ASSERT(offsetof(ModelFileHeader, vertexAnimJob) == 0x88);
STATIC_ASSERT(offsetof(ModelFileHeader, normalAnimJob) == 0xac);
STATIC_ASSERT(offsetof(ModelFileHeader, modelId) == 0x04);
STATIC_ASSERT(offsetof(ModelFileHeader, modNo) == 0x04);
STATIC_ASSERT(offsetof(ModelFileHeader, jointData) == 0x3C);
STATIC_ASSERT(offsetof(ModelFileHeader, jointFuzzScales) == 0x40);
STATIC_ASSERT(offsetof(ModelFileHeader, vertexFuzzScale) == 0x44);
STATIC_ASSERT(offsetof(ModelFileHeader, extraJointDefs) == 0x54);
STATIC_ASSERT(offsetof(ModelFileHeader, collisionTriangles) == 0x5C);
STATIC_ASSERT(offsetof(ModelFileHeader, collisionBlocks) == 0x60);
STATIC_ASSERT(offsetof(ModelFileHeader, displayLists) == 0xD0);
STATIC_ASSERT(offsetof(ModelFileHeader, morphTargetPtrs) == 0xDC);
STATIC_ASSERT(offsetof(ModelFileHeader, hitVolumes) == 0x58);
STATIC_ASSERT(offsetof(ModelFileHeader, hitReactTable) == 0x58);
STATIC_ASSERT(offsetof(ModelFileHeader, moveData) == 0x64);
STATIC_ASSERT(offsetof(ModelFileHeader, cachedAnimIds) == 0x6C);
STATIC_ASSERT(offsetof(ModelFileHeader, animationCacheSize) == 0x84);
STATIC_ASSERT(offsetof(ModelFileHeader, moveGroupBaseIndices) == 0x70);
STATIC_ASSERT(offsetof(ModelFileHeader, moveCount) == 0xEC);
STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20);
STATIC_ASSERT(offsetof(ModelFileHeader, normalAnimEntries) == 0xC8);
STATIC_ASSERT(offsetof(ModelFileHeader, collisionBlockCount) == 0xF0);
STATIC_ASSERT(offsetof(ModelFileHeader, textureCount) == 0xF2);
STATIC_ASSERT(offsetof(ModelFileHeader, jointCount) == 0xF3);
STATIC_ASSERT(offsetof(ModelFileHeader, hitVolumeCount) == 0xF7);
STATIC_ASSERT(offsetof(ModelFileHeader, morphTargetCount) == 0xF9);
STATIC_ASSERT(offsetof(ModelFileHeader, texMtxCount) == 0xFA);

typedef struct ModelDisplayListEntry {
    void* dlist;
    u16 dlistSize;
    u8 pad06[0x16];
} ModelDisplayListEntry;

STATIC_ASSERT(sizeof(ModelDisplayListEntry) == 0x1C);
STATIC_ASSERT(offsetof(ModelDisplayListEntry, dlist) == 0);
STATIC_ASSERT(offsetof(ModelDisplayListEntry, dlistSize) == 4);

/* ModelFileHeader.hitVolumes entry: joint-space sphere transformed by the
 * joint matrix each update (objUpdateHitSpheres). */
typedef struct ModelHitSphereDef {
    s16 jointIdx;
    u8 pad02[2];
    f32 radius;        /* scaled by anim.rootMotionScale at update */
    f32 center[3];     /* joint-space center */
    u16 linkedSpheres; /* packed relative indices for track-contact sweeps */
    s8 sphereIndex;    /* owning sphere for mask tests */
    s8 maskBit;        /* bit selected from the object's hit-volume mask */
} ModelHitSphereDef;   /* 0x18 */

STATIC_ASSERT(sizeof(ModelHitSphereDef) == 0x18);
STATIC_ASSERT(offsetof(ModelHitSphereDef, jointIdx) == 0x00);
STATIC_ASSERT(offsetof(ModelHitSphereDef, radius) == 0x04);
STATIC_ASSERT(offsetof(ModelHitSphereDef, center) == 0x08);
STATIC_ASSERT(offsetof(ModelHitSphereDef, linkedSpheres) == 0x14);
STATIC_ASSERT(offsetof(ModelHitSphereDef, sphereIndex) == 0x16);
STATIC_ASSERT(offsetof(ModelHitSphereDef, maskBit) == 0x17);

/* Runtime double-buffered hit-sphere record (ObjModel.hitVolumeSphereBuffers). */
typedef struct ObjModelHitSphere {
    f32 radius;
    f32 pos[3];
} ObjModelHitSphere; /* 0x10 */

STATIC_ASSERT(sizeof(ObjModelHitSphere) == 0x10);
STATIC_ASSERT(offsetof(ObjModelHitSphere, radius) == 0x00);
STATIC_ASSERT(offsetof(ObjModelHitSphere, pos) == 0x04);

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
    f32 previousWeight; /* weight observed by the preceding blend-channel apply pass */
    f32 weightRate;     /* 0x08: per-dt weight delta (weight += weightRate * dt) */
    s8 morphTargetA;    /* 0x0C: index into morphTargetPtrs[] for blend source A (-1 = none) */
    s8 morphTargetB;    /* 0x0D: index into morphTargetPtrs[] for blend source B (-1 = none) */
    u8 flags;
    u8 unk0F;
} ObjModelBlendChannel;

/* ObjModelBlendChannel.flags */
#define BLENDCHAN_FLAG_MANUAL         0x01 /* weight is manual; skip auto-advance */
#define BLENDCHAN_FLAG_RESET_WEIGHT   0x02 /* reset weight to base pending */
#define BLENDCHAN_FLAG_DIRTY          0x04 /* refresh this buffer, then request another refresh */
#define BLENDCHAN_FLAG_REFRESH_NEXT   0x08 /* second vertex-buffer refresh pending */
#define BLENDCHAN_FLAG_KEEP_WEIGHT    0x10 /* retain weight when changing targets */
#define BLENDCHAN_FLAG_ALLOW_NEGATIVE 0x20 /* permit weights down to -1 instead of zero */

STATIC_ASSERT(sizeof(ObjModelBlendChannel) == 0x10);
STATIC_ASSERT(offsetof(ObjModelBlendChannel, previousWeight) == 0x04);
STATIC_ASSERT(offsetof(ObjModelBlendChannel, weightRate) == 0x08);
STATIC_ASSERT(offsetof(ObjModelBlendChannel, morphTargetA) == 0x0c);
STATIC_ASSERT(offsetof(ObjModelBlendChannel, morphTargetB) == 0x0d);
STATIC_ASSERT(offsetof(ObjModelBlendChannel, flags) == 0x0e);

/*
 * ObjModel - per-object model working set built by modelLoad_layoutBuffers
 * (all buffers carved from one allocation). Double-buffered matrix/vertex
 * buffers are selected by flags bits 0/1.
 */
typedef struct ModelJointWork {
    Vec* jointPositions;
    f32* jointRadii;
    f32* radiiSq;
    f32* jointLengths;
    f32* jointCullDistances;
    u8* unk14;
    u8* touchedJoints;
} ModelJointWork;

STATIC_ASSERT(sizeof(ModelJointWork) == 0x1C);
STATIC_ASSERT(offsetof(ModelJointWork, jointPositions) == 0x00);
STATIC_ASSERT(offsetof(ModelJointWork, jointRadii) == 0x04);
STATIC_ASSERT(offsetof(ModelJointWork, jointLengths) == 0x0C);
STATIC_ASSERT(offsetof(ModelJointWork, jointCullDistances) == 0x10);
STATIC_ASSERT(offsetof(ModelJointWork, touchedJoints) == 0x18);

typedef struct ObjModel {
    union {
        ModelFileHeader* file;
        ModelFileHeader* animDef;
    };
    u8 unk04[8];
    u8* jointMatrices[2];
    ModelJointWork* skeletonJointData;
    u16 bufferFlags; /* 1 = mtx buffer select, 2 = vtx buffer select, 0x40 = textures loaded */
    u8 unk1A[2];
    u8* vtxBuf[2];
    u8* normalBuf;
    struct ObjModelBlendChannel* blendChannels; /* 3 channels */
    union {
        void* animStateA;
        ObjAnimState* currentState;
    };
    union {
        void* animStateB; /* only with load flag 0x80 */
        ObjAnimState* activeState;
    };
    ModelRenderOpTextureRefs* textureRefs;
    void* renderCallback;
    void* postRenderCallback;
    s32* vertexAnimOffsets;             /* 0x40: byte offset for each vertex animation chunk */
    u8** normalAnimOutputs;             /* 0x44: one destination in normalBuf per normal animation chunk */
    u8* hitVolumeSphereBuffers[2];      /* 0x48: double-buffered runtime hit spheres */
    u8* activeHitVolumeSpheres;         /* 0x50: current hit-sphere buffer */
    GroundShadowQuad* groundShadowQuad; /* 0x54: allocated only with load flag 0x8000 */
    void* renderAttachment;
    u8* curMtxBuf;
    u8 vtxBufDirty; /* 0x60: set when the active vertex buffer needs re-layout; cleared at layout */
    u8 unk61[3];
} ObjModel;

s16* ObjModel_GetBaseVertexCoords(ModelFileHeader* modelFile, int vertexIndex);
s16* ObjModel_GetCurrentVertexCoords(ObjModel* model, int vertexIndex);
void modelInitBones(f32 scale, void* model);
void ObjModel_ClearRenderAttachment(ObjModel* model);
void ObjModel_EnableDefaultRenderCallback(void* object, ObjModel* model, f32* mtx, int enabled, f32 scale);
void ObjModel_SetRenderCallback(u8* model, void* callback);
void ObjModel_SetPostRenderCallback(ObjModel* model, void* callback);
void* ObjModel_GetRenderCallback(ObjModel* model);
void* ObjModel_GetPostRenderCallback(ObjModel* model);
Texture* ObjModel_GetTexture(ModelFileHeader* modelFile, int textureIndex);
Shader* ObjModel_GetRenderOp(ModelFileHeader* modelFile, int renderOpIndex);
ModelRenderOpTextureRefs* ObjModel_GetRenderOpTextureRefs(ObjModel* model, int renderOpIndex);

STATIC_ASSERT(offsetof(ObjModel, bufferFlags) == 0x18);
STATIC_ASSERT(sizeof(ObjModel) == 0x64);
STATIC_ASSERT(offsetof(ObjModel, vertexAnimOffsets) == 0x40);
STATIC_ASSERT(offsetof(ObjModel, normalAnimOutputs) == 0x44);
STATIC_ASSERT(offsetof(ObjModel, animDef) == 0x00);
STATIC_ASSERT(offsetof(ObjModel, currentState) == 0x2C);
STATIC_ASSERT(offsetof(ObjModel, activeState) == 0x30);
STATIC_ASSERT(offsetof(ObjModel, skeletonJointData) == 0x14);
STATIC_ASSERT(offsetof(ObjModel, hitVolumeSphereBuffers) == 0x48);
STATIC_ASSERT(offsetof(ObjModel, activeHitVolumeSpheres) == 0x50);
STATIC_ASSERT(offsetof(ObjModel, groundShadowQuad) == 0x54);
STATIC_ASSERT(offsetof(ObjModel, textureRefs) == 0x34);
STATIC_ASSERT(offsetof(ObjModel, renderCallback) == 0x38);
STATIC_ASSERT(offsetof(ObjModel, vtxBufDirty) == 0x60);

/* Verlet-style bone-chain node (player tail etc.), simulated by the
 * modelChainUpdateNodesPassive / modelChainUpdateNodes /
 * modelChainInitNodesFromJoints / modelChainApplyDampingAndJitter cluster. */
typedef struct ObjModelChainNode {
    Vec pos;         /* 0x00: current world position */
    Vec posDelta;    /* 0x0C: per-frame momentum (damped + jittered) */
    Vec localOffset; /* 0x18: rest offset from the parent node */
    Mtx mtx;         /* 0x24: node world matrix */
} ObjModelChainNode; /* 0x54 */

typedef struct ObjModelChainDesc {
    s32* jointIndices; /* per-node model joint index */
    s32 nodeCount;
} ObjModelChainDesc;

typedef struct ObjModelChainEntry {
    ObjModelChainNode* nodes; /* nodeCount+1 records */
    ObjModelChainDesc* desc;
    s32 nodeCount;
} ObjModelChainEntry;

typedef struct ObjModelChain {
    ObjModelChainEntry* entries;
    s32 count;
    f32 stiffness; /* 0x08: dot-product lerp stiffness toward the target orientation */
    f32 damping;   /* 0x0C: per-frame momentum damping multiplier */
    f32 gravityY;  /* 0x10: additive Y gravity applied to momentum */
    f32 phase;
    u8 updatedThisFrame; /* 0x18: set during update, cleared by AdvancePhase */
    u8 firstUpdateDone;
    u8 enabled;
} ObjModelChain;

typedef void (*ObjModelChainUpdateCallback)(ModelFileHeader* file, ObjModel* model, f32* vector, int callbackArg,
                                            int nodeIndex, f32 phase);

STATIC_ASSERT(sizeof(ObjModelChainNode) == 0x54);
STATIC_ASSERT(offsetof(ObjModelChainNode, pos) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChainNode, posDelta) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelChainNode, localOffset) == 0x18);
STATIC_ASSERT(offsetof(ObjModelChainNode, mtx) == 0x24);
STATIC_ASSERT(sizeof(ObjModelChainDesc) == 0x08);
STATIC_ASSERT(offsetof(ObjModelChainDesc, jointIndices) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChainDesc, nodeCount) == 0x04);
STATIC_ASSERT(sizeof(ObjModelChain) == 0x1C);
STATIC_ASSERT(sizeof(ObjModelChainEntry) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelChainEntry, nodes) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChainEntry, desc) == 0x04);
STATIC_ASSERT(offsetof(ObjModelChainEntry, nodeCount) == 0x08);
STATIC_ASSERT(offsetof(ObjModelChain, entries) == 0x00);
STATIC_ASSERT(offsetof(ObjModelChain, count) == 0x04);
STATIC_ASSERT(offsetof(ObjModelChain, stiffness) == 0x08);
STATIC_ASSERT(offsetof(ObjModelChain, damping) == 0x0C);
STATIC_ASSERT(offsetof(ObjModelChain, gravityY) == 0x10);
STATIC_ASSERT(offsetof(ObjModelChain, phase) == 0x14);
STATIC_ASSERT(offsetof(ObjModelChain, updatedThisFrame) == 0x18);
STATIC_ASSERT(offsetof(ObjModelChain, firstUpdateDone) == 0x19);
STATIC_ASSERT(offsetof(ObjModelChain, enabled) == 0x1A);

ObjModelJointMatrix* ObjModel_GetJointMatrix(u8* modelBytes, int jointIndex);
u16 modelFileHeaderGetCullDistance(ModelFileHeader* modelFile);
void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out);
int ObjModel_NeedsBlendChannelUpdate(ObjModel* model);
void ObjModel_ClearBlendChannels(ObjModel* model);
void ObjModel_SetBlendChannelWeight(ObjModel* model, int channel, f32 weight);
void ObjModel_SetBlendChannelTargets(ObjModel* model, int channel, int targetA, int targetB, f32 weightRate, int flags);
void ObjModel_SampleJointTransform(ObjModel* model, int animState, int frameSource, f32 phase, f32 rootMotionScale,
                                   f32* outPosition, s16* outRotation);
ObjModelChain* ObjModelChain_Alloc(void* models, int count);
void ObjModelChain_SetOrigin(ObjModelChain* chain, f32 x, f32 y, f32 z);
void ObjModelChain_SetEnabled(ObjModelChain* chain, u8 enabled);
void ObjModelChain_AdvancePhase(ObjModelChain* chain);
void ObjModelChain_Free(ObjModelChain* chain);

void setGQR6_2(int loadScale, int loadType, int storeScale, int storeType);
void modelBlendMorphTargets(u8* srcVtx, u8* dstVtx, u16 vtxCount, u16* targetA, u16* targetB, int blendScale);
void* modelLoad_layoutBuffers(u8* p, int b, int isType1, u8* c);
void modelAnimResetState(void* m, void* data);
int modelLoadAnimations(ModelFileHeader* file, int modelId, void* animBase);
void ObjModel_AdvanceBlendChannels(ObjModel* model, f32 dt);
void ObjModel_LoadRenderOpTextures(u8* model, GameObject* object);
void ObjModel_Release(u8* model);
void* ObjModel_LoadAnimData(u8* modelData, int loadFlags, u8* destination);
void* ObjModel_Load(int modelId, int loadFlags, int* outSize);
void Model_GetVertexPosition(ModelFileHeader* model, int vertexIndex, f32* out);
void ObjModel_InitRenderBuffers(void);
void ObjModel_InitResourceCaches(void);
void ObjModel_InitScratchBuffers(void);
void ObjModel_TouchModelCache(void);
void* loadModelInstance(int resourceId, int arg, void* buffer);
void* loadAnimation(ModelFileHeader* hdr, s16 id, int b, struct ObjAnimCachedMove* bufout);

int loadModelAndAnimTabs(void);
void postRenderSetAlphaBlendState(void);
void ObjModelChain_Update(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                          ObjModelChainUpdateCallback callback);
void ObjModelChain_ResetFirstUpdate(ObjModelChain* chain);

#endif
