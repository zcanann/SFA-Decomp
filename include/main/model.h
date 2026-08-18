#ifndef MAIN_MODEL_H_
#define MAIN_MODEL_H_

#include "global.h"
#include "main/texture.h"
#include "dolphin/mtx.h"

typedef struct GameObject GameObject;
typedef struct ObjAnimState ObjAnimState;

typedef struct ShaderLayer
{
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

typedef struct Shader
{
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

typedef struct ModelRenderOpTextureRefs
{
    void* texture0;
    void* texture1;
    u8 swapSelector;
    u8 pad09[3];
} ModelRenderOpTextureRefs;

STATIC_ASSERT(sizeof(ModelRenderOpTextureRefs) == 0x0C);
STATIC_ASSERT(offsetof(ModelRenderOpTextureRefs, texture1) == 0x04);
STATIC_ASSERT(offsetof(ModelRenderOpTextureRefs, swapSelector) == 0x08);

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
    u8 *unk18;
    u8 *unk1C;
    s32 *textureIds; /* file texture ids, patched to texture ptrs on load */
    u8 flags24; /* bit 8 = 9-byte (else 3-byte) entries at normals */
    u8 unk25[3];
    u8 *vertices; /* 6 bytes each, vertexCount */
    u8 *normals;  /* 3 or 9 bytes each, normalCount */
    u8 *colors;   /* GX_VA_CLR0 array, stride 2 */
    u8 *texCoords; /* GX_VA_TEX0/TEX1 array, stride 4 */
    Shader *renderOps;
    u8 *jointData;
    u8 *jointBlendData; /* 0x40: per-joint blend/pivot table (stride joff); [+0..8]=pivot XYZ (PSMTXTrans to/from origin for scale-fuzz), [+0xc]=scale divisor; passed to ObjModel_BlendVertexStream; offset->ptr relocated on load */
    f32 vertexAnimPivot[3];
    f32 vertexAnimScaleDivisor;
    u8 *extraJointDefs; /* 0x54: extraJointCount 3-byte records {jointA, jointB, weight*4}; modelCalcVtxGroupMtxs blends the two joint matrices into the extra joint at jointCount+i; offset->ptr relocated on load */
    union {
        u8 *hitVolumes;      /* 0x18-byte ModelHitSphereDef records */
        void *hitReactTable; /* animation-bank hit-reaction rows */
    };
    u8 *collisionTriangles; /* 0x5c: 8-byte triangle vertex-index records (hit-detect mesh) */
    u8 *collisionBlocks;    /* 0x60: 0x14-byte spatial blocks (AABB + triangle range), collisionBlockCount entries */
    union {
        u8 *animationModelPtrs;
        u8 **moveData;
    };
    u8 *animationDataSection;
    union {
        u8 *animationHeaderBuffer; /* per-joint s16 table */
        s16 *cachedAnimIds;
    };
    union {
        s16 animGroupBaseIndices[8]; /* group bases from modelLoadAnimations */
        s16 moveGroupBaseIndices[8];
    };
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
    u8 **morphTargetPtrs; /* pointer table, morphTargetCount entries */
    u16 cullDistance;
    u16 shaderFlags;
    u16 vertexCount;
    u16 normalCount;
    u8 unkE8[4];
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
    u8 hitVolumeCount; /* 0xF7: count of 0x10-byte runtime hit-sphere records */
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

/* ObjModel.bufferFlags bits */
#define OBJMODEL_BUFFER_FLAG_HITSPHERE_SELECT 0x4 /* selects a hitVolumeSphereBuffers entry */
#define OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED 0x40

STATIC_ASSERT(offsetof(ModelFileHeader, modelId) == 0x04);
STATIC_ASSERT(offsetof(ModelFileHeader, modNo) == 0x04);
STATIC_ASSERT(offsetof(ModelFileHeader, jointData) == 0x3C);
STATIC_ASSERT(offsetof(ModelFileHeader, hitVolumes) == 0x58);
STATIC_ASSERT(offsetof(ModelFileHeader, hitReactTable) == 0x58);
STATIC_ASSERT(offsetof(ModelFileHeader, moveData) == 0x64);
STATIC_ASSERT(offsetof(ModelFileHeader, cachedAnimIds) == 0x6C);
STATIC_ASSERT(offsetof(ModelFileHeader, moveGroupBaseIndices) == 0x70);
STATIC_ASSERT(offsetof(ModelFileHeader, moveCount) == 0xEC);
STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20);
STATIC_ASSERT(offsetof(ModelFileHeader, blendAnimEntries) == 0xC8);
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

/* ModelFileHeader.hitVolumes entry: joint-space sphere transformed by the
 * joint matrix each update (objUpdateHitSpheres). */
typedef struct ModelHitSphereDef {
    s16 jointIdx;
    u8 pad02[2];
    f32 radius;    /* scaled by anim.rootMotionScale at update */
    f32 center[3]; /* joint-space center */
    u16 linkedSpheres; /* packed relative indices for track-contact sweeps */
    s8 sphereIndex;    /* owning sphere for mask tests */
    s8 maskBit;        /* bit selected from the object's hit-volume mask */
} ModelHitSphereDef; /* 0x18 */

STATIC_ASSERT(sizeof(ModelHitSphereDef) == 0x18);
STATIC_ASSERT(offsetof(ModelHitSphereDef, linkedSpheres) == 0x14);
STATIC_ASSERT(offsetof(ModelHitSphereDef, sphereIndex) == 0x16);
STATIC_ASSERT(offsetof(ModelHitSphereDef, maskBit) == 0x17);

/* Runtime double-buffered hit-sphere record (ObjModel.hitVolumeSphereBuffers). */
typedef struct ObjModelHitSphere {
    f32 radius;
    f32 pos[3];
} ObjModelHitSphere; /* 0x10 */

STATIC_ASSERT(sizeof(ObjModelHitSphere) == 0x10);

/* Vertex-anim job header + chunk records consumed by ObjModel_Blend{Vertex,
 * Normal}Stream (the raw .c spells chunkCount as ((ModelFileHeader*)hdr)->flags;
 * the stride 0x74 matches ModelFileHeader.vertexAnimEntries). */
typedef struct ModelVtxAnimJob {
    u8 unk00[2];
    u16 chunkCount; /* 0x02 */
    u8 unk04[2];
    u8 quantShift;  /* 0x06: GQR6/7 scale for the s16/s8 streams */
    u8 unk07[5];
    struct ModelVtxAnimChunk *chunks; /* 0x0C */
} ModelVtxAnimJob;

typedef struct ModelVtxAnimChunk {
    u8 unk00[0x60];
    s32 srcDataOffset; /* 0x60: into the anim data */
    u8 *weightStream;  /* 0x64 */
    u8 unk68[4];
    u8 mtxIdxA;      /* 0x6C: * 0x30 into the reordered matrix array */
    u8 mtxIdxB;      /* 0x6D */
    u8 unk6E;
    u8 weightWords;  /* 0x6F */
    u16 vtxCount;    /* 0x70 */
    u8 dstByteOffset; /* 0x72 */
    u8 vtxWords;     /* 0x73 */
} ModelVtxAnimChunk; /* 0x74 */

STATIC_ASSERT(sizeof(ModelVtxAnimChunk) == 0x74);
STATIC_ASSERT(offsetof(ModelVtxAnimJob, chunkCount) == 0x02);
STATIC_ASSERT(offsetof(ModelVtxAnimJob, chunks) == 0x0C);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, srcDataOffset) == 0x60);
STATIC_ASSERT(offsetof(ModelVtxAnimChunk, vtxCount) == 0x70);

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
typedef struct ModelJointWork {
    u8 *unk00;
    f32 *jointRadii;
    f32 *radiiSq;
    f32 *jointLengths;
    f32 *jointCullDistances;
    u8 *unk14;
    u8 *touchedJoints;
} ModelJointWork;

STATIC_ASSERT(sizeof(ModelJointWork) == 0x1C);
STATIC_ASSERT(offsetof(ModelJointWork, jointRadii) == 0x04);
STATIC_ASSERT(offsetof(ModelJointWork, jointLengths) == 0x0C);
STATIC_ASSERT(offsetof(ModelJointWork, jointCullDistances) == 0x10);
STATIC_ASSERT(offsetof(ModelJointWork, touchedJoints) == 0x18);

typedef struct ObjModel {
    union {
        ModelFileHeader *file;
        ModelFileHeader *animDef;
    };
    u8 unk04[8];
    u8 *jointMatrices[2];
    ModelJointWork *skeletonJointData;
    u16 bufferFlags; /* 1 = mtx buffer select, 2 = vtx buffer select, 0x40 = textures loaded */
    u8 unk1A[2];
    u8 *vtxBuf[2];
    u8 *normalBuf;
    struct ObjModelBlendChannel *blendChannels; /* 3 channels */
    union {
        void *animStateA;
        ObjAnimState *currentState;
    };
    union {
        void *animStateB; /* only with load flag 0x80 */
        ObjAnimState *activeState;
    };
    ModelRenderOpTextureRefs *textureRefs;
    void *renderCallback;
    void *postRenderCallback;
    s32 *vertexAnimData; /* 0x40: per-entry s32 array (file->vertexAnimCount), filled from vertexAnimEntries[i]+0x60 */
    s32 *blendAnimData;  /* 0x44: per-entry s32 array (file->blendAnimCount), filled from normalBuf + blendAnimEntries[i]+0x60 */
    u8 *hitVolumeSphereBuffers[2]; /* 0x48: double-buffered runtime hit spheres */
    u8 *activeHitVolumeSpheres; /* 0x50: current hit-sphere buffer */
    u8 *groundShadowVerts; /* 0x54: ground-shadow quad buffer (s16 verts; status byte at +0x18: 0 = rebuild via buildGroundShadowQuad, 0xff = skip draw); allocated only with load flag 0x8000 */
    void *renderAttachment;
    u8 *curMtxBuf;
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
STATIC_ASSERT(offsetof(ObjModel, animDef) == 0x00);
STATIC_ASSERT(offsetof(ObjModel, currentState) == 0x2C);
STATIC_ASSERT(offsetof(ObjModel, activeState) == 0x30);
STATIC_ASSERT(offsetof(ObjModel, skeletonJointData) == 0x14);
STATIC_ASSERT(offsetof(ObjModel, hitVolumeSphereBuffers) == 0x48);
STATIC_ASSERT(offsetof(ObjModel, activeHitVolumeSpheres) == 0x50);
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
    s32 *jointIndices; /* per-node model joint index */
    s32 nodeCount;
} ObjModelChainDesc;

typedef struct ObjModelChainEntry {
    ObjModelChainNode *nodes; /* nodeCount+1 records */
    ObjModelChainDesc *desc;
    s32 nodeCount;
} ObjModelChainEntry;

typedef struct ObjModelChain {
    ObjModelChainEntry *entries;
    s32 count;
    f32 stiffness; /* 0x08: dot-product lerp stiffness toward the target orientation */
    f32 damping;   /* 0x0C: per-frame momentum damping multiplier */
    f32 gravityY;  /* 0x10: additive Y gravity applied to momentum */
    f32 phase;
    u8 updatedThisFrame; /* 0x18: set during update, cleared by AdvancePhase */
    u8 firstUpdateDone;
    u8 enabled;
} ObjModelChain;

typedef void (*ObjModelChainUpdateCallback)(int animState, int* model, f32* vector, int callbackArg, int nodeIndex,
                                            f32 phase);

STATIC_ASSERT(sizeof(ObjModelChainNode) == 0x54);
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

ObjModelJointMatrix *ObjModel_GetJointMatrix(u8 *modelBytes, int jointIndex);
u16 modelFileHeaderGetCullDistance(ModelFileHeader* modelFile);
void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out);
int ObjModel_HasActiveBlendChannels(ObjModel* model);
void ObjModel_ClearBlendChannels(ObjModel* model);
void ObjModel_SetBlendChannelWeight(ObjModel* model, int channel, f32 weight);
void ObjModel_SetBlendChannelTargets(ObjModel* model, int channel, int targetA, int targetB, f32 weight, int flags);
void ObjModel_SampleJointTransform(ObjModel* model, int animState, int frameSource, f32 phase, f32 rootMotionScale,
                                   f32* outPosition, s16* outRotation);
ObjModelChain *ObjModelChain_Alloc(void *models, int count);
void ObjModelChain_SetOrigin(ObjModelChain *chain, f32 x, f32 y, f32 z);
void ObjModelChain_SetEnabled(ObjModelChain *chain, u8 enabled);
void ObjModelChain_AdvancePhase(ObjModelChain *chain);
void ObjModelChain_Free(ObjModelChain *chain);

void setGQR6_2(int a, int b, int c, int d);
void modelApplyBoneTransforms(u8* srcVtx, u8* dstVtx, u16 vtxCount, u8* targetA, u8* targetB, int blendScale);
void* modelLoad_layoutBuffers(u8* p, int b, int isType1, u8* c);
void modelAnimResetState(void* m, void* data);
int modelLoadAnimations(void* model, int id, void* animBase);
void ObjModel_AdvanceBlendChannels(u8* model, f32 dt);
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
void* loadAnimation(ModelFileHeader* hdr, s16 id, int b, u8* bufout);

int loadModelAndAnimTabs(void);
void postRenderSetAlphaBlendState(void);
void ObjModelChain_Update(int* model, int animState, ObjModelChain* chain, ObjModelChainUpdateCallback callback);
void ObjModelChain_ResetFirstUpdate(ObjModelChain* chain);

#endif
