#include "main/asset_load.h"
#include "main/dll/objmodel_types.h"
#include "main/model.h"
#include "main/game_object.h"
#include "main/object_transform.h"
#include "main/gameplay_runtime.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "main/sfa_extern_decls.h"
#include "main/rcp_dolphin.h"
#include "main/objprint_dolphin.h"
#define GX_BM_BLEND 1
#define GX_BL_ONE 1
#define GX_BL_SRCALPHA 4
#define GX_LO_NOOP 5
#define GX_AOP_AND 0
#define GX_ALWAYS 7
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void gxTextureFn_80072dfc(void* obj_a, void** obj_b, int slot);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);

u16*
FUN_80017460(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , int param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

u16*
FUN_80017468(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

extern f32 timeDelta;

u32
FUN_80017500(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, int param_9)
{
    return 0;
}

u32
FUN_8001786c(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12)
{
    return 0;
}

u8*
FUN_80017998(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
)
{
    return 0;
}

int return0_8002969C(void) { return 0x0; }
int return0_8002A5B8(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void* fn_80028354(u8* modelFile, int index)
{
    return ((ModelFileHeader*)modelFile)->collisionTriangles + index * 8;
}

void* fn_80028364(u8* modelFile, int index)
{
    return ((ModelFileHeader*)modelFile)->collisionBlocks + index * 0x14;
}

void* modelFileGetDisplayList(u8* modelFile, int displayListIndex)
{
    return ((ModelFileHeader*)modelFile)->displayLists + displayListIndex * 0x1c;
}

void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out)
{
    ObjModelInstanceLite* model;
    u32 jointCount;
    u8* jointMtx;

    model = (ObjModelInstanceLite*)modelBytes;
    jointCount = model->file->jointCount;
    if (jointIndex >= (int)(jointCount != 0 ? jointCount + model->file->extraJointCount : 1))
    {
        jointIndex = 0;
    }

    jointMtx = model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40;
    out[0] = *(f32*)(jointMtx + 0xc);
    out[1] = *(f32*)(jointMtx + 0x1c);
    out[2] = *(f32*)(jointMtx + 0x2c);
}

void* ObjModel_GetTexture(u8* model, int textureIndex)
{
    return textureIdxToPtr(((ModelFileHeader*)model)->textureIds[textureIndex]);
}

void* ObjModel_GetBaseVertexCoords(u8* model, int vertexIndex)
{
    return ((ModelFileHeader*)model)->vertices + vertexIndex * 6;
}

void* ObjModel_GetRenderOp(u8* model, int renderOpIndex)
{
    return ((ModelFileHeader*)model)->renderOps + renderOpIndex * 0x44;
}

u16 modelFileHeaderGetCullDistance(u8* modelFile)
{
    return ((ModelFileHeader*)modelFile)->cullDistance;
}

void ObjModel_ClearRenderAttachment(u8* model)
{
    if (((ObjModel*)model)->renderAttachment != NULL)
    {
        mm_free(((ObjModel*)model)->renderAttachment);
        ((ObjModel*)model)->renderAttachment = NULL;
    }
    else
    {
        ((ObjModel*)model)->renderCallback = NULL;
    }
}

void ObjModel_EnableDefaultRenderCallback(void* obj, u8* model, f32* mtx, int enabled, f32 scale)
{
    if (((ObjModel*)model)->renderAttachment == NULL)
    {
        ((ObjModel*)model)->renderCallback = gxTextureFn_80072dfc;
    }
}

void* ObjModel_GetCurrentVertexCoords(u8* model, int vertexIndex)
{
    model += (((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4);
    return ((ObjModel*)model)->vtxBuf0 + vertexIndex * 6;
}

void* ObjModel_GetPostRenderCallback(u8* model)
{
    return ((ObjModel*)model)->postRenderCallback;
}

void postRenderSetAlphaBlendState(void)
{
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void ObjModel_SetPostRenderCallback(u8* model, void* callback)
{
    ((ObjModel*)model)->postRenderCallback = callback;
}

void* ObjModel_GetRenderCallback(u8* model)
{
    return ((ObjModel*)model)->renderCallback;
}

void ObjModel_SetRenderCallback(u8* model, void* callback)
{
    ((ObjModel*)model)->renderCallback = callback;
}

void ObjModel_ToggleVertexBuffer(u8* model)
{
    ((ObjModel*)model)->bufferFlags ^= 2;
}

void ObjModel_ToggleMatrixBuffer(u8* model)
{
    ((ObjModel*)model)->bufferFlags ^= 1;
}

ObjModelJointMatrix* ObjModel_GetJointMatrix(u8* modelBytes, int jointIndex)
{
    ObjModelInstanceLite* model;
    u32 jointCount;

    model = (ObjModelInstanceLite*)modelBytes;
    jointCount = model->file->jointCount;
    if (jointIndex >= (int)(jointCount != 0 ? jointCount + model->file->extraJointCount : 1))
    {
        jointIndex = 0;
    }

    return (ObjModelJointMatrix*)(model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40);
}

void* ObjModel_GetRenderOpTextureRefs(u8* model, int renderOpIndex)
{
    return ((ObjModel*)model)->textureRefs + renderOpIndex * 0xc;
}

int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize)
{
    return baseSize + resource[8] * resource[7];
}

int getHudHiddenFrameCount(void);

#pragma scheduling on
#pragma peephole on
void __set_debug_bba(u8* p)
{
    p[0x19] = 0;
}

int roundUpTo4(int x);

int roundUpTo8(int x);

int roundUpTo16(int x);

int roundUpTo32(int x);

void ObjModelChain_SetEnabled(ObjModelChain* chain, u8 enabled)
{
    chain->enabled = enabled;
}

extern void* mmAlloc(int size, int type, int flag);
extern void* memset(void* dst, int val, int n);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);
extern void PSMTXMultVecSR(f32 * mtx, f32 * in, f32 * out);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

void ObjModelChain_SetOrigin(ObjModelChain* chain, f32 x, f32 y, f32 z)
{
    chain->originX = x;
    chain->originY = y;
    chain->originZ = z;
}

int alignUp2(int x);

extern int getLoadedFileFlags(int);

void* getCache(void);

extern f32 gModelPhaseWrapPeriod;

void cacheQueueWait(int sync);

#pragma scheduling off
#pragma peephole off
void ObjModelChain_AdvancePhase(ObjModelChain* chain)
{
    chain->updateFlag = 0;
    chain->phase += timeDelta;
    if (chain->phase > gModelPhaseWrapPeriod)
    {
        chain->phase -= *(f32*)&gModelPhaseWrapPeriod;
    }
}


extern void setGQR7(u32 v);
extern int textureLoad(int id, int flag);

asm
void setGQR6(register u32 v)
{
    nofralloc
    mtspr GQR6, v
    blr
}

asm
void setGQR7(register u32 v)
{
    nofralloc
    mtspr GQR7, v
    blr
}

#pragma dont_inline on
void setGQR7Packed(int a, int b, int c, int d)
{
    setGQR7((((a << 8) + b) << 16) | ((c << 8) + d));
}

#pragma dont_inline off
int ObjModel_HasActiveBlendChannels(u8* model)
{
    ObjModelBlendChannel* ch;

    if (((ObjModel*)model)->file->morphTargetPtrs == NULL)
    {
        return 0;
    }
    ch = ((ObjModel*)model)->blendChannels;
    if (ch[0].weight != ch[0].targetWeight || (ch[0].flags0E & 0xe))
    {
        return 1;
    }
    if (ch[1].weight != ch[1].targetWeight || (ch[1].flags0E & 0xe))
    {
        return 1;
    }
    if (ch[2].weight != ch[2].targetWeight || (ch[2].flags0E & 0xe))
    {
        return 1;
    }
    return 0;
}

void ObjModel_SetBlendChannelWeight(u8* model, int channel, f32 weight)
{
    ObjModelBlendChannel* ch;

    if (channel > 2 || ((ObjModel*)model)->file->morphTargetPtrs == NULL)
    {
        return;
    }
    ch = ((ObjModel*)model)->blendChannels + channel;
    if (weight != ch->weight)
    {
        ch->weight = weight;
    }
    ch[0].flags0E |= 4;
}

typedef f32 Mtx[3][4];
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);
extern int* gModelAnimOffsetTable;

#pragma opt_propagation off
int modelGetAmapSize(int animId, int amapFlag, int jointCount)
{
    int size;
    if (amapFlag != 0)
    {
        size = jointCount * 2 + 8;
        while (size & 7)
        {
            size++;
        }
    }
    else
    {
        {
            int words;
            words = jointCount * 4;
            size = words;
        }
        while (size & 7)
        {
            size++;
        }
        fileLoadToBufferOffset(0x31, gModelAnimOffsetTable, (animId & ~3) << 2, 0x20);
        size += gModelAnimOffsetTable[(animId & 3) + 1] - gModelAnimOffsetTable[animId & 3];
    }
    return size;
}
#pragma opt_propagation reset


extern int gModelTabEntryCount;
extern void* gModelAnimFlagsTable;
extern int lbl_803DCB58;
extern void shaderInit(u8* def, void* out, int arg, int n);

void ObjModel_RelocateModelData(u8* m)
{
    int i;
    if (*(u32*)&((ModelFileHeader*)m)->unk58)
    {
        ((ModelFileHeader*)m)->unk58 = m + *(u32*)&((ModelFileHeader*)m)->unk58;
    }
    if (*(u32*)&((ModelFileHeader*)m)->jointData)
    {
        ((ModelFileHeader*)m)->jointData = m + *(u32*)&((ModelFileHeader*)m)->jointData;
        if (*(u32*)&((ModelFileHeader*)m)->unk18)
        {
            ((ModelFileHeader*)m)->unk18 = m + *(u32*)&((ModelFileHeader*)m)->unk18;
        }
        if (*(u32*)&((ModelFileHeader*)m)->unk1C)
        {
            ((ModelFileHeader*)m)->unk1C = m + *(u32*)&((ModelFileHeader*)m)->unk1C;
        }
        if (*(u32*)&((ModelFileHeader*)m)->unk40)
        {
            ((ModelFileHeader*)m)->unk40 = m + *(u32*)&((ModelFileHeader*)m)->unk40;
        }
    }
    if (*(u32*)&((ModelFileHeader*)m)->unk54)
    {
        ((ModelFileHeader*)m)->unk54 = m + *(u32*)&((ModelFileHeader*)m)->unk54;
    }
    if (*(u32*)&((ModelFileHeader*)m)->textureIds)
    {
        *(u8**)&((ModelFileHeader*)m)->textureIds = m + *(u32*)&((ModelFileHeader*)m)->textureIds;
    }
    ((ModelFileHeader*)m)->vertices = m + *(u32*)&((ModelFileHeader*)m)->vertices;
    if (*(u32*)&((ModelFileHeader*)m)->normals)
    {
        ((ModelFileHeader*)m)->normals = m + *(u32*)&((ModelFileHeader*)m)->normals;
    }
    if (*(u32*)&((ModelFileHeader*)m)->unk30)
    {
        ((ModelFileHeader*)m)->unk30 = m + *(u32*)&((ModelFileHeader*)m)->unk30;
    }
    if (*(u32*)&((ModelFileHeader*)m)->unk34)
    {
        ((ModelFileHeader*)m)->unk34 = m + *(u32*)&((ModelFileHeader*)m)->unk34;
    }
    if (*(u32*)&((ModelFileHeader*)m)->instrs)
    {
        ((ModelFileHeader*)m)->instrs = m + *(u32*)&((ModelFileHeader*)m)->instrs;
    }
    if (*(u32*)&((ModelFileHeader*)m)->displayLists)
    {
        ((ModelFileHeader*)m)->displayLists = m + *(u32*)&((ModelFileHeader*)m)->displayLists;
    }
    if (*(u32*)&((ModelFileHeader*)m)->morphTargetPtrs)
    {
        ((ModelFileHeader*)m)->morphTargetPtrs = m + *(u32*)&((ModelFileHeader*)m)->morphTargetPtrs;
    }
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries)
    {
        ((ModelFileHeader*)m)->vertexAnimEntries = m + *(u32*)&((ModelFileHeader*)m)->vertexAnimEntries;
    }
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimBase)
    {
        ((ModelFileHeader*)m)->vertexAnimBase = m + *(u32*)&((ModelFileHeader*)m)->vertexAnimBase;
    }
    if (*(u32*)&((ModelFileHeader*)m)->blendAnimEntries)
    {
        ((ModelFileHeader*)m)->blendAnimEntries = m + *(u32*)&((ModelFileHeader*)m)->blendAnimEntries;
    }
    if (*(u32*)&((ModelFileHeader*)m)->blendAnimBase)
    {
        ((ModelFileHeader*)m)->blendAnimBase = m + *(u32*)&((ModelFileHeader*)m)->blendAnimBase;
    }
    if (*(u32*)&((ModelFileHeader*)m)->renderOps)
    {
        ((ModelFileHeader*)m)->renderOps = m + *(u32*)&((ModelFileHeader*)m)->renderOps;
    }
    for (i = 0; i < ((ModelFileHeader*)m)->unkF5 + ((ModelFileHeader*)m)->shadowDisplayListCount; i++)
    {
        *(u8**)(((ModelFileHeader*)m)->displayLists + i * 0x1c) = m + *(u32*)(((ModelFileHeader*)m)->displayLists + i *
            0x1c);
    }
    for (i = 0; i < ((ModelFileHeader*)m)->morphTargetCount; i++)
    {
        *(u8**)(((ModelFileHeader*)m)->morphTargetPtrs + i * 4) = m + *(u32*)(((ModelFileHeader*)m)->morphTargetPtrs + i
            * 4);
    }
    if (*(u32*)&((ModelFileHeader*)m)->collisionTriangles)
    {
        ((ModelFileHeader*)m)->collisionTriangles = m + *(u32*)&((ModelFileHeader*)m)->collisionTriangles;
    }
    if (*(u32*)&((ModelFileHeader*)m)->collisionBlocks)
    {
        ((ModelFileHeader*)m)->collisionBlocks = m + *(u32*)&((ModelFileHeader*)m)->collisionBlocks;
    }
}

extern int getTableFileEntry(int fileId, int index, int* out);
/* defined in pi_dolphin.c with 5 params; the retail caller here emits a
   6th arg (the model id) -- keep the caller-side arity */
extern void loadModelsBin(int fileOffset, int* jointCount, int* headerSize, int* amapFlag, int* dataLen, int id);
extern int loadAndDecompressDataFile(int id, void* buf, int blockOff, int len, int a, int b, int c);

#pragma dont_inline on
void* ObjModel_LoadModelData(int id)
{
    int fileOffset, dataLen, jointCount, headerSize, amapFlag;
    int amapSize;
    void* model;
    if (getTableFileEntry(0x2a, id, &fileOffset) == 0)
    {
        return NULL;
    }
    loadModelsBin(fileOffset, &jointCount, &headerSize, &amapFlag, &dataLen, id);
    headerSize = roundUpTo8(headerSize);
    headerSize += 0xb0;
    amapSize = modelGetAmapSize(id, amapFlag, jointCount);
    model = (void*)roundUpTo16((int)mmAlloc(dataLen + amapSize + 0x1f4, 9, 0));
    loadAndDecompressDataFile(0x2b, model, fileOffset, dataLen, 0, id, 0);
    *(s16*)((u8*)model + 0x84) = headerSize;
    *(u16*)((u8*)model + 0x4) = id;
    *(u16*)((u8*)model + 0xec) = jointCount;
    *(u16*)((u8*)model + 0x2) &= ~0x40;
    *(u8*)model = 1;
    if (*(u16*)((u8*)model + 0xec) == 0)
    {
        *(u16*)((u8*)model + 0x2) |= 2;
    }
    if (amapFlag != 0)
    {
        *(u16*)((u8*)model + 0x2) |= 0x40;
    }
    return model;
}

#pragma dont_inline off
void ObjModel_ResolveRenderOpTextures(u8* m)
{
    int j, k;
    u8* op;
    for (j = 0; j < m[0xf8]; j++)
    {
        op = *(u8**)(m + 0x38) + j * 0x44;
        for (k = 0; k < op[0x41]; k++)
        {
            /* e is an 8-byte per-renderop texture record whose id sits at
               e + 0x24; the GameObject overlay below is offset-equivalent and
               its member spelling is byte-load-bearing (a raw *(int*)(e + 0x24)
               re-spelling shifts MWCC's alias/CSE class) -- keep as is. */
            u8* e = op + k * 8;
            if (*(int*)&((GameObject*)e)->anim.velocityX != -1)
            {
                *(int*)&((GameObject*)e)->anim.velocityX = ((int*)*(u8**)(m + 0x20))[*(int*)&((GameObject*)e)->anim.velocityX];
            }
            else
            {
                *(int*)&((GameObject*)e)->anim.velocityX = 0;
            }
        }
        if (*(int*)(op + 0x34) != -1)
        {
            *(int*)(op + 0x34) = ((int*)*(u8**)(m + 0x20))[*(int*)(op + 0x34)];
        }
        else
        {
            *(int*)(op + 0x34) = 0;
        }
        if (*(int*)(op + 0x38) != -1)
        {
            *(int*)(op + 0x38) = ((int*)*(u8**)(m + 0x20))[*(int*)(op + 0x38)];
        }
        else
        {
            *(int*)(op + 0x38) = 0;
        }
        if (*(int*)(op + 0x1c) != -1)
        {
            if (*(int*)(op + 0x1c) == -2)
            {
                *(int*)(op + 0x1c) = 0;
            }
            else
            {
                *(int*)(op + 0x1c) = 1;
            }
        }
        else
        {
            *(int*)(op + 0x1c) = 0;
        }
        if (*(int*)(op + 0x18) != -1)
        {
            *(int*)(op + 0x18) = ((int*)*(u8**)(m + 0x20))[*(int*)(op + 0x18)];
        }
        else
        {
            *(int*)(op + 0x18) = 0;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xc))
        {
            *(int*)(op + 0x8) = 0;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xe00))
        {
            *(int*)(op + 0x14) = 0;
        }
    }
}

#pragma dont_inline on
void ObjModel_RelocateAnimData(u8* m, u8* dst)
{
    int i;
    ((ModelFileHeader*)m)->vertexAnimEntriesRaw = ((ModelFileHeader*)m)->vertexAnimEntries;
    for (i = 0; i < ((ModelFileHeader*)m)->vertexAnimCount; i++)
    {
        ((ObjModel*)dst)->vertexAnimData[i] = *(int*)(((ModelFileHeader*)m)->vertexAnimEntries + i * 0x74 + 0x60);
        if (*(u32*)(((ModelFileHeader*)m)->vertexAnimEntries + i * 0x74 + 0x64) < *(u32*)&((ModelFileHeader*)m)->
            vertexAnimBase)
        {
            *(u32*)(((ModelFileHeader*)m)->vertexAnimEntries + i * 0x74 + 0x64) =
                *(u32*)&((ModelFileHeader*)m)->vertexAnimBase + *(u32*)(((ModelFileHeader*)m)->vertexAnimEntries + i *
                    0x74 + 0x64);
        }
    }
    ((ModelFileHeader*)m)->blendAnimEntriesRaw = ((ModelFileHeader*)m)->blendAnimEntries;
    for (i = 0; i < ((ModelFileHeader*)m)->blendAnimCount; i++)
    {
        ((ObjModel*)dst)->blendAnimData[i] =
            *(int*)&((ObjModel*)dst)->normalBuf + *(int*)(((ModelFileHeader*)m)->blendAnimEntries + i * 0x74 + 0x60);
        if (*(u32*)(((ModelFileHeader*)m)->blendAnimEntries + i * 0x74 + 0x64) < *(u32*)&((ModelFileHeader*)m)->
            blendAnimBase)
        {
            *(u32*)(((ModelFileHeader*)m)->blendAnimEntries + i * 0x74 + 0x64) =
                *(u32*)&((ModelFileHeader*)m)->blendAnimBase + *(u32*)(((ModelFileHeader*)m)->blendAnimEntries + i *
                    0x74 + 0x64);
        }
    }
}

#pragma dont_inline off
void ObjModel_LoadRenderOpTextures(u8* model, int arg)
{
    int i;
    u8* hdr = *(u8**)model;
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED)
    {
        return;
    }
    ((ObjModel*)model)->bufferFlags |= OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
    for (i = 0; i < (*(u8**)model)[0xf8]; i++)
    {
        shaderInit(((ModelFileHeader*)hdr)->renderOps + i * 0x44, ((ObjModel*)model)->textureRefs + i * 0xc, arg,
                   ((ModelFileHeader*)hdr)->shaderFlags);
    }
}

int loadModelAndAnimTabs(void)
{
    int* p = getCurrentDataFile(0x2a);
    if (p == NULL)
    {
        return 0;
    }
    gModelTabEntryCount = 0;
    while (*p != -1)
    {
        p++;
        gModelTabEntryCount++;
    }
    gModelTabEntryCount--;
    gModelAnimFlagsTable = getCurrentDataFile(0x2f);
    if (gModelAnimFlagsTable == NULL)
    {
        return 0;
    }
    lbl_803DCB58 = 0;
    return 1;
}

extern void* memcpy(void* dst, const void* src, int n);
extern u32 PPCMfhid2(void);

extern f32 PSVECDotProduct(f32 * a, f32 * b);

void copyToCache(void* dst, void* src, u32 count);

void ObjModel_InitRenderBuffers(void)
{
    if ((PPCMfhid2() & 0x10000000) == 0)
    {
        void* cache = getCache();
        DCInvalidateRange(cache, 0x4000);
        LCEnable();
    }
    ObjModel_InitScratchBuffers();
    setGQR6_2(7, 4, 7, 4);
}

typedef struct
{
    s16* start;
    s16* end;
    u8 _8[4];
    u8 size;
    u8 stride;
    u8 _e[2];
    s16* iter;
} ModelStream;

extern ModelStream* gModelList;

void modelFn_800292e0(void)
{
    u8 buf[8];
    gModelList->iter = gModelList->start;
    while (gModelList->iter != gModelList->end)
    {
        s16* iter = gModelList->iter;
        if (*iter == -1)
        {
            memset(buf, 0, gModelList->size);
        }
        else
        {
            memcpy(buf, iter + 1, gModelList->size);
        }
        gModelList->iter += gModelList->stride;
    }
}

void* animationLoad(int id, int a, int b, int e, int f);

void model_multMtxs(u8* model, f32* out)
{
    u8* hdr = *(u8**)model;
    u32 i;
    for (i = 0; i < hdr[0xf3]; i++)
    {
        int j = i;
        u8* h = *(u8**)model;
        u32 cnt = h[0xf3];
        int lim;
        f32* base;
        if (cnt != 0)
        {
            lim = cnt + h[0xf4];
        }
        else
        {
            lim = 1;
        }
        if (j >= lim)
        {
            j = 0;
        }
        base = *(f32**)(model + 0xc + (((ObjModel*)model)->bufferFlags & 1) * 4);
        PSMTXConcat(out, base + j * 0x10, base + j * 0x10);
    }
}

void ObjModelChain_Free(ObjModelChain* chain)
{
    int i;
    for (i = 0; i < chain->count; i++)
    {
        mm_free(chain->entries[i].frameBuffer);
    }
    mm_free(chain->entries);
    mm_free(chain);
}

extern f32 gModelDefaultOriginX;
extern f32 gModelDefaultOriginY;
extern f32 gModelDefaultOriginZ;
extern f32 lbl_803DE828;
extern const f32 gModelVertexScale;

ObjModelChain* ObjModelChain_Alloc(void* models, int count)
{
    int** p;
    int off;
    ObjModelChain* state;
    int i;

    state = mmAlloc(0x1c, 0x1a, 0);
    state->count = count;
    state->unk19 = 0;
    state->updateFlag = 0;
    state->entries = mmAlloc(count * 0xc, 0x1a, 0);
    i = 0;
    p = models;
    off = 0;
    for (; i < count; i++)
    {
        *(int**)((char*)state->entries + off + 4) = *p;
        *(int*)((char*)state->entries + off + 8) = (*p)[1];
        *(void**)((char*)state->entries + off) = mmAlloc((*(int*)((char*)state->entries + off + 8) + 1) * 0x54, 0x1a, 0);
        p++;
        off += 0xc;
    }
    state->originX = gModelDefaultOriginX;
    state->originY = gModelDefaultOriginY;
    state->originZ = gModelDefaultOriginZ;
    state->phase = lbl_803DE828;
    state->enabled = 1;
    return state;
}

void Model_GetVertexPosition(u8* model, int vertexIndex, f32* out)
{
    s16* vertex;

    vertex = (s16*)(((ModelFileHeader*)model)->vertices + vertexIndex * 6);
    if ((((ModelFileHeader*)model)->flags & 0x800) != 0)
    {
        out[0] = vertex[0];
        out[1] = vertex[1];
        out[2] = vertex[2];
    }
    else
    {
        out[0] = vertex[0] * gModelVertexScale;
        out[1] = vertex[1] * gModelVertexScale;
        out[2] = vertex[2] * gModelVertexScale;
    }
}


void memcpyToCache(void* dst, void* src, u32 count);

void* ObjAnim_LoadCachedMove(int animId, int moveIndex, u8* cache, ObjAnimDef* animDef)
{
    void* out = NULL;
    animationLoad((int)&out, animId, moveIndex, (int)cache, (int)animDef);
    return out;
}

extern u8* gModelCacheBuffersA[];
extern u8* gModelCacheBuffersB[];

#pragma dont_inline on
void ObjModel_InitScratchBuffers(void)
{
    u8* c = getCache();
    gModelCacheBuffersA[0] = c;
    gModelCacheBuffersA[1] = c + 0x1000;
    gModelCacheBuffersA[2] = c + 0x2000;
    gModelCacheBuffersA[3] = c + 0x3000;
    c = getCache();
    gModelCacheBuffersB[0] = c;
    gModelCacheBuffersB[1] = c + 0x1000;
    gModelCacheBuffersB[2] = c + 0x1800;
    gModelCacheBuffersB[3] = c + 0x2000;
    gModelCacheBuffersB[4] = c + 0x3000;
    gModelCacheBuffersB[5] = c + 0x3800;
}

extern void ObjModel_SetBlendChannelTargets(u8* model, int channel, int a, int b, f32 weight, int flags);

#pragma dont_inline off
void ObjModel_ClearBlendChannels(u8* model)
{
    if (((ObjModel*)model)->file->morphTargetPtrs != NULL)
    {
        ObjModel_SetBlendChannelTargets(model, 0, -1, -1, lbl_803DE828, 7);
        ObjModel_SetBlendChannelTargets(model, 1, -1, -1, lbl_803DE828, 7);
        ObjModel_SetBlendChannelTargets(model, 2, -1, -1, lbl_803DE828, 7);
    }
}

extern f32 lbl_803DE840;

void ObjModel_SetBlendChannelTargets(u8* model, int channel, int a, int b, f32 weight, int flags)
{
    ObjModelBlendChannel* ch;
    u8* hdr;
    if (channel > 2 || ((ModelFileHeader*)(hdr = *(u8**)model))->morphTargetPtrs == NULL)
    {
        return;
    }
    if (a < -1)
    {
        return;
    }
    if (b < -1)
    {
        return;
    }
    if (a >= ((ModelFileHeader*)hdr)->morphTargetCount || b >= ((ModelFileHeader*)hdr)->morphTargetCount)
    {
        return;
    }
    ch = ((ObjModel*)model)->blendChannels + channel;
    if (a == -1 && b == -1)
    {
        if (ch[0].morphTargetA != -1 || ch[0].morphTargetB != -1)
        {
            flags |= 6;
        }
        else
        {
            return;
        }
    }
    if (ch[0].morphTargetA == a && ch[0].morphTargetB == b)
    {
        return;
    }
    ch[0].morphTargetA = a;
    ch[0].morphTargetB = b;
    if (!(flags & 0x10))
    {
        ch[0].weight = lbl_803DE828;
    }
    ch[0].targetWeight = lbl_803DE840;
    ch[0].weightRate = weight;
    ch[0].flags0E = flags | 4;
}

extern f32 lbl_803DE818;
extern f32 lbl_803DE868;
extern f32 lbl_803DE86C;
extern f32 lbl_803DE870;

void ObjModel_ApplyBlendChannels(u8* model)
{
    u8* hdr;
    ObjModelBlendChannel* ch;
    int i;
    s16 defFrame;
    int chanActive[3] = {0, 0, 0};
    int chanFade[3] = {0, 0, 0};
    void* targetA;
    void* targetB;
    int srcVtx;
    int dstVtx;
    int fadeBits;
    f32 weight;
    f32 tw;
    f32 eased;

    hdr = *(u8**)model;
    if (((ModelFileHeader*)hdr)->morphTargetPtrs == NULL)
    {
        return;
    }
    defFrame = ((ModelFileHeader*)hdr)->vertexCount + 1;
    for (i = 0; i < 3; i++)
    {
        ch = ((ObjModel*)model)->blendChannels + i;
        if (ch[0].weight != ch[0].targetWeight)
        {
            ch[0].flags0E &= ~0xc;
            ch[0].flags0E |= 4;
        }
        fadeBits = ch[0].flags0E & 0xc;
        chanFade[i] = fadeBits;
        if (ch[0].morphTargetA != -1 || ch[0].morphTargetB != -1 || fadeBits != 0)
        {
            chanActive[i] = 1;
        }
        if (chanFade[i] & 4)
        {
            ch[0].flags0E &= ~4;
            ch[0].flags0E |= 8;
        }
        else if (chanFade[i] & 8)
        {
            ch[0].flags0E &= ~8;
        }
    }
    if (chanActive[0] == 0 && chanActive[1] == 0 && chanActive[2] == 0)
    {
        return;
    }
    if (chanActive[1])
    {
        chanActive[0] = 0;
    }
    if (chanFade[2])
    {
        chanFade[0] = 1;
        chanFade[1] = 1;
    }
    if ((chanActive[0] && chanFade[0]) || (chanActive[1] && chanFade[1]))
    {
        if (chanActive[2])
        {
            chanFade[2] = 1;
        }
    }
    for (i = 0; i < 3; i++)
    {
        if (chanActive[i] && ((ModelFileHeader*)hdr)->vertexAnimEntries)
        {
            chanFade[i] = 1;
        }
        ch = ((ObjModel*)model)->blendChannels + i;
        if (ch[0].flags0E & 2)
        {
            ch[0].flags0E &= ~2;
            ch[0].weight = lbl_803DE828;
        }
        if (chanActive[i] && chanFade[i])
        {
            if (ch[0].morphTargetA > -1)
            {
                targetA = (void*)((int*)(((ModelFileHeader*)hdr)->morphTargetPtrs))[ch[0].morphTargetA];
            }
            else
            {
                targetA = &defFrame;
            }
            if (ch[0].morphTargetB > -1)
            {
                targetB = (void*)((int*)(((ModelFileHeader*)hdr)->morphTargetPtrs))[ch[0].morphTargetB];
            }
            else
            {
                targetB = &defFrame;
            }
            if (i == 2)
            {
                if (chanActive[0] == 0 && chanActive[1] == 0)
                {
                    srcVtx = *(int*)&((ModelFileHeader*)hdr)->vertices;
                }
                else
                {
                    srcVtx = *(int*)(model + ((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4 + 0x1c);
                }
            }
            else
            {
                srcVtx = *(int*)&((ModelFileHeader*)hdr)->vertices;
            }
            weight = ch[0].weight;
            if (weight > lbl_803DE818)
            {
                ch[0].weight = lbl_803DE818;
            }
            else if (weight < lbl_803DE828)
            {
                if (ch[0].flags0E & 0x20)
                {
                    if (weight < lbl_803DE840)
                    {
                        ch[0].weight = lbl_803DE840;
                    }
                }
                else
                {
                    ch[0].weight = lbl_803DE828;
                }
            }
            weight = ch[0].weight;
            if (weight >= lbl_803DE828)
            {
                tw = weight;
                eased = lbl_803DE868 * tw + lbl_803DE86C * (tw * tw) - tw * (tw * tw);
            }
            else
            {
                tw = weight * lbl_803DE840;
                eased = lbl_803DE868 * tw + lbl_803DE86C * (tw * tw) - tw * (tw * tw);
                eased = eased * lbl_803DE840;
            }
            dstVtx = *(int*)(model + ((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4 + 0x1c);
            modelApplyBoneTransforms(srcVtx, dstVtx, ((ModelFileHeader*)hdr)->vertexCount, targetA, targetB,
                                     (int)(lbl_803DE870 * eased));
            ((ObjModel*)model)->unk60 = 1;
        }
        if (ch[0].targetWeight != ch[0].weight)
        {
            ch[0].targetWeight = ch[0].weight;
        }
    }
}

extern f32 lbl_803DE874;
extern f32 lbl_803DE878;
extern f32 lbl_803DE87C;

#pragma scheduling on
void ObjModel_AdvanceBlendChannels(u8* model, f32 dt)
{
    int i;
    ObjModelBlendChannel* ch;
    if (((ObjModel*)model)->file->morphTargetPtrs == NULL)
    {
        return;
    }
    for (i = 0; i < 3; i++)
    {
        ch = ((ObjModel*)model)->blendChannels + i;
        if (ch[0].morphTargetA == -1 && ch[0].morphTargetB == -1)
        {
            continue;
        }
        if (ch[0].flags0E & 1)
        {
            continue;
        }
        ch[0].weight = ch[0].weightRate * dt + ch[0].weight;
        if (ch[0].weight >= lbl_803DE874)
        {
            ch[0].weight = lbl_803DE874;
            ch[0].weightRate = lbl_803DE878;
            ch[0].flags0E &= ~4;
        }
        else if (ch[0].weight <= lbl_803DE87C)
        {
            ch[0].weight = lbl_803DE87C;
            ch[0].weightRate = lbl_803DE878;
            ch[0].flags0E &= ~4;
        }
    }
}


#pragma scheduling off
void* ObjModel_LoadAnimData(u8* p, int b, int c)
{
    void* m = modelLoad_layoutBuffers(p, b, p[0] == 1, c);
    modelAnimResetState(m, ((ObjModel*)m)->animStateA);
    if (((ObjModel*)m)->animStateB != NULL)
    {
        modelAnimResetState(m, ((ObjModel*)m)->animStateB);
    }
    ObjModel_RelocateAnimData(p, m);
    *(int*)(p + 8) = 0;
    DCStoreRange(p, ((ModelFileHeader*)p)->dataSize);
    return m;
}

extern int modelLoad_calcSizes(void* model, int arg, int* out, int flag);
extern int ModelList_getHeader(void* list, int index, void* out);
extern void modelInitModelList(void* list, s16 index, void* out);
extern s16* gModelResourceBuffer;

void* ObjModel_Load(int id, int loadFlag, int* outSize)
{
    int sizes[7];
    int realId;
    u8* header;
    int i;
    u8* h;
    int off;
    int tex;
    int idc;
    idc = id;
    if (idc < 0)
    {
        realId = -idc;
    }
    else
    {
        fileLoadToBufferOffset(0x2c, gModelResourceBuffer, idc * 2, 8);
        realId = gModelResourceBuffer[0];
    }
    if (ModelList_getHeader(gModelList, realId, &header) == 0)
    {
        header = ObjModel_LoadModelData(realId);
        ObjModel_RelocateModelData(header);
        h = header;
        i = 0;
        off = i;
        for (; i < h[0xf2]; i++)
        {
            tex = textureLoad(-(*(int*)(*(int*)(h + 0x20) + off) | 0x8000), 1);
            *(int*)(*(int*)(h + 0x20) + off) = tex;
            off += 4;
        }
        ObjModel_ResolveRenderOpTextures(header);
        modelLoadAnimations(header, realId, header + *(int*)((u8*)header + 0xc));
        modelInitModelList(gModelList, realId, &header);
    }
    else
    {
        (*(u8*)header)++;
    }
    *outSize = modelLoad_calcSizes(header, loadFlag, sizes, 0);
    return header;
}


extern void model_adjustModelList(void* list, int index);
extern void model_findIdxInModelList(void* list, void* header, int* outIndex);
extern void* gModelTexAtlasList;
extern void* allocModelStruct(int size, int align);
extern int* lbl_803DCB5C;

#pragma peephole off
void ObjModel_InitResourceCaches(void)
{
    void* m;
    gModelList = allocModelStruct(0x8c, 4);
    gModelTexAtlasList = allocModelStruct(0xc4, 4);
    m = mmAlloc(0x830, 0xa, 0);
    gModelResourceBuffer = m;
    gModelAnimOffsetTable = (int*)((u8*)m + 0x800);
    lbl_803DCB5C = (int*)((u8*)m + 0x810);
    loadModelAndAnimTabs();
}

#pragma peephole off
void ObjModel_Release(u8* model)
{
    u8* header;
    int z[2];
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED)
    {
        ((ObjModel*)model)->bufferFlags &= ~OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
        z[0] = 0;
        for (z[1] = z[0]; z[0] < (*(u8**)model)[0xf8]; z[1] += 0xc, z[0]++)
        {
            ShaderDef_free((int*)(((ObjModel*)model)->textureRefs + z[1]));
        }
    }
    header = *(u8**)model;
    if (((ObjModel*)model)->renderAttachment != NULL)
    {
        mm_free(((ObjModel*)model)->renderAttachment);
    }
    if (--*(u8*)header == 0)
    {
        model_adjustModelList(gModelList, *(u16*)(header + 0x4));
        z[0] = 0;
        for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->textureCount; z[1] += 4, z[0]++)
        {
            textureFree(textureIdxToPtr(*(s32*)((u8*)((ModelFileHeader*)header)->textureIds + z[1])));
        }
        if (((ModelFileHeader*)header)->animationModelPtrs != NULL && ((ModelFileHeader*)header)->animationCount != 0)
        {
            z[0] = 0;
            for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->animationCount; z[1] += 4, z[0]++)
            {
                int idx;
                void* tex = *(void**)(((ModelFileHeader*)header)->animationModelPtrs + z[1]);
                if (tex != NULL && (s8)-- * (u8*)tex <= 0)
                {
                    model_findIdxInModelList(gModelTexAtlasList, &tex, &idx);
                    model_adjustModelList(gModelTexAtlasList, idx);
                    mm_free(tex);
                }
            }
        }
        mm_free(header);
    }
}

void setGQR6_2(int a, int b, int c, int d)
{
    setGQR6((((a << 8) + b) << 16) | ((c << 8) + d));
}

/* Per-bone delta-transform opcode bits: a set bit means the X/Y/Z
   component is present (as an s16) in the stream, else it is 0. */
#define MODEL_BONEXFORM_HAS_X 0x2000
#define MODEL_BONEXFORM_HAS_Y 0x4000
#define MODEL_BONEXFORM_HAS_Z 0x8000

/* Hand-written assembly in the retail game: modelBoneTransforms_next is a
   private subroutine of modelApplyBoneTransform with a custom calling
   convention no C signature can express -- it takes the delta-stream cursor
   in r20 (advanced in place), returns the unpacked x/y/z deltas in
   r10/r12/r15, and clobbers only r21/r22, letting the caller keep its own
   incoming arguments live in the volatile argument registers across the
   calls. modelApplyBoneTransform itself is EABI-conformant externally.

   Behavior: interpolates two per-vertex s16 delta streams (a = *pd, b = *pe)
   with weights (0x10000 - f) and f, adds the result to the source vertex
   stream p (6-byte x/y/z records), and writes n blended vertices to out.
   Each stream record is a u16 header: low 13 bits = vertex index, top three
   bits flag which of x/y/z deltas follow (MODEL_BONEXFORM_HAS_*).
   Vertices before both streams' next index are copied through unchanged. */
#pragma peephole on
#pragma dont_inline on
asm void modelBoneTransforms_next(void)
{
    nofralloc
    lhz r21, 0(r20)
    addi r20, r20, 2
    andi. r22, r21, MODEL_BONEXFORM_HAS_X
    li r10, 0
    beq lbl_BTN_y
    lha r10, 0(r20)
    addi r20, r20, 2
lbl_BTN_y:
    andi. r22, r21, MODEL_BONEXFORM_HAS_Y
    li r12, 0
    beq lbl_BTN_z
    lha r12, 0(r20)
    addi r20, r20, 2
lbl_BTN_z:
    andi. r22, r21, MODEL_BONEXFORM_HAS_Z
    li r15, 0
    beqlr
    lha r15, 0(r20)
    addi r20, r20, 2
    blr
}

asm void modelApplyBoneTransform(u8* p, u8* out, u16 n, u8** pd, u8** pe, int f, u16 pos)
{
    // clang-format off
    nofralloc
    mflr r0
    stwu r1, -80(r1)
    stw r0, 84(r1)
    stmw r14, 8(r1)
    lwz r23, 0(r6)      // a = *pd
    lwz r24, 0(r7)      // b = *pe
    li r25, 0           // i = 0
    lis r17, 1
    subf r17, r8, r17   // wHi = 0x10000 - f
lbl_ABT_top:
    lha r18, 0(r23)
    lha r19, 0(r24)
    andi. r18, r18, 0x1fff
    andi. r19, r19, 0x1fff
    subf r18, r9, r18   // aIdx = (*a & 0x1fff) - pos
    subf r19, r9, r19   // bIdx = (*b & 0x1fff) - pos
lbl_ABT_copy:
    cmpw r25, r5
    bge lbl_ABT_done
    cmpw r25, r18
    bge lbl_ABT_a
    cmpw r25, r19
    bge lbl_ABT_bOnly
    lwz r20, 0(r3)      // copy an untouched 6-byte vertex
    lha r22, 4(r3)
    addi r3, r3, 6
    stw r20, 0(r4)
    addi r25, r25, 1
    sth r22, 4(r4)
    addi r4, r4, 6
    b lbl_ABT_copy
lbl_ABT_a:
    cmpw r25, r19
    bne lbl_ABT_aOnly
    mr r20, r24         // both streams hit: blend a and b deltas
    bl modelBoneTransforms_next
    mr r24, r20
    mr r11, r10
    mr r14, r12
    mr r16, r15
    mr r20, r23
    bl modelBoneTransforms_next
    mr r23, r20
    mullw r10, r10, r17
    mullw r12, r12, r17
    mullw r15, r15, r17
    mullw r11, r11, r8
    mullw r14, r14, r8
    mullw r16, r16, r8
    add r10, r10, r11
    add r12, r12, r14
    add r15, r15, r16
    srwi r10, r10, 16
    srwi r12, r12, 16
    srwi r15, r15, 16
    lha r11, 0(r3)
    lha r14, 2(r3)
    lha r16, 4(r3)
    add r10, r10, r11
    add r12, r12, r14
    add r15, r15, r16
    sth r10, 0(r4)
    sth r12, 2(r4)
    sth r15, 4(r4)
    addi r3, r3, 6
    addi r4, r4, 6
    addi r25, r25, 1
    b lbl_ABT_top
lbl_ABT_aOnly:
    mr r20, r23         // only stream a hits: weight by wHi
    bl modelBoneTransforms_next
    mr r23, r20
    mullw r10, r10, r17
    mullw r12, r12, r17
    mullw r15, r15, r17
    srwi r10, r10, 16
    srwi r12, r12, 16
    srwi r15, r15, 16
    lha r11, 0(r3)
    lha r14, 2(r3)
    lha r16, 4(r3)
    add r10, r10, r11
    add r12, r12, r14
    add r15, r15, r16
    sth r10, 0(r4)
    sth r12, 2(r4)
    sth r15, 4(r4)
    addi r3, r3, 6
    addi r4, r4, 6
    addi r25, r25, 1
    b lbl_ABT_top
lbl_ABT_bOnly:
    mr r20, r24         // only stream b hits: weight by f
    bl modelBoneTransforms_next
    mr r24, r20
    mullw r10, r10, r8
    mullw r12, r12, r8
    mullw r15, r15, r8
    srwi r10, r10, 16
    srwi r12, r12, 16
    srwi r15, r15, 16
    lha r11, 0(r3)
    lha r14, 2(r3)
    lha r16, 4(r3)
    add r10, r10, r11
    add r12, r12, r14
    add r15, r15, r16
    sth r10, 0(r4)
    sth r12, 2(r4)
    sth r15, 4(r4)
    addi r3, r3, 6
    addi r4, r4, 6
    addi r25, r25, 1
    b lbl_ABT_top
lbl_ABT_done:
    stw r23, 0(r6)      // *pd = a
    stw r24, 0(r7)      // *pe = b
    lwz r0, 84(r1)
    mtlr r0
    lmw r14, 8(r1)
    addi r1, r1, 80
    blr
    // clang-format on
}
#pragma dont_inline reset
#pragma peephole off

extern void debugPrintf(char* fmt, ...);
extern void lbl_80006C6C(int* out, u8* a, void* buf, int c, int d, u8* e, int f, int g);
extern u8 gModelJointScratchBuffer[];

void modelAnimUpdateChannels(u8* hdr, u8* stk, int n)
{
    u8* animChan;
    u8* blendChan;
    int i;
    u8* blendSrc;
    u8* blendDst;
    u8* jointTypeSrc;
    int cmdStep;
    int jointOff;
    int jointIdx;
    int frameInt;
    int dataOff;
    f32 frameFlt;

    i = 0;
    animChan = stk;
    blendChan = stk;
    for (; i < n; i++)
    {
        if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
        {
            blendDst = *(u8**)(stk + *(u16*)(animChan + 0x44) * 4 + 0x1c);
            blendSrc = blendDst;
            blendDst += 0x80;
        }
        else
        {
            blendSrc = *(u8**)(hdr + 0x68) + *(u16*)(animChan + 0x44) * (((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8);
            blendDst = *(u8**)(*(u8**)(hdr + 0x64) + *(u16*)(animChan + 0x44) * 4);
        }
        cmdStep = *(u8*)(*(u8**)(blendChan + 0x34) + 2);
        jointIdx = 0;
        jointOff = 0;
        jointTypeSrc = blendSrc;
        while (jointIdx < ((ModelFileHeader*)hdr)->jointCount)
        {
            *(u8*)(i + *(int*)&((ModelFileHeader*)hdr)->jointData + jointOff + 2) = *jointTypeSrc;
            jointOff += 0x1c;
            jointIdx++;
            jointTypeSrc++;
        }
        frameInt = (int)*(f32*)(blendChan + 4);
        frameFlt = frameInt;
        if (frameFlt != *(f32*)(blendChan + 4))
        {
            *(s16*)(animChan + 0x4c) = cmdStep;
        }
        else
        {
            *(s16*)(animChan + 0x4c) = 0;
        }
        if (*(s8*)(stk + i + 0x60) != 0 && frameFlt == *(f32*)(blendChan + 0x14) - lbl_803DE818)
        {
            *(s16*)(animChan + 0x4c) = (s16)(-cmdStep * frameInt);
        }
        dataOff = *(s16*)(blendDst + 2) + cmdStep * frameInt;
        *(u8**)(blendChan + 0x2c) = blendDst + dataOff;
        animChan += 2;
        blendChan += 4;
    }
}

#pragma ppc_unroll_factor_limit 8
#pragma ppc_unroll_instructions_limit 256
void modelWalkAnimFn_800248b8(u8* dst, u8* model, u8* channel, f32 blend, int flags)
{
    /* channel points at an ObjAnimState. stk is an on-stack working copy of
       one (spelled as raw bytes: the retail frame reserves only 0x64 bytes,
       sizeof(ObjAnimState) is 0x68). Some u16/s8 channel loads inside the
       unrolled i/j loops must keep the raw *(u16*)(channel + 0x58)-style
       spelling -- retyping them to ObjAnimState members changes MWCC's
       alias/CSE class there and shifts bytes. */
    u8 stk[0x64];
    int mtxBuf;
    int outFlags;
    u8* hdr;
    int slotEvent;
    int ctrlFlags;
    int slotCount;
    int j;
    int srcSlot;
    u8 slotFrameType;
    f32 slotPhase;
    f32 slotLength;

    hdr = *(u8**)model;
    {
        u8* mtxBufs = model + 12;
        mtxBuf = *(int*)(mtxBufs + (*(u16*)(model + 0x18) & 1) * 4);
    }
    ((ObjAnimState*)channel)->framePhase = blend * ((ObjAnimState*)channel)->frameLength;
    outFlags = 0;
    if (((ModelFileHeader*)hdr)->flags & 8)
    {
        *(u32*)(stk + 0x1c) = *(u32*)&((ObjAnimState*)channel)->moveCache[0];
        *(u32*)(stk + 0x20) = *(u32*)&((ObjAnimState*)channel)->moveCache[1];
        *(u32*)(stk + 0x24) = *(u32*)&((ObjAnimState*)channel)->blendMoveCache[0];
        *(u32*)(stk + 0x28) = *(u32*)&((ObjAnimState*)channel)->blendMoveCache[1];
        for (j = 0; j < 2; j++)
        {
            if (*(u16*)(channel + 0x58))
            {
                srcSlot = j;
            }
            else
            {
                srcSlot = 0;
            }
            *(u16*)(stk + j * 2 + 0x44) = *(u16*)(channel + srcSlot * 2 + 0x44);
            *(u8*)(stk + j + 0x60) = *(u8*)(channel + srcSlot + 0x60);
            *(f32*)(stk + j * 4 + 0x14) = *(f32*)(channel + srcSlot * 4 + 0x14);
            *(f32*)(stk + j * 4 + 4) = *(f32*)(channel + srcSlot * 4 + 4);
            *(u32*)(stk + j * 4 + 0x34) = *(u32*)(channel + srcSlot * 4 + 0x34);
        }
        *(u16*)(stk + 0x58) = ((ObjAnimState*)channel)->eventCountdown;
        modelAnimUpdateChannels(hdr, stk, 2);
        ctrlFlags = ((ObjAnimState*)channel)->moveControlFlags;
        if (ctrlFlags & 1)
        {
            outFlags |= 0x10;
        }
        if (ctrlFlags & 4)
        {
            outFlags |= 0x20;
        }
        lbl_80006C6C(&mtxBuf, dst, stk, *(int*)&((ModelFileHeader*)hdr)->jointData, ((ModelFileHeader*)hdr)->jointCount, gModelJointScratchBuffer, flags, outFlags | 0x40);
    }
    else
    {
        u8* blendChan;
        u8* animChan;
        int i;
        int blendMask;

        for (i = 0, blendChan = channel, animChan = channel; i < 2; i++, blendChan += 4, animChan += 2)
        {
            if (i != 0)
            {
                slotEvent = *(u16*)(channel + 0x5c);
            }
            else
            {
                slotEvent = *(u16*)(channel + 0x5a);
            }
            if (slotEvent != 0)
            {
                if (*(u16*)(channel + 0x58))
                {
                    blendMask = 4 << i;
                }
                else
                {
                    blendMask = 0;
                }
                slotFrameType = *(u8*)(channel + i + 0x60);
                *(u8*)(stk + 0x60) = slotFrameType;
                slotLength = *(f32*)(blendChan + 0x14);
                *(f32*)(stk + 0x14) = slotLength;
                slotPhase = *(f32*)(blendChan + 4);
                *(f32*)(stk + 4) = slotPhase;
                *(u32*)(stk + 0x34) = *(u32*)(blendChan + 0x34);
                *(u8*)(stk + 0x61) = slotFrameType;
                *(f32*)(stk + 0x18) = slotLength;
                *(f32*)(stk + 8) = slotPhase;
                *(u32*)(stk + 0x38) = *(u32*)(blendChan + 0x3c);
                if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
                {
                    *(u16*)(stk + 0x44) = 0;
                    *(u16*)(stk + 0x46) = 1;
                    *(u32*)(stk + 0x1c) = *(u32*)(channel + *(u16*)(animChan + 0x44) * 4 + 0x1c);
                    *(u32*)(stk + 0x20) = *(u32*)(channel + *(u16*)(animChan + 0x48) * 4 + 0x24);
                }
                else
                {
                    *(u16*)(stk + 0x44) = *(u16*)(animChan + 0x44);
                    *(u16*)(stk + 0x46) = *(u16*)(animChan + 0x48);
                }
                *(u16*)(stk + 0x58) = slotEvent;
                modelAnimUpdateChannels(hdr, stk, 2);
                lbl_80006C6C(&mtxBuf, dst, stk, *(int*)&((ModelFileHeader*)hdr)->jointData, ((ModelFileHeader*)hdr)->jointCount, gModelJointScratchBuffer, flags, blendMask);
                if (blendMask != 0)
                {
                    outFlags |= 1 << i;
                }
            }
        }
        if ((((ObjAnimState*)channel)->eventState == 0 && ((ObjAnimState*)channel)->prevEventState == 0) || outFlags != 0)
        {
            slotCount = 1;
            if (*(u16*)(channel + 0x58) != 0)
            {
                slotCount = 2;
            }
            *(u32*)(stk + 0x1c) = *(u32*)&((ObjAnimState*)channel)->moveCache[0];
            *(u32*)(stk + 0x20) = *(u32*)&((ObjAnimState*)channel)->moveCache[1];
            *(u32*)(stk + 0x24) = *(u32*)&((ObjAnimState*)channel)->blendMoveCache[0];
            *(u32*)(stk + 0x28) = *(u32*)&((ObjAnimState*)channel)->blendMoveCache[1];
            {
                u8* srcSlots = channel;
                u8* dstSlots = stk;
                u8* dstTypes = stk;
                u8* srcF = channel;
                u8* dstF = stk;
                for (j = 0; j < slotCount; j++)
                {
                    *(u16*)(dstSlots + 0x44) = *(u16*)(srcSlots + 0x44);
                    *(u8*)(dstTypes + 0x60) = *(u8*)(channel + (j + 0x60));
                    *(f32*)(dstF + 0x14) = *(f32*)(srcF + 0x14);
                    *(f32*)(dstF + 4) = *(f32*)(srcF + 4);
                    *(u32*)(dstF + 0x34) = *(u32*)(srcF + 0x34);
                    srcSlots += 2;
                    dstSlots += 2;
                    dstTypes += 1;
                    srcF += 4;
                    dstF += 4;
                }
            }
            *(u16*)(stk + 0x58) = ((ObjAnimState*)channel)->eventCountdown;
            modelAnimUpdateChannels(hdr, stk, slotCount);
            ctrlFlags = ((ObjAnimState*)channel)->moveControlFlags;
            if (ctrlFlags & 1)
            {
                outFlags |= 0x10;
            }
            if (ctrlFlags & 4)
            {
                outFlags |= 0x20;
            }
            lbl_80006C6C(&mtxBuf, dst, stk, *(int*)&((ModelFileHeader*)hdr)->jointData, ((ModelFileHeader*)hdr)->jointCount, gModelJointScratchBuffer, flags, outFlags);
        }
    }
}
#pragma ppc_unroll_factor_limit 4
#pragma ppc_unroll_instructions_limit 96

extern void* animLoadFromTable(u8* hdr, int idx, int a, u8* b);

#define LOADCOLOR_BLOCK(SLOT)                                                         \
    {                                                                                 \
        int idx;                                                                      \
        u32 v;                                                                        \
        int sz4;                                                                      \
        u8 buf[4];                                                                    \
        int sz;                                                                       \
        u8 *hp;                                                                       \
                                                                                      \
        v = (u32)(SLOT);                                                              \
        idx = **(s16 **)(hdr + 0x6c);                                                 \
        if ((getLoadedFileFlags(0) & 0x100000) == 0 || *(u16 *)(hdr + 4) == 1 ||      \
            *(u16 *)(hdr + 4) == 3) {                                                 \
            if (v == 0) {                                                             \
                if (ModelList_getHeader(gModelTexAtlasList, idx, &hp) == 0) {               \
                    sz4 = *(int *)((u8 *)gModelAnimFlagsTable + idx * 4);                     \
                    loadAndDecompressDataFile(0x30, 0, sz4, 0, (int)&sz, idx, 1);     \
                    hp = mmAlloc(sz, 10, 0);                                    \
                    loadAndDecompressDataFile(0x30, hp, sz4, sz, (int)buf, idx, 0); \
                    *hp = 1;                                                          \
                    modelInitModelList(gModelTexAtlasList, idx, &hp);                       \
                } else {                                                              \
                    *hp += 1;                                                         \
                }                                                                     \
            } else {                                                                  \
                animLoadFromTable(hdr, idx, 0, (u8 *)v);                               \
            }                                                                         \
        }                                                                             \
    }

void modelAnimResetState(void* m, void* data)
{
    ObjAnimState* channel = data;
    u8* hdr;
    u8* mdl;
    f32 f;

    channel->moveCacheSlot = 0;
    channel->eventStep = 0;
    channel->eventCountdown = 0;
    channel->eventState = 0;
    channel->prevEventState = 0;
    f = lbl_803DE828;
    channel->frameStep = f;
    channel->framePhase = f;
    channel->frameLength = f;
    channel->frameType = 0;
    hdr = *(u8**)m;
    if (((ModelFileHeader*)hdr)->animationCount != 0)
    {
        if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
        {
            LOADCOLOR_BLOCK(channel->moveCache[0])
            LOADCOLOR_BLOCK(channel->moveCache[1])
            LOADCOLOR_BLOCK(channel->blendMoveCache[0])
            LOADCOLOR_BLOCK(channel->blendMoveCache[1])
            channel->moveCacheSlot = 0;
            mdl = channel->moveCache[channel->moveCacheSlot] + 0x80;
        }
        else
        {
            mdl = *(u8**)(*(u8**)(hdr + 0x64) + channel->moveCacheSlot * 4);
        }
        channel->moveFrameData = (ObjAnimFrameCommand*)(mdl + 6);
        channel->frameType = (s8)(*(u8*)(mdl + 1) & 0xf0);
        channel->frameLength = (f32)((u8*)channel->moveFrameData)[1];
        if (channel->frameType == 0)
        {
            channel->frameLength -= lbl_803DE818;
        }
        channel->prevFrameType = channel->frameType;
        channel->prevMoveFrameData = channel->moveFrameData;
        channel->prevMoveCacheSlot = channel->moveCacheSlot;
        channel->prevFramePhase = channel->framePhase;
        channel->prevFrameLength = channel->frameLength;
        channel->savedFrameStep = channel->frameStep;
        channel->blendFrameData = channel->moveFrameData;
        channel->blendCacheSlot = channel->moveCacheSlot;
        channel->prevBlendFrameData = channel->moveFrameData;
        channel->prevBlendCacheSlot = channel->moveCacheSlot;
    }
}

#define BLENDTBL_ENTRY(K, OFF)                              \
    if (poseWeights[K] != 0) {                                        \
        ((s16 *)gModelJointScratchBuffer)[outPos++] = (s16)(offA + (OFF));     \
        ((s16 *)gModelJointScratchBuffer)[outPos++] = (s16)(offB + (OFF));     \
        ((s16 *)gModelJointScratchBuffer)[outPos++] = poseWeights[K];                  \
        ((s16 *)gModelJointScratchBuffer)[outPos++] = poseWeights[K];                  \
    }

void ObjModel_BuildAnimBlendTable(u8* obj, u8* channel, u8* hdr)
{
    ObjAnimComponent* objAnim;
    int poseOff;
    ObjModelInstance* modelDef;
    int defOff;
    int i;
    u32 jointRemap;
    int offA;
    int offB;
    int outPos;
    s16* poseWeights;
    u8* rowA;
    u8* rowB;

    if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
    {
        rowA = *(u8**)((u8*)(channel + 0x1c) + *(u16*)(channel + 0x44) * 4);
        rowB = *(u8**)((u8*)(channel + 0x1c) + *(u16*)(channel + 0x46) * 4);
    }
    else
    {
        rowA = *(u8**)(hdr + 0x68) + *(u16*)(channel + 0x44) * (((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8);
        rowB = *(u8**)(hdr + 0x68) + *(u16*)(channel + 0x46) * (((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8);
    }
    objAnim = (ObjAnimComponent*)obj;
    modelDef = objAnim->modelInstance;
    defOff = 0;
    outPos = 0;
    i = 0;
    poseOff = 0;
    for (; i < modelDef->jointCount; i++)
    {
        jointRemap = *(u8*)(modelDef->jointData + defOff + objAnim->bankIndex + 1);
        if (jointRemap != 0xff)
        {
            poseWeights = (s16*)(objAnim->jointPoseData + poseOff);
            offA = *(s8*)(rowA + jointRemap) << 6;
            offB = *(s8*)(rowB + jointRemap) << 6;
            BLENDTBL_ENTRY(0, 0)
            BLENDTBL_ENTRY(1, 2)
            BLENDTBL_ENTRY(2, 4)
            BLENDTBL_ENTRY(3, 0xc)
            BLENDTBL_ENTRY(4, 0xe)
            BLENDTBL_ENTRY(5, 0x10)
            BLENDTBL_ENTRY(6, 0x18)
            BLENDTBL_ENTRY(7, 0x1a)
            BLENDTBL_ENTRY(8, 0x1c)
        }
        defOff += modelDef->modelCount + 1;
        poseOff += 0x12;
    }
    ((s16*)gModelJointScratchBuffer)[outPos++] = 0x1000;
    ((s16*)gModelJointScratchBuffer)[outPos] = 0x1000;
}

void* modelLoad_layoutBuffers(u8* p, int b, int isType1, int c)
{
    int o2;
    u8* out2;
    int szs[7];
    int pos;
    int end;
    int n;
    u8* out;
    int k;
    u8* q;
    f32 f;

    out = (u8*)c;
    if (p == 0)
    {
        return 0;
    }
    modelLoad_calcSizes(p, b, szs, 0);
    out2 = (u8*)((int)out | (int)out);
    pos = roundUpTo32((int)out + 0x64);
    *(int*)&((ObjModel*)out)->jointMatrices[0] = pos;
    pos += szs[6] >> 1;
    *(int*)&((ObjModel*)out)->jointMatrices[1] = pos;
    pos += szs[6] >> 1;
    *(int*)&((ObjModel*)out)->curMtxBuf = *(int*)&((ObjModel*)out)->jointMatrices[0];
    if (((ModelFileHeader*)p)->morphTargetCount != 0 || ((ModelFileHeader*)p)->vertexAnimEntries != NULL || (((
        ModelFileHeader*)p)->flags & MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS))
    {
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out2)->vtxBuf0 = pos;
        pos = roundUpTo32(pos + ((ModelFileHeader*)p)->vertexCount * 6);
        *(int*)&((ObjModel*)out2)->vtxBuf1 = pos;
        end = pos + ((ModelFileHeader*)p)->vertexCount * 6;
        memcpy(((ObjModel*)out2)->vtxBuf0, ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out2)->vtxBuf0, ((ModelFileHeader*)p)->vertexCount * 6);
        memcpy(((ObjModel*)out2)->vtxBuf1, ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out2)->vtxBuf1, ((ModelFileHeader*)p)->vertexCount * 6);
        pos = roundUpTo32(end);
    }
    else
    {
        end = *(int*)&((ModelFileHeader*)p)->vertices;
        *(int*)&((ObjModel*)out)->vtxBuf1 = end;
        *(int*)&((ObjModel*)out2)->vtxBuf0 = end;
    }
    if (((ModelFileHeader*)p)->blendAnimEntries != NULL)
    {
        if (((ModelFileHeader*)p)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE)
        {
            n = 9;
        }
        else
        {
            n = 3;
        }
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out2)->normalBuf = pos;
        end = pos + ((ModelFileHeader*)p)->normalCount * n;
        memcpy(((ObjModel*)out2)->normalBuf, ((ModelFileHeader*)p)->normals, ((ModelFileHeader*)p)->normalCount * n);
        DCFlushRange(((ObjModel*)out2)->normalBuf, n * ((ModelFileHeader*)p)->normalCount);
        pos = roundUpTo32(end);
    }
    else
    {
        *(int*)&((ObjModel*)out2)->normalBuf = *(int*)&((ModelFileHeader*)p)->normals;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out2)->animStateA = pos;
    pos += 0x68;
    if (b & 0x80)
    {
        *(int*)&((ObjModel*)out2)->animStateB = pos;
        pos += 0x68;
    }
    if (((ModelFileHeader*)p)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
    {
        pos = roundUpTo8(pos);
        q = ((ObjModel*)out2)->animStateA;
        *(int*)(q + 0x1c) = pos;
        pos += szs[5];
        *(int*)(q + 0x20) = pos;
        pos += szs[5];
        *(int*)(q + 0x24) = pos;
        pos += szs[5];
        *(int*)(q + 0x28) = pos;
        pos += szs[5];
        q = ((ObjModel*)out2)->animStateB;
        if (q != 0)
        {
            *(int*)(q + 0x1c) = pos;
            pos += szs[5];
            *(int*)(q + 0x20) = pos;
            pos += szs[5];
            *(int*)(q + 0x24) = pos;
            pos += szs[5];
            *(int*)(q + 0x28) = pos;
            pos += szs[5];
        }
    }
    if (((ModelFileHeader*)p)->morphTargetCount != 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->blendChannels = pos;
        pos += 0x30;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        *(s8*)(q + 0xc) = -1;
        *(s8*)(q + 0xd) = -1;
        f = lbl_803DE828;
        *(f32*)(q + 0) = f;
        *(f32*)(q + 4) = f;
        *(f32*)(q + 8) = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        *(s8*)(q + 0x1c) = -1;
        *(s8*)(q + 0x1d) = -1;
        *(f32*)(q + 0x10) = f;
        *(f32*)(q + 0x14) = f;
        *(f32*)(q + 0x18) = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        *(s8*)(q + 0x2c) = -1;
        *(s8*)(q + 0x2d) = -1;
        *(f32*)(q + 0x20) = f;
        *(f32*)(q + 0x24) = f;
        *(f32*)(q + 0x28) = f;
    }
    if (szs[1] > 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->unk48 = pos;
        o2 = ((ModelFileHeader*)p)->unkF7;
        pos += o2 * 0x10;
        *(int*)&((ObjModel*)out2)->unk4C = pos;
        pos += ((ModelFileHeader*)p)->unkF7 * 0x10;
        *(int*)&((ObjModel*)out2)->unk50 = *(int*)&((ObjModel*)out2)->unk48;
    }
    if (((ModelFileHeader*)p)->jointData != NULL && ((ModelFileHeader*)p)->jointCount != 0 && ((
        ModelFileHeader*)p)->unk18 != NULL && ((ModelFileHeader*)p)->unk1C != NULL)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->jointWorkspace = pos;
        pos += 0x1c;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 0) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 0xc;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 4) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 8) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 0xc) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 0x10) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out2)->jointWorkspace + 0x18) = pos;
        pos += ((ModelFileHeader*)p)->jointCount;
    }
    else
    {
        *(int*)&((ObjModel*)out2)->jointWorkspace = 0;
    }
    if (((ModelFileHeader*)p)->vertexAnimEntries != NULL)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->vertexAnimData = pos;
        pos += ((ModelFileHeader*)p)->vertexAnimCount * 4;
    }
    if (((ModelFileHeader*)p)->blendAnimEntries != NULL)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->blendAnimData = pos;
        pos += ((ModelFileHeader*)p)->blendAnimCount * 4;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out2)->textureRefs = pos;
    pos += ((ModelFileHeader*)p)->renderOpCount * 0xc;
    k = 0;
    o2 = 0;
    for (; k < (int)((ModelFileHeader*)p)->renderOpCount; k++)
    {
        *(u8*)(((ObjModel*)out2)->textureRefs + o2 + 8) = 0;
        o2 += 0xc;
    }
    if (b & 0x8000)
    {
        pos = alignUp2(pos);
        *(int*)&((ObjModel*)out2)->unk54 = pos;
        *(u8*)(((ObjModel*)out2)->unk54 + 0x18) = 0;
    }
    *(int*)&((ObjModel*)out2)->renderAttachment = 0;
    ((ObjModel*)out2)->file = (ModelFileHeader*)p;
    ((ObjModel*)out2)->unk60 = 0;
    return out2;
}

extern char sModelAnimationBufferOverflowWarning[];

#pragma opt_loop_invariants off
int modelLoadAnimations(void* model, int id, void* animBase)
{
    u8* hdr = model;
    u8* buf = animBase;
    int* tbl;
    int tabBase;
    int wrOff;
    int sz;
    int hdrOff;
    int groupSlot;
    int i;
    int animIdx;
    int rdOff;
    int padBytes;
    int animId;
    int dataOff;
    int listIdx;
    u8* atlasEntry;
    u8 buf2[4];
    int sz2;
    u8* atlasHdr;
    u8* atlasPtr;
    u8 newRefCount;

    padBytes = 0;
    tbl = gModelAnimOffsetTable;
    fileLoadToBufferOffset(0x2d, tbl, id << 1, 0x10);
    tabBase = *(s16*)tbl;
    if (((ModelFileHeader*)hdr)->animationCount == 0)
    {
        return 0;
    }
    sz = (((ModelFileHeader*)hdr)->animationCount << 1) + 8;
    if (sz > 0x800)
    {
        debugPrintf(sModelAnimationBufferOverflowWarning, sz);
    }
    fileLoadToBufferOffset(0x31, gModelAnimOffsetTable, (id & ~3) << 2, 0x20);
    ((ModelFileHeader*)hdr)->animationDataFileOffset = gModelAnimOffsetTable[id & 3];
    dataOff = gModelAnimOffsetTable[id & 3];
    id = gModelAnimOffsetTable[(id & 3) + 1] - dataOff;
    if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
    {
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = buf;
        while (sz & 7)
        {
            sz++;
        }
        padBytes = sz;
        buf += sz;
        fileLoadToBufferOffset(0x2e, ((ModelFileHeader*)hdr)->animationHeaderBuffer, tabBase, sz);
    }
    else
    {
        fileLoadToBufferOffset(0x2e, gModelResourceBuffer, tabBase, sz);
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = (u8*)gModelResourceBuffer;
    }
    hdrOff = 0;
    groupSlot = 1;
    *(s16*)(hdr + (groupSlot - 1) * 2 + 0x70) = hdrOff;
    i = 0;
    for (; i < (int)((ModelFileHeader*)hdr)->animationCount; i++)
    {
        if (*(s16*)(((ModelFileHeader*)hdr)->animationHeaderBuffer + hdrOff) == -1)
        {
            *(s16*)(hdr + groupSlot++ * 2 + 0x70) = (s16)(i + 1);
        }
        hdrOff += 2;
    }
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) == 0)
    {
        *(int*)&((ModelFileHeader*)hdr)->animationHeaderBuffer = 0;
        ((ModelFileHeader*)hdr)->animationModelPtrs = buf;
        buf += ((ModelFileHeader*)hdr)->animationCount * 4;
        padBytes += ((ModelFileHeader*)hdr)->animationCount * 4;
        while (padBytes & 7)
        {
            buf++;
            padBytes++;
        }
        ((ModelFileHeader*)hdr)->animationDataSection = buf;
        fileLoadToBufferOffset(0x32, ((ModelFileHeader*)hdr)->animationDataSection,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset, id);
        animIdx = 0;
        rdOff = 0;
        wrOff = rdOff;
        do
        {
            animId = *(s16*)((u8*)gModelResourceBuffer + rdOff);
            if (animId != -1)
            {
                if ((getLoadedFileFlags(0) & 0x100000) && *(u16*)(hdr + 4) != 1 &&
                    *(u16*)(hdr + 4) != 3)
                {
                    atlasPtr = 0;
                }
                else
                {
                    if (ModelList_getHeader(gModelTexAtlasList, animId, &atlasHdr) == 0)
                    {
                        dataOff = *(int*)((u8*)gModelAnimFlagsTable + animId * 4);
                        loadAndDecompressDataFile(0x30, 0, dataOff, 0, (int)&sz2, animId, 1);
                        atlasHdr = mmAlloc(sz2, 10, 0);
                        loadAndDecompressDataFile(0x30, atlasHdr, dataOff, sz2, (int)buf2, animId, 0);
                        *atlasHdr = 1;
                        modelInitModelList(gModelTexAtlasList, animId, &atlasHdr);
                    }
                    else
                    {
                        *atlasHdr += 1;
                    }
                    atlasPtr = atlasHdr;
                }
                *(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + wrOff) = atlasPtr;
                if (*(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + wrOff) == 0)
                {
                    int relIdx;
                    int relOff;

                    relIdx = 0;
                    relOff = 0;
                    for (; relIdx < animIdx; relIdx++)
                    {
                        atlasEntry = *(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + relOff);
                        if (atlasEntry != 0)
                        {
                            newRefCount = (*atlasEntry -= 1);
                            if ((s8)newRefCount <= 0)
                            {
                                model_findIdxInModelList(gModelTexAtlasList, &atlasEntry, &listIdx);
                                model_adjustModelList(gModelTexAtlasList, listIdx);
                                mm_free(atlasEntry);
                            }
                        }
                        relOff += 4;
                    }
                    *(int*)&((ModelFileHeader*)hdr)->animationModelPtrs = 0;
                    return 1;
                }
            }
            else
            {
                *(int*)(((ModelFileHeader*)hdr)->animationModelPtrs + wrOff) = 0;
            }
            rdOff += 2;
            wrOff += 4;
            animIdx++;
        }
        while (animIdx < (int)((ModelFileHeader*)hdr)->animationCount);
    }
    else
    {
        *(int*)&((ModelFileHeader*)hdr)->animationModelPtrs = 0;
    }
    return 0;
}

void* mmAlloc(int size, int type, int flag);

#pragma opt_loop_invariants on
int modelLoad_calcSizes(void* model, int flags, int* sizes, int forceBlendChannels)
{
    u8* hdr = model;
    int total;

    if (((ModelFileHeader*)hdr)->animationCount != 0)
    {
        sizes[6] = ((u32)((ModelFileHeader*)hdr)->jointCount + (u32)((ModelFileHeader*)hdr)->extraJointCount) * 0x80;
    }
    else
    {
        sizes[6] = 0x80;
    }
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || ((ModelFileHeader*)hdr)->vertexAnimEntries != 0 || (((
        ModelFileHeader*)hdr)->flags & MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS) != 0)
    {
        sizes[0] = (u32)((ModelFileHeader*)hdr)->vertexCount * 0xc + 0x60;
    }
    else
    {
        sizes[0] = 0;
    }
    if (((ModelFileHeader*)hdr)->blendAnimEntries != 0)
    {
        int vtxBytes = sizes[0];
        int normalStride;
        if (((ModelFileHeader*)hdr)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE)
        {
            normalStride = 9;
        }
        else
        {
            normalStride = 3;
        }
        {
            int normalBytes = ((ModelFileHeader*)hdr)->normalCount * normalStride;
            vtxBytes = normalBytes + vtxBytes;
        }
        sizes[0] = vtxBytes + 0x40;
    }
    {
        int hitSphereBytes = ((ModelFileHeader*)hdr)->unkF7 << 4;
        sizes[1] = hitSphereBytes << 1;
    }
    sizes[3] = 0;
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) != 0)
    {
        sizes[5] = ((ModelFileHeader*)hdr)->unk84;
        while ((sizes[5] & 7) != 0)
        {
            *(int*)((int)sizes + 0x14) = *(int*)((int)sizes + 0x14) + 1;
        }
        sizes[3] = sizes[5] << 2;
    }
    sizes[4] = 0x68;
    if ((flags & 0x80) != 0)
    {
        sizes[4] = sizes[4] << 1;
        sizes[3] = sizes[3] << 1;
    }
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || forceBlendChannels != 0)
    {
        sizes[4] = sizes[4] + 0x30;
        total = sizes[4] + 100;
        total = sizes[3] + total;
        total = (sizes[1] + 8) + total;
        total = sizes[6] + total;
    }
    else
    {
        total = sizes[4] + 100;
        total = sizes[3] + total;
        total = (sizes[1] + 8) + total;
        total = sizes[6] + total;
    }
    total = total + sizes[0];
    if (((ModelFileHeader*)hdr)->jointData != 0 && ((ModelFileHeader*)hdr)->jointCount != 0 && ((ModelFileHeader*)hdr)->
        unk18 != 0)
    {
        total = ((u32)((ModelFileHeader*)hdr)->jointCount << 1) + ((((u32)((ModelFileHeader*)hdr)->jointCount * 7) << 2)
            + 0x1c + total);
    }
    if (((ModelFileHeader*)hdr)->vertexAnimEntries != 0)
    {
        total = (u32)((ModelFileHeader*)hdr)->vertexAnimCount * 4 + total;
        total = total + 4;
    }
    if (((ModelFileHeader*)hdr)->blendAnimEntries != 0)
    {
        total = (u32)((ModelFileHeader*)hdr)->blendAnimCount * 4 + total;
        total = total + 4;
    }
    total = total + (u32)((ModelFileHeader*)hdr)->renderOpCount * 0xc;
    if ((flags & 0x8000) != 0)
    {
        total = total + 0x1a;
    }
    return roundUpTo32(((total + 0x2f) & ~0xf) + 0x10);
}

extern f32 lbl_803DE850;

#pragma dont_inline on
void fn_80026928(int* obj, int b, int* desc)
{
    int i;

    i = 0;
    for (; i < desc[2]; i++)
    {
        int jointIdx = *(int*)(*(int*)desc[1] + i * 4);
        int entry = *desc + i * 0x54;
        int idx;
        u8* hdr;
        u32 n;
        int lim;

        *(f32*)(entry + 0x18) = *(f32*)(*(int*)(b + 0x3c) + jointIdx * 0x1c + 4);
        *(f32*)&((ObjModel*)entry)->vtxBuf0 = *(f32*)(*(int*)(b + 0x3c) + jointIdx * 0x1c + 8);
        *(f32*)&((ObjModel*)entry)->vtxBuf1 = *(f32*)(*(int*)(b + 0x3c) + jointIdx * 0x1c + 0xc);

        idx = jointIdx;
        hdr = *(u8**)obj;
        n = ((ModelFileHeader*)hdr)->jointCount;
        if (n != 0)
        {
            lim = n + ((ModelFileHeader*)hdr)->extraJointCount;
        }
        else
        {
            lim = 1;
        }
        if (jointIdx >= lim)
        {
            idx = 0;
        }
        *(f32*)&((ObjModel*)entry)->file = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0xc);

        idx = jointIdx;
        hdr = *(u8**)obj;
        n = ((ModelFileHeader*)hdr)->jointCount;
        if (n != 0)
        {
            lim = n + ((ModelFileHeader*)hdr)->extraJointCount;
        }
        else
        {
            lim = 1;
        }
        if (jointIdx >= lim)
        {
            idx = 0;
        }
        *(f32*)(entry + 4) = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x1c);

        idx = jointIdx;
        hdr = *(u8**)obj;
        n = ((ModelFileHeader*)hdr)->jointCount;
        if (n != 0)
        {
            lim = n + ((ModelFileHeader*)hdr)->extraJointCount;
        }
        else
        {
            lim = 1;
        }
        if (jointIdx >= lim)
        {
            idx = 0;
        }
        *(f32*)(entry + 8) = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x2c);

    }
    {
        int lastJointIdx;
        u8* lastHdr;
        u32 lastCnt;
        int lastLim;
        int lastEntry = *desc + i * 0x54;
        f32 zero = lbl_803DE828;

        *(f32*)(lastEntry + 0x18) = zero;
        *(f32*)(lastEntry + 0x1c) = zero;
        *(f32*)(lastEntry + 0x20) = lbl_803DE850;
        {
            int* jointIdxArr = (int*)*(int*)desc[1];
            lastJointIdx = jointIdxArr[desc[2] - 1];
        }
        lastHdr = *(u8**)obj;
        lastCnt = *(u8*)(lastHdr + 0xf3);
        if (lastCnt != 0)
        {
            lastLim = lastCnt + *(u8*)(lastHdr + 0xf4);
        }
        else
        {
            lastLim = 1;
        }
        if (lastJointIdx >= lastLim)
        {
            lastJointIdx = 0;
        }
        PSMTXMultVec((f32*)(obj[(*(u16*)((u8*)obj + 0x18) & 1) + 3] + lastJointIdx * 0x40), (f32*)(lastEntry + 0x18), (f32*)lastEntry);
    }
}

#pragma opt_common_subs off
void* animLoadFromTable(u8* hdr, int id, int idx, u8* out)
{
    int size;
    int flags;
    int out2;
    u8* buf;
    int stride;

    flags = 0;
    fileLoadToBufferOffset(0x52, &flags, id << 2, 4);
    if (flags & 0x10000000)
    {
        loadAndDecompressDataFile(0x51, 0, flags, 0, (int)&size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(0x51, buf, flags, size, (int)&out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    else
    {
        flags = *(u32*)((int)gModelAnimFlagsTable + id * 4);
        loadAndDecompressDataFile(0x30, 0, flags, 0, (int)&size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(0x30, buf, flags, size, (int)&out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    return buf;
}

#pragma dont_inline off
#pragma opt_common_subs on
#pragma optimization_level 1
void* loadAnimation(int hdr, s16 id, int b, u8* bufout)
{
    int tmp;
    int size;
    u8* ptr;
    u32 v;
    int i;
    u32 ftype;

    if ((getLoadedFileFlags(0) & 0x100000) != 0 && (ftype = *(u16*)(hdr + 4)) != 1 && ftype != 3)
    {
        return 0;
    }
    if (bufout == 0)
    {
        if (ModelList_getHeader(gModelTexAtlasList, (i = id), &ptr) == 0)
        {
            u8* np;
            int idx2;
            v = ((u32*)gModelAnimFlagsTable)[(idx2 = i)];
            loadAndDecompressDataFile(0x30, 0, v, 0, (int)&size, i, 1);
            ptr = np = mmAlloc(size, 10, 0);
            loadAndDecompressDataFile(0x30, np, v, size, (int)&tmp, i, 0);
            *ptr = 1;
            modelInitModelList(gModelTexAtlasList, id, &ptr);
        }
        else
        {
            u8* p = ptr;
            *p += 1;
        }
        return ptr;
    }
    return animLoadFromTable((u8*)hdr, id, (s16)b, bufout);
}
#pragma optimization_level reset

typedef struct
{
    u8 pad[0xc];
    u8* buf;
} AnimBufSel;

extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * out);
extern f32 gModelJitterAxis[];

#pragma dont_inline on
void modelAnimFn_80026790(u8* model, int idx, u8* m, u8* anim)
{
    extern f32 lbl_803DCB48;
    extern f32 lbl_803DE844;
    extern f32 lbl_803DE848;
    extern f32 lbl_803DE84C;
    extern f32 lbl_803DE850;
    f32 vec[3];
    u8* hdr;
    int total;
    u8* base;
    f32 dot;
    f32 scaled;
    f32 amp;
    int off;
    int i;

    idx = 0;
    hdr = *(u8**)model;
    if (hdr[0xf3] != 0)
    {
        total = hdr[0xf3] + hdr[0xf4];
    }
    else
    {
        total = 1;
    }
    if (idx >= total)
    {
        idx = 0;
    }
    {
        u8* p = model + 0xc;
        base = *(u8**)((u8*)p + ((((ObjModel*)model)->bufferFlags & 1) << 2)) + idx * 0x40;
    }
    vec[0] = *(f32*)(base + 0x20);
    vec[1] = *(f32*)(base + 0x24);
    vec[2] = *(f32*)(base + 0x28);
    dot = PSVECDotProduct(vec, gModelJitterAxis);
    if (dot < lbl_803DE828)
    {
        dot = lbl_803DE828;
    }
    scaled = lbl_803DCB48 * (lbl_803DE844 - dot);
    amp = lbl_803DE848 * randomGetRange((int)(lbl_803DE84C * scaled), (int)(lbl_803DE850 * scaled));
    i = 0;
    off = 0;
    while (i < *(int*)(anim + 8) + 1)
    {
        u8* p = *(u8**)anim + off;
        *(f32*)&((ModelFileHeader*)p)->dataSize = *(f32*)&((ModelFileHeader*)p)->dataSize * *(f32*)&((ModelFileHeader*)m)->dataSize + gModelJitterAxis[0] * amp;
        *(f32*)(p + 0x10) = gModelJitterAxis[1] * amp + (*(f32*)(p + 0x10) * *(f32*)&((ModelFileHeader*)m)->dataSize + *(f32*)(m + 0x10));
        *(f32*)(p + 0x14) = *(f32*)(p + 0x14) * *(f32*)&((ModelFileHeader*)m)->dataSize + gModelJitterAxis[2] * amp;
        off += 0x54;
        i++;
    }
}

extern void PSMTXRotAxisRad(f32* m, f32* axis, f32 angle);

typedef struct ObjHitBufs
{
    u8 pad00[0x48];
    u8* bufs[2];
    u8* cur;
} ObjHitBufs;

#pragma dont_inline off
void objUpdateHitSpheres(u8* a, u8* b, u8* c, u8* d, u8* e)
{
    extern f32 lbl_803DE828;
    extern f32 lbl_803DCED0;
    extern f32 lbl_803DCECC;
    u8* mtx;
    int off[2];
    u8* prevSphere;
    int i;
    u8* hitReact;
    u8* samples;
    u8* src;
    f32 vec[3];
    f32 zero;
    f32 motionScale;
    u32 bufSel;
    int idx;
    int sampleCount;
    void* hitSample;
    u32 cnt;
    int lim;
    ObjHitBufs* st;

    hitSample = NULL;
    hitReact = *(u8**)(e + 0x54);
    if (hitReact != NULL)
    {
        if (*(u8*)(*(u8**)(e + 0x50) + 0x66) != 0)
        {
            sampleCount = (int)*(s16*)(hitReact + 4) >> 2;
            if (sampleCount > 0)
            {
                samples = *(u8**)(hitReact + 8);
                idx = (int)(((GameObject*)e)->anim.currentMoveProgress * sampleCount);
                if (idx >= sampleCount)
                {
                    idx = sampleCount - 1;
                }
                hitSample = *(void**)(samples + idx * 4);
            }
        }
        else
        {
            hitSample = *(void**)(hitReact + 0x48);
        }
    }

    if (*(u8**)(c + 0x54) != NULL)
    {
        *(u8*)(*(u8**)(c + 0x54) + 0xaf) -= 1;
        if (*(s8*)(*(u8**)(c + 0x54) + 0xaf) < 0)
        {
            *(u8*)(*(u8**)(c + 0x54) + 0xaf) = 0;
        }
        *(u32*)(*(u8**)(c + 0x54) + 0x4c) = *(u32*)(*(u8**)(c + 0x54) + 0x48);
        *(void**)(*(u8**)(c + 0x54) + 0x48) = hitSample;
    }

    st = (ObjHitBufs*)a;
    *(u16*)(a + 0x18) ^= 4;
    bufSel = (*(u16*)(a + 0x18) >> 2) & 1;
    st->cur = st->bufs[bufSel];
    mtx = d;
    i = 0;
    off[0] = 0;
    off[1] = off[0];
    prevSphere = st->bufs[bufSel ^ 1];
    for (; i < *(u8*)(b + 0xf7); i++)
    {
        if (d == NULL)
        {
            idx = *(s16*)(*(u8**)(b + 0x58) + off[0]);
            cnt = *(u8*)(*(u8**)a + 0xf3);
            if (cnt != 0)
            {
                lim = cnt + *(u8*)(*(u8**)a + 0xf4);
            }
            else
            {
                lim = 1;
            }
            if (idx >= lim)
            {
                idx = 0;
            }
            mtx = (u8*)((int*)a)[(*(u16*)(a + 0x18) & 1) + 3] + idx * 0x40;
        }
        if (i == 0 && e != c)
        {
            zero = lbl_803DE828;
            vec[0] = zero;
            vec[1] = zero;
            vec[2] = zero;
            PSMTXMultVec((f32*)mtx, vec, vec);
            ((GameObject*)c)->anim.localPosX = vec[0] + playerMapOffsetX;
            ((GameObject*)c)->anim.localPosY = vec[1];
            ((GameObject*)c)->anim.localPosZ = vec[2] + playerMapOffsetZ;
            Obj_GetWorldPosition((u32)c, (f32 *)(c + 0x18), (f32 *)(c + 0x1c), (f32 *)(c + 0x20));
        }
        vec[0] = *(f32*)(*(u8**)(b + 0x58) + off[0] + 8);
        vec[1] = *(f32*)(*(u8**)(b + 0x58) + off[0] + 0xc);
        vec[2] = *(f32*)(*(u8**)(b + 0x58) + off[0] + 0x10);
        *(f32*)(st->cur + off[1]) = *(f32*)(*(u8**)(b + 0x58) + off[0] + 4) * (motionScale = ((GameObject*)e)->anim.rootMotionScale);
        PSMTXMultVec((f32*)mtx, vec, (f32*)(st->cur + (off[1] + 4)));
        *(f32*)(prevSphere + 4) = (lbl_803DCED0 + *(f32*)(prevSphere + 4)) - playerMapOffsetX;
        *(f32*)(prevSphere + 0xc) = (lbl_803DCECC + *(f32*)(prevSphere + 0xc)) - playerMapOffsetZ;
        off[0] += 0x18;
        off[1] += 0x10;
        prevSphere += 0x10;
    }
}

extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXReorder(f32 * src, f32 * dst);

#pragma scheduling on
#pragma peephole on
static u8* modelGetBoneMtx(u8* m, int idx)
{
    u32 cnt;
    int lim;

    cnt = *(u8*)(*(u8**)m + 0xf3);
    if (cnt != 0)
    {
        lim = cnt + *(u8*)(*(u8**)m + 0xf4);
    }
    else
    {
        lim = 1;
    }
    if (idx >= lim)
    {
        idx = 0;
    }
    return (u8*)((int*)m)[(*(u16*)(m + 0x18) & 1) + 3] + idx * 0x40;
}

#pragma scheduling off
#pragma peephole off
void modelInitBoneMtxs(u8* m, u8* out)
{
    u8* hdr;
    u32 i;
    u8* mtx;
    int boneOff;
    u8* bone;
    u8* dst;
    f32 tmp[12];

    hdr = *(u8**)m;
    i = 0;
    boneOff = 0;
    dst = out;
    for (; i < ((ModelFileHeader*)hdr)->jointCount; i++)
    {
        mtx = modelGetBoneMtx(m, i);
        bone = ((ModelFileHeader*)hdr)->jointData + boneOff;
        PSMTXTrans(tmp, -*(f32*)(bone + 0x10), -*(f32*)(bone + 0x14), -*(f32*)(bone + 0x18));
        PSMTXConcat((f32*)mtx, tmp, tmp);
        PSMTXReorder(tmp, (f32*)dst);
        boneOff += 0x1c;
        dst += 0x30;
    }
}

void modelInitBoneMtxs2(u8* m, u8* out2, u8* out)
{
    u8* dst;
    int boneOff;
    u8* hdr;
    u32 i;
    u8* mtx;
    u8* bone;
    f32 tmp[12];

    hdr = *(u8**)m;
    if (((ModelFileHeader*)hdr)->jointCount == 0)
    {
        mtx = modelGetBoneMtx(m, 0);
        PSMTXConcat((f32*)out2, (f32*)mtx, (f32*)mtx);
    }
    else
    {
        i = 0;
        boneOff = 0;
        dst = out;
        for (; i < ((ModelFileHeader*)hdr)->jointCount; i++)
        {
            mtx = modelGetBoneMtx(m, i);
            bone = ((ModelFileHeader*)hdr)->jointData + boneOff;
            PSMTXTrans(tmp, -*(f32*)(bone + 0x10), -*(f32*)(bone + 0x14), -*(f32*)(bone + 0x18));
            PSMTXConcat((f32*)mtx, tmp, tmp);
            PSMTXReorder(tmp, (f32*)dst);
            PSMTXConcat((f32*)out2, (f32*)mtx, (f32*)mtx);
            boneOff += 0x1c;
            dst += 0x30;
        }
    }
}

void modelApplyBoneTransforms(int a, int b, u16 c, void* d, void* e, int f)
{
    extern u16 gModelCopyChunkWordLimit;
    extern void modelApplyBoneTransform(void* p, void* out, u16 n, void** pd, void** pe, int f, u16 pos);
    u16 pos;
    u16 chunk;
    u16 words;
    u16 nextChunk;
    u16 nextWords;
    u16 buf;
    u8* cache;
    u16 t;
    u8* out;
    u8* ptr;
    int sync;

    cache = getCache();
    pos = 0;
    if (c > gModelCopyChunkWordLimit)
    {
        chunk = gModelCopyChunkWordLimit;
    }
    else
    {
        chunk = c;
    }
    words = (u32)(chunk * 6 + 0x1f & 0xffe0) >> 5;
    copyToCache(cache, (void*)a, words);
    buf = 0;
    sync = 0;
    while (c != 0)
    {
        c -= chunk;
        if (c != 0)
        {
            if (c > gModelCopyChunkWordLimit)
            {
                nextChunk = gModelCopyChunkWordLimit;
            }
            else
            {
                nextChunk = c;
            }
            nextWords = (u32)(nextChunk * 6 + 0x1f & 0xffe0) >> 5;
            copyToCache(cache + (buf ^ 1) * 0x2000, (u8*)a + (pos + gModelCopyChunkWordLimit) * 6, nextWords);
            sync = 1;
        }
        cacheQueueWait(sync);
        t = buf;
        ptr = cache + t * 0x2000;
        out = ptr + 0x1000;
        modelApplyBoneTransform(ptr, out, chunk, &d, &e, f, pos);
        memcpyToCache((u8*)b + pos * 6, out, words);
        pos += chunk;
        sync = 1;
        buf = t ^ 1;
        chunk = nextChunk;
        words = nextWords;
    }
    cacheQueueWait(0);
}

extern void fn_80026308(int* a, int b, u8* p, u8* q, int d, int i);
extern void fn_80025F38(int* a, int b, u8* p, u8* q);

#pragma peephole on
#pragma peephole off
void playerTailFn_80026b3c(int* a, int b, u8* p, int d)
{
    int off;
    int i;

    if (p[0x1a] != 0)
    {
        i = 0;
        off = 0;
        for (; i < *(int*)(p + 4); i++)
        {
            if (*(u8*)(p + 0x19) == 0)
            {
                fn_80026928(a, b, (int*)(*(int*)p + off));
            }
            if (getHudHiddenFrameCount() == 0)
            {
                modelAnimFn_80026790((u8*)a, b, p, (u8*)(*(int*)p + off));
                fn_80026308(a, b, p, (u8*)(*(int*)p + off), d, i);
            }
            else
            {
                fn_80025F38(a, b, p, (u8*)(*(int*)p + off));
            }
            off += 0xc;
        }
        *(u8*)(p + 0x18) = 1;
        *(u8*)(p + 0x19) = 1;
    }
}
#pragma peephole reset

typedef struct
{
    int f0, f4, f8, fc, f10;
} MRIState;

extern void modelRenderInstrsState_init(MRIState* state, u8* data, int bits, int bits2);
extern u8* modelRenderFn_80006744(u8* p, int count, MRIState* state, int stride);
/* defined in render.c as (..., int gap, u8 bitWidth) returning int; the
   retail caller here passes/receives through int/u8* -- keep that view */
extern u8* fn_80006B1C(MRIState* src, MRIState* dst, int count, int gap, int bitWidth);

#pragma peephole off
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize)
{
    MRIState dstState;
    MRIState srcState;
    u8* dstBits;
    u8* srcBits;
    int vertBits;
    u8* p;
    u8* end;
    int v;
    int t;

    memcpy(dst, src, *(u16*)(src + 2));
    srcBits = src + *(u16*)(dst + 2);
    dstBits = dst + *(u16*)(dst + 2);
    vertBits = dst[8] << 3;
    modelRenderInstrsState_init(&dstState, dstBits, (dstSize - *(u16*)(dst + 2)) << 3,
                                (dstSize - *(u16*)(dst + 2)) << 3);
    modelRenderInstrsState_init(&srcState, srcBits, (srcSize - *(u16*)(dst + 2)) << 3,
                                (srcSize - *(u16*)(dst + 2)) << 3);
    memset(dstBits, 0, dstSize - *(u16*)(dst + 2));
    p = dst + 0xa;
    end = dst + *(u16*)(dst + 2);
    while (p < end)
    {
        v = *(s16*)p;
        p += 2;
        t = v & 0xF;
        if (t != 0)
        {
            if (t < 0)
            {
                srcBits = fn_80006B1C(&srcState, &dstState, dst[7], vertBits, t);
            }
            else
            {
                srcBits = modelRenderFn_80006744(srcBits, dst[7], &dstState, vertBits);
            }
        }
    }
    *(u16*)dst &= ~0x20;
    if (*(u16*)(dst + 4) != 0)
    {
        u32 oldOff = *(u16*)(dst + 4);
        *(u16*)(dst + 4) = *(u16*)(dst + 2) + (vertBits >> 3) * (dst[7] + 2);
        *(u16*)(dst + 4) = (*(u16*)(dst + 4) + 7) & ~7;
        memcpy(dst + *(u16*)(dst + 4), src + *(u16*)(src + 4), srcSize - oldOff);
    }
}

extern s16 gModelRootRotX;
extern s16 gModelRootRotY;
extern s16 gModelRootRotZ;
extern void ObjModel_SampleJointTransform(u8* model, int a, int b, f32 t, f32 s, f32* outPos, s16* outRot);
extern void modelAnimFn_800246a0(u8* dst, u8* model, u8* ch, f32 t, int max, int b, int c, int d, int e, s16 f);

void ObjModel_UpdateAnimMatrices(u8* model, u8* blend, u8* obj, u8* dst)
{
    ObjAnimState* ch;
    ObjAnimState* ch2;
    f32 pos[3];
    s16 rot[3];

    ObjModel_BuildAnimBlendTable(obj, *(u8**)(model + 0x2c), blend);
    ((ObjModel*)model)->bufferFlags ^= 1;
    ch = ((ObjModel*)model)->animStateA;
    if (ch->moveControlFlags & 4)
    {
        ObjModel_SampleJointTransform(model, 0, 0, ((GameObject*)obj)->anim.currentMoveProgress,
                                      ((GameObject*)obj)->anim.rootMotionScale, pos, rot);
        gModelRootRotX = rot[0];
        gModelRootRotY = rot[1];
        gModelRootRotZ = rot[2];
    }
    if (*(u16*)(*(u8**)model + 2) & 8)
    {
        modelWalkAnimFn_800248b8(dst, model, *(u8**)(model + 0x2c),
                                 ((GameObject*)obj)->anim.currentMoveProgress, 0x7f);
    }
    else if (((ObjAnimState*)((ObjModel*)model)->animStateA)->moveControlFlags & 8)
    {
        ch2 = ((ObjModel*)model)->animStateB;
        modelAnimFn_800246a0(dst, model, (u8*)ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 0, 2, 0x14,
                             (s16)ch->eventState);
        modelAnimFn_800246a0(dst, model, (u8*)ch2, ((GameObject*)obj)->anim.activeMoveProgress, 0x7f, 0, 0, 2, 0x18,
                             (s16)ch2->eventState);
        modelAnimFn_800246a0(dst, model, (u8*)ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 0, 0, 7,
                             (s16)ch2->eventCountdown);
        modelAnimFn_800246a0(dst, model, (u8*)ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 1, 1, 1,
                             (s16)ch->eventCountdown);
    }
    else
    {
        modelWalkAnimFn_800248b8(dst, model, *(u8**)(model + 0x2c),
                                 ((GameObject*)obj)->anim.currentMoveProgress, 0x7f);
        ch2 = ((ObjModel*)model)->animStateB;
        if (ch2 != NULL && ((GameObject*)obj)->anim.activeMove > -1)
        {
            ObjModel_BuildAnimBlendTable(obj, *(u8**)(model + 0x30), blend);
            modelWalkAnimFn_800248b8(dst, model, *(u8**)(model + 0x30),
                                     ((GameObject*)obj)->anim.activeMoveProgress, -1);
        }
    }
}

typedef struct
{
    u8 _0[0xc];
    int bufs[2];
} MdlSelBufs;

typedef struct
{
    u8 _0[0x34];
    int vals[2];
} ChF34;

void modelAnimFn_800246a0(u8* dst, u8* model, u8* channel, f32 t, int flags, int slotA, int slotB, int blendSel, int mode, s16 eventVal)
{
    u8 stk[0x64];
    int mtxBuf;
    u8* hdr;
    u32 idxA;
    u8 idxB;
    int fl;
    int cacheOff;
    u8* p;

    hdr = *(u8**)model;
    {
        u32 sel = *(u16*)(model + 0x18) & 1;
        u8* pb = model + 12;
        mtxBuf = *(int*)(pb + sel * 4);
    }
    if ((u8)mode & 0x10)
    {
        ((ObjAnimState*)channel)->framePhase = t * ((ObjAnimState*)channel)->frameLength;
    }
    idxA = (u8)slotA;
    p = channel + idxA;
    *(u8*)(stk + 0x60) = *(u8*)(p + 0x60);
    p = channel + idxA * 4;
    *(f32*)(stk + 0x14) = *(f32*)(p + 0x14);
    *(f32*)(stk + 4) = *(f32*)(p + 4);
    *(int*)(stk + 0x34) = *(int*)&((ModelFileHeader*)p)->unk34;
    idxB = (u8)slotB;
    p = channel + idxB;
    *(u8*)(stk + 0x61) = *(u8*)(p + 0x60);
    p = channel + idxB * 4;
    *(f32*)(stk + 0x18) = *(f32*)(p + 0x14);
    *(f32*)(stk + 8) = *(f32*)(p + 4);
    idxB = (u8)blendSel;
    p = channel + 0x34;
    *(int*)(stk + 0x38) = *(int*)(p + idxB * 4);
    if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
    {
        *(u16*)(stk + 0x44) = 0;
        *(u16*)(stk + 0x46) = 1;
        cacheOff = *(u16*)((u8*)(channel + 0x44) + idxA * 2) * 4;
        *(int*)(stk + 0x1c) = *(int*)((u8*)(channel + 0x1c) + cacheOff);
        if (idxB < 2)
        {
            cacheOff = *(u16*)((u8*)(channel + 0x44) + idxB * 2) * 4;
            *(int*)(stk + 0x20) = *(int*)((u8*)(channel + 0x1c) + cacheOff);
        }
        else
        {
            cacheOff = *(u16*)((u8*)(channel + 0x44) + idxB * 2) * 4;
            *(int*)(stk + 0x20) = *(int*)((u8*)(channel + 0x24) + cacheOff);
        }
    }
    else
    {
        *(u16*)(stk + 0x44) = *(u16*)((u8*)(channel + 0x44) + idxA * 2);
        *(u16*)(stk + 0x46) = *(u16*)((u8*)(channel + 0x44) + idxB * 2);
    }
    if (eventVal == 0)
    {
        eventVal = 1;
    }
    *(u16*)(stk + 0x58) = eventVal;
    modelAnimUpdateChannels(hdr, stk, 2);
    {
        int modeLow = mode & 0xF;
        mode = modeLow;
        if ((modeLow & 0xC) == 0)
        {
            int sv = ((ObjAnimState*)channel)->moveControlFlags;
            if (sv & 1)
            {
                mode = (modeLow | 0x10) & 0xFF;
            }
            if (sv & 4)
            {
                mode = (mode | 0x20) & 0xFF;
            }
        }
    }
    lbl_80006C6C(&mtxBuf, dst, stk, *(int*)&((ModelFileHeader*)hdr)->jointData, ((ModelFileHeader*)hdr)->jointCount, gModelJointScratchBuffer, flags, (u8)mode);
}

asm void ObjModel_TransformVerticesWithTranslation(register u8* m1, register u8* m2, register u8* src, register int d1, register int d2, register int count)
{
    nofralloc
    stwu r1, -160(r1)
    stfd f14, 8(r1)
    addi r9, count, -1
    stfd f15, 16(r1)
    stfd f16, 24(r1)
    stfd f17, 32(r1)
    stfd f18, 40(r1)
    stfd f19, 48(r1)
    stfd f20, 56(r1)
    stfd f21, 64(r1)
    stfd f22, 72(r1)
    stfd f23, 80(r1)
    stfd f24, 88(r1)
    stfd f25, 96(r1)
    stfd f26, 104(r1)
    stfd f27, 112(r1)
    mtctr r9
    psq_l f0, 0(m1), 0, 0
    addi d1, d1, -2
    psq_l f1, 8(m1), 1, 0
    addi d2, d2, -2
    psq_l f6, 36(m1), 0, 0
    addi src, src, -2
    psq_lu f8, 2(d1), 0, 7
    psq_l f7, 44(m1), 1, 0
    psq_lu f9, 4(d1), 1, 7
    psq_lu f27, 2(src), 0, 6
    ps_madds0 f15, f0, f8, f6
    psq_l f2, 12(m1), 0, 0
    ps_madds0 f16, f1, f8, f7
    psq_l f3, 20(m1), 1, 0
    psq_l f5, 32(m1), 1, 0
    ps_madds1 f15, f2, f8, f15
    psq_l f19, 0(m2), 0, 0
    ps_madds1 f16, f3, f8, f16
    psq_l f4, 24(m1), 0, 0
    psq_l f20, 8(m2), 1, 0
    psq_l f21, 12(m2), 0, 0
    ps_madds0 f15, f4, f9, f15
    psq_l f22, 20(m2), 1, 0
    ps_madds0 f16, f5, f9, f16
    psq_l f23, 24(m2), 0, 0
    psq_l f24, 32(m2), 1, 0
    psq_l f25, 36(m2), 0, 0
    ps_muls0 f15, f15, f27
    psq_l f26, 44(m2), 1, 0
    ps_muls0 f16, f16, f27
    ps_madds0 f11, f19, f8, f25
    ps_madds0 f12, f20, f8, f26
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 2(d1), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 4(d1), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
lbl_TVWT_loop:
    ps_madds0 f15, f0, f8, f6
    psq_stu f11, 2(d2), 0, 7
    ps_madds0 f16, f1, f8, f7
    psq_stu f12, 4(d2), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    psq_lu f27, 2(src), 0, 6
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_madds0 f11, f19, f8, f25
    ps_madds0 f12, f20, f8, f26
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 2(d1), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 4(d1), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    bdnz lbl_TVWT_loop
    psq_stu f11, 2(d2), 0, 7
    psq_stu f12, 4(d2), 1, 7
    lfd f14, 8(r1)
    lfd f15, 16(r1)
    lfd f16, 24(r1)
    lfd f17, 32(r1)
    lfd f18, 40(r1)
    lfd f19, 48(r1)
    lfd f20, 56(r1)
    lfd f21, 64(r1)
    lfd f22, 72(r1)
    lfd f23, 80(r1)
    lfd f24, 88(r1)
    lfd f25, 96(r1)
    lfd f26, 104(r1)
    lfd f27, 112(r1)
    addi r1, r1, 160
    blr
}

void ObjModel_BlendPrimaryVertexStream(u8* mtxs, u8* hdr, u8* data, int* offs, u8* out)
{
    u16 sizes[2];

    setGQR7Packed(hdr[6], 7, hdr[6], 7);
    ObjModel_InitScratchBuffers();
    if (((ModelFileHeader*)hdr)->flags != 0)
    {
        u8* q;
        int words;
        int w2;
        u32 i;
        u32 nb;
        u8* dst;

        q = *(u8**)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], data + *(int*)(q + 0x60), words);
        sizes[0] = words;
        w2 = (u32)(((q = *(u8**)(hdr + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + 4), *(u8**)(q + 0x64), w2);
        for (i = 0; i < (u32)(((ModelFileHeader*)hdr)->flags - 1); i++)
        {
            q = *(u8**)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nb * 2)], data + *(int*)(q + 0xd4), words);
            sizes[(i + 1) & 1] = words;
            {
                u8* q2;
                int w3 = (u32)(((q2 = *(u8**)(hdr + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nb * 2) + 1)], *(u8**)(q2 + 0xd8), w3);
            }
            cacheQueueWait(2);
            dst = out + offs[i];
            ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                      gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                      q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                      q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                      *(u16*)(q + 0x70));
            memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        q = *(u8**)(hdr + 0xc) + i * 0x74;
        cacheQueueWait(0);
        dst = out + offs[i];
        ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                  gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                  q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                  q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                  *(u16*)(q + 0x70));
        memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
        cacheQueueWait(0);
    }
}

asm void ObjModel_TransformVerticesLinear(register u8* m1, register u8* m2, register u8* src, register int d1, register int d2, register int count)
{
    nofralloc
    stwu r1, -160(r1)
    stfd f14, 8(r1)
    addi r9, count, -1
    stfd f15, 16(r1)
    stfd f16, 24(r1)
    stfd f17, 32(r1)
    stfd f18, 40(r1)
    stfd f19, 48(r1)
    stfd f20, 56(r1)
    stfd f21, 64(r1)
    stfd f22, 72(r1)
    stfd f23, 80(r1)
    stfd f24, 88(r1)
    stfd f25, 96(r1)
    stfd f26, 104(r1)
    stfd f27, 112(r1)
    mtctr r9
    psq_l f0, 0(m1), 0, 0
    addi d1, d1, -1
    psq_l f1, 8(m1), 1, 0
    addi d2, d2, -1
    addi src, src, -2
    psq_lu f8, 1(d1), 0, 7
    psq_lu f9, 2(d1), 1, 7
    psq_lu f27, 2(src), 0, 6
    ps_muls0 f15, f0, f8
    psq_l f2, 12(m1), 0, 0
    ps_muls0 f16, f1, f8
    psq_l f3, 20(m1), 1, 0
    psq_l f5, 32(m1), 1, 0
    ps_madds1 f15, f2, f8, f15
    psq_l f19, 0(m2), 0, 0
    ps_madds1 f16, f3, f8, f16
    psq_l f4, 24(m1), 0, 0
    psq_l f20, 8(m2), 1, 0
    psq_l f21, 12(m2), 0, 0
    ps_madds0 f15, f4, f9, f15
    psq_l f22, 20(m2), 1, 0
    ps_madds0 f16, f5, f9, f16
    psq_l f23, 24(m2), 0, 0
    psq_l f24, 32(m2), 1, 0
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 1(d1), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 2(d1), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
lbl_TVL_loop:
    ps_muls0 f15, f0, f8
    psq_stu f11, 1(d2), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 2(d2), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    psq_lu f27, 2(src), 0, 6
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 1(d1), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 2(d1), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    bdnz lbl_TVL_loop
    psq_stu f11, 1(d2), 0, 7
    psq_stu f12, 2(d2), 1, 7
    lfd f14, 8(r1)
    lfd f15, 16(r1)
    lfd f16, 24(r1)
    lfd f17, 32(r1)
    lfd f18, 40(r1)
    lfd f19, 48(r1)
    lfd f20, 56(r1)
    lfd f21, 64(r1)
    lfd f22, 72(r1)
    lfd f23, 80(r1)
    lfd f24, 88(r1)
    lfd f25, 96(r1)
    lfd f26, 104(r1)
    lfd f27, 112(r1)
    addi r1, r1, 160
    blr
}
asm void ObjModel_TransformQuadVerticesLinear(register u8* m1, register u8* m2, register u8* src, register int d1, register int d2, register int count)
{
    nofralloc
    stwu    r1,-160(r1)
    stfd    f14,8(r1)
    addi    r9,count,-1
    stfd    f15,16(r1)
    stfd    f16,24(r1)
    stfd    f17,32(r1)
    stfd    f18,40(r1)
    stfd    f19,48(r1)
    stfd    f20,56(r1)
    stfd    f21,64(r1)
    stfd    f22,72(r1)
    stfd    f23,80(r1)
    stfd    f24,88(r1)
    stfd    f25,96(r1)
    stfd    f26,104(r1)
    stfd    f27,112(r1)
    mtctr   r9
    psq_l   f0,0(m1),0,0
    addi    d1,d1,-1
    psq_l   f1,8(m1),1,0
    addi    d2,d2,-1
    addi    src,src,-2
    psq_lu  f8,1(d1),0,7
    psq_lu  f9,2(d1),1,7
    psq_lu  f27,2(src),0,6
    ps_muls0 f15,f0,f8
    psq_l   f2,12(m1),0,0
    ps_muls0 f16,f1,f8
    psq_l   f3,20(m1),1,0
    psq_l   f5,32(m1),1,0
    ps_madds1 f15,f2,f8,f15
    psq_l   f19,0(m2),0,0
    ps_madds1 f16,f3,f8,f16
    psq_l   f4,24(m1),0,0
    psq_l   f20,8(m2),1,0
    psq_l   f21,12(m2),0,0
    ps_madds0 f15,f4,f9,f15
    psq_l   f22,20(m2),1,0
    ps_madds0 f16,f5,f9,f16
    psq_l   f23,24(m2),0,0
    psq_l   f24,32(m2),1,0
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
    ps_muls0 f15,f0,f8
    psq_stu f11,1(d2),0,7
    ps_muls0 f16,f1,f8
    psq_stu f12,2(d2),1,7
    ps_madds1 f15,f2,f8,f15
    ps_madds1 f16,f3,f8,f16
    ps_madds0 f15,f4,f9,f15
    ps_madds0 f16,f5,f9,f16
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
    ps_muls0 f15,f0,f8
    psq_stu f11,1(d2),0,7
    ps_muls0 f16,f1,f8
    psq_stu f12,2(d2),1,7
    ps_madds1 f15,f2,f8,f15
    ps_madds1 f16,f3,f8,f16
    ps_madds0 f15,f4,f9,f15
    ps_madds0 f16,f5,f9,f16
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
lbl_TQVL_loop:
    ps_muls0 f15,f0,f8
    psq_stu f11,1(d2),0,7
    ps_muls0 f16,f1,f8
    psq_stu f12,2(d2),1,7
    ps_madds1 f15,f2,f8,f15
    ps_madds1 f16,f3,f8,f16
    ps_madds0 f15,f4,f9,f15
    ps_madds0 f16,f5,f9,f16
    psq_lu  f27,2(src),0,6
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
    ps_muls0 f15,f0,f8
    psq_stu f11,1(d2),0,7
    ps_muls0 f16,f1,f8
    psq_stu f12,2(d2),1,7
    ps_madds1 f15,f2,f8,f15
    ps_madds1 f16,f3,f8,f16
    ps_madds0 f15,f4,f9,f15
    ps_madds0 f16,f5,f9,f16
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
    ps_muls0 f15,f0,f8
    psq_stu f11,1(d2),0,7
    ps_muls0 f16,f1,f8
    psq_stu f12,2(d2),1,7
    ps_madds1 f15,f2,f8,f15
    ps_madds1 f16,f3,f8,f16
    ps_madds0 f15,f4,f9,f15
    ps_madds0 f16,f5,f9,f16
    ps_muls0 f15,f15,f27
    ps_muls0 f16,f16,f27
    ps_muls0 f11,f19,f8
    ps_muls0 f12,f20,f8
    ps_madds1 f11,f21,f8,f11
    ps_madds1 f12,f22,f8,f12
    psq_lu  f8,1(d1),0,7
    ps_madds0 f11,f23,f9,f11
    ps_madds0 f12,f24,f9,f12
    psq_lu  f9,2(d1),1,7
    ps_madds1 f11,f11,f27,f15
    ps_madds1 f12,f12,f27,f16
    bdnz lbl_TQVL_loop
    psq_stu f11,1(d2),0,7
    psq_stu f12,2(d2),1,7
    lfd     f14,8(r1)
    lfd     f15,16(r1)
    lfd     f16,24(r1)
    lfd     f17,32(r1)
    lfd     f18,40(r1)
    lfd     f19,48(r1)
    lfd     f20,56(r1)
    lfd     f21,64(r1)
    lfd     f22,72(r1)
    lfd     f23,80(r1)
    lfd     f24,88(r1)
    lfd     f25,96(r1)
    lfd     f26,104(r1)
    lfd     f27,112(r1)
    addi    r1,r1,160
    blr
}

void ObjModel_BlendSecondaryVertexStream(u8* mtxs, u8* hdr, u8* data, u8** outs, int quad)
{
    u16 sizes[2];

    setGQR7Packed(hdr[6], 6, hdr[6], 6);
    ObjModel_InitScratchBuffers();
    if (((ModelFileHeader*)hdr)->flags != 0)
    {
        u8* q;
        int words;
        int w2;
        u32 i;
        u32 nb;
        u8* dst;

        q = *(u8**)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], data + *(int*)(q + 0x60), words);
        sizes[0] = words;
        w2 = (u32)(((q = *(u8**)(hdr + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + 4), *(u8**)(q + 0x64), w2);
        for (i = 0; i < (u32)(((ModelFileHeader*)hdr)->flags - 1); i++)
        {
            q = *(u8**)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nb * 2)], data + *(int*)(q + 0xd4), words);
            sizes[(i + 1) & 1] = words;
            {
                u8* q2;
                int w3 = (u32)(((q2 = *(u8**)(hdr + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nb * 2) + 1)], *(u8**)(q2 + 0xd8), w3);
            }
            cacheQueueWait(2);
            if ((u8)quad)
            {
                dst = outs[i];
                ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                     gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                     q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                     q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                     *(u16*)(q + 0x70));
                memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
            }
            else
            {
                dst = outs[i];
                ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                 *(u16*)(q + 0x70));
                memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
            }
        }
        q = *(u8**)(hdr + 0xc) + i * 0x74;
        cacheQueueWait(0);
        if ((u8)quad)
        {
            dst = outs[i];
            ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                                 *(u16*)(q + 0x70));
            memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        else
        {
            dst = outs[i];
            ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                             gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                             q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                             q[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)],
                                             *(u16*)(q + 0x70));
            memcpyToCache(dst, gModelCacheBuffersA[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        cacheQueueWait(0);
    }
}

extern f32 lbl_803DE880;
extern void fn_80007F78(u8 * ch, s16 * outRot, s16 * outRot2);

void ObjModel_SampleJointTransform(u8* model, int b, int idx, f32 t, f32 s, f32* outPos, s16* outRot)
{
    ObjAnimState* ch;
    int saved;
    s16 srot[3];
    u8* anim;

    if (((ObjModel*)model)->file->animationCount == 0)
    {
        f32 z = lbl_803DE828;
        outPos[0] = z;
        outPos[1] = z;
        outPos[2] = z;
        outRot[0] = 0;
        outRot[1] = 0;
        outRot[2] = 0;
    }
    if (b != 0)
    {
        ch = ((ObjModel*)model)->animStateB;
    }
    else
    {
        ch = ((ObjModel*)model)->animStateA;
    }
    saved = *(int*)&ch->moveFrameData;
    {
        /* the four frame-data pointers (move/prevMove/blend/prevBlend) are
           indexed as one array here; the selected one is swapped into the
           moveFrameData slot for fn_80007F78, then restored */
        ObjAnimFrameCommand** p = &ch->moveFrameData;
        ch->moveFrameData = p[idx];
    }
    if (*(u16*)(*(u8**)model + 2) & 0x40)
    {
        if (idx > 1)
        {
            u8** q = ch->blendMoveCache;
            u16* p = &ch->moveCacheSlot;
            anim = q[p[idx]] + 0x80;
        }
        else
        {
            u8** q = ch->moveCache;
            u16* p = &ch->moveCacheSlot;
            anim = q[p[idx]] + 0x80;
        }
    }
    else
    {
        u16* p = &ch->moveCacheSlot;
        anim = ((u8**)*(int*)(*(u8**)model + 0x64))[p[idx]];
    }
    ch->framePhase = t * ch->frameLength;
    {
        int bv = ((u8*)ch->moveFrameData)[2];
        f32 fr = ch->framePhase;
        int n = fr;
        f32 fcv = n;
        if (fcv != fr)
        {
            *(s16*)((u8*)ch + 0x4c) = bv;
        }
        else
        {
            *(s16*)((u8*)ch + 0x4c) = 0;
        }
        if (ch->frameType != 0 && fcv == ch->frameLength - lbl_803DE818)
        {
            *(s16*)((u8*)ch + 0x4c) = (s16)(-bv * n);
        }
        *(u8**)((u8*)ch + 0x2c) = anim + *(s16*)(anim + 2) + bv * n;
    }
    fn_80007F78((u8*)ch, srot, outRot);
    *(int*)&ch->moveFrameData = saved;
    {
        f32 k = lbl_803DE880;
        outPos[0] = k * srot[0];
        outPos[1] = k * srot[1];
        outPos[2] = k * srot[2];
    }
    outPos[0] = outPos[0] + *(f32*)(*(u8**)(*(u8**)model + 0x3c) + 4);
    outPos[1] = outPos[1] + *(f32*)(*(u8**)(*(u8**)model + 0x3c) + 8);
    outPos[2] = outPos[2] + *(f32*)(*(u8**)(*(u8**)model + 0x3c) + 0xc);
    outPos[0] *= s;
    outPos[1] *= s;
    outPos[2] *= s;
}

extern void PSMTXCopy(f32 * src, f32 * dst);
extern void PSMTXTranspose(f32 * src, f32 * dst);
extern void PSMTXIdentity(f32 * m);
extern f32 fn_802920A4(f32 x);
extern f32 gModelDotClampMax;
extern f32 gModelDotClampMin;
extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;

#pragma scheduling on
#pragma peephole on
static int boneBlendSlotLimit(u8* model)
{
    u8* p = *(u8**)model;
    if (p[0xf3] != 0)
    {
        return p[0xf3] + p[0xf4];
    }
    return 1;
}

#pragma scheduling off
#pragma peephole off
void fn_80025F38(int* a, int b, u8* blend, u8* chain)
{
    u8* model = (u8*)a;
    f32 tmp[12];
    f32 mt[12];
    f32 target[3];
    f32 work[3];
    f32 out[3];
    f32 dir2[3];
    f32 dir1[3];
    f32 axis[3];
    int nextIdx;
    int i;
    int idx;
    f32* m;
    int prevOff;
    f32 dot;
    f32 cap;
    u8* bankSel;

    idx = *(s8*)(*(u8**)(b + 0x3c) + (*(int***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    bankSel = model + 0xc;
    PSMTXCopy(*(f32**)(bankSel + ((((ObjModel*)model)->bufferFlags & 1) << 2)) + idx * 0x10, tmp);
    idx = (*(int***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    bankSel = model + 0xc;
    m = *(f32**)(bankSel + ((((ObjModel*)model)->bufferFlags & 1) << 2)) + idx * 0x10;
    cap = gModelDotClampMax;
    for (i = 1; i < *(int*)(chain + 8) + 1; i++)
    {
        nextIdx = (*(int***)(chain + 4))[0][i];
        PSMTXMultVec(tmp, (f32*)(*(u8**)chain + (i - 1) * 0x54 + 0x18), out);
        target[0] = lbl_803DCED0 + (*(f32*)(*(u8**)chain + i * 0x54) + *(f32*)(*(u8**)chain + i * 0x54 + 0xc)) -
            playerMapOffsetX;
        target[1] = *(f32*)(*(u8**)chain + i * 0x54 + 4) + *(f32*)(*(u8**)chain + i * 0x54 + 0x10);
        target[2] = lbl_803DCECC + (*(f32*)(*(u8**)chain + i * 0x54 + 8) + *(f32*)(*(u8**)chain + i * 0x54 + 0x14)) -
            playerMapOffsetZ;
        work[0] = *(f32*)(*(u8**)chain + i * 0x54 - 0x3c);
        work[1] = *(f32*)(*(u8**)chain + i * 0x54 - 0x38);
        work[2] = *(f32*)(*(u8**)chain + i * 0x54 - 0x34);
        PSVECAdd(work, (f32*)(*(u8**)chain + i * 0x54 + 0x18), work);
        PSMTXMultVec(tmp, work, work);
        PSVECSubtract(target, out, dir1);
        PSVECNormalize(dir1, dir1);
        PSVECSubtract(work, out, dir2);
        PSVECNormalize(dir2, dir2);
        dot = PSVECDotProduct(dir2, dir1);
        if (dot < cap && dot > gModelDotClampMin)
        {
            if (dot < lbl_803DE818 && dot > lbl_803DE840)
            {
                PSVECCrossProduct(dir2, dir1, axis);
                if (dot < lbl_803DE840)
                {
                    dot = lbl_803DE840;
                }
                else
                {
                    f32 sub = lbl_803DE818 - dot;
                    dot = sub * *(f32*)(blend + 8) + dot;
                }
                PSMTXTranspose(tmp, mt);
                PSMTXMultVecSR(mt, axis, axis);
                PSMTXRotAxisRad(m, axis, fn_802920A4(dot));
            }
            else
            {
                PSMTXIdentity(m);
            }
        }
        PSMTXConcat(tmp, m, m);
        m[3] = out[0];
        m[7] = out[1];
        m[11] = out[2];
        PSMTXCopy(m, tmp);
        work[0] = *(f32*)(*(u8**)chain + i * 0x54 + 0x18);
        work[1] = *(f32*)(*(u8**)chain + i * 0x54 + 0x1c);
        work[2] = *(f32*)(*(u8**)chain + i * 0x54 + 0x20);
        PSMTXMultVec(m, work, work);
        PSMTXCopy(m, (f32*)(*(u8**)chain + (i - 1) * 0x54 + 0x24));
        if (i < *(int*)(chain + 8))
        {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model))
            {
                idx = 0;
            }
            m = *(f32**)((u8*)model + ((((ObjModel*)model)->bufferFlags & 1) << 2) + 0xc) + idx * 0x10;
        }
    }
}

void fn_80026308(int* a, int b, u8* blend, u8* chain, int cb, int cbArg)
{
    u8* model = (u8*)a;
    f32 tmp[12];
    f32 mt[12];
    f32 target[3];
    f32 work[3];
    f32 out[3];
    f32 dir2[3];
    f32 dir1[3];
    f32 axis[3];
    int nextIdx;
    int i;
    int idx;
    f32* m;
    int prevOff;
    f32 dot;
    f32 cap;

    idx = *(s8*)(*(u8**)(b + 0x3c) + (*(int***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    PSMTXCopy(*(f32**)((u8*)(model + 0xc) + ((((ObjModel*)model)->bufferFlags & 1) << 2)) + idx * 0x10, tmp);
    idx = (*(int***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    m = *(f32**)((u8*)(model + 0xc) + ((((ObjModel*)model)->bufferFlags & 1) << 2)) + idx * 0x10;
    cap = gModelDotClampMax;
    for (i = 1; i < *(int*)(chain + 8) + 1; i++)
    {
        nextIdx = (*(int***)(chain + 4))[0][i];
        PSMTXMultVec(tmp, (f32*)(*(u8**)chain + (i - 1) * 0x54 + 0x18), out);
        target[0] = lbl_803DCED0 + (*(f32*)(*(u8**)chain + i * 0x54) + *(f32*)(*(u8**)chain + i * 0x54 + 0xc)) -
            playerMapOffsetX;
        target[1] = *(f32*)(*(u8**)chain + i * 0x54 + 4) + *(f32*)(*(u8**)chain + i * 0x54 + 0x10);
        target[2] = lbl_803DCECC + (*(f32*)(*(u8**)chain + i * 0x54 + 8) + *(f32*)(*(u8**)chain + i * 0x54 + 0x14)) -
            playerMapOffsetZ;
        work[0] = *(f32*)(*(u8**)chain + i * 0x54 - 0x3c);
        work[1] = *(f32*)(*(u8**)chain + i * 0x54 - 0x38);
        work[2] = *(f32*)(*(u8**)chain + i * 0x54 - 0x34);
        if ((u32)cb != 0)
        {
            ((void (*)(int, int*, f32*, int, int, f32))cb)(b, a, work, cbArg, i, *(f32*)(blend + 0x14));
        }
        PSVECAdd(work, (f32*)(*(u8**)chain + i * 0x54 + 0x18), work);
        PSMTXMultVec(tmp, work, work);
        PSVECSubtract(target, out, dir1);
        PSVECNormalize(dir1, dir1);
        PSVECSubtract(work, out, dir2);
        PSVECNormalize(dir2, dir2);
        dot = PSVECDotProduct(dir2, dir1);
        if (dot < cap && dot > gModelDotClampMin)
        {
            PSVECCrossProduct(dir2, dir1, axis);
            if (dot < lbl_803DE840)
            {
                dot = lbl_803DE840;
            }
            else
            {
                f32 sub = lbl_803DE818 - dot;
                dot = sub * *(f32*)(blend + 8) + dot;
            }
            PSMTXTranspose(tmp, mt);
            PSMTXMultVecSR(mt, axis, axis);
            PSMTXRotAxisRad(m, axis, fn_802920A4(dot));
        }
        else
        {
            PSMTXIdentity(m);
        }
        PSMTXConcat(tmp, m, m);
        m[3] = out[0];
        m[7] = out[1];
        m[11] = out[2];
        PSMTXCopy(m, tmp);
        work[0] = *(f32*)(*(u8**)chain + i * 0x54 + 0x18);
        work[1] = *(f32*)(*(u8**)chain + i * 0x54 + 0x1c);
        work[2] = *(f32*)(*(u8**)chain + i * 0x54 + 0x20);
        PSMTXMultVec(m, work, work);
        PSMTXCopy(m, (f32*)(*(u8**)chain + (i - 1) * 0x54 + 0x24));
        if (i < *(int*)(chain + 8))
        {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model))
            {
                idx = 0;
            }
            m = *(f32**)((u8*)model + ((((ObjModel*)model)->bufferFlags & 1) << 2) + 0xc) + idx * 0x10;
        }
        *(f32*)(*(u8**)chain + i * 0x54 + 0xc) = work[0] - (lbl_803DCED0 + *(f32*)(*(u8**)chain + i * 0x54) -
            playerMapOffsetX);
        *(f32*)(*(u8**)chain + i * 0x54 + 0x10) = work[1] - *(f32*)(*(u8**)chain + i * 0x54 + 4);
        *(f32*)(*(u8**)chain + i * 0x54 + 0x14) = work[2] - (lbl_803DCECC + *(f32*)(*(u8**)chain + i * 0x54 + 8) -
            playerMapOffsetZ);
        *(f32*)(*(u8**)chain + i * 0x54) = work[0];
        *(f32*)(*(u8**)chain + i * 0x54 + 4) = work[1];
        *(f32*)(*(u8**)chain + i * 0x54 + 8) = work[2];
    }
}
