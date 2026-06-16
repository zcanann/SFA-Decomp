#include "main/asset_load.h"
#include "main/dll/objmodel_types.h"
#include "main/model.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern void mm_free(void* ptr);
extern void gxTextureFn_80072dfc(void* obj, void** model, int param_3);
extern void* textureIdxToPtr(int textureId);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void gxSetZMode_(u32 enable, int func, u32 update);
extern void gxSetPeControl_ZCompLoc_(u32 beforeTex);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);

undefined2*
FUN_80017460(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

undefined2*
FUN_80017468(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

extern f32 timeDelta;

undefined4
FUN_80017500(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
    return 0;
}

undefined4
FUN_8001786c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12)
{
    return 0;
}

undefined*
FUN_80017998(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
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
    return ((ModelFileHeader*)modelFile)->unk5C + index * 8;
}

void* fn_80028364(u8* modelFile, int index)
{
    return ((ModelFileHeader*)modelFile)->unk60 + index * 0x14;
}

void* modelFileGetDisplayList(u8* modelFile, int displayListIndex)
{
    return ((ModelFileHeader*)modelFile)->displayLists + displayListIndex * 0x1c;
}

void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out)
{
    ObjModelInstanceLite* model;
    uint jointCount;
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
    GXSetBlendMode(1, 4, 1, 5);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
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
    uint jointCount;

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
extern void textureFree(void* tex);

void ObjModelChain_SetOrigin(ObjModelChain* chain, f32 x, f32 y, f32 z)
{
    chain->originX = x;
    chain->originY = y;
    chain->originZ = z;
}

int alignUp2(int x);

extern int getLoadedFileFlags(int);
extern int randomGetRange(int lo, int hi);

void* getCache(void);

extern f32 lbl_803DE854;

void cacheQueueWait(int sync);

#pragma scheduling off
#pragma peephole off
void ObjModelChain_AdvancePhase(ObjModelChain* chain)
{
    chain->updateFlag = 0;
    chain->phase += timeDelta;
    if (chain->phase > lbl_803DE854)
    {
        chain->phase -= *(f32*)&lbl_803DE854;
    }
}

void mm_free(void* p);

extern void setGQR7(u32 v);

extern int textureLoad(int id, int flag);
extern void* loadAnimation(int hdr, s16 id, int b, u8* bufout);

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

    if (channel > 2)
    {
        return;
    }
    if (((ObjModel*)model)->file->morphTargetPtrs == NULL)
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

extern int* lbl_803DCB60;

int modelGetAmapSize(int a, int b, int c)
{
    int size;
    if (b != 0)
    {
        size = c * 2 + 8;
        while (size & 7)
        {
            size++;
        }
    }
    else
    {
        size = c * 4;
        while (size & 7)
        {
            size++;
        }
        fileLoadToBufferOffset(0x31, lbl_803DCB60, (a & ~3) << 2, 0x20);
        size += lbl_803DCB60[(a & 3) + 1] - lbl_803DCB60[a & 3];
    }
    return size;
}

extern void* getCurrentDataFile(int id);
extern int lbl_803DCB68;
extern void* lbl_803DCB4C;
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
    for (i = 0; i < ((ModelFileHeader*)m)->unkF5 + ((ModelFileHeader*)m)->unkF6; i++)
    {
        *(u8**)(((ModelFileHeader*)m)->displayLists + i * 0x1c) = m + *(u32*)(((ModelFileHeader*)m)->displayLists + i *
            0x1c);
    }
    for (i = 0; i < ((ModelFileHeader*)m)->morphTargetCount; i++)
    {
        *(u8**)(((ModelFileHeader*)m)->morphTargetPtrs + i * 4) = m + *(u32*)(((ModelFileHeader*)m)->morphTargetPtrs + i
            * 4);
    }
    if (*(u32*)&((ModelFileHeader*)m)->unk5C)
    {
        ((ModelFileHeader*)m)->unk5C = m + *(u32*)&((ModelFileHeader*)m)->unk5C;
    }
    if (*(u32*)&((ModelFileHeader*)m)->unk60)
    {
        ((ModelFileHeader*)m)->unk60 = m + *(u32*)&((ModelFileHeader*)m)->unk60;
    }
}

extern int getTableFileEntry(int fileId, int index, int* out);
extern void loadModelsBin();
extern int loadAndDecompressDataFile(int id, void* buf, int blockOff, int len, int a, int b, int c);

#pragma dont_inline on
void* ObjModel_LoadModelData(int id)
{
    int fileOffset, dataLen, jointCount, headerSize, amapFlag;
    void* model;
    if (getTableFileEntry(0x2a, id, &fileOffset) == 0)
    {
        return NULL;
    }
    ((void (*)(int, int*, int*, int*, int*, int))loadModelsBin)(fileOffset, &jointCount, &headerSize, &amapFlag, &dataLen, id);
    headerSize = roundUpTo8(headerSize);
    headerSize += 0xb0;
    model = (void*)roundUpTo16((int)mmAlloc(dataLen + modelGetAmapSize(id, amapFlag, jointCount) + 0x1f4, 9, 0));
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
            u8* e = op + k * 8;
            if (*(int*)(e + 0x24) != -1)
            {
                *(int*)(e + 0x24) = ((int*)*(u8**)(m + 0x20))[*(int*)(e + 0x24)];
            }
            else
            {
                *(int*)(e + 0x24) = 0;
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
        if (!(*(u16*)(m + 0xe2) & 0xc))
        {
            *(int*)(op + 0x8) = 0;
        }
        if (!(*(u16*)(m + 0xe2) & 0xe00))
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
        ((ObjModel*)dst)->unk40[i] = *(int*)(((ModelFileHeader*)m)->vertexAnimEntries + i * 0x74 + 0x60);
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
        ((ObjModel*)dst)->unk44[i] =
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
    if (((ObjModel*)model)->bufferFlags & 0x40)
    {
        return;
    }
    ((ObjModel*)model)->bufferFlags |= 0x40;
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
    lbl_803DCB68 = 0;
    while (*p != -1)
    {
        p++;
        lbl_803DCB68++;
    }
    lbl_803DCB68--;
    lbl_803DCB4C = getCurrentDataFile(0x2f);
    if (lbl_803DCB4C == NULL)
    {
        return 0;
    }
    lbl_803DCB58 = 0;
    return 1;
}

extern void DCFlushRange(void* addr, u32 nBytes);

extern void* memcpy(void* dst, const void* src, int n);
extern u32 PPCMfhid2(void);
extern void DCInvalidateRange(void* addr, u32 nBytes);
extern void LCEnable(void);
extern void ObjModel_InitScratchBuffers(void);
extern void setGQR6_2(int a, int b, int c, int d);
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

extern ModelStream* lbl_803DCB54;

void modelFn_800292e0(void)
{
    u8 buf[8];
    lbl_803DCB54->iter = lbl_803DCB54->start;
    while (lbl_803DCB54->iter != lbl_803DCB54->end)
    {
        s16* iter = lbl_803DCB54->iter;
        if (*iter == -1)
        {
            memset(buf, 0, lbl_803DCB54->size);
        }
        else
        {
            memcpy(buf, iter + 1, lbl_803DCB54->size);
        }
        lbl_803DCB54->iter += lbl_803DCB54->stride;
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
        base = *(f32**)(model + 0xc + (*(u16*)(model + 0x18) & 1) * 4);
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

extern f32 lbl_803DE858;
extern f32 lbl_803DE85C;
extern f32 lbl_803DE860;
extern f32 lbl_803DE828;
extern f32 lbl_803DE864;

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
    p = (int**)models;
    off = 0;
    for (i = 0; i < count; i++)
    {
        *(int**)((char*)state->entries + off + 4) = *p;
        *(int*)((char*)state->entries + off + 8) = (*p)[1];
        *(void**)((char*)state->entries + off) = mmAlloc((*(int*)((char*)state->entries + off + 8) + 1) * 0x54, 0x1a, 0);
        p++;
        off += 0xc;
    }
    state->originX = lbl_803DE858;
    state->originY = lbl_803DE85C;
    state->originZ = lbl_803DE860;
    state->phase = lbl_803DE828;
    state->enabled = 1;
    return state;
}

void Model_GetVertexPosition(u8* model, int vertexIndex, f32* out)
{
    s16* vertex;
    f32 scale;

    vertex = (s16*)(((ModelFileHeader*)model)->vertices + vertexIndex * 6);
    if ((((ModelFileHeader*)model)->flags & 0x800) != 0)
    {
        out[0] = (f32)vertex[0];
        out[1] = (f32)vertex[1];
        out[2] = (f32)vertex[2];
    }
    else
    {
        out[0] = (f32)vertex[0] * (scale = lbl_803DE864);
        out[1] = (f32)vertex[1] * scale;
        out[2] = (f32)vertex[2] * scale;
    }
}

int randomGetRange(int lo, int hi);

void memcpyToCache(void* dst, void* src, u32 count);

void* ObjAnim_LoadCachedMove(int animId, int moveIndex, u8* cache, ObjAnimDef* animDef)
{
    void* out = NULL;
    animationLoad((int)&out, animId, moveIndex, (int)cache, (int)animDef);
    return out;
}

extern u8* lbl_80340898[];
extern u8* lbl_80340880[];

#pragma dont_inline on
void ObjModel_InitScratchBuffers(void)
{
    u8* c = getCache();
    lbl_80340898[0] = c;
    lbl_80340898[1] = c + 0x1000;
    lbl_80340898[2] = c + 0x2000;
    lbl_80340898[3] = c + 0x3000;
    c = getCache();
    lbl_80340880[0] = c;
    lbl_80340880[1] = c + 0x1000;
    lbl_80340880[2] = c + 0x1800;
    lbl_80340880[3] = c + 0x2000;
    lbl_80340880[4] = c + 0x3000;
    lbl_80340880[5] = c + 0x3800;
}

extern void ObjModel_SetBlendChannelTargets(u8* model, int ch, int a, int b, f32 w, int c);

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
    if (channel > 2)
    {
        return;
    }
    hdr = *(u8**)model;
    if (((ModelFileHeader*)hdr)->morphTargetPtrs == NULL)
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
    if (a >= ((ModelFileHeader*)hdr)->morphTargetCount)
    {
        return;
    }
    if (b >= ((ModelFileHeader*)hdr)->morphTargetCount)
    {
        return;
    }
    ch = ((ObjModel*)model)->blendChannels + channel;
    if (a == -1 && b == -1)
    {
        if (ch[0].unk0C == -1 && ch[0].unk0D == -1)
        {
            return;
        }
        flags |= 6;
    }
    if (ch[0].unk0C == a && ch[0].unk0D == b)
    {
        return;
    }
    ch[0].unk0C = a;
    ch[0].unk0D = b;
    if (!(flags & 0x10))
    {
        ch[0].weight = lbl_803DE828;
    }
    ch[0].targetWeight = lbl_803DE840;
    ch[0].unk08 = weight;
    ch[0].flags0E = flags | 4;
}

extern void modelApplyBoneTransforms(int a, int b, u16 c, void* d, void* e, int f);
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
    int arrB[3] = {0, 0, 0};
    int arrA[3] = {0, 0, 0};
    void* boneA;
    void* boneB;
    int arg0;
    int arg1;
    int fl;
    f32 w;
    f32 t;
    f32 r;

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
        fl = ch[0].flags0E & 0xc;
        arrA[i] = fl;
        if (ch[0].unk0C != -1 || ch[0].unk0D != -1 || fl != 0)
        {
            arrB[i] = 1;
        }
        if (arrA[i] & 4)
        {
            ch[0].flags0E &= ~4;
            ch[0].flags0E |= 8;
        }
        else if (arrA[i] & 8)
        {
            ch[0].flags0E &= ~8;
        }
    }
    if (arrB[0] == 0 && arrB[1] == 0 && arrB[2] == 0)
    {
        return;
    }
    if (arrB[1])
    {
        arrB[0] = 0;
    }
    if (arrA[2])
    {
        arrA[0] = 1;
        arrA[1] = 1;
    }
    if ((arrB[0] && arrA[0]) || (arrB[1] && arrA[1]))
    {
        if (arrB[2])
        {
            arrA[2] = 1;
        }
    }
    for (i = 0; i < 3; i++)
    {
        if (arrB[i] && ((ModelFileHeader*)hdr)->vertexAnimEntries)
        {
            arrA[i] = 1;
        }
        ch = ((ObjModel*)model)->blendChannels + i;
        if (ch[0].flags0E & 2)
        {
            ch[0].flags0E &= ~2;
            ch[0].weight = lbl_803DE828;
        }
        if (arrB[i] && arrA[i])
        {
            if (ch[0].unk0C > -1)
            {
                boneA = (void*)((int*)(((ModelFileHeader*)hdr)->morphTargetPtrs))[ch[0].unk0C];
            }
            else
            {
                boneA = &defFrame;
            }
            if (ch[0].unk0D > -1)
            {
                boneB = (void*)((int*)(((ModelFileHeader*)hdr)->morphTargetPtrs))[ch[0].unk0D];
            }
            else
            {
                boneB = &defFrame;
            }
            if (i == 2)
            {
                if (arrB[0] == 0 && arrB[1] == 0)
                {
                    arg0 = *(int*)&((ModelFileHeader*)hdr)->vertices;
                }
                else
                {
                    arg0 = *(int*)(model + ((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4 + 0x1c);
                }
            }
            else
            {
                arg0 = *(int*)&((ModelFileHeader*)hdr)->vertices;
            }
            w = ch[0].weight;
            if (w > lbl_803DE818)
            {
                ch[0].weight = lbl_803DE818;
            }
            else if (w < lbl_803DE828)
            {
                if (ch[0].flags0E & 0x20)
                {
                    if (w < lbl_803DE840)
                    {
                        ch[0].weight = lbl_803DE840;
                    }
                }
                else
                {
                    ch[0].weight = lbl_803DE828;
                }
            }
            w = ch[0].weight;
            if (w >= lbl_803DE828)
            {
                t = w;
                r = lbl_803DE868 * t + lbl_803DE86C * (t * t) - t * (t * t);
            }
            else
            {
                t = w * lbl_803DE840;
                r = lbl_803DE868 * t + lbl_803DE86C * (t * t) - t * (t * t);
                r = r * lbl_803DE840;
            }
            arg1 = *(int*)(model + ((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4 + 0x1c);
            modelApplyBoneTransforms(arg0, arg1, ((ModelFileHeader*)hdr)->vertexCount, boneA, boneB,
                                     (int)(lbl_803DE870 * r));
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
        if (ch[0].unk0C == -1 && ch[0].unk0D == -1)
        {
            continue;
        }
        if (ch[0].flags0E & 1)
        {
            continue;
        }
        ch[0].weight = ch[0].unk08 * dt + ch[0].weight;
        if (ch[0].weight >= lbl_803DE874)
        {
            ch[0].weight = lbl_803DE874;
            ch[0].unk08 = lbl_803DE878;
            ch[0].flags0E &= ~4;
        }
        else if (ch[0].weight <= lbl_803DE87C)
        {
            ch[0].weight = lbl_803DE87C;
            ch[0].unk08 = lbl_803DE878;
            ch[0].flags0E &= ~4;
        }
    }
}

extern void* modelLoad_layoutBuffers(u8* p, int b, int isType1, int c);
extern void modelAnimResetState(void* m, void* data);
extern void DCStoreRange(void* p, int size);

#pragma scheduling off
void* ObjModel_LoadAnimData(u8* p, int b, int c)
{
    void* m = modelLoad_layoutBuffers(p, b, p[0] == 1, c);
    modelAnimResetState(m, *(void**)((u8*)m + 0x2c));
    if (*(void**)((u8*)m + 0x30) != NULL)
    {
        modelAnimResetState(m, *(void**)((u8*)m + 0x30));
    }
    ObjModel_RelocateAnimData(p, m);
    *(int*)(p + 8) = 0;
    DCStoreRange(p, *(int*)(p + 0xc));
    return m;
}

extern int modelLoadAnimations(void* model, int id, void* animBase);
extern int modelLoad_calcSizes(void* model, int arg, int* out, int flag);
extern int ModelList_getHeader(void* list, int index, void* out);
extern void modelInitModelList(void* list, s16 index, void* out);
extern s16* lbl_803DCB64;

void* ObjModel_Load(int id, int arg2, int* outSize)
{
    int sizes[7];
    int realId;
    u8* header;
    int off;
    u8* h;
    int i;
    int tex;
    int idc;
    idc = id;
    if (idc < 0)
    {
        realId = -idc;
    }
    else
    {
        fileLoadToBufferOffset(0x2c, lbl_803DCB64, idc * 2, 8);
        realId = lbl_803DCB64[0];
    }
    if (ModelList_getHeader(lbl_803DCB54, realId, &header) == 0)
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
        modelLoadAnimations(header, realId, (u8*)header + *(int*)((u8*)header + 0xc));
        modelInitModelList(lbl_803DCB54, realId, &header);
    }
    else
    {
        (*(u8*)header)++;
    }
    *outSize = modelLoad_calcSizes(header, arg2, sizes, 0);
    return header;
}

extern void ShaderDef_free(int* def);
extern void model_adjustModelList(void* list, int index);
extern void model_findIdxInModelList(void* list, void* header, int* outIndex);
extern void* lbl_803DCB50;
extern void* allocModelStruct(int size, int align);
extern int* lbl_803DCB5C;

#pragma peephole off
void ObjModel_InitResourceCaches(void)
{
    void* m;
    lbl_803DCB54 = allocModelStruct(0x8c, 4);
    lbl_803DCB50 = allocModelStruct(0xc4, 4);
    m = mmAlloc(0x830, 0xa, 0);
    lbl_803DCB64 = m;
    lbl_803DCB60 = (int*)((u8*)m + 0x800);
    lbl_803DCB5C = (int*)((u8*)m + 0x810);
    loadModelAndAnimTabs();
}

#pragma peephole off
void ObjModel_Release(u8* model)
{
    u8* header;
    int i;
    if (((ObjModel*)model)->bufferFlags & 0x40)
    {
        ((ObjModel*)model)->bufferFlags &= ~0x40;
        for (i = 0; i < (*(u8**)model)[0xf8]; i++)
        {
            ShaderDef_free((int*)(((ObjModel*)model)->textureRefs + i * 0xc));
        }
    }
    header = *(u8**)model;
    if (((ObjModel*)model)->renderAttachment != NULL)
    {
        mm_free(((ObjModel*)model)->renderAttachment);
    }
    if (--*(u8*)header == 0)
    {
        model_adjustModelList(lbl_803DCB54, *(u16*)(header + 0x4));
        for (i = 0; i < ((ModelFileHeader*)header)->textureCount; i++)
        {
            textureFree(textureIdxToPtr(((ModelFileHeader*)header)->textureIds[i]));
        }
        if (((ModelFileHeader*)header)->animationModelPtrs != NULL && ((ModelFileHeader*)header)->animationCount != 0)
        {
            for (i = 0; i < ((ModelFileHeader*)header)->animationCount; i++)
            {
                void* tex = *(void**)(((ModelFileHeader*)header)->animationModelPtrs + i * 4);
                if (tex != NULL && (s8)-- * (u8*)tex <= 0)
                {
                    int idx;
                    model_findIdxInModelList(lbl_803DCB50, &tex, &idx);
                    model_adjustModelList(lbl_803DCB50, idx);
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

extern void debugPrintf(char* fmt, ...);

extern void lbl_80006C6C(int* out, u8* a, void* buf, int c, int d, u8* e, int f, int g);
extern u8 lbl_80340740[];

void modelAnimUpdateChannels(u8* hdr, u8* stk, int n)
{
    u8* p2;
    u8* p4;
    int i;
    u8* p5;
    u8* p6;
    u8* q;
    int bv;
    int off;
    int k;
    int n2;
    int t;
    f32 g;

    i = 0;
    p2 = stk;
    p4 = stk;
    for (; i < n; i++)
    {
        if (*(u16*)(hdr + 2) & 0x40)
        {
            p6 = *(u8**)(stk + *(u16*)(p2 + 0x44) * 4 + 0x1c);
            p5 = p6;
            p6 += 0x80;
        }
        else
        {
            p5 = *(u8**)(hdr + 0x68) + *(u16*)(p2 + 0x44) * (((*(u8*)(hdr + 0xf3) - 1) & ~7) + 8);
            p6 = *(u8**)(*(u8**)(hdr + 0x64) + *(u16*)(p2 + 0x44) * 4);
        }
        bv = *(u8*)(*(u8**)(p4 + 0x34) + 2);
        k = 0;
        off = 0;
        q = p5;
        while (k < *(u8*)(hdr + 0xf3))
        {
            *(u8*)(i + *(int*)(hdr + 0x3c) + off + 2) = *q;
            off += 0x1c;
            k++;
            q++;
        }
        n2 = (int)*(f32*)(p4 + 4);
        g = (f32)n2;
        if (g != *(f32*)(p4 + 4))
        {
            *(s16*)(p2 + 0x4c) = (s16)bv;
        }
        else
        {
            *(s16*)(p2 + 0x4c) = 0;
        }
        if (*(s8*)(stk + i + 0x60) != 0 && g == *(f32*)(p4 + 0x14) - lbl_803DE818)
        {
            *(s16*)(p2 + 0x4c) = (s16)(-bv * n2);
        }
        t = *(s16*)(p6 + 2) + bv * n2;
        *(u8**)(p4 + 0x2c) = p6 + t;
        p2 += 2;
        p4 += 4;
    }
}

#pragma ppc_unroll_factor_limit 8
#pragma ppc_unroll_instructions_limit 256
void modelWalkAnimFn_800248b8(u8* a, u8* b, u8* c, int d, f32 e)
{
    u8 stk[0x64];
    int px;
    int fl;
    u8* hdr;
    int v;
    int sv;
    int n;
    int j;
    int idx;
    u8 bvv;
    f32 fb;
    f32 fa;

    hdr = *(u8**)b;
    px = ((int*)(b + (*(u16*)(b + 0x18) & 1) * 4))[3];
    *(f32*)(c + 4) = e * *(f32*)(c + 0x14);
    fl = 0;
    if (*(u16*)(hdr + 2) & 8)
    {
        *(u32*)(stk + 0x1c) = *(u32*)(c + 0x1c);
        *(u32*)(stk + 0x20) = *(u32*)(c + 0x20);
        *(u32*)(stk + 0x24) = *(u32*)(c + 0x24);
        *(u32*)(stk + 0x28) = *(u32*)(c + 0x28);
        for (j = 0; j < 2; j++)
        {
            if (*(u16*)(c + 0x58))
            {
                idx = j;
            }
            else
            {
                idx = 0;
            }
            *(u16*)(stk + j * 2 + 0x44) = *(u16*)(c + idx * 2 + 0x44);
            *(u8*)(stk + j + 0x60) = *(u8*)(c + idx + 0x60);
            *(f32*)(stk + j * 4 + 0x14) = *(f32*)(c + idx * 4 + 0x14);
            *(f32*)(stk + j * 4 + 4) = *(f32*)(c + idx * 4 + 4);
            *(u32*)(stk + j * 4 + 0x34) = *(u32*)(c + idx * 4 + 0x34);
        }
        *(u16*)(stk + 0x58) = *(u16*)(c + 0x58);
        modelAnimUpdateChannels(hdr, stk, 2);
        sv = *(s8*)(c + 0x63);
        if (sv & 1)
        {
            fl |= 0x10;
        }
        if (sv & 4)
        {
            fl |= 0x20;
        }
        lbl_80006C6C(&px, a, stk, *(int*)(hdr + 0x3c), *(u8*)(hdr + 0xf3), lbl_80340740, d, fl | 0x40);
    }
    else
    {
        u8* p4;
        u8* p2;
        int i;
        int m;

        i = 0;
        p4 = c;
        p2 = c;
        for (; i < 2; i++)
        {
            if (i != 0)
            {
                v = *(u16*)(c + 0x5c);
            }
            else
            {
                v = *(u16*)(c + 0x5a);
            }
            if (v != 0)
            {
                if (*(u16*)(c + 0x58))
                {
                    m = 4 << i;
                }
                else
                {
                    m = 0;
                }
                bvv = *(u8*)(c + i + 0x60);
                *(u8*)(stk + 0x60) = bvv;
                fa = *(f32*)(p4 + 0x14);
                *(f32*)(stk + 0x14) = fa;
                fb = *(f32*)(p4 + 4);
                *(f32*)(stk + 4) = fb;
                *(u32*)(stk + 0x34) = *(u32*)(p4 + 0x34);
                *(u8*)(stk + 0x61) = bvv;
                *(f32*)(stk + 0x18) = fa;
                *(f32*)(stk + 8) = fb;
                *(u32*)(stk + 0x38) = *(u32*)(p4 + 0x3c);
                if (*(u16*)(hdr + 2) & 0x40)
                {
                    *(u16*)(stk + 0x44) = 0;
                    *(u16*)(stk + 0x46) = 1;
                    *(u32*)(stk + 0x1c) = *(u32*)(c + *(u16*)(p2 + 0x44) * 4 + 0x1c);
                    *(u32*)(stk + 0x20) = *(u32*)(c + *(u16*)(p2 + 0x48) * 4 + 0x24);
                }
                else
                {
                    *(u16*)(stk + 0x44) = *(u16*)(p2 + 0x44);
                    *(u16*)(stk + 0x46) = *(u16*)(p2 + 0x48);
                }
                *(u16*)(stk + 0x58) = (u16)v;
                modelAnimUpdateChannels(hdr, stk, 2);
                lbl_80006C6C(&px, a, stk, *(int*)(hdr + 0x3c), *(u8*)(hdr + 0xf3), lbl_80340740, d, m);
                if (m != 0)
                {
                    fl |= 1 << i;
                }
            }
            p4 += 4;
            p2 += 2;
        }
        if ((*(u16*)(c + 0x5a) == 0 && *(u16*)(c + 0x5c) == 0) || fl != 0)
        {
            n = 1;
            if (*(u16*)(c + 0x58) != 0)
            {
                n = 2;
            }
            *(u32*)(stk + 0x1c) = *(u32*)(c + 0x1c);
            *(u32*)(stk + 0x20) = *(u32*)(c + 0x20);
            *(u32*)(stk + 0x24) = *(u32*)(c + 0x24);
            *(u32*)(stk + 0x28) = *(u32*)(c + 0x28);
            for (j = 0; j < n; j++)
            {
                *(u16*)(stk + j * 2 + 0x44) = *(u16*)(c + j * 2 + 0x44);
                *(u8*)(stk + j + 0x60) = *(u8*)(c + j + 0x60);
                *(f32*)(stk + j * 4 + 0x14) = *(f32*)(c + j * 4 + 0x14);
                *(f32*)(stk + j * 4 + 4) = *(f32*)(c + j * 4 + 4);
                *(u32*)(stk + j * 4 + 0x34) = *(u32*)(c + j * 4 + 0x34);
            }
            *(u16*)(stk + 0x58) = *(u16*)(c + 0x58);
            modelAnimUpdateChannels(hdr, stk, n);
            sv = *(s8*)(c + 0x63);
            if (sv & 1)
            {
                fl |= 0x10;
            }
            if (sv & 4)
            {
                fl |= 0x20;
            }
            lbl_80006C6C(&px, a, stk, *(int*)(hdr + 0x3c), *(u8*)(hdr + 0xf3), lbl_80340740, d, fl);
        }
    }
}
#pragma ppc_unroll_factor_limit 4
#pragma ppc_unroll_instructions_limit 96

extern void* animLoadFromTable(u8* hdr, int idx, int a, u8* b);

#define LOADCOLOR_BLOCK(OFF)                                                          \
    {                                                                                 \
        u32 v;                                                                        \
        int idx;                                                                      \
        int sz4;                                                                      \
        u8 buf[4];                                                                    \
        int sz;                                                                       \
        u8 *hp;                                                                       \
                                                                                      \
        v = *(u32 *)(p2 + (OFF));                                                     \
        idx = **(s16 **)(hdr + 0x6c);                                                 \
        if ((getLoadedFileFlags(0) & 0x100000) == 0 || *(u16 *)(hdr + 4) == 1 ||      \
            *(u16 *)(hdr + 4) == 3) {                                                 \
            if (v == 0) {                                                             \
                if (ModelList_getHeader(lbl_803DCB50, idx, &hp) == 0) {               \
                    sz4 = *(int *)((u8 *)lbl_803DCB4C + idx * 4);                     \
                    loadAndDecompressDataFile(0x30, 0, sz4, 0, (int)&sz, idx, 1);     \
                    hp = (u8 *)mmAlloc(sz, 10, 0);                                    \
                    loadAndDecompressDataFile(0x30, (void *)hp, sz4, sz, (int)buf, idx, 0); \
                    *hp = 1;                                                          \
                    modelInitModelList(lbl_803DCB50, idx, &hp);                       \
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
    u8* p2 = (u8*)data;
    u8* hdr;
    u8* mdl;
    f32 f;

    hdr = *(u8**)m;
    *(u16*)(p2 + 0x44) = 0;
    *(u16*)(p2 + 0x5e) = 0;
    *(u16*)(p2 + 0x58) = 0;
    *(u16*)(p2 + 0x5a) = 0;
    *(u16*)(p2 + 0x5c) = 0;
    f = lbl_803DE828;
    *(f32*)(p2 + 0xc) = f;
    *(f32*)(p2 + 4) = f;
    *(f32*)(p2 + 0x14) = f;
    *(u8*)(p2 + 0x60) = 0;
    if (*(u16*)(hdr + 0xec) != 0)
    {
        if (*(u16*)(hdr + 2) & 0x40)
        {
            LOADCOLOR_BLOCK(0x1c)
            LOADCOLOR_BLOCK(0x20)
            LOADCOLOR_BLOCK(0x24)
            LOADCOLOR_BLOCK(0x28)
            *(u16*)(p2 + 0x44) = 0;
            mdl = *(u8**)(p2 + *(u16*)(p2 + 0x44) * 4 + 0x1c) + 0x80;
        }
        else
        {
            mdl = *(u8**)(*(u8**)(hdr + 0x64) + *(u16*)(p2 + 0x44) * 4);
        }
        *(u8**)(p2 + 0x34) = mdl + 6;
        *(s8*)(p2 + 0x60) = (s8)(*(u8*)(mdl + 1) & 0xf0);
        *(f32*)(p2 + 0x14) = (f32) * (u8*)(*(u8**)(p2 + 0x34) + 1);
        if (*(s8*)(p2 + 0x60) == 0)
        {
            *(f32*)(p2 + 0x14) -= lbl_803DE818;
        }
        *(u8*)(p2 + 0x61) = *(u8*)(p2 + 0x60);
        *(u32*)(p2 + 0x38) = *(u32*)(p2 + 0x34);
        *(u16*)(p2 + 0x46) = *(u16*)(p2 + 0x44);
        *(f32*)(p2 + 8) = *(f32*)(p2 + 4);
        *(f32*)(p2 + 0x18) = *(f32*)(p2 + 0x14);
        *(f32*)(p2 + 0x10) = *(f32*)(p2 + 0xc);
        *(u32*)(p2 + 0x3c) = *(u32*)(p2 + 0x34);
        *(u16*)(p2 + 0x48) = *(u16*)(p2 + 0x44);
        *(u32*)(p2 + 0x40) = *(u32*)(p2 + 0x34);
        *(u16*)(p2 + 0x4a) = *(u16*)(p2 + 0x44);
    }
}

#define BLENDTBL_ENTRY(K, OFF)                              \
    if (p[K] != 0) {                                        \
        ((s16 *)lbl_80340740)[w++] = (s16)(v1 + (OFF));     \
        ((s16 *)lbl_80340740)[w++] = (s16)(v2 + (OFF));     \
        ((s16 *)lbl_80340740)[w++] = p[K];                  \
        ((s16 *)lbl_80340740)[w++] = p[K];                  \
    }

void ObjModel_BuildAnimBlendTable(u8* obj, u8* p2, u8* hdr)
{
    ObjAnimComponent* objAnim;
    int poff;
    ObjModelInstance* modelDef;
    int boff;
    int i;
    u32 u;
    int v1;
    int w;
    s16* p;
    u8* b1;
    int v2;
    u8* b2;

    if (*(u16*)(hdr + 2) & 0x40)
    {
        b1 = *(u8**)(p2 + *(u16*)(p2 + 0x44) * 4 + 0x1c);
        b2 = *(u8**)(p2 + *(u16*)(p2 + 0x46) * 4 + 0x1c);
    }
    else
    {
        b1 = *(u8**)(hdr + 0x68) + *(u16*)(p2 + 0x44) * (((*(u8*)(hdr + 0xf3) - 1) & ~7) + 8);
        b2 = *(u8**)(hdr + 0x68) + *(u16*)(p2 + 0x46) * (((*(u8*)(hdr + 0xf3) - 1) & ~7) + 8);
    }
    objAnim = (ObjAnimComponent*)obj;
    modelDef = objAnim->modelInstance;
    boff = 0;
    w = 0;
    i = 0;
    poff = 0;
    for (; i < (int)modelDef->jointCount; i++)
    {
        u = *(u8*)(modelDef->jointData + boff + objAnim->bankIndex + 1);
        if (u != 0xff)
        {
            p = (s16*)(objAnim->jointPoseData + poff);
            v1 = *(s8*)(b1 + u) << 6;
            v2 = *(s8*)(b2 + u) << 6;
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
        boff += modelDef->modelCount + 1;
        poff += 0x12;
    }
    ((s16*)lbl_80340740)[w++] = 0x1000;
    ((s16*)lbl_80340740)[w] = 0x1000;
}

void* modelLoad_layoutBuffers(u8* p, int b, int isType1, int c)
{
    u8* out;
    int szs[7];
    int pos;
    int end;
    int n;
    int k;
    int o2;
    u8* q;
    f32 f;

    out = (u8*)c;
    if (p == 0)
    {
        return 0;
    }
    modelLoad_calcSizes(p, b, szs, 0);
    pos = roundUpTo32((int)out + 0x64);
    *(int*)&((ObjModel*)out)->jointMatrices[0] = pos;
    pos += szs[6] >> 1;
    *(int*)&((ObjModel*)out)->jointMatrices[1] = pos;
    pos += szs[6] >> 1;
    *(int*)&((ObjModel*)out)->curMtxBuf = *(int*)&((ObjModel*)out)->jointMatrices[0];
    if (((ModelFileHeader*)p)->morphTargetCount != 0 || *(int*)&((ModelFileHeader*)p)->vertexAnimEntries != 0 || (((
        ModelFileHeader*)p)->flags & 0x10))
    {
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out)->vtxBuf0 = pos;
        pos = roundUpTo32(pos + ((ModelFileHeader*)p)->vertexCount * 6);
        *(int*)&((ObjModel*)out)->vtxBuf1 = pos;
        end = pos + ((ModelFileHeader*)p)->vertexCount * 6;
        memcpy(((ObjModel*)out)->vtxBuf0, ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out)->vtxBuf0, ((ModelFileHeader*)p)->vertexCount * 6);
        memcpy(((ObjModel*)out)->vtxBuf1, ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out)->vtxBuf1, ((ModelFileHeader*)p)->vertexCount * 6);
        pos = roundUpTo32(end);
    }
    else
    {
        end = *(int*)&((ModelFileHeader*)p)->vertices;
        *(int*)&((ObjModel*)out)->vtxBuf1 = end;
        *(int*)&((ObjModel*)out)->vtxBuf0 = end;
    }
    if (*(int*)&((ModelFileHeader*)p)->blendAnimEntries != 0)
    {
        if (((ModelFileHeader*)p)->flags24 & 8)
        {
            n = 9;
        }
        else
        {
            n = 3;
        }
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out)->normalBuf = pos;
        end = pos + ((ModelFileHeader*)p)->normalCount * n;
        memcpy(((ObjModel*)out)->normalBuf, ((ModelFileHeader*)p)->normals, ((ModelFileHeader*)p)->normalCount * n);
        DCFlushRange(((ObjModel*)out)->normalBuf, n * ((ModelFileHeader*)p)->normalCount);
        pos = roundUpTo32(end);
    }
    else
    {
        *(int*)&((ObjModel*)out)->normalBuf = *(int*)&((ModelFileHeader*)p)->normals;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out)->animStateA = pos;
    pos += 0x68;
    if (b & 0x80)
    {
        *(int*)&((ObjModel*)out)->animStateB = pos;
        pos += 0x68;
    }
    if (((ModelFileHeader*)p)->flags & 0x40)
    {
        pos = roundUpTo8(pos);
        q = ((ObjModel*)out)->animStateA;
        *(int*)(q + 0x1c) = pos;
        pos += szs[5];
        *(int*)(q + 0x20) = pos;
        pos += szs[5];
        *(int*)(q + 0x24) = pos;
        pos += szs[5];
        *(int*)(q + 0x28) = pos;
        pos += szs[5];
        q = ((ObjModel*)out)->animStateB;
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
        *(int*)&((ObjModel*)out)->blendChannels = pos;
        pos += 0x30;
        q = (u8*)((ObjModel*)out)->blendChannels;
        *(s8*)(q + 0xc) = -1;
        *(s8*)(q + 0xd) = -1;
        f = lbl_803DE828;
        *(f32*)(q + 0) = f;
        *(f32*)(q + 4) = f;
        *(f32*)(q + 8) = f;
        q = (u8*)((ObjModel*)out)->blendChannels;
        *(s8*)(q + 0x1c) = -1;
        *(s8*)(q + 0x1d) = -1;
        *(f32*)(q + 0x10) = f;
        *(f32*)(q + 0x14) = f;
        *(f32*)(q + 0x18) = f;
        q = (u8*)((ObjModel*)out)->blendChannels;
        *(s8*)(q + 0x2c) = -1;
        *(s8*)(q + 0x2d) = -1;
        *(f32*)(q + 0x20) = f;
        *(f32*)(q + 0x24) = f;
        *(f32*)(q + 0x28) = f;
    }
    if (szs[1] > 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out)->unk48 = pos;
        pos += ((ModelFileHeader*)p)->unkF7 * 0x10;
        *(int*)&((ObjModel*)out)->unk4C = pos;
        pos += ((ModelFileHeader*)p)->unkF7 * 0x10;
        *(int*)&((ObjModel*)out)->unk50 = *(int*)&((ObjModel*)out)->unk48;
    }
    if (*(int*)&((ModelFileHeader*)p)->jointData != 0 && ((ModelFileHeader*)p)->jointCount != 0 && *(int*)&((
        ModelFileHeader*)p)->unk18 != 0 && *(int*)&((ModelFileHeader*)p)->unk1C != 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out)->unk14 = pos;
        pos += 0x1c;
        *(int*)(((ObjModel*)out)->unk14 + 0) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 0xc;
        *(int*)(((ObjModel*)out)->unk14 + 4) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out)->unk14 + 8) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out)->unk14 + 0xc) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out)->unk14 + 0x10) = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)(((ObjModel*)out)->unk14 + 0x18) = pos;
        pos += ((ModelFileHeader*)p)->jointCount;
    }
    else
    {
        *(int*)&((ObjModel*)out)->unk14 = 0;
    }
    if (*(int*)&((ModelFileHeader*)p)->vertexAnimEntries != 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out)->unk40 = pos;
        pos += ((ModelFileHeader*)p)->vertexAnimCount * 4;
    }
    if (*(int*)&((ModelFileHeader*)p)->blendAnimEntries != 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out)->unk44 = pos;
        pos += ((ModelFileHeader*)p)->blendAnimCount * 4;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out)->textureRefs = pos;
    pos += ((ModelFileHeader*)p)->renderOpCount * 0xc;
    k = 0;
    o2 = 0;
    for (; k < (int)((ModelFileHeader*)p)->renderOpCount; k++)
    {
        *(u8*)(((ObjModel*)out)->textureRefs + o2 + 8) = 0;
        o2 += 0xc;
    }
    if (b & 0x8000)
    {
        pos = alignUp2(pos);
        *(int*)&((ObjModel*)out)->unk54 = pos;
        *(u8*)(((ObjModel*)out)->unk54 + 0x18) = 0;
    }
    *(int*)&((ObjModel*)out)->renderAttachment = 0;
    ((ObjModel*)out)->file = (ModelFileHeader*)p;
    ((ObjModel*)out)->unk60 = 0;
    return out;
}

extern char sModelAnimationBufferOverflowWarning[];

#pragma opt_loop_invariants off
int modelLoadAnimations(void* model, int id, void* animBase)
{
    u8* hdr = (u8*)model;
    u8* buf = (u8*)animBase;
    int* tbl;
    int base;
    int aln;
    int sz;
    int o;
    int slot;
    int i;
    int cnt;
    int toff;
    int woff;
    int anim;
    int sz4;
    int idxout;
    u8* q2;
    u8 buf2[4];
    int sz2;
    u8* hp2;
    u8* pc;
    int d;

    aln = 0;
    tbl = lbl_803DCB60;
    fileLoadToBufferOffset(0x2d, tbl, id << 1, 0x10);
    base = *(s16*)tbl;
    if (((ModelFileHeader*)hdr)->animationCount == 0)
    {
        return 0;
    }
    sz = (((ModelFileHeader*)hdr)->animationCount << 1) + 8;
    if (sz > 0x800)
    {
        debugPrintf(sModelAnimationBufferOverflowWarning, sz);
    }
    fileLoadToBufferOffset(0x31, lbl_803DCB60, (id & ~3) << 2, 0x20);
    ((ModelFileHeader*)hdr)->animationDataFileOffset = *(int*)((u8*)lbl_803DCB60 + (id & 3) * 4);
    sz4 = *(int*)((u8*)lbl_803DCB60 + (id & 3) * 4);
    id = *(int*)((u8*)lbl_803DCB60 + (id & 3) * 4 + 4) - sz4;
    if (((ModelFileHeader*)hdr)->flags & 0x40)
    {
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = buf;
        while (sz & 7)
        {
            sz++;
        }
        aln = sz;
        buf += sz;
        fileLoadToBufferOffset(0x2e, ((ModelFileHeader*)hdr)->animationHeaderBuffer, base, sz);
    }
    else
    {
        fileLoadToBufferOffset(0x2e, lbl_803DCB64, base, sz);
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = (u8*)lbl_803DCB64;
    }
    o = 0;
    slot = 1;
    *(s16*)(hdr + (slot - 1) * 2 + 0x70) = o;
    i = 0;
    for (; i < (int)((ModelFileHeader*)hdr)->animationCount; i++)
    {
        if (*(s16*)(((ModelFileHeader*)hdr)->animationHeaderBuffer + o) == -1)
        {
            *(s16*)(hdr + slot++ * 2 + 0x70) = (s16)(i + 1);
        }
        o += 2;
    }
    if ((((ModelFileHeader*)hdr)->flags & 0x40) == 0)
    {
        *(int*)&((ModelFileHeader*)hdr)->animationHeaderBuffer = 0;
        ((ModelFileHeader*)hdr)->animationModelPtrs = buf;
        buf += ((ModelFileHeader*)hdr)->animationCount * 4;
        aln += ((ModelFileHeader*)hdr)->animationCount * 4;
        while (aln & 7)
        {
            buf++;
            aln++;
        }
        ((ModelFileHeader*)hdr)->animationDataSection = buf;
        fileLoadToBufferOffset(0x32, ((ModelFileHeader*)hdr)->animationDataSection,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset, id);
        cnt = 0;
        toff = 0;
        woff = toff;
        do
        {
            anim = *(s16*)((u8*)lbl_803DCB64 + toff);
            if (anim != -1)
            {
                if ((getLoadedFileFlags(0) & 0x100000) && *(u16*)(hdr + 4) != 1 &&
                    *(u16*)(hdr + 4) != 3)
                {
                    pc = 0;
                }
                else
                {
                    if (ModelList_getHeader(lbl_803DCB50, anim, &hp2) == 0)
                    {
                        sz4 = *(int*)((u8*)lbl_803DCB4C + anim * 4);
                        loadAndDecompressDataFile(0x30, 0, sz4, 0, (int)&sz2, anim, 1);
                        hp2 = (u8*)mmAlloc(sz2, 10, 0);
                        loadAndDecompressDataFile(0x30, (void*)hp2, sz4, sz2, (int)buf2, anim, 0);
                        *hp2 = 1;
                        modelInitModelList(lbl_803DCB50, anim, &hp2);
                    }
                    else
                    {
                        *hp2 += 1;
                    }
                    pc = hp2;
                }
                *(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + woff) = pc;
                if (*(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + woff) == 0)
                {
                    int k;
                    int o3;

                    k = 0;
                    o3 = 0;
                    for (; k < cnt; k++)
                    {
                        q2 = *(u8**)(((ModelFileHeader*)hdr)->animationModelPtrs + o3);
                        if (q2 != 0)
                        {
                            d = *q2 - 1;
                            *q2 = d;
                            if ((s8)d <= 0)
                            {
                                model_findIdxInModelList(lbl_803DCB50, &q2, &idxout);
                                model_adjustModelList(lbl_803DCB50, idxout);
                                mm_free(q2);
                            }
                        }
                        o3 += 4;
                    }
                    *(int*)&((ModelFileHeader*)hdr)->animationModelPtrs = 0;
                    return 1;
                }
            }
            else
            {
                *(int*)(((ModelFileHeader*)hdr)->animationModelPtrs + woff) = 0;
            }
            toff += 2;
            woff += 4;
            cnt++;
        }
        while (cnt < (int)((ModelFileHeader*)hdr)->animationCount);
    }
    else
    {
        *(int*)&((ModelFileHeader*)hdr)->animationModelPtrs = 0;
    }
    return 0;
}

void* mmAlloc(int size, int type, int flag);

#pragma opt_loop_invariants on
int modelLoad_calcSizes(void* model, int flags, int* sizes, int a4)
{
    u8* hdr = (u8*)model;
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
        ModelFileHeader*)hdr)->flags & 0x10) != 0)
    {
        sizes[0] = (u32)((ModelFileHeader*)hdr)->vertexCount * 0xc + 0x60;
    }
    else
    {
        sizes[0] = 0;
    }
    if (((ModelFileHeader*)hdr)->blendAnimEntries != 0)
    {
        int cur = sizes[0];
        int n = ((ModelFileHeader*)hdr)->normalCount;
        int k;
        if (((ModelFileHeader*)hdr)->flags24 & 8)
        {
            k = 9;
        }
        else
        {
            k = 3;
        }
        {
            int prod = n * k;
            cur = prod + cur;
        }
        sizes[0] = cur + 0x40;
    }
    {
        int half = ((ModelFileHeader*)hdr)->unkF7 << 4;
        sizes[1] = half << 1;
    }
    sizes[3] = 0;
    if ((((ModelFileHeader*)hdr)->flags & 0x40) != 0)
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
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || a4 != 0)
    {
        sizes[4] = sizes[4] + 0x30;
        total = sizes[3] + (sizes[4] + 100);
        total = (sizes[1] + 8) + total;
        total = sizes[6] + total;
    }
    else
    {
        total = sizes[4] + 100;
        total = ((sizes[6] + sizes[1]) + 8) + total;
        total = sizes[3] + total;
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
void fn_80026928(int* obj, int b, int* p3)
{
    int off4;
    int off54;
    int i;

    i = 0;
    off4 = 0;
    off54 = off4;
    for (; i < p3[2]; i++)
    {
        int e = *(int*)(*(int*)p3[1] + off4);
        int dst = *p3 + off54;
        int idx;
        u8* hdr;
        u32 n;
        int lim;

        *(f32*)(dst + 0x18) = *(f32*)(*(int*)(b + 0x3c) + e * 0x1c + 4);
        *(f32*)(dst + 0x1c) = *(f32*)(*(int*)(b + 0x3c) + e * 0x1c + 8);
        *(f32*)(dst + 0x20) = *(f32*)(*(int*)(b + 0x3c) + e * 0x1c + 0xc);

        idx = e;
        hdr = *(u8**)obj;
        n = *(u8*)(hdr + 0xf3);
        if (n != 0)
        {
            lim = n + *(u8*)(hdr + 0xf4);
        }
        else
        {
            lim = 1;
        }
        if (e >= lim)
        {
            idx = 0;
        }
        *(f32*)(dst + 0) = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0xc);

        idx = e;
        hdr = *(u8**)obj;
        n = *(u8*)(hdr + 0xf3);
        if (n != 0)
        {
            lim = n + *(u8*)(hdr + 0xf4);
        }
        else
        {
            lim = 1;
        }
        if (e >= lim)
        {
            idx = 0;
        }
        *(f32*)(dst + 4) = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x1c);

        idx = e;
        hdr = *(u8**)obj;
        n = *(u8*)(hdr + 0xf3);
        if (n != 0)
        {
            lim = n + *(u8*)(hdr + 0xf4);
        }
        else
        {
            lim = 1;
        }
        if (e >= lim)
        {
            idx = 0;
        }
        *(f32*)(dst + 8) = *(f32*)(*(int*)((int)obj + ((*(u16*)((u8*)obj + 0x18) & 1) << 2) + 0xc) + idx * 0x40 + 0x2c);

        off4 += 4;
        off54 += 0x54;
    }
    {
        int out = *p3 + i * 0x54;
        f32 z = lbl_803DE828;
        int e2;
        u8* hdr2;
        u32 n2;
        int lim2;

        *(f32*)(out + 0x18) = z;
        *(f32*)(out + 0x1c) = z;
        *(f32*)(out + 0x20) = lbl_803DE850;
        {
            int* arr = (int*)*(int*)p3[1];
            e2 = arr[p3[2] - 1];
        }
        hdr2 = *(u8**)obj;
        n2 = *(u8*)(hdr2 + 0xf3);
        if (n2 != 0)
        {
            lim2 = n2 + *(u8*)(hdr2 + 0xf4);
        }
        else
        {
            lim2 = 1;
        }
        if (e2 >= lim2)
        {
            e2 = 0;
        }
        PSMTXMultVec((f32*)(obj[(*(u16*)((u8*)obj + 0x18) & 1) + 3] + e2 * 0x40), (f32*)(out + 0x18), (f32*)out);
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
        stride = ((*(u8*)(hdr + 0xf3) - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, *(int*)(hdr + 0x80) + idx * stride, stride);
    }
    else
    {
        flags = *(u32*)((int)lbl_803DCB4C + id * 4);
        loadAndDecompressDataFile(0x30, 0, flags, 0, (int)&size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(0x30, buf, flags, size, (int)&out2, id, 0);
        stride = ((*(u8*)(hdr + 0xf3) - 1) & ~7) + 8;
        fileLoadToBufferOffset(0x32, out, *(int*)(hdr + 0x80) + idx * stride, stride);
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

    if ((getLoadedFileFlags(0) & 0x100000) != 0 && *(u16*)(hdr + 4) != 1 && *(u16*)(hdr + 4) != 3)
    {
        return 0;
    }
    if (bufout == 0)
    {
        if (ModelList_getHeader(lbl_803DCB50, (i = id), &ptr) == 0)
        {
            v = ((u32*)lbl_803DCB4C)[i];
            loadAndDecompressDataFile(0x30, 0, v, 0, (int)&size, i, 1);
            ptr = mmAlloc(size, 10, 0);
            loadAndDecompressDataFile(0x30, ptr, v, size, (int)&tmp, i, 0);
            *ptr = 1;
            modelInitModelList(lbl_803DCB50, id, &ptr);
        }
        else
        {
            *ptr += 1;
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

extern f32 lbl_802CABB8[];

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
    int r;

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
    base = ((AnimBufSel*)(model + ((*(u16*)(model + 0x18) & 1) << 2)))->buf + idx * 0x40;
    vec[0] = *(f32*)(base + 0x20);
    vec[1] = *(f32*)(base + 0x24);
    vec[2] = *(f32*)(base + 0x28);
    dot = PSVECDotProduct(vec, lbl_802CABB8);
    if (dot < lbl_803DE828)
    {
        dot = lbl_803DE828;
    }
    scaled = lbl_803DCB48 * (lbl_803DE844 - dot);
    r = randomGetRange((int)(lbl_803DE84C * scaled), (int)(lbl_803DE850 * scaled));
    amp = (f32)r * lbl_803DE848;
    i = 0;
    off = 0;
    while (i < *(int*)(anim + 8) + 1)
    {
        u8* p = *(u8**)anim + off;
        *(f32*)(p + 0xc) = *(f32*)(p + 0xc) * *(f32*)(m + 0xc) + lbl_802CABB8[0] * amp;
        *(f32*)(p + 0x10) = lbl_802CABB8[1] * amp + (*(f32*)(p + 0x10) * *(f32*)(m + 0xc) + *(f32*)(m + 0x10));
        *(f32*)(p + 0x14) = *(f32*)(p + 0x14) * *(f32*)(m + 0xc) + lbl_802CABB8[2] * amp;
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
    int srcOff;
    int dstOff;
    u8* prev;
    int i;
    void* result;
    u8* state;
    u8* arr;
    u8* src;
    f32 vec[3];
    f32 zero;
    u32 sel;
    int idx;
    int count;
    u32 cnt;
    int lim;
    ObjHitBufs* st;

    result = NULL;
    state = *(u8**)(e + 0x54);
    if (state != NULL)
    {
        if (*(u8*)(*(u8**)(e + 0x50) + 0x66) != 0)
        {
            count = (int)*(s16*)(state + 4) >> 2;
            if (count > 0)
            {
                arr = *(u8**)(state + 8);
                idx = (int)(((GameObject*)e)->anim.currentMoveProgress * (f32)count);
                if (idx >= count)
                {
                    idx = count - 1;
                }
                result = *(void**)(arr + idx * 4);
            }
        }
        else
        {
            result = *(void**)(state + 0x48);
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
        *(void**)(*(u8**)(c + 0x54) + 0x48) = result;
    }

    st = (ObjHitBufs*)a;
    *(u16*)(a + 0x18) ^= 4;
    sel = (*(u16*)(a + 0x18) >> 2) & 1;
    st->cur = st->bufs[sel];
    mtx = d;
    i = 0;
    srcOff = 0;
    dstOff = srcOff;
    prev = st->bufs[sel ^ 1];
    for (; i < *(u8*)(b + 0xf7); i++)
    {
        if (d == NULL)
        {
            idx = *(s16*)(*(u8**)(b + 0x58) + srcOff);
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
        src = *(u8**)(b + 0x58);
        vec[0] = *(f32*)(src + (srcOff + 8));
        vec[1] = *(f32*)(src + (srcOff + 0xc));
        vec[2] = *(f32*)(src + (srcOff + 0x10));
        *(f32*)(st->cur + dstOff) = *(f32*)(src + (srcOff + 4)) * ((GameObject*)e)->anim.rootMotionScale;
        PSMTXMultVec((f32*)mtx, vec, (f32*)(st->cur + (dstOff + 4)));
        *(f32*)(prev + 4) = (lbl_803DCED0 + *(f32*)(prev + 4)) - playerMapOffsetX;
        *(f32*)(prev + 0xc) = (lbl_803DCECC + *(f32*)(prev + 0xc)) - playerMapOffsetZ;
        srcOff += 0x18;
        dstOff += 0x10;
        prev += 0x10;
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
    u8* hdr;
    int boneOff;
    u8* dst;
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
    extern u16 lbl_803DB440;
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
    if (c > lbl_803DB440)
    {
        chunk = lbl_803DB440;
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
            if (c > lbl_803DB440)
            {
                nextChunk = lbl_803DB440;
            }
            else
            {
                nextChunk = c;
            }
            nextWords = (u32)(nextChunk * 6 + 0x1f & 0xffe0) >> 5;
            copyToCache(cache + (buf ^ 1) * 0x2000, (u8*)a + (pos + lbl_803DB440) * 6, nextWords);
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
extern u8* fn_80006B1C(MRIState* src, MRIState* dst, int count, int gap);

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
                srcBits = ((u8 *(*)(void*, void*, int, int, int))
                    fn_80006B1C)(&srcState, &dstState, dst[7], vertBits, t);
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

extern s16 lbl_803DC7A4;
extern s16 lbl_803DC7A6;
extern s16 lbl_803DC7A8;
extern void ObjModel_SampleJointTransform(u8* model, int a, int b, f32 t, f32 s, f32* outPos, s16* outRot);
extern void modelAnimFn_800246a0(u8* dst, u8* model, u8* ch, f32 t, int max, int b, int c, int d, int e, s16 f);

void ObjModel_UpdateAnimMatrices(u8* model, u8* blend, u8* obj, u8* dst)
{
    u8* ch;
    u8* ch2;
    f32 pos[3];
    s16 rot[3];

    ObjModel_BuildAnimBlendTable(obj, *(u8**)(model + 0x2c), blend);
    *(u16*)(model + 0x18) ^= 1;
    ch = *(u8**)(model + 0x2c);
    if ((s8)ch[0x63] & 4)
    {
        ObjModel_SampleJointTransform(model, 0, 0, ((GameObject*)obj)->anim.currentMoveProgress,
                                      ((GameObject*)obj)->anim.rootMotionScale, pos, rot);
        lbl_803DC7A4 = rot[0];
        lbl_803DC7A6 = rot[1];
        lbl_803DC7A8 = rot[2];
    }
    if (*(u16*)(*(u8**)model + 2) & 8)
    {
        ((void (*)(u8*, u8*, u8*, f32, int))modelWalkAnimFn_800248b8)(dst, model, *(u8**)(model + 0x2c),
                                                                      ((GameObject*)obj)->anim.currentMoveProgress,
                                                                      0x7f);
    }
    else if ((s8)(*(u8**)(model + 0x2c))[0x63] & 8)
    {
        ch2 = *(u8**)(model + 0x30);
        modelAnimFn_800246a0(dst, model, ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 0, 2, 0x14,
                             (s16) * (u16*)(ch + 0x5a));
        modelAnimFn_800246a0(dst, model, ch2, ((GameObject*)obj)->anim.activeMoveProgress, 0x7f, 0, 0, 2, 0x18,
                             (s16) * (u16*)(ch2 + 0x5a));
        modelAnimFn_800246a0(dst, model, ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 0, 0, 7,
                             (s16) * (u16*)(ch2 + 0x58));
        modelAnimFn_800246a0(dst, model, ch, ((GameObject*)obj)->anim.currentMoveProgress, 0x7f, 0, 1, 1, 1,
                             (s16) * (u16*)(ch + 0x58));
    }
    else
    {
        ((void (*)(u8*, u8*, u8*, f32, int))modelWalkAnimFn_800248b8)(dst, model, *(u8**)(model + 0x2c),
                                                                      ((GameObject*)obj)->anim.currentMoveProgress,
                                                                      0x7f);
        ch2 = *(u8**)(model + 0x30);
        if (ch2 != NULL && ((GameObject*)obj)->anim.activeMove > -1)
        {
            ObjModel_BuildAnimBlendTable(obj, *(u8**)(model + 0x30), blend);
            ((void (*)(u8*, u8*, u8*, f32, int))modelWalkAnimFn_800248b8)(
                dst, model, *(u8**)(model + 0x30), ((GameObject*)obj)->anim.activeMoveProgress, -1);
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

void modelAnimFn_800246a0(u8* a, u8* b, u8* c, f32 t, int d, int e, int f, int g, int h, s16 w)
{
    u8 stk[0x64];
    int px;
    u8* hdr;
    u32 i1;
    u32 i2;
    int fl;
    u8* p;

    hdr = *(u8**)b;
    {
        u32 sel = *(u16*)(b + 0x18) & 1;
        px = ((MdlSelBufs*)b)->bufs[sel];
    }
    if ((u8)h & 0x10)
    {
        *(f32*)(c + 4) = t * *(f32*)(c + 0x14);
    }
    i1 = (u8)e;
    p = c + i1;
    *(u8*)(stk + 0x60) = *(u8*)(p + 0x60);
    p = c + i1 * 4;
    *(f32*)(stk + 0x14) = *(f32*)(p + 0x14);
    *(f32*)(stk + 4) = *(f32*)(p + 4);
    *(int*)(stk + 0x34) = *(int*)(p + 0x34);
    i2 = (u8)f;
    p = c + i2;
    *(u8*)(stk + 0x61) = *(u8*)(p + 0x60);
    p = c + i2 * 4;
    *(f32*)(stk + 0x18) = *(f32*)(p + 0x14);
    *(f32*)(stk + 8) = *(f32*)(p + 4);
    i2 = (u8)g;
    *(int*)(stk + 0x38) = ((ChF34*)c)->vals[i2];
    if (*(u16*)(hdr + 2) & 0x40)
    {
        *(u16*)(stk + 0x44) = 0;
        *(u16*)(stk + 0x46) = 1;
        p = c + i1 * 2;
        p = c + *(u16*)(p + 0x44) * 4;
        *(int*)(stk + 0x1c) = *(int*)(p + 0x1c);
        if (i2 < 2)
        {
            p = c + i2 * 2;
            p = c + *(u16*)(p + 0x44) * 4;
            *(int*)(stk + 0x20) = *(int*)(p + 0x1c);
        }
        else
        {
            p = c + i2 * 2;
            p = c + *(u16*)(p + 0x44) * 4;
            *(int*)(stk + 0x20) = *(int*)(p + 0x24);
        }
    }
    else
    {
        p = c + i1 * 2;
        *(u16*)(stk + 0x44) = *(u16*)(p + 0x44);
        p = c + i2 * 2;
        *(u16*)(stk + 0x46) = *(u16*)(p + 0x44);
    }
    if (w == 0)
    {
        w = 1;
    }
    *(u16*)(stk + 0x58) = w;
    modelAnimUpdateChannels(hdr, stk, 2);
    h = h & 0xF;
    if ((h & 0xC) == 0)
    {
        int sv = *(s8*)(c + 0x63);
        if (sv & 1)
        {
            h = (u8)(h | 0x10);
        }
        if (sv & 4)
        {
            h = (u8)(h | 0x20);
        }
    }
    lbl_80006C6C(&px, a, stk, *(int*)(hdr + 0x3c), *(u8*)(hdr + 0xf3), lbl_80340740, d, (u8)h);
}

extern void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, int d1, int d2, int count);

void ObjModel_BlendPrimaryVertexStream(u8* mtxs, u8* hdr, u8* data, int* offs, u8* out)
{
    u16 sizes[2];

    setGQR7Packed(hdr[6], 7, hdr[6], 7);
    ObjModel_InitScratchBuffers();
    if (*(u16*)(hdr + 2) != 0)
    {
        u8* q;
        int words;
        int w2;
        u32 i;
        u32 nb;
        u8* dst;
        u8** cp;

        q = *(u8**)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(lbl_80340898[0], data + *(int*)(q + 0x60), words);
        sizes[0] = words;
        w2 = (u32)(((q = *(u8**)(hdr + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)lbl_80340898 + 4), *(u8**)(q + 0x64), w2);
        cp = lbl_80340898;
        for (i = 0; i < (u32)(*(u16*)(hdr + 2) - 1); i++)
        {
            q = *(u8**)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            copyToCache(cp[(u8)(nb * 2)], data + *(int*)(q + 0xd4), words);
            sizes[nb] = words;
            {
                u8* q2;
                int w3 = (u32)(((q2 = *(u8**)(hdr + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(cp[(u8)((u8)(nb * 2) + 1)], *(u8**)(q2 + 0xd8), w3);
            }
            cacheQueueWait(2);
            dst = out + offs[i];
            ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                      cp[(u8)((i & 1) * 2) + 1],
                                                      q[0x72] + (int)cp[(u8)((i & 1) * 2)],
                                                      q[0x72] + (int)cp[(u8)((i & 1) * 2)],
                                                      *(u16*)(q + 0x70));
            memcpyToCache(dst, cp[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        q = *(u8**)(hdr + 0xc) + i * 0x74;
        cacheQueueWait(0);
        dst = out + offs[i];
        ObjModel_TransformVerticesWithTranslation(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                  lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                  q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                  q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                  *(u16*)(q + 0x70));
        memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        cacheQueueWait(0);
    }
}

extern void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, int d1, int d2, int count);
extern void ObjModel_TransformQuadVerticesLinear(u8* m1, u8* m2, u8* src, int d1, int d2, int count);

void ObjModel_BlendSecondaryVertexStream(u8* mtxs, u8* hdr, u8* data, u8** outs, int quad)
{
    u16 sizes[2];

    setGQR7Packed(hdr[6], 6, hdr[6], 6);
    ObjModel_InitScratchBuffers();
    if (*(u16*)(hdr + 2) != 0)
    {
        u8* q;
        int words;
        int w2;
        u32 i;
        u32 nb;
        u8* dst;

        q = *(u8**)(hdr + 0xc);
        words = (u32)((q[0x73] << 5) + 0x1f) >> 5;
        copyToCache(lbl_80340898[0], data + *(int*)(q + 0x60), words);
        sizes[0] = words;
        w2 = (u32)(((q = *(u8**)(hdr + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)lbl_80340898 + 4), *(u8**)(q + 0x64), w2);
        for (i = 0; i < (u32)(*(u16*)(hdr + 2) - 1); i++)
        {
            q = *(u8**)(hdr + 0xc) + i * 0x74;
            words = (u32)((q[0xe7] << 5) + 0x1f) >> 5;
            nb = (i + 1) & 1;
            copyToCache(lbl_80340898[(u8)(nb * 2)], data + *(int*)(q + 0xd4), words);
            sizes[nb] = words;
            {
                u8* q2;
                int w3 = (u32)(((q2 = *(u8**)(hdr + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(lbl_80340898[(u8)((u8)(nb * 2) + 1)], *(u8**)(q2 + 0xd8), w3);
            }
            cacheQueueWait(2);
            if ((u8)quad)
            {
                dst = outs[i];
                ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                     lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                     q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                     q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                     *(u16*)(q + 0x70));
                memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
            }
            else
            {
                dst = outs[i];
                ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 *(u16*)(q + 0x70));
                memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
            }
        }
        q = *(u8**)(hdr + 0xc) + i * 0x74;
        cacheQueueWait(0);
        if ((u8)quad)
        {
            dst = outs[i];
            ObjModel_TransformQuadVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                                 lbl_80340898[(u8)((i & 1) * 2) + 1],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                                 *(u16*)(q + 0x70));
            memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        else
        {
            dst = outs[i];
            ObjModel_TransformVerticesLinear(mtxs + q[0x6c] * 0x30, mtxs + q[0x6d] * 0x30,
                                             lbl_80340898[(u8)((i & 1) * 2) + 1],
                                             q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                             q[0x72] + (int)lbl_80340898[(u8)((i & 1) * 2)],
                                             *(u16*)(q + 0x70));
            memcpyToCache(dst, lbl_80340898[(u8)((i & 1) * 2)], sizes[i & 1]);
        }
        cacheQueueWait(0);
    }
}

extern f32 lbl_803DE880;
extern void fn_80007F78(u8 * ch, s16 * outRot, s16 * outRot2);

void ObjModel_SampleJointTransform(u8* model, int b, int idx, f32 t, f32 s, f32* outPos, s16* outRot)
{
    u8* ch;
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
        ch = *(u8**)&((ObjModel*)model)->animStateB;
    }
    else
    {
        ch = *(u8**)&((ObjModel*)model)->animStateA;
    }
    saved = *(int*)(ch + 0x34);
    *(int*)(ch + 0x34) = ((int*)(ch + idx * 4))[0xd];
    if (*(u16*)(*(u8**)model + 2) & 0x40)
    {
        if (idx > 1)
        {
            anim = ((u8**)(ch + ((u16*)(ch + idx * 2))[0x22] * 4))[9] + 0x80;
        }
        else
        {
            anim = ((u8**)(ch + ((u16*)(ch + idx * 2))[0x22] * 4))[7] + 0x80;
        }
    }
    else
    {
        anim = ((u8**)*(int*)(*(u8**)model + 0x64))[((u16*)(ch + idx * 2))[0x22]];
    }
    *(f32*)(ch + 4) = t * *(f32*)(ch + 0x14);
    {
        int bv = (*(u8**)(ch + 0x34))[2];
        f32 fr = *(f32*)(ch + 4);
        int n = (int)fr;
        f32 fcv = (f32)n;
        if (fcv != fr)
        {
            *(s16*)(ch + 0x4c) = (s16)bv;
        }
        else
        {
            *(s16*)(ch + 0x4c) = 0;
        }
        if (*(s8*)(ch + 0x60) != 0 && fcv == *(f32*)(ch + 0x14) - lbl_803DE818)
        {
            *(s16*)(ch + 0x4c) = (s16)(-bv * n);
        }
        *(u8**)(ch + 0x2c) = anim + (*(s16*)(anim + 2) + bv * n);
    }
    fn_80007F78(ch, srot, outRot);
    *(int*)(ch + 0x34) = saved;
    {
        f32 k = lbl_803DE880;
        outPos[0] = k * (f32)srot[0];
        outPos[1] = k * (f32)srot[1];
        outPos[2] = k * (f32)srot[2];
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
extern f32 lbl_803DE838;
extern f32 lbl_803DE83C;
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
    f32* m;
    int i;
    int idx;
    int nextIdx;
    int prevOff;
    f32 dot;
    f32 cap;
    u8* bankSel;

    idx = *(s8*)(*(u8**)(b + 0x3c) + (*(int***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    bankSel = model + ((*(u16*)(model + 0x18) & 1) << 2);
    PSMTXCopy(*(f32**)(bankSel + 0xc) + idx * 0x10, tmp);
    idx = (*(int***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    bankSel = model + ((*(u16*)(model + 0x18) & 1) << 2);
    m = *(f32**)(bankSel + 0xc) + idx * 0x10;
    cap = lbl_803DE838;
    for (i = 1; i < *(int*)(chain + 8) + 1; i++)
    {
        nextIdx = (*(int***)(chain + 4))[0][i];
        prevOff = (i - 1) * 0x54;
        PSMTXMultVec(tmp, (f32*)(*(u8**)chain + prevOff + 0x18), out);
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
        if (dot < cap && dot > lbl_803DE83C)
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
                    dot = (lbl_803DE818 - dot) * *(f32*)(blend + 8) + dot;
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
        PSMTXCopy(m, (f32*)(*(u8**)chain + prevOff + 0x24));
        if (i < *(int*)(chain + 8))
        {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model))
            {
                idx = 0;
            }
            m = *(f32**)((u8*)model + ((*(u16*)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
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
    f32* m;
    int i;
    int idx;
    int nextIdx;
    int prevOff;
    f32 dot;
    f32 cap;

    idx = *(s8*)(*(u8**)(b + 0x3c) + (*(int***)(chain + 4))[0][0] * 0x1c);
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    PSMTXCopy(*(f32**)(model + ((*(u16*)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10, tmp);
    idx = (*(int***)(chain + 4))[0][0];
    if (idx >= boneBlendSlotLimit(model))
    {
        idx = 0;
    }
    m = *(f32**)(model + ((*(u16*)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
    cap = lbl_803DE838;
    for (i = 1; i < *(int*)(chain + 8) + 1; i++)
    {
        nextIdx = (*(int***)(chain + 4))[0][i];
        prevOff = (i - 1) * 0x54;
        PSMTXMultVec(tmp, (f32*)(*(u8**)chain + prevOff + 0x18), out);
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
        if (dot < cap && dot > lbl_803DE83C)
        {
            PSVECCrossProduct(dir2, dir1, axis);
            if (dot < lbl_803DE840)
            {
                dot = lbl_803DE840;
            }
            else
            {
                dot = (lbl_803DE818 - dot) * *(f32*)(blend + 8) + dot;
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
        PSMTXCopy(m, (f32*)(*(u8**)chain + prevOff + 0x24));
        if (i < *(int*)(chain + 8))
        {
            idx = nextIdx;
            if (nextIdx >= boneBlendSlotLimit(model))
            {
                idx = 0;
            }
            m = *(f32**)((u8*)model + ((*(u16*)(model + 0x18) & 1) << 2) + 0xc) + idx * 0x10;
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
