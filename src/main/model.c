#include "main/asset_load.h"
#include "dolphin/mtx.h"
#include "track/intersect_texture_api.h"
#include "track/intersect_depth_state_api.h"
#include "main/hud_visibility_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "main/model.h"
#include "main/objmodel.h"
#include "main/model_engine.h"
#include "main/model_runtime_api.h"
#include "main/mm.h"
#include "game/objects/object.h"
#include "main/object_transform.h"
#include "main/objHitReact_types.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/PPCArch.h"
#include "main/rcp_dolphin.h"
#include "main/pi_dolphin.h"
#include "main/loaded_file_flags.h"
#include "main/table_file.h"
#include "main/frame_timing.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "main/shader_init_api.h"
#include "main/acosf_api.h"
#include "main/render_internal.h"
#include "string.h"
#include "main/vecmath.h"
#include "dolphin/os/OSFastCast.h"

static u32 sGQR7Config;
int gModelTabEntryCount;
s16* gModelResourceBuffer;
int* gModelAnimOffsetTable;
int* lbl_803DCB5C;
int lbl_803DCB58;
ModelList* gModelList;
ModelList* gModelAnimCacheList;
u32* gModelAnimDataOffsetTable;
f32 gModelChainJitterScale;

u16 gModelCopyChunkWordLimit = 0x2A0;
#define MODEL_BONEXFORM_HAS_X 0x2000
#define MODEL_BONEXFORM_HAS_Y 0x4000
#define MODEL_BONEXFORM_HAS_Z 0x8000
void* animLoadFromTable(u8* hdr, int idx, int a, u8* b);
#define LOADCOLOR_BLOCK(SLOT)                                                         \
    {                                                                                 \
        int idx;                                                                      \
        u32 v;                                                                        \
        int sz4;                                                                      \
        int unusedSize;                                                               \
        int sz;                                                                       \
        u8 *hp;                                                                       \
                                                                                      \
        v = (u32)(SLOT);                                                              \
        idx = *(s16 *)((ModelFileHeader *)hdr)->animationHeaderBuffer;                \
        if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) == 0 || *(u16 *)(hdr + 4) == 1 ||      \
            *(u16 *)(hdr + 4) == 3) {                                                 \
            if (v == 0) {                                                             \
                if (ModelList_getHeader(gModelAnimCacheList, idx, &hp) == 0) {               \
                    sz4 = gModelAnimDataOffsetTable[idx];                                   \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, sz4, 0, &sz, idx, 1);    \
                    hp = mmAlloc(sz, 10, 0);                                           \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, hp, sz4, sz,     \
                                              &unusedSize, idx, 0);                    \
                    *hp = 1;                                                          \
                    modelInitModelList(gModelAnimCacheList, idx, &hp);                       \
                } else {                                                              \
                    *hp += 1;                                                         \
                }                                                                     \
            } else {                                                                  \
                animLoadFromTable(hdr, idx, 0, (u8 *)v);                               \
            }                                                                         \
        }                                                                             \
    }
extern s16 gModelJointScratchBuffer[0xa0];
#define BLENDTBL_ENTRY(K, OFF)                              \
    if (poseWeights[K] != 0) {                                        \
        gModelJointScratchBuffer[outPos++] = (s16)(offA + (OFF));     \
        gModelJointScratchBuffer[outPos++] = (s16)(offB + (OFF));     \
        gModelJointScratchBuffer[outPos++] = poseWeights[K];                  \
        gModelJointScratchBuffer[outPos++] = poseWeights[K];                  \
    }
extern char sModelAnimationBufferOverflowWarning[];
extern Vec gModelJitterAxis;
typedef struct ObjHitBufs
{
    u8 pad00[0x48];
    u8* bufs[2];
    u8* cur;
} ObjHitBufs;

void setGQR7Packed(int a, int b, int c, int d);
u8* modelBoneTransforms_next(u8* stream, int* dx, int* dy, int* dz);
static inline void* modelGetBoneMtx(ObjModel* model, int idx);
void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformQuadVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void modelApplyBoneTransform(u8* p, u8* out, u16 n, u8** pd, u8** pe, int f, u16 pos)
{
    u8* a = *pd;
    u8* b = *pe;
    int i = 0;
    int wHi = 0x10000 - f;
    int aIdx;
    int bIdx;
    int ax, ay, az;
    int bx, by, bz;

    while (i < n)
    {
        aIdx = (*(s16*)a & 0x1fff) - pos;
        bIdx = (*(s16*)b & 0x1fff) - pos;
        if (i >= aIdx)
        {
            if (i == bIdx)
            {
                b = modelBoneTransforms_next(b, &bx, &by, &bz);
                a = modelBoneTransforms_next(a, &ax, &ay, &az);
                *(u16*)out = ((u32)(ax * wHi + bx * f) >> 16) + *(s16*)p;
                *(u16*)(out + 2) = ((u32)(ay * wHi + by * f) >> 16) + *(s16*)(p + 2);
                *(u16*)(out + 4) = ((u32)(az * wHi + bz * f) >> 16) + *(s16*)(p + 4);
            }
            else
            {
                a = modelBoneTransforms_next(a, &ax, &ay, &az);
                *(u16*)out = ((u32)(ax * wHi) >> 16) + *(s16*)p;
                *(u16*)(out + 2) = ((u32)(ay * wHi) >> 16) + *(s16*)(p + 2);
                *(u16*)(out + 4) = ((u32)(az * wHi) >> 16) + *(s16*)(p + 4);
            }
        }
        else if (i >= bIdx)
        {
            b = modelBoneTransforms_next(b, &bx, &by, &bz);
            *(u16*)out = ((u32)(bx * f) >> 16) + *(s16*)p;
            *(u16*)(out + 2) = ((u32)(by * f) >> 16) + *(s16*)(p + 2);
            *(u16*)(out + 4) = ((u32)(bz * f) >> 16) + *(s16*)(p + 4);
        }
        else
        {
            *(u32*)out = *(u32*)p;
            *(u16*)(out + 4) = *(s16*)(p + 4);
        }
        p += 6;
        out += 6;
        i++;
    }
    *pd = a;
    *pe = b;
}

u8* modelBoneTransforms_next(u8* stream, int* dx, int* dy, int* dz)
{
    u16 flags = *(u16*)stream;

    stream += 2;
    *dx = 0;
    if (flags & MODEL_BONEXFORM_HAS_X)
    {
        *dx = *(s16*)stream;
        stream += 2;
    }
    *dy = 0;
    if (flags & MODEL_BONEXFORM_HAS_Y)
    {
        *dy = *(s16*)stream;
        stream += 2;
    }
    *dz = 0;
    if (flags & MODEL_BONEXFORM_HAS_Z)
    {
        *dz = *(s16*)stream;
        stream += 2;
    }
    return stream;
}

void modelAnimUpdateChannels(ModelFileHeader* file, ObjAnimState* work, int channelCount)
{
    int i;
    u8* mtxSlotRow;
    int frameStride;
    u8* frameStream;
    int boneByteOff;
    int boneIdx;
    int frameIdx;
    int streamOff;
    f32 frameIdxF;

    for (i = 0; i < channelCount; i++)
    {
        if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
        {
            frameStream = work->cachedMoves[work->cacheSlots[i]];
            mtxSlotRow = frameStream;
            frameStream += 0x80;
        }
        else
        {
            mtxSlotRow = file->animationDataSection +
                         work->cacheSlots[i] * (((file->jointCount - 1) & ~7) + 8);
            frameStream = ((u8**)file->animationModelPtrs)[work->cacheSlots[i]];
        }
        frameStride = ((u8*)work->frameData[i])[2];
        boneIdx = 0;
        boneByteOff = 0;
        while (boneIdx < file->jointCount)
        {
            (file->jointData + boneByteOff)[offsetof(ModelBone, idx) + i + 1] = mtxSlotRow[boneIdx];
            boneByteOff += sizeof(ModelBone);
            boneIdx++;
        }
        frameIdx = (int)work->framePhases[i];
        frameIdxF = frameIdx;
        if (frameIdxF != work->framePhases[i])
        {
            work->frameStreamStrides[i] = frameStride;
        }
        else
        {
            work->frameStreamStrides[i] = 0;
        }
        if (work->frameTypes[i] != 0 && frameIdxF == work->frameLengths[i] - 1.0f)
        {
            work->frameStreamStrides[i] = (s16)(-frameStride * frameIdx);
        }
        streamOff = *(s16*)(frameStream + 2);
        work->frameStreamCursors[i] = frameStream + streamOff + frameStride * frameIdx;
    }
}

void modelAnimEvalSlotPair(u8* dst, ObjModel* model, ObjAnimState* channel, f32 t, int flags, int slotA,
                           int slotB, int blendSel, int mode, s16 eventVal)
{
    ObjAnimState work;
    int mtxBuf;
    ModelFileHeader* file;
    u32 idxA;
    u8 idxB;

    file = model->file;
    mtxBuf = (int)model->jointMatrices[model->bufferFlags & 1];
    if ((u8)mode & 0x10)
    {
        channel->framePhase = t * channel->frameLength;
    }
    idxA = (u8)slotA;
    work.frameTypes[0] = channel->frameTypes[idxA];
    work.frameLengths[0] = channel->frameLengths[idxA];
    work.framePhases[0] = channel->framePhases[idxA];
    work.frameData[0] = channel->frameData[idxA];
    idxB = (u8)slotB;
    work.frameTypes[1] = channel->frameTypes[idxB];
    work.frameLengths[1] = channel->frameLengths[idxB];
    work.framePhases[1] = channel->framePhases[idxB];
    idxB = (u8)blendSel;
    work.frameData[1] = channel->frameData[idxB];
    if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
    {
        work.cacheSlots[0] = 0;
        work.cacheSlots[1] = 1;
        work.cachedMoves[0] = channel->cachedMoves[channel->cacheSlots[idxA]];
        if (idxB < 2)
        {
            work.cachedMoves[1] = channel->cachedMoves[channel->cacheSlots[idxB]];
        }
        else
        {
            work.cachedMoves[1] = channel->cachedMoves[2 + channel->cacheSlots[idxB]];
        }
    }
    else
    {
        work.cacheSlots[0] = channel->cacheSlots[idxA];
        work.cacheSlots[1] = channel->cacheSlots[idxB];
    }
    if (eventVal == 0)
    {
        eventVal = 1;
    }
    work.eventCountdown = eventVal;
    modelAnimUpdateChannels(file, &work, 2);
    {
        int modeLow = mode & 0xF;
        mode = modeLow;
        if ((modeLow & 0xC) == 0)
        {
            int sv = channel->moveControlFlags;
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
    modelAnimBuildJointMatrices(&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                (u8*)gModelJointScratchBuffer, flags, (u8)mode);
}
void modelAnimEvalChannels(u8* dst, ObjModel* model, ObjAnimState* channel, f32 blend, int flags)
{
    ObjAnimState work;
    int mtxBuf;
    int slotEvent;
    int outFlags;
    ModelFileHeader* file;
    int ctrlFlags;
    int slotCount;
    int j;
    int srcSlot;

    file = model->file;
    mtxBuf = (int)model->jointMatrices[model->bufferFlags & 1];
    channel->framePhase = blend * channel->frameLength;
    outFlags = 0;
    if (file->flags & 8)
    {
        work.cachedMoves[0] = channel->cachedMoves[0];
        work.cachedMoves[1] = channel->cachedMoves[1];
        work.cachedMoves[2] = channel->cachedMoves[2];
        work.cachedMoves[3] = channel->cachedMoves[3];
        for (j = 0; j < 2; j++)
        {
            if (channel->eventCountdown != 0)
            {
                srcSlot = j;
            }
            else
            {
                srcSlot = 0;
            }
            work.cacheSlots[j] = channel->cacheSlots[srcSlot];
            work.frameTypes[j] = channel->frameTypes[srcSlot];
            work.frameLengths[j] = channel->frameLengths[srcSlot];
            work.framePhases[j] = channel->framePhases[srcSlot];
            work.frameData[j] = channel->frameData[srcSlot];
        }
        work.eventCountdown = channel->eventCountdown;
        modelAnimUpdateChannels(file, &work, 2);
        ctrlFlags = channel->moveControlFlags;
        if (ctrlFlags & 1)
        {
            outFlags |= 0x10;
        }
        if (ctrlFlags & 4)
        {
            outFlags |= 0x20;
        }
        modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                    (u8*)gModelJointScratchBuffer, flags, outFlags | 0x40);
    }
    else
    {
        int i;
        int blendMask;

        for (i = 0; i < 2; i++)
        {
            if (i != 0)
            {
                slotEvent = channel->prevEventState;
            }
            else
            {
                slotEvent = channel->eventState;
            }
            if (slotEvent != 0)
            {
                if (channel->eventCountdown != 0)
                {
                    blendMask = 4 << i;
                }
                else
                {
                    blendMask = 0;
                }
                work.frameTypes[0] = channel->frameTypes[i];
                work.frameLengths[0] = channel->frameLengths[i];
                work.framePhases[0] = channel->framePhases[i];
                work.frameData[0] = channel->frameData[i];
                work.frameTypes[1] = channel->frameTypes[i];
                work.frameLengths[1] = channel->frameLengths[i];
                work.framePhases[1] = channel->framePhases[i];
                work.frameData[1] = channel->frameData[i + 2];
                if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
                {
                    work.cacheSlots[0] = 0;
                    work.cacheSlots[1] = 1;
                    work.cachedMoves[0] = channel->cachedMoves[channel->cacheSlots[i]];
                    work.cachedMoves[1] = channel->cachedMoves[2 + channel->cacheSlots[i + 2]];
                }
                else
                {
                    work.cacheSlots[0] = channel->cacheSlots[i];
                    work.cacheSlots[1] = channel->cacheSlots[i + 2];
                }
                work.eventCountdown = slotEvent;
                modelAnimUpdateChannels(file, &work, 2);
                modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                            (u8*)gModelJointScratchBuffer, flags, blendMask);
                if (blendMask != 0)
                {
                    outFlags |= 1 << i;
                }
            }
        }
        if ((channel->eventStates[0] == 0 && channel->eventStates[1] == 0) || outFlags != 0)
        {
            slotCount = 1;
            if (channel->eventCountdown != 0)
            {
                slotCount = 2;
            }
            work.cachedMoves[0] = channel->cachedMoves[0];
            work.cachedMoves[1] = channel->cachedMoves[1];
            work.cachedMoves[2] = channel->cachedMoves[2];
            work.cachedMoves[3] = channel->cachedMoves[3];
            j = 0;
            while (j < slotCount)
            {
                work.cacheSlots[j] = channel->cacheSlots[j];
                work.frameTypes[j] = channel->frameTypes[j];
                work.frameLengths[j] = channel->frameLengths[j];
                work.framePhases[j] = channel->framePhases[j];
                work.frameData[j] = channel->frameData[j];
                j++;
            }
            work.eventCountdown = channel->eventCountdown;
            modelAnimUpdateChannels(file, &work, slotCount);
            ctrlFlags = channel->moveControlFlags;
            if (ctrlFlags & 1)
            {
                outFlags |= 0x10;
            }
            if (ctrlFlags & 4)
            {
                outFlags |= 0x20;
            }
            modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                        (u8*)gModelJointScratchBuffer, flags, outFlags);
        }
    }
}

void* ObjAnim_LoadCachedMove(int animId, int moveIndex, u8* cache, ObjAnimDef* animDef)
{
    void* out = NULL;
    animationLoad(&out, animId, moveIndex, cache, animDef);
    return out;
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
    f = 0.0f;
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
            mdl = ((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[channel->moveCacheSlot];
        }
        channel->moveFrameData = (ObjAnimFrameCommand*)(mdl + 6);
        channel->frameType = (s8)(*(u8*)(mdl + 1) & 0xf0);
        channel->frameLength = (f32)((u8*)channel->moveFrameData)[1];
        if (channel->frameType == 0)
        {
            channel->frameLength -= 1.0f;
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
int modelLoadAnimations(void* model, int id, void* animBase)
{
    int tabBase;
    u8* buf = animBase;
    int* tbl;
    u8* hdr = model;
    int sz;
    int hdrOff[1];
    int animOff;
    int groupSlot;
    int i;
    int animIdx;
    int padBytes;
    int animId;
    int dataOff;
    int listIdx;
    u8* atlasEntry;
    int unusedSize;
    int sz2;
    u8* atlasHdr;
    u8* atlasPtr;
    u8 newRefCount;

    padBytes = 0;
    tbl = gModelAnimOffsetTable;
    fileLoadToBufferOffset(MLDF_FILEID_MODANIM_TAB, tbl, id << 1, 0x10);
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
    fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (id & ~3) << 2, 0x20);
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
        fileLoadToBufferOffset(MLDF_FILEID_MODANIM_BIN, ((ModelFileHeader*)hdr)->animationHeaderBuffer, tabBase, sz);
    }
    else
    {
        fileLoadToBufferOffset(MLDF_FILEID_MODANIM_BIN, gModelResourceBuffer, tabBase, sz);
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = (u8*)gModelResourceBuffer;
    }
    hdrOff[0] = 0;
    groupSlot = 0;
    {
        u8* slot = hdr + groupSlot++ * 2;
        *(s16*)(slot + 0x70) = (s16)hdrOff[0];
    }
    i = 0;
    for (; i < (int)((ModelFileHeader*)hdr)->animationCount; i++)
    {
        if (*(s16*)(((ModelFileHeader*)hdr)->animationHeaderBuffer + hdrOff[0]) == -1)
        {
            ((ModelFileHeader*)hdr)->animGroupBaseIndices[groupSlot++] = (s16)(i + 1);
        }
        hdrOff[0] += 2;
    }
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) == 0)
    {
        ((ModelFileHeader*)hdr)->animationHeaderBuffer = NULL;
        ((ModelFileHeader*)hdr)->animationModelPtrs = buf;
        buf += ((ModelFileHeader*)hdr)->animationCount * (int)sizeof(u8*);
        padBytes += ((ModelFileHeader*)hdr)->animationCount * (int)sizeof(u8*);
        while (padBytes & 7)
        {
            buf++;
            padBytes++;
        }
        ((ModelFileHeader*)hdr)->animationDataSection = buf;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, ((ModelFileHeader*)hdr)->animationDataSection,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset, id);
        animIdx = 0;
        do
        {
            animId = *(s16*)((u8*)gModelResourceBuffer + animIdx * 2);
            if (animId != -1)
            {
                if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) && *(u16*)(hdr + 4) != 1 &&
                    *(u16*)(hdr + 4) != 3)
                {
                    atlasPtr = 0;
                }
                else
                {
                    if (ModelList_getHeader(gModelAnimCacheList, animId, &atlasHdr) == 0)
                    {
                        animOff = gModelAnimDataOffsetTable[animId];
                        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animOff, 0, &sz2, animId, 1);
                        atlasHdr = mmAlloc(sz2, 10, 0);
                        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, atlasHdr, animOff, sz2, &unusedSize, animId,
                                                  0);
                        *atlasHdr = 1;
                        modelInitModelList(gModelAnimCacheList, animId, &atlasHdr);
                    }
                    else
                    {
                        *atlasHdr += 1;
                    }
                    atlasPtr = atlasHdr;
                }
                ((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[animIdx] = atlasPtr;
                if (((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[animIdx] == 0)
                {
                    int relIdx;

                    relIdx = 0;
                    for (; relIdx < animIdx; relIdx++)
                    {
                        atlasEntry = ((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[relIdx];
                        if (atlasEntry != 0)
                        {
                            newRefCount = (*atlasEntry -= 1);
                            if ((s8)newRefCount <= 0)
                            {
                                model_findIdxInModelList(gModelAnimCacheList, &atlasEntry, &listIdx);
                                model_adjustModelList(gModelAnimCacheList, listIdx);
                                mm_free(atlasEntry);
                            }
                        }
                    }
                    ((ModelFileHeader*)hdr)->animationModelPtrs = NULL;
                    return 1;
                }
            }
            else
            {
                ((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[animIdx] = NULL;
            }
            animIdx++;
        }
        while (animIdx < (int)((ModelFileHeader*)hdr)->animationCount);
    }
    else
    {
        ((ModelFileHeader*)hdr)->animationModelPtrs = NULL;
    }
    return 0;
}
int modelGetAmapSize(int modelId, int amapFlag, int animCount)
{
    int amapSize;
    int totalSize;
    int index;

    totalSize = 0;
    if (amapFlag != 0)
    {
        totalSize += animCount * 2 + 8;
        while (totalSize & 7)
        {
            totalSize++;
        }
    }
    else
    {
        totalSize += animCount * (int)sizeof(u8*);
        while (totalSize & 7)
        {
            totalSize++;
        }
        index = modelId & 3;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (modelId & ~3) << 2, 0x20);
        amapSize = gModelAnimOffsetTable[index + 1] - gModelAnimOffsetTable[index];
        totalSize += amapSize;
    }
    return totalSize;
}

int modelLoad_calcSizes(void* model, int flags, int* sizes, int forceBlendChannels)
{
    u8* hdr = model;
    int total;
    int va;

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
        int normalStride;
        if (((ModelFileHeader*)hdr)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE)
        {
            normalStride = 9;
        }
        else
        {
            normalStride = 3;
        }
        sizes[0] += ((ModelFileHeader*)hdr)->normalCount * normalStride + 0x40;
    }
    {
        int hitSphereBytes = ((ModelFileHeader*)hdr)->hitVolumeCount * sizeof(ObjModelHitSphere);
        sizes[1] = hitSphereBytes << 1;
    }
    sizes[3] = 0;
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) != 0)
    {
        sizes[5] = ((ModelFileHeader*)hdr)->headerSize;
        while ((sizes[5] & 7) != 0)
        {
            *(int*)((int)sizes + 0x14) = *(int*)((int)sizes + 0x14) + 1;
        }
        sizes[3] = sizes[5] << 2;
    }
    sizes[4] = (int)sizeof(ObjAnimState);
    if ((flags & 0x80) != 0)
    {
        sizes[4] = sizes[4] << 1;
        sizes[3] = sizes[3] << 1;
    }
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || forceBlendChannels != 0)
    {
        sizes[4] = sizes[4] + sizeof(ObjModelBlendChannel) * 3;
        total = sizes[3] + sizes[4] + (int)sizeof(ObjModel);
        total = (sizes[6] + sizes[1] + 8) + total;
    }
    else
    {
        total = sizes[4] + (int)sizeof(ObjModel);
        total = (sizes[3] + sizes[6] + sizes[1] + 8) + total;
    }
    total = total + sizes[0];
    if (((ModelFileHeader*)hdr)->jointData != 0 && ((ModelFileHeader*)hdr)->jointCount != 0 && ((ModelFileHeader*)hdr)->
        unk18 != 0)
    {
        total = ((u32)((ModelFileHeader*)hdr)->jointCount << 1) + (((u32)((ModelFileHeader*)hdr)->jointCount * 7) << 2)
            + (int)sizeof(ModelJointWork) + total;
    }
    if (((ModelFileHeader*)hdr)->vertexAnimEntries != 0)
    {
        total = (va = (u32)((ModelFileHeader*)hdr)->vertexAnimCount * 4, va + total);
        total = total + 4;
    }
    if (((ModelFileHeader*)hdr)->blendAnimEntries != 0)
    {
        total = (va = (u32)((ModelFileHeader*)hdr)->blendAnimCount * 4, va + total);
        total = total + 4;
    }
    total += (u32)((ModelFileHeader*)hdr)->renderOpCount * (int)sizeof(ModelRenderOpTextureRefs);
    if ((flags & 0x8000) != 0)
    {
        total += 0x1a;
    }
    return roundUpTo32(((total + 0x2f) & ~0xf) + 0x10);
}

static inline int modelGetJointMatrixCount(const ObjModel* model)
{
    const ModelFileHeader* file = model->file;

    if (file->jointCount != 0)
    {
        return file->jointCount + file->extraJointCount;
    }
    return 1;
}

static inline void* modelGetBoneMtx(ObjModel* model, int idx)
{
    int joint = idx;
    u8* base;

    if (joint >= modelGetJointMatrixCount(model))
    {
        joint = 0;
    }
    base = model->jointMatrices[model->bufferFlags & 1];
    return base + joint * sizeof(ObjModelJointMatrix);
}

void* modelLoad_layoutBuffers(u8* p, int b, int isType1, u8* c)
{
    int o2;
    u8* out2;
    int szs[7];
    int pos;
    int end;
    int normalStride;
    u8* out;
    int k;
    u8* q;
    f32 f;

    out = c;
    if (p == 0)
    {
        return 0;
    }
    modelLoad_calcSizes(p, b, szs, 0);
    out2 = (u8*)((int)out | (int)out);
    pos = roundUpTo32((int)out + 0x64);
    *(int*)&((ObjModel*)out)->jointMatrices[0] = pos;
    pos += szs[6] >> 1;
    ((ObjModel*)out)->jointMatrices[1] = (u8*)pos;
    pos += szs[6] >> 1;
    ((ObjModel*)out)->curMtxBuf = ((ObjModel*)out)->jointMatrices[0];
    if (((ModelFileHeader*)p)->morphTargetCount != 0 || ((ModelFileHeader*)p)->vertexAnimEntries != NULL || (((
        ModelFileHeader*)p)->flags & MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS))
    {
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out2)->vtxBuf[0] = pos;
        pos = roundUpTo32(pos + ((ModelFileHeader*)p)->vertexCount * 6);
        *(int*)&((ObjModel*)out2)->vtxBuf[1] = pos;
        end = pos + ((ModelFileHeader*)p)->vertexCount * 6;
        memcpy(((ObjModel*)out2)->vtxBuf[0], ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out2)->vtxBuf[0], ((ModelFileHeader*)p)->vertexCount * 6);
        memcpy(((ObjModel*)out2)->vtxBuf[1], ((ModelFileHeader*)p)->vertices, ((ModelFileHeader*)p)->vertexCount * 6);
        DCFlushRange(((ObjModel*)out2)->vtxBuf[1], ((ModelFileHeader*)p)->vertexCount * 6);
        pos = roundUpTo32(end);
    }
    else
    {
        end = *(int*)&((ModelFileHeader*)p)->vertices;
        *(int*)&((ObjModel*)out)->vtxBuf[1] = end;
        *(int*)&((ObjModel*)out2)->vtxBuf[0] = end;
    }
    if (((ModelFileHeader*)p)->blendAnimEntries != NULL)
    {
        if (((ModelFileHeader*)p)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE)
        {
            normalStride = 9;
        }
        else
        {
            normalStride = 3;
        }
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out2)->normalBuf = pos;
        end = pos + ((ModelFileHeader*)p)->normalCount * normalStride;
        memcpy(((ObjModel*)out2)->normalBuf, ((ModelFileHeader*)p)->normals, ((ModelFileHeader*)p)->normalCount * normalStride);
        DCFlushRange(((ObjModel*)out2)->normalBuf, normalStride * ((ModelFileHeader*)p)->normalCount);
        pos = roundUpTo32(end);
    }
    else
    {
        ((ObjModel*)out2)->normalBuf = ((ModelFileHeader*)p)->normals;
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
        ((ObjAnimState*)q)->moveCache[0] = (u8*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->moveCache[1] = (u8*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->blendMoveCache[0] = (u8*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->blendMoveCache[1] = (u8*)pos;
        pos += szs[5];
        q = ((ObjModel*)out2)->animStateB;
        if (q != 0)
        {
            ((ObjAnimState*)q)->moveCache[0] = (u8*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->moveCache[1] = (u8*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->blendMoveCache[0] = (u8*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->blendMoveCache[1] = (u8*)pos;
            pos += szs[5];
        }
    }
    if (((ModelFileHeader*)p)->morphTargetCount != 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->blendChannels = pos;
        pos += sizeof(ObjModelBlendChannel) * 3;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)->morphTargetA = -1;
        ((ObjModelBlendChannel*)q)->morphTargetB = -1;
        f = 0.0f;
        ((ObjModelBlendChannel*)q)->weight = f;
        ((ObjModelBlendChannel*)q)->targetWeight = f;
        ((ObjModelBlendChannel*)q)->weightRate = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)[1].morphTargetA = -1;
        ((ObjModelBlendChannel*)q)[1].morphTargetB = -1;
        ((ObjModelBlendChannel*)q)[1].weight = f;
        ((ObjModelBlendChannel*)q)[1].targetWeight = f;
        ((ObjModelBlendChannel*)q)[1].weightRate = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)[2].morphTargetA = -1;
        ((ObjModelBlendChannel*)q)[2].morphTargetB = -1;
        ((ObjModelBlendChannel*)q)[2].weight = f;
        ((ObjModelBlendChannel*)q)[2].targetWeight = f;
        ((ObjModelBlendChannel*)q)[2].weightRate = f;
    }
    if (szs[1] > 0)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[0] = pos;
        o2 = ((ModelFileHeader*)p)->hitVolumeCount;
        pos += o2 * sizeof(ObjModelHitSphere);
        *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[1] = pos;
        pos += ((ModelFileHeader*)p)->hitVolumeCount * sizeof(ObjModelHitSphere);
        *(int*)&((ObjModel*)out2)->activeHitVolumeSpheres =
            *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[0];
    }
    if (((ModelFileHeader*)p)->jointData != NULL && ((ModelFileHeader*)p)->jointCount != 0 && ((
        ModelFileHeader*)p)->unk18 != NULL && ((ModelFileHeader*)p)->unk1C != NULL)
    {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->skeletonJointData = pos;
        pos += sizeof(ModelJointWork);
        *(int*)&((ObjModel*)out2)->skeletonJointData->jointPositions = pos;
        pos += ((ModelFileHeader*)p)->jointCount * sizeof(Vec);
        *(int*)&((ObjModel*)out2)->skeletonJointData->jointRadii = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)&((ObjModel*)out2)->skeletonJointData->radiiSq = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)&((ObjModel*)out2)->skeletonJointData->jointLengths = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)&((ObjModel*)out2)->skeletonJointData->jointCullDistances = pos;
        pos += ((ModelFileHeader*)p)->jointCount * 4;
        *(int*)&((ObjModel*)out2)->skeletonJointData->touchedJoints = pos;
        pos += ((ModelFileHeader*)p)->jointCount;
    }
    else
    {
        *(int*)&((ObjModel*)out2)->skeletonJointData = 0;
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
    pos += ((ModelFileHeader*)p)->renderOpCount * sizeof(ModelRenderOpTextureRefs);
    k = 0;
    o2 = 0;
    for (; k < (int)((ModelFileHeader*)p)->renderOpCount; k++)
    {
        ((ObjModel*)out2)->textureRefs[k].swapSelector = 0;
    }
    if (b & 0x8000)
    {
        pos = alignUp2(pos);
        *(int*)&((ObjModel*)out2)->groundShadowVerts = pos;
        *(u8*)(((ObjModel*)out2)->groundShadowVerts + 0x18) = 0;
    }
    ((ObjModel*)out2)->renderAttachment = NULL;
    ((ObjModel*)out2)->file = (ModelFileHeader*)p;
    ((ObjModel*)out2)->vtxBufDirty = 0;
    return out2;
}

static void modelChainUpdateNodesPassive(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                                         ObjModelChainEntry* entry)
{
    Mtx tmp;
    Mtx mt;
    Vec target;
    Vec work;
    Vec out;
    Vec dir2;
    Vec dir1;
    Vec axis;
    int nextIdx;
    int i;
    int idx;
    MtxPtr m;
    f32 dot;

    idx = ((ModelBone*)file->jointData)[entry->desc->jointIndices[0]].parent;
    PSMTXCopy(modelGetBoneMtx(model, idx), tmp);
    m = modelGetBoneMtx(model, entry->desc->jointIndices[0]);
    for (i = 1; i < entry->nodeCount + 1; i++)
    {
        nextIdx = entry->desc->jointIndices[i];
        PSMTXMultVec(tmp, &entry->nodes[i - 1].localOffset, &out);
        target.x = entry->nodes[i].pos.x + entry->nodes[i].posDelta.x + gMapSavedPlayerOffsetX -
                   playerMapOffsetX;
        target.y = entry->nodes[i].pos.y + entry->nodes[i].posDelta.y;
        target.z = entry->nodes[i].pos.z + entry->nodes[i].posDelta.z + gMapSavedPlayerOffsetZ -
                   playerMapOffsetZ;
        work.x = entry->nodes[i - 1].localOffset.x;
        work.y = entry->nodes[i - 1].localOffset.y;
        work.z = entry->nodes[i - 1].localOffset.z;
        PSVECAdd(&work, &entry->nodes[i].localOffset, &work);
        PSMTXMultVec(tmp, &work, &work);
        PSVECSubtract(&target, &out, &dir1);
        PSVECNormalize(&dir1, &dir1);
        PSVECSubtract(&work, &out, &dir2);
        PSVECNormalize(&dir2, &dir2);
        dot = PSVECDotProduct(&dir2, &dir1);
        if (dot < 0.999f && dot > -0.999f)
        {
            if (dot < 1.0f && dot > -1.0f)
            {
                PSVECCrossProduct(&dir2, &dir1, &axis);
                if (dot < -1.0f)
                {
                    dot = -1.0f;
                }
                else
                {
                    f32 sub = 1.0f - dot;
                    dot = sub * chain->stiffness + dot;
                }
                PSMTXTranspose(tmp, mt);
                PSMTXMultVecSR(mt, &axis, &axis);
                PSMTXRotAxisRad(m, &axis, acosf(dot));
            }
            else
            {
                PSMTXIdentity(m);
            }
        }
        PSMTXConcat(tmp, m, m);
        m[0][3] = out.x;
        m[1][3] = out.y;
        m[2][3] = out.z;
        PSMTXCopy(m, tmp);
        work.x = entry->nodes[i].localOffset.x;
        work.y = entry->nodes[i].localOffset.y;
        work.z = entry->nodes[i].localOffset.z;
        PSMTXMultVec(m, &work, &work);
        PSMTXCopy(m, entry->nodes[i - 1].mtx);
        if (i < entry->nodeCount)
        {
            m = modelGetBoneMtx(model, nextIdx);
        }
    }
}
static void modelChainUpdateNodes(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                                  ObjModelChainEntry* entry, ObjModelChainUpdateCallback callback, int callbackArg)
{
    Mtx tmp;
    Mtx mt;
    Vec target;
    Vec work;
    Vec out;
    Vec dir2;
    Vec dir1;
    Vec axis;
    int nextIdx;
    int i;
    int idx;
    MtxPtr m;
    f32 dot;

    idx = ((ModelBone*)file->jointData)[entry->desc->jointIndices[0]].parent;
    PSMTXCopy(modelGetBoneMtx(model, idx), tmp);
    m = modelGetBoneMtx(model, entry->desc->jointIndices[0]);
    for (i = 1; i < entry->nodeCount + 1; i++)
    {
        nextIdx = entry->desc->jointIndices[i];
        PSMTXMultVec(tmp, &entry->nodes[i - 1].localOffset, &out);
        target.x = entry->nodes[i].pos.x + entry->nodes[i].posDelta.x + gMapSavedPlayerOffsetX -
                   playerMapOffsetX;
        target.y = entry->nodes[i].pos.y + entry->nodes[i].posDelta.y;
        target.z = entry->nodes[i].pos.z + entry->nodes[i].posDelta.z + gMapSavedPlayerOffsetZ -
                   playerMapOffsetZ;
        work.x = entry->nodes[i - 1].localOffset.x;
        work.y = entry->nodes[i - 1].localOffset.y;
        work.z = entry->nodes[i - 1].localOffset.z;
        if (callback != NULL)
        {
            callback(file, model, (f32*)&work, callbackArg, i, chain->phase);
        }
        PSVECAdd(&work, &entry->nodes[i].localOffset, &work);
        PSMTXMultVec(tmp, &work, &work);
        PSVECSubtract(&target, &out, &dir1);
        PSVECNormalize(&dir1, &dir1);
        PSVECSubtract(&work, &out, &dir2);
        PSVECNormalize(&dir2, &dir2);
        dot = PSVECDotProduct(&dir2, &dir1);
        if (dot < 0.999f && dot > -0.999f)
        {
            PSVECCrossProduct(&dir2, &dir1, &axis);
            if (dot < -1.0f)
            {
                dot = -1.0f;
            }
            else
            {
                f32 sub = 1.0f - dot;
                dot = sub * chain->stiffness + dot;
            }
            PSMTXTranspose(tmp, mt);
            PSMTXMultVecSR(mt, &axis, &axis);
            PSMTXRotAxisRad(m, &axis, acosf(dot));
        }
        else
        {
            PSMTXIdentity(m);
        }
        PSMTXConcat(tmp, m, m);
        m[0][3] = out.x;
        m[1][3] = out.y;
        m[2][3] = out.z;
        PSMTXCopy(m, tmp);
        work.x = entry->nodes[i].localOffset.x;
        work.y = entry->nodes[i].localOffset.y;
        work.z = entry->nodes[i].localOffset.z;
        PSMTXMultVec(m, &work, &work);
        PSMTXCopy(m, entry->nodes[i - 1].mtx);
        if (i < entry->nodeCount)
        {
            m = modelGetBoneMtx(model, nextIdx);
        }
        entry->nodes[i].posDelta.x =
            work.x - (gMapSavedPlayerOffsetX + entry->nodes[i].pos.x - playerMapOffsetX);
        entry->nodes[i].posDelta.y = work.y - entry->nodes[i].pos.y;
        entry->nodes[i].posDelta.z =
            work.z - (gMapSavedPlayerOffsetZ + entry->nodes[i].pos.z - playerMapOffsetZ);
        entry->nodes[i].pos.x = work.x;
        entry->nodes[i].pos.y = work.y;
        entry->nodes[i].pos.z = work.z;
    }
}
static void modelChainApplyDampingAndJitter(ObjModel* model, ModelFileHeader* unused, ObjModelChain* chain,
                                           ObjModelChainEntry* entry)
{
    Vec vec;
    int modelIndex;
    ModelFileHeader* hdr;
    u32 count;
    int total;
    u8* base;
    f32 dot;
    f32 scaled;
    f32 amp;
    int off;
    int i;

    modelIndex = 0;
    hdr = model->file;
    count = hdr->jointCount;
    if (count != 0)
    {
        total = count + hdr->extraJointCount;
    }
    else
    {
        total = 1;
    }
    if (modelIndex >= total)
    {
        modelIndex = 0;
    }
    base = model->jointMatrices[model->bufferFlags & 1] + modelIndex * 0x40;
    vec.x = *(f32*)(base + 0x20);
    vec.y = *(f32*)(base + 0x24);
    vec.z = *(f32*)(base + 0x28);
    dot = PSVECDotProduct(&vec, &gModelJitterAxis);
    if (dot < 0.0f)
    {
        dot = 0.0f;
    }
    scaled = gModelChainJitterScale * (1.2f - dot);
    amp = 0.01f * randomGetRange((int)(75.0f * scaled), (int)(100.0f * scaled));
    i = 0;
    off = 0;
    while (i < entry->nodeCount + 1)
    {
        u8* p = (u8*)entry->nodes + off;
        *(f32*)&((ModelFileHeader*)p)->dataSize = *(f32*)&((ModelFileHeader*)p)->dataSize * chain->damping + gModelJitterAxis.x * amp;
        *(f32*)(p + 0x10) = gModelJitterAxis.y * amp + (*(f32*)(p + 0x10) * chain->damping + chain->gravityY);
        *(f32*)(p + 0x14) = *(f32*)(p + 0x14) * chain->damping + gModelJitterAxis.z * amp;
        off += 0x54;
        i++;
    }
}

static void modelChainInitNodesFromJoints(int* obj, ModelFileHeader* b, int* desc)
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

        *(f32*)(entry + 0x18) = *(f32*)((int)b->jointData + jointIdx * 0x1c + 4);
        *(f32*)&((ObjModel*)entry)->vtxBuf[0] = *(f32*)((int)b->jointData + jointIdx * 0x1c + 8);
        *(f32*)&((ObjModel*)entry)->vtxBuf[1] = *(f32*)((int)b->jointData + jointIdx * 0x1c + 0xc);

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
        f32 zero = 0.0f;

        *(f32*)(lastEntry + 0x18) = zero;
        *(f32*)(lastEntry + 0x1c) = zero;
        *(f32*)(lastEntry + 0x20) = 100.0f;
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
        PSMTXMultVec((MtxPtr)(obj[(*(u16*)((u8*)obj + 0x18) & 1) + 3] + lastJointIdx * 0x40), (Vec*)(lastEntry + 0x18),
                     (Vec*)lastEntry);
    }
}

void ObjModelChain_Update(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain, ObjModelChainUpdateCallback callback)
{
    int off;
    int i;

    if (chain->enabled != 0)
    {
        i = 0;
        off = 0;
        for (; i < chain->count; i++)
        {
            if (chain->firstUpdateDone == 0)
            {
                modelChainInitNodesFromJoints((int*)model, file, (int*)((u8*)chain->entries + off));
            }
            if (getHudHiddenFrameCount() == 0)
            {
                modelChainApplyDampingAndJitter(model, file, chain,
                                                (ObjModelChainEntry*)((u8*)chain->entries + off));
                modelChainUpdateNodes(model, file, chain,
                                      (ObjModelChainEntry*)((u8*)chain->entries + off), callback, i);
            }
            else
            {
                modelChainUpdateNodesPassive(model, file, chain,
                                             (ObjModelChainEntry*)((u8*)chain->entries + off));
            }
            off += 0xc;
        }
        chain->updatedThisFrame = 1;
        chain->firstUpdateDone = 1;
    }
}

void ObjModelChain_SetEnabled(ObjModelChain* chain, u8 enabled)
{
    chain->enabled = enabled;
}
void ObjModelChain_SetOrigin(ObjModelChain* chain, f32 x, f32 y, f32 z)
{
    chain->stiffness = x;
    chain->damping = y;
    chain->gravityY = z;
}
void ObjModelChain_ResetFirstUpdate(ObjModelChain* chain)
{
    chain->firstUpdateDone = 0;
}

void ObjModelChain_AdvancePhase(ObjModelChain* chain)
{
    chain->updatedThisFrame = 0;
    chain->phase += timeDelta;
    if (chain->phase > 1000.0f)
    {
        chain->phase -= 1000.0f;
    }
}

extern const f32 gModelVertexScale;

void ObjModelChain_Free(ObjModelChain* chain)
{
    int i;
    for (i = 0; i < chain->count; i++)
    {
        mm_free(chain->entries[i].nodes);
    }
    mm_free(chain->entries);
    mm_free(chain);
}

ObjModelChain* ObjModelChain_Alloc(void* models, int count)
{
    int** p;
    int off;
    ObjModelChain* state;
    int i;

    state = mmAlloc(sizeof(ObjModelChain), 0x1a, 0);
    state->count = count;
    state->firstUpdateDone = 0;
    state->updatedThisFrame = 0;
    state->entries = mmAlloc(count * sizeof(ObjModelChainEntry), 0x1a, 0);
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
    state->stiffness = 0.12f;
    state->damping = 0.675f;
    state->gravityY = -0.15f;
    state->phase = 0.0f;
    state->enabled = 1;
    return state;
}

void Model_GetVertexPosition(ModelFileHeader* model, int vertexIndex, f32* out)
{
    s16* vertex;

    vertex = (s16*)(model->vertices + vertexIndex * 6);
    if ((model->flags & 0x800) != 0)
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

/* Double-buffered DMA-cache vertex transform: stream vtxCount verts through a
   two-slot scratch cache (0x2000 apart, transform output at +0x1000), copying
   worker chunks in via copyToCache while the previous chunk is being processed,
   then writing transformed verts (6 bytes each) back to dstVtx. */
int loadModelAndAnimTabs(void)
{
    int* p = getCurrentDataFile(MLDF_FILEID_MODELS_TAB_A);
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
    gModelAnimDataOffsetTable = getCurrentDataFile(MLDF_FILEID_ANIM_TAB_A);
    if (gModelAnimDataOffsetTable == NULL)
    {
        return 0;
    }
    lbl_803DCB58 = 0;
    return 1;
}

void modelApplyBoneTransforms(u8* srcVtx, u8* dstVtx, u16 vtxCount, u8* targetA, u8* targetB, int blendScale)
{
    u16 vtxPos;
    u16 chunk;
    u16 words;
    u16 nextChunk;
    u16 nextWords;
    u16 bufIdx;
    u8* cache;
    u8* out;
    int curBuf;
    u8* in;
    int sync;

    cache = getCache();
    vtxPos = 0;
    if (vtxCount > gModelCopyChunkWordLimit)
    {
        chunk = gModelCopyChunkWordLimit;
    }
    else
    {
        chunk = vtxCount;
    }
    words = (u32)(chunk * 6 + 0x1f & 0xffe0) >> 5;
    copyToCache(cache, srcVtx, words);
    bufIdx = 0;
    sync = 0;
    while (vtxCount != 0)
    {
        vtxCount -= chunk;
        if (vtxCount != 0)
        {
            if (vtxCount > gModelCopyChunkWordLimit)
            {
                nextChunk = gModelCopyChunkWordLimit;
            }
            else
            {
                nextChunk = vtxCount;
            }
            nextWords = (u32)(nextChunk * 6 + 0x1f & 0xffe0) >> 5;
            copyToCache(cache + (bufIdx ^ 1) * 0x2000, srcVtx + (vtxPos + gModelCopyChunkWordLimit) * 6, nextWords);
            sync = 1;
        }
        cacheQueueWait(sync);
        curBuf = bufIdx;
        in = cache + curBuf * 0x2000;
        out = in + 0x1000;
        modelApplyBoneTransform(in, out, chunk, (u8**)&targetA, (u8**)&targetB, blendScale, vtxPos);
        memcpyToCache(dstVtx + vtxPos * 6, out, words);
        vtxPos += chunk;
        sync = 1;
        bufIdx = curBuf ^ 1;
        chunk = nextChunk;
        words = nextWords;
    }
    cacheQueueWait(0);
}

void model_multMtxs(u8* model, f32* out)
{
    ModelFileHeader* hdr = ((ObjModel*)model)->file;
    u32 i;
    for (i = 0; i < hdr->jointCount; i++)
    {
        int j = i;
        ModelFileHeader* h = ((ObjModel*)model)->file;
        u32 cnt = h->jointCount;
        int lim;
        MtxPtr base;
        if (cnt != 0)
        {
            lim = cnt + h->extraJointCount;
        }
        else
        {
            lim = 1;
        }
        if (j >= lim)
        {
            j = 0;
        }
        base = (MtxPtr)((ObjModel*)model)->jointMatrices[((ObjModel*)model)->bufferFlags & 1];
        PSMTXConcat((MtxPtr)out, base + j * 4, base + j * 4);
    }
}
void modelInitBoneMtxs(ObjModel* model, f32* outReordered) {
    ModelFileHeader* file;
    u32 i;
    ROMtxPtr reorderCursor[1];
    int boneByteOff[1];
    MtxPtr mtx;
    ModelBone* bone;
    Mtx transMtx;

    file = model->file;
    i = 0;
    boneByteOff[0] = 0;
    reorderCursor[0] = (ROMtxPtr)outReordered;
    for (; i < file->jointCount; i++) {
        mtx = modelGetBoneMtx(model, i);
        bone = (ModelBone*)(file->jointData + boneByteOff[0]);
        PSMTXTrans(transMtx, -bone->tail[0], -bone->tail[1], -bone->tail[2]);
        PSMTXConcat(mtx, transMtx, transMtx);
        PSMTXReorder(transMtx, reorderCursor[0]);
        reorderCursor[0] += 4;
        boneByteOff[0] += 0x1c;
    }
}

void modelInitBoneMtxs2(ObjModel* model, f32* worldMtx, f32* outReordered)
{
    int boneByteOff;
    ROMtxPtr reorderCursor;
    ModelFileHeader* file;
    u32 i;
    MtxPtr jointMtx;
    ModelBone* bone;
    Mtx transMtx;

    file = model->file;
    if (file->jointCount == 0)
    {
        u32 cnt;
        int lim;
        int idx;

        idx = 0;
        cnt = file->jointCount;
        if (cnt != 0)
        {
            lim = cnt + file->extraJointCount;
        }
        else
        {
            lim = 1;
        }
        if (lim <= 0)
        {
            idx = 0;
        }
        jointMtx = (MtxPtr)(model->jointMatrices[model->bufferFlags & 1] + idx * 0x40);
        PSMTXConcat((MtxPtr)worldMtx, jointMtx, jointMtx);
    }
    else
    {
        i = 0;
        boneByteOff = 0;
        reorderCursor = (ROMtxPtr)outReordered;
        for (; i < file->jointCount; i++)
        {
            jointMtx = modelGetBoneMtx(model, i);
            bone = (ModelBone*)(file->jointData + boneByteOff);
            PSMTXTrans(transMtx, -bone->tail[0], -bone->tail[1], -bone->tail[2]);
            PSMTXConcat(jointMtx, transMtx, transMtx);
            PSMTXReorder(transMtx, reorderCursor);
            PSMTXConcat((MtxPtr)worldMtx, jointMtx, jointMtx);
            boneByteOff += 0x1c;
            reorderCursor += 4;
        }
    }
}

typedef struct ModelBlendChannelFlags {
    int values[3];
} ModelBlendChannelFlags;

const ModelBlendChannelFlags sModelBlendChannelActiveInit = {{0, 0, 0}};
const ModelBlendChannelFlags sModelBlendChannelFadeInit = {{0, 0, 0}};

void ObjModel_ApplyBlendChannels(ObjModel* model)
{
    ModelFileHeader* hdr;
    ObjModelBlendChannel* ch;
    int i;
    s16 defFrame;
    ModelBlendChannelFlags chanActive = sModelBlendChannelActiveInit;
    ModelBlendChannelFlags chanFade = sModelBlendChannelFadeInit;
    u8* targetA;
    u8* targetB;
    u8* srcVtx;
    u8* dstVtx;
    int fadeBits;

    hdr = model->file;
    if (hdr->morphTargetPtrs == NULL)
    {
        return;
    }
    defFrame = hdr->vertexCount + 1;
    for (i = 0; i < 3; i++)
    {
        ch = &model->blendChannels[i];
        if (ch->weight != ch->targetWeight)
        {
            ch->flags0E &= ~0xc;
            ch->flags0E |= BLENDCHAN_FLAG_FADING;
        }
        fadeBits = ch->flags0E & 0xc;
        chanFade.values[i] = fadeBits;
        if (ch->morphTargetA != -1 || ch->morphTargetB != -1 || fadeBits != 0)
        {
            chanActive.values[i] = 1;
        }
        if (chanFade.values[i] & 4)
        {
            ch->flags0E &= ~BLENDCHAN_FLAG_FADING;
            ch->flags0E |= BLENDCHAN_FLAG_FADED;
        }
        else if (chanFade.values[i] & 8)
        {
            ch->flags0E &= ~BLENDCHAN_FLAG_FADED;
        }
    }
    if (chanActive.values[0] == 0 && chanActive.values[1] == 0 && chanActive.values[2] == 0)
    {
        return;
    }
    if (chanActive.values[1])
    {
        chanActive.values[0] = 0;
    }
    if (chanFade.values[2])
    {
        chanFade.values[0] = 1;
        chanFade.values[1] = 1;
    }
    if ((chanActive.values[0] && chanFade.values[0]) || (chanActive.values[1] && chanFade.values[1]))
    {
        if (chanActive.values[2])
        {
            chanFade.values[2] = 1;
        }
    }
    for (i = 0; i < 3; i++)
    {
        if (chanActive.values[i] && hdr->vertexAnimEntries)
        {
            chanFade.values[i] = 1;
        }
        ch = &model->blendChannels[i];
        if (ch->flags0E & BLENDCHAN_FLAG_RESET_WEIGHT)
        {
            ch->flags0E &= ~BLENDCHAN_FLAG_RESET_WEIGHT;
            ch->weight = 0.0f;
        }
        if (chanActive.values[i] && chanFade.values[i])
        {
            f32 weight;
            f32 tw;
            f32 eased;

            if (ch->morphTargetA > -1)
            {
                targetA = hdr->morphTargetPtrs[ch->morphTargetA];
            }
            else
            {
                targetA = (u8*)&defFrame;
            }
            if (ch->morphTargetB > -1)
            {
                targetB = hdr->morphTargetPtrs[ch->morphTargetB];
            }
            else
            {
                targetB = (u8*)&defFrame;
            }
            if (i == 2)
            {
                if (chanActive.values[0] == 0 && chanActive.values[1] == 0)
                {
                    srcVtx = hdr->vertices;
                }
                else
                {
                    srcVtx = model->vtxBuf[(model->bufferFlags >> 1) & 1];
                }
            }
            else
            {
                srcVtx = hdr->vertices;
            }
            weight = ch->weight;
            if (weight > 1.0f)
            {
                ch->weight = 1.0f;
            }
            else if (weight < 0.0f)
            {
                if (ch->flags0E & BLENDCHAN_FLAG_CLAMP_TARGET)
                {
                    if (weight < -1.0f)
                    {
                        ch->weight = -1.0f;
                    }
                }
                else
                {
                    ch->weight = 0.0f;
                }
            }
            tw = ch->weight;
            if (tw >= 0.0f)
            {
                eased = 0.5f * tw + 1.5f * (tw * tw) - tw * (tw * tw);
            }
            else
            {
                tw *= -1.0f;
                eased = 0.5f * tw + 1.5f * (tw * tw) - tw * (tw * tw);
                eased *= -1.0f;
            }
            dstVtx = model->vtxBuf[(model->bufferFlags >> 1) & 1];
            modelApplyBoneTransforms(srcVtx, dstVtx, hdr->vertexCount, targetA, targetB,
                                     (int)(65536.0f * eased));
            model->vtxBufDirty = 1;
        }
        if (ch->targetWeight != ch->weight)
        {
            ch->targetWeight = ch->weight;
        }
    }
}

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
        if (ch[0].flags0E & BLENDCHAN_FLAG_MANUAL)
        {
            continue;
        }
        ch[0].weight = ch[0].weightRate * dt + ch[0].weight;
        if (ch[0].weight >= 0.99f)
        {
            ch[0].weight = 0.99f;
            ch[0].weightRate = 0.001f;
            ch[0].flags0E &= ~BLENDCHAN_FLAG_FADING;
        }
        else if (ch[0].weight <= 0.002f)
        {
            ch[0].weight = 0.002f;
            ch[0].weightRate = 0.001f;
            ch[0].flags0E &= ~BLENDCHAN_FLAG_FADING;
        }
    }
}

int ObjModel_HasActiveBlendChannels(ObjModel* model)
{
    ObjModelBlendChannel* ch;

    if (model->file->morphTargetPtrs == NULL)
    {
        return 0;
    }
    ch = model->blendChannels;
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

void ObjModel_SetBlendChannelWeight(ObjModel* model, int channel, f32 weight)
{
    ObjModelBlendChannel* ch;

    if (channel > 2 || model->file->morphTargetPtrs == NULL)
    {
        return;
    }
    ch = model->blendChannels + channel;
    if (weight != ch->weight)
    {
        ch->weight = weight;
    }
    ch[0].flags0E |= BLENDCHAN_FLAG_FADING;
}

void ObjModel_SetBlendChannelTargets(ObjModel* model, int channel, int a, int b, f32 weight, int flags)
{
    ObjModelBlendChannel* ch;
    u8* hdr;
    if (channel > 2 || ((ModelFileHeader*)(hdr = (u8*)model->file))->morphTargetPtrs == NULL)
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
    ch = model->blendChannels + channel;
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
        ch[0].weight = 0.0f;
    }
    ch[0].targetWeight = -1.0f;
    ch[0].weightRate = weight;
    ch[0].flags0E = flags | BLENDCHAN_FLAG_FADING;
}

void ObjModel_ClearBlendChannels(ObjModel* model)
{
    if (model->file->morphTargetPtrs != NULL)
    {
        ObjModel_SetBlendChannelTargets(model, 0, -1, -1, 0.0f, 7);
        ObjModel_SetBlendChannelTargets(model, 1, -1, -1, 0.0f, 7);
        ObjModel_SetBlendChannelTargets(model, 2, -1, -1, 0.0f, 7);
    }
}

void objUpdateHitSpheres(u8* hitState, u8* hdrOwner, u8* prevObj, u8* boneMtx, u8* obj)
{
    int off[2];
    u8* prevSphere;
    int i;
    u8* mtx;
    u8* hitReact;
    u8* samples;
    Vec vec;
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
    hitReact = (u8*)((GameObject*)obj)->anim.hitReactState;
    if (hitReact != NULL)
    {
        if (((GameObject*)obj)->anim.modelInstance->hitReactStateCount != 0)
        {
            sampleCount = (int)*(s16*)(hitReact + 4) >> 2;
            if (sampleCount > 0)
            {
                samples = *(u8**)(hitReact + 8);
                idx = (int)(((GameObject*)obj)->anim.currentMoveProgress * sampleCount);
                if (idx >= sampleCount)
                {
                    idx = sampleCount - 1;
                }
                samples = *(u8**)(samples + idx * 4);
                hitSample = samples;
            }
        }
        else
        {
            hitSample = *(void**)(hitReact + 0x48);
        }
    }

    if (((GameObject*)prevObj)->anim.hitReactState != NULL)
    {
        *(u8*)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0xaf) -= 1;
        if (*(s8*)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0xaf) < 0)
        {
            *(u8*)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0xaf) = 0;
        }
        *(u32*)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0x4c) = *(u32*)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0x48);
        *(void**)((u8*)((GameObject*)prevObj)->anim.hitReactState + 0x48) = hitSample;
    }

    st = (ObjHitBufs*)hitState;
    ((ObjModel*)hitState)->bufferFlags ^= 4;
    bufSel = (((ObjModel*)hitState)->bufferFlags >> 2) & 1;
    st->cur = st->bufs[bufSel];
    mtx = boneMtx;
    i = 0;
    off[0] = 0;
    off[1] = off[0];
    prevSphere = st->bufs[bufSel ^ 1];
    for (; i < *(u8*)(hdrOwner + 0xf7); i++)
    {
        if (boneMtx == NULL)
        {
            idx = *(s16*)(((ModelFileHeader*)hdrOwner)->hitVolumes + off[0]);
            cnt = ((ObjModel*)hitState)->file->jointCount;
            if (cnt != 0)
            {
                lim = cnt + ((ObjModel*)hitState)->file->extraJointCount;
            }
            else
            {
                lim = 1;
            }
            if (idx >= lim)
            {
                idx = 0;
            }
            mtx = ((ObjModel*)hitState)->jointMatrices[((ObjModel*)hitState)->bufferFlags & 1] + idx * 0x40;
        }
        if (i == 0 && obj != prevObj)
        {
            zero = 0.0f;
            vec.x = zero;
            vec.y = zero;
            vec.z = zero;
            PSMTXMultVec((MtxPtr)mtx, &vec, &vec);
            ((GameObject*)prevObj)->anim.localPosX = vec.x + playerMapOffsetX;
            ((GameObject*)prevObj)->anim.localPosY = vec.y;
            ((GameObject*)prevObj)->anim.localPosZ = vec.z + playerMapOffsetZ;
            Obj_GetWorldPosition((GameObject*)prevObj, (f32 *)(prevObj + 0x18), (f32 *)(prevObj + 0x1c),
                                 (f32 *)(prevObj + 0x20));
        }
        vec.x = *(f32*)(*(u8**)(hdrOwner + 0x58) + off[0] + 8);
        vec.y = *(f32*)(*(u8**)(hdrOwner + 0x58) + off[0] + 0xc);
        vec.z = *(f32*)(*(u8**)(hdrOwner + 0x58) + off[0] + 0x10);
        *(f32*)(st->cur + off[1]) = *(f32*)(*(u8**)(hdrOwner + 0x58) + off[0] + 4) * (motionScale = ((GameObject*)obj)->anim.rootMotionScale);
        PSMTXMultVec((MtxPtr)mtx, &vec, (Vec*)((st->cur + 4) + off[1]));
        *(f32*)(prevSphere + 4) = (gMapSavedPlayerOffsetX + *(f32*)(prevSphere + 4)) - playerMapOffsetX;
        *(f32*)(prevSphere + 0xc) = (gMapSavedPlayerOffsetZ + *(f32*)(prevSphere + 0xc)) - playerMapOffsetZ;
        off[0] += 0x18;
        off[1] += 0x10;
        prevSphere += 0x10;
    }
}

void ObjModel_SampleJointTransform(ObjModel* model, int b, int idx, f32 t, f32 s, f32* outPos, s16* outRot)
{
    ObjAnimState* ch;
    ObjAnimFrameCommand* saved;
    s16 srot[3];
    int bv;
    u8* anim;

    if (model->file->animationCount == 0)
    {
        f32 z = 0.0f;
        outPos[0] = z;
        outPos[1] = z;
        outPos[2] = z;
        outRot[0] = 0;
        outRot[1] = 0;
        outRot[2] = 0;
    }
    if (b != 0)
    {
        ch = model->animStateB;
    }
    else
    {
        ch = model->animStateA;
    }
    saved = ch->moveFrameData;
    {
        /* the four frame-data pointers (move/prevMove/blend/prevBlend) are
           indexed as one array here; the selected one is swapped into the
           moveFrameData slot for modelRenderInterpolateRootTransform, then restored */
        ObjAnimFrameCommand** p = &ch->moveFrameData;
        ch->moveFrameData = p[idx];
    }
    if (model->file->flags & MODEL_FLAG_VERTEX_ANIM_AREA)
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
        anim = ((u8**)model->file->animationModelPtrs)[p[idx]];
    }
    ch->framePhase = t * ch->frameLength;
    bv = ((u8*)ch->moveFrameData)[2];
    {
        f32 fr = ch->framePhase;
        int n = fr;
        f32 fcv = n;
        if (fcv != fr)
        {
            ch->frameStreamStrides[0] = bv;
        }
        else
        {
            ch->frameStreamStrides[0] = 0;
        }
        if (ch->frameType != 0 && fcv == ch->frameLength - 1.0f)
        {
            ch->frameStreamStrides[0] = (s16)(-bv * n);
        }
        ch->frameStreamCursors[0] = anim + *(s16*)(anim + 2) + bv * n;
    }
    modelRenderInterpolateRootTransform(ch, srot, outRot);
    ch->moveFrameData = saved;
    {
        f32 k = 0.001953125f;
        outPos[0] = k * srot[0];
        outPos[1] = k * srot[1];
        outPos[2] = k * srot[2];
    }
    outPos[0] = outPos[0] + ((ModelBone*)model->file->jointData)->head[0];
    outPos[1] = outPos[1] + ((ModelBone*)model->file->jointData)->head[1];
    outPos[2] = outPos[2] + ((ModelBone*)model->file->jointData)->head[2];
    outPos[0] *= s;
    outPos[1] *= s;
    outPos[2] *= s;
}

void* animLoadFromTable(u8* hdr, int id, int idx, u8* out)
{
    int size;
    int flags;
    int out2;
    u8* buf;
    int stride;

    flags = 0;
    fileLoadToBufferOffset(MLDF_FILEID_PREANIM_TAB, &flags, id * sizeof(u32), 4);
    if (flags & 0x10000000)
    {
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, 0, flags, 0, &size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out, ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    else
    {
        flags = gModelAnimDataOffsetTable[id];
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, flags, 0, &size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out, ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    return buf;
}
void* loadAnimation(ModelFileHeader* hdr, s16 id, int b, u8* bufout)
{
    int tmp;
    int size;
    u8* ptr;
    int animOffset;
    int i;
    u32 ftype;

    if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) != 0 && (ftype = hdr->modelId) != 1 && ftype != 3)
    {
        return 0;
    }
    if (bufout == 0)
    {
        if (ModelList_getHeader(gModelAnimCacheList, (i = id), &ptr) == 0)
        {
            u8* np;
            animOffset = gModelAnimDataOffsetTable[id];
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animOffset, 0, &size, i, 1);
            ptr = np = mmAlloc(size, 10, 0);
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, np, animOffset, size, &tmp, i, 0);
            *ptr = 1;
            modelInitModelList(gModelAnimCacheList, id, &ptr);
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

void* modelFileGetCollisionTriangle(u8* modelFile, int index)
{
    return ((ModelFileHeader*)modelFile)->collisionTriangles + index * 8;
}

void* modelFileGetCollisionBlock(u8* modelFile, int index)
{
    return ((ModelFileHeader*)modelFile)->collisionBlocks + index * 0x14;
}

void* modelFileGetDisplayList(u8* modelFile, int displayListIndex)
{
    return ((ModelFileHeader*)modelFile)->displayLists + displayListIndex * 0x1c;
}

void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out)
{
    ObjModel* model;
    u32 jointCount;
    u8* jointMtx;

    model = (ObjModel*)modelBytes;
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

Texture* ObjModel_GetTexture(ModelFileHeader* model, int textureIndex)
{
    return textureIdxToPtr(model->textureIds[textureIndex]);
}

s16* ObjModel_GetBaseVertexCoords(ModelFileHeader* modelFile, int vertexIndex)
{
    return (s16*)(modelFile->vertices + vertexIndex * 6);
}

Shader* ObjModel_GetRenderOp(ModelFileHeader* model, int renderOpIndex)
{
    return &model->renderOps[renderOpIndex];
}

extern u8* gModelCacheBuffersA[4];
u8* gModelCacheBuffersB[6];

u16 modelFileHeaderGetCullDistance(ModelFileHeader* modelFile)
{
    return modelFile->cullDistance;
}

void ObjModel_ClearRenderAttachment(ObjModel* model)
{
    if (model->renderAttachment != NULL)
    {
        mm_free(model->renderAttachment);
        model->renderAttachment = NULL;
    }
    else
    {
        model->renderCallback = NULL;
    }
}

void ObjModel_EnableDefaultRenderCallback(void* object, ObjModel* model, f32* mtx, int enabled, f32 scale)
{
    if (model->renderAttachment == NULL)
    {
        model->renderCallback = objFrozenRenderCb;
    }
}

s16* ObjModel_GetCurrentVertexCoords(ObjModel* model, int vertexIndex)
{
    return (s16*)(model->vtxBuf[(model->bufferFlags >> 1) & 1] + vertexIndex * 6);
}

void* ObjModel_GetPostRenderCallback(ObjModel* model)
{
    return model->postRenderCallback;
}

void postRenderSetAlphaBlendState(void)
{
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void ObjModel_SetPostRenderCallback(ObjModel* model, void* callback)
{
    model->postRenderCallback = callback;
}

void* ObjModel_GetRenderCallback(ObjModel* model)
{
    return model->renderCallback;
}

void ObjModel_SetRenderCallback(u8* model, void* callback)
{
    ((ObjModel*)model)->renderCallback = callback;
}

void ObjModel_ToggleVertexBuffer(ObjModel* model)
{
    model->bufferFlags ^= 2;
}

/* Per-bone delta-transform opcode bits: a set bit means the X/Y/Z
   component is present (as an s16) in the stream, else it is 0. */

void ObjModel_ToggleMatrixBuffer(ObjModel* model)
{
    model->bufferFlags ^= 1;
}

ObjModelJointMatrix* ObjModel_GetJointMatrix(u8* modelBytes, int jointIndex)
{
    ObjModel* model;
    u32 jointCount;

    model = (ObjModel*)modelBytes;
    jointCount = model->file->jointCount;
    if (jointIndex >= (int)(jointCount != 0 ? jointCount + model->file->extraJointCount : 1))
    {
        jointIndex = 0;
    }

    return (ObjModelJointMatrix*)(model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40);
}

s16 gModelJointScratchBuffer[0xa0];
ModelRenderOpTextureRefs* ObjModel_GetRenderOpTextureRefs(ObjModel* model, int renderOpIndex)
{
    return &model->textureRefs[renderOpIndex];
}

void ObjModel_LoadRenderOpTextures(u8* model, GameObject* object)
{
    int i;
    u8* hdr = (u8*)((ObjModel*)model)->file;
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED)
    {
        return;
    }
    ((ObjModel*)model)->bufferFlags |= OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
    for (i = 0; i < ((ObjModel*)model)->file->renderOpCount; i++)
    {
        shaderInit((u8*)&((ModelFileHeader*)hdr)->renderOps[i], &((ObjModel*)model)->textureRefs[i], object,
                   ((ModelFileHeader*)hdr)->shaderFlags);
    }
}

extern s16 gModelRootRotX;
extern s16 gModelRootRotY;
extern s16 gModelRootRotZ;

static void ObjModel_BuildAnimBlendTable(u8* obj, u8* channel, u8* hdr)
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
        rowA = *(u8**)((u8*)(channel + 0x1c) + ((ObjAnimState*)channel)->moveCacheSlot * 4);
        rowB = *(u8**)((u8*)(channel + 0x1c) + ((ObjAnimState*)channel)->prevMoveCacheSlot * 4);
    }
    else
    {
        rowA = ((ModelFileHeader*)hdr)->animationDataSection + ((ObjAnimState*)channel)->moveCacheSlot * (((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8);
        rowB = ((ModelFileHeader*)hdr)->animationDataSection + ((ObjAnimState*)channel)->prevMoveCacheSlot * (((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8);
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
    gModelJointScratchBuffer[outPos++] = 0x1000;
    gModelJointScratchBuffer[outPos] = 0x1000;
}

void ObjModel_UpdateAnimMatrices(ObjModel* model, ModelFileHeader* blend, GameObject* obj, f32* dst)
{
    ObjAnimState* ch;
    ObjAnimState* ch2;
    f32 pos[3];
    s16 rot[3];

    ObjModel_BuildAnimBlendTable((u8*)obj, (u8*)model->animStateA, (u8*)blend);
    ((ObjModel*)model)->bufferFlags ^= 1;
    ch = ((ObjModel*)model)->animStateA;
    if (ch->moveControlFlags & 4)
    {
        ObjModel_SampleJointTransform((ObjModel*)model, 0, 0, obj->anim.currentMoveProgress,
                                      obj->anim.rootMotionScale, pos, rot);
        gModelRootRotX = rot[0];
        gModelRootRotY = rot[1];
        gModelRootRotZ = rot[2];
    }
    if (model->file->flags & 8)
    {
        modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateA,
                              obj->anim.currentMoveProgress, 0x7f);
    }
    else if (((ObjAnimState*)((ObjModel*)model)->animStateA)->moveControlFlags & OBJANIM_MOVE_CONTROL_REFRESH_SAVED_STEP)
    {
        ch2 = ((ObjModel*)model)->animStateB;
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 0, 2, 0x14,
                             (s16)ch->eventState);
        modelAnimEvalSlotPair((u8*)dst, model, ch2, obj->anim.activeMoveProgress, 0x7f, 0, 0, 2, 0x18,
                             (s16)ch2->eventState);
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 0, 0, 7,
                             (s16)ch2->eventCountdown);
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 1, 1, 1,
                             (s16)ch->eventCountdown);
    }
    else
    {
        modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateA,
                              obj->anim.currentMoveProgress, 0x7f);
        ch2 = ((ObjModel*)model)->animStateB;
        if (ch2 != NULL && obj->anim.activeMove > -1)
        {
            ObjModel_BuildAnimBlendTable((u8*)obj, (u8*)model->animStateB, (u8*)blend);
            modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateB,
                                  obj->anim.activeMoveProgress, -1);
        }
    }
}
void ObjModel_RelocateAnimData(u8* m, u8* dst);

void ObjModel_ResolveRenderOpTextures(u8* m)
{
    int j, k;
    u8* op;
    for (j = 0; j < ((ModelFileHeader*)m)->renderOpCount; j++)
    {
        op = (u8*)&((ModelFileHeader*)m)->renderOps[j];
        for (k = 0; k < ((Shader*)op)->layerCount; k++)
        {
            ShaderLayer* e = &((Shader*)op)->layers[k];
            if (e->textureIndex != -1)
            {
                e->textureIndex = ((ModelFileHeader*)m)->textureIds[e->textureIndex];
            }
            else
            {
                e->texture = NULL;
            }
        }
        if (*(int*)(op + 0x34) != -1)
        {
            *(int*)(op + 0x34) = ((ModelFileHeader*)m)->textureIds[*(int*)(op + 0x34)];
        }
        else
        {
            ((Shader*)op)->auxTexture = NULL;
        }
        if (((Shader*)op)->indTextureId != -1)
        {
            ((Shader*)op)->indTextureId = ((ModelFileHeader*)m)->textureIds[((Shader*)op)->indTextureId];
        }
        else
        {
            ((Shader*)op)->indTexture = NULL;
        }
        if (*(int*)(op + 0x1c) != -1)
        {
            if (*(int*)(op + 0x1c) == -2)
            {
                ((Shader*)op)->unk1C = 0;
            }
            else
            {
                ((Shader*)op)->unk1C = 1;
            }
        }
        else
        {
            ((Shader*)op)->unk1C = 0;
        }
        if (((Shader*)op)->textureId != -1)
        {
            ((Shader*)op)->textureId = ((ModelFileHeader*)m)->textureIds[((Shader*)op)->textureId];
        }
        else
        {
            ((Shader*)op)->textureId = 0;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xc))
        {
            ((Shader*)op)->reg1Texture = NULL;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xe00))
        {
            ((Shader*)op)->reg2Texture = NULL;
        }
    }
}

void* ObjModel_LoadModelData(int id);

void ObjModel_RelocateAnimData(u8* m, u8* dst)
{
    int i;
    ((ModelFileHeader*)m)->vertexAnimEntriesRaw = ((ModelFileHeader*)m)->vertexAnimEntries;
    for (i = 0; i < ((ModelFileHeader*)m)->vertexAnimCount; i++)
    {
        ((ObjModel*)dst)->vertexAnimData[i] = ((ModelVtxAnimChunk*)((ModelFileHeader*)m)->vertexAnimEntries)[i].
            srcDataOffset;
        if (((ModelVtxAnimChunk*)((ModelFileHeader*)m)->vertexAnimEntries)[i].weightStream < ((ModelFileHeader*)m)->
            vertexAnimBase)
        {
            ((ModelVtxAnimChunk*)((ModelFileHeader*)m)->vertexAnimEntries)[i].weightStream =
                ((ModelFileHeader*)m)->vertexAnimBase + (u32)((ModelVtxAnimChunk*)((ModelFileHeader*)m)->
                    vertexAnimEntries)[i].weightStream;
        }
    }
    ((ModelFileHeader*)m)->blendAnimEntriesRaw = ((ModelFileHeader*)m)->blendAnimEntries;
    for (i = 0; i < ((ModelFileHeader*)m)->blendAnimCount; i++)
    {
        ((ObjModel*)dst)->blendAnimData[i] =
            *(int*)&((ObjModel*)dst)->normalBuf + ((ModelVtxAnimChunk*)((ModelFileHeader*)m)->blendAnimEntries)[i].
            srcDataOffset;
        if (((ModelVtxAnimChunk*)((ModelFileHeader*)m)->blendAnimEntries)[i].weightStream < ((ModelFileHeader*)m)->
            blendAnimBase)
        {
            ((ModelVtxAnimChunk*)((ModelFileHeader*)m)->blendAnimEntries)[i].weightStream =
                ((ModelFileHeader*)m)->blendAnimBase + (u32)((ModelVtxAnimChunk*)((ModelFileHeader*)m)->
                    blendAnimEntries)[i].weightStream;
        }
    }
}

void ObjModel_RelocateModelData(u8* m)
{
    int i;
    if (*(u32*)&((ModelFileHeader*)m)->hitVolumes)
    {
        ((ModelFileHeader*)m)->hitVolumes = m + *(u32*)&((ModelFileHeader*)m)->hitVolumes;
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
        if (*(u32*)&((ModelFileHeader*)m)->jointBlendData)
        {
            ((ModelFileHeader*)m)->jointBlendData = m + *(u32*)&((ModelFileHeader*)m)->jointBlendData;
        }
    }
    if (*(u32*)&((ModelFileHeader*)m)->extraJointDefs)
    {
        ((ModelFileHeader*)m)->extraJointDefs = m + *(u32*)&((ModelFileHeader*)m)->extraJointDefs;
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
    if (*(u32*)&((ModelFileHeader*)m)->colors)
    {
        ((ModelFileHeader*)m)->colors = m + *(u32*)&((ModelFileHeader*)m)->colors;
    }
    if (*(u32*)&((ModelFileHeader*)m)->texCoords)
    {
        ((ModelFileHeader*)m)->texCoords = m + *(u32*)&((ModelFileHeader*)m)->texCoords;
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
        ((ModelFileHeader*)m)->morphTargetPtrs = (u8**)(m + *(u32*)&((ModelFileHeader*)m)->morphTargetPtrs);
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
        ((ModelFileHeader*)m)->renderOps = (Shader*)(m + *(u32*)&((ModelFileHeader*)m)->renderOps);
    }
    for (i = 0; i < ((ModelFileHeader*)m)->displayListCount + ((ModelFileHeader*)m)->shadowDisplayListCount; i++)
    {
        *(u8**)(((ModelFileHeader*)m)->displayLists + i * 0x1c) = m + *(u32*)(((ModelFileHeader*)m)->displayLists + i *
            0x1c);
    }
    for (i = 0; i < ((ModelFileHeader*)m)->morphTargetCount; i++)
    {
        ((ModelFileHeader*)m)->morphTargetPtrs[i] = m + *(u32*)&((ModelFileHeader*)m)->morphTargetPtrs[i];
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

void* ObjModel_LoadModelData(int id)
{
    int fileOffset, dataLen, animCount, headerSize, amapFlag;
    int amapSize;
    void* model;
    if (getTableFileEntry(MLDF_FILEID_MODELS_TAB_A, id, &fileOffset) == 0)
    {
        return NULL;
    }
    loadModelsBin(fileOffset, &animCount, &headerSize, &amapFlag, &dataLen, id);
    headerSize = roundUpTo8(headerSize);
    headerSize += 0xb0;
    amapSize = modelGetAmapSize(id, amapFlag, animCount);
    model = (void*)roundUpTo16((int)mmAlloc(dataLen + amapSize + 0x1f4, 9, 0));
    loadAndDecompressDataFile(MLDF_FILEID_MODELS_BIN_A, model, fileOffset, dataLen, 0, id, 0);
    ((ModelFileHeader*)model)->headerSize = headerSize;
    ((ModelFileHeader*)model)->modelId = id;
    ((ModelFileHeader*)model)->animationCount = animCount;
    ((ModelFileHeader*)model)->flags &= ~MODEL_FLAG_VERTEX_ANIM_AREA;
    ((ModelFileHeader*)model)->refCount = 1;
    if (((ModelFileHeader*)model)->animationCount == 0)
    {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_NO_ANIMATIONS;
    }
    if (amapFlag != 0)
    {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_VERTEX_ANIM_AREA;
    }
    return model;
}

void ObjModel_TouchModelCache(void)
{
    u8 buf[8];
    gModelList->iter = gModelList->entries;
    while (gModelList->iter != gModelList->end)
    {
        s16* iter = gModelList->iter;
        if (*iter == -1)
        {
            memset(buf, 0, gModelList->dataSize);
        }
        else
        {
            memcpy(buf, iter + 1, gModelList->dataSize);
        }
        gModelList->iter += gModelList->strideShorts;
    }
}

void ObjModel_Release(u8* model)
{
    u8* header;
    int z[2];
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED)
    {
        ((ObjModel*)model)->bufferFlags &= ~OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
        z[0] = 0;
        for (z[1] = z[0]; z[0] < ((ObjModel*)model)->file->renderOpCount; z[1] += 0xc, z[0]++)
        {
            ShaderDef_free((void**)&((ObjModel*)model)->textureRefs[z[0]]);
        }
    }
    header = (u8*)((ObjModel*)model)->file;
    if (((ObjModel*)model)->renderAttachment != NULL)
    {
        mm_free(((ObjModel*)model)->renderAttachment);
    }
    if (--((ModelFileHeader*)header)->refCount == 0)
    {
        model_adjustModelList(gModelList, ((ModelFileHeader*)header)->modelId); /* modelId */
        z[0] = 0;
        for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->textureCount; z[1] += 4, z[0]++)
        {
            textureFree((Texture*)(textureIdxToPtr(*(s32*)((u8*)((ModelFileHeader*)header)->textureIds + z[1]))));
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
                    model_findIdxInModelList(gModelAnimCacheList, &tex, &idx);
                    model_adjustModelList(gModelAnimCacheList, idx);
                    mm_free(tex);
                }
            }
        }
        mm_free(header);
    }
}

void* ObjModel_LoadAnimData(u8* p, int b, u8* c)
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

void* ObjModel_Load(int id, int loadFlag, int* outSize)
{
    int sizes[7];
    int realId[1];
    u8* header;
    int i[1];
    u8* h[1];
    int off[1];
    void* tex;
    int idc;
    realId[0] = 0;
    i[0] = 0;
    idc = id;
    if (idc < 0)
    {
        realId[0] = -idc;
    }
    else
    {
        fileLoadToBufferOffset(MLDF_FILEID_MODELIND_BIN, gModelResourceBuffer, idc * 2, 8);
        realId[0] = gModelResourceBuffer[0];
    }
    if (ModelList_getHeader(gModelList, realId[0], &header) == 0)
    {
        header = ObjModel_LoadModelData(realId[0]);
        ObjModel_RelocateModelData(header);
        h[0] = header;
        i[0] = 0;
        off[0] = i[0];
        for (; i[0] < h[0][0xf2]; i[0]++)
        {
            tex = textureLoad(-(*(int*)(*(int*)(h[0] + 0x20) + off[0]) | 0x8000), 1);
            *(void**)(*(int*)(h[0] + 0x20) + off[0]) = tex;
            off[0] += 4;
        }
        ObjModel_ResolveRenderOpTextures(header);
        modelLoadAnimations(header, realId[0], header + ((ModelFileHeader*)header)->dataSize);
        modelInitModelList(gModelList, realId[0], &header);
    }
    else
    {
        (*(u8*)header)++;
    }
    *outSize = modelLoad_calcSizes(header, loadFlag, sizes, 0);
    return header;
}

void* loadModelInstance(int resourceId, int arg, void* buffer) { return NULL; }

void ObjModel_InitResourceCaches(void)
{
    void* m;
    int* p;
    gModelList = allocModelStruct(0x8c, (int)sizeof(u8*));
    gModelAnimCacheList = allocModelStruct(0xc4, (int)sizeof(u8*));
    m = mmAlloc(0x830, 0xa, 0);
    gModelResourceBuffer = m;
    gModelAnimOffsetTable = (int*)((u8*)m + 0x800);
    lbl_803DCB5C = (int*)((u8*)m + 0x810);
    p = getCurrentDataFile(MLDF_FILEID_MODELS_TAB_A);
    if (p == NULL)
    {
        return;
    }
    gModelTabEntryCount = 0;
    while (*p != -1)
    {
        p++;
        gModelTabEntryCount++;
    }
    gModelTabEntryCount--;
    gModelAnimDataOffsetTable = getCurrentDataFile(MLDF_FILEID_ANIM_TAB_A);
    if (gModelAnimDataOffsetTable == NULL)
    {
        return;
    }
    lbl_803DCB58 = 0;
}

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

void ObjModel_BlendNormalStream(u8* mtxs, u8* job, u8* animData, u8** outs, int quad)
{
    u16 chunkWords[2];

    setGQR7Packed(job[6], 6, job[6], 6);
    ObjModel_InitScratchBuffers();
    if (((ModelFileHeader*)job)->flags != 0)
    {
        u8* chunk;
        int vtxWords;
        int weightWords;
        u32 i;
        u32 nextSlot;
        u8* chunkDst;
        u8* lastChunk;

        chunk = *(u8**)(job + 0xc);
        vtxWords = (u32)((chunk[0x73] << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + *(int*)(chunk + 0x60), vtxWords);
        chunkWords[0] = vtxWords;
        weightWords = (u32)(((chunk = *(u8**)(job + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + 4), *(u8**)(chunk + 0x64), weightWords);
        for (i = 0; i < (u32)(((ModelFileHeader*)job)->flags - 1); i++)
        {
            int nextVtxWords;

            chunk = *(u8**)(job + 0xc) + i * 0x74;
            nextVtxWords = (u32)((chunk[0xe7] << 5) + 0x1f) >> 5;
            nextSlot = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nextSlot * 2)], animData + *(int*)(chunk + 0xd4), nextVtxWords);
            chunkWords[(i + 1) & 1] = nextVtxWords;
            {
                u8* nextChunk;
                int nextWeightWords = (u32)(((nextChunk = *(u8**)(job + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nextSlot * 2) + 1)], *(u8**)(nextChunk + 0xd8), nextWeightWords);
            }
            cacheQueueWait(2);
            if ((u8)quad)
            {
                chunkDst = outs[i];
                ObjModel_TransformQuadVerticesLinear(mtxs + chunk[0x6c] * 0x30, mtxs + chunk[0x6d] * 0x30,
                                                     gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                     (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                     (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                     *(u16*)(chunk + 0x70));
                memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
            }
            else
            {
                chunkDst = outs[i];
                ObjModel_TransformVerticesLinear(mtxs + chunk[0x6c] * 0x30, mtxs + chunk[0x6d] * 0x30,
                                                 gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                 (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                 (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                 *(u16*)(chunk + 0x70));
                memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
            }
        }
        lastChunk = *(u8**)(job + 0xc) + i * 0x74;
        cacheQueueWait(0);
        if ((u8)quad)
        {
            chunkDst = outs[i];
            ObjModel_TransformQuadVerticesLinear(mtxs + lastChunk[0x6c] * 0x30, mtxs + lastChunk[0x6d] * 0x30,
                                                 gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                 (u8*)(lastChunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                 (u8*)(lastChunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                 *(u16*)(lastChunk + 0x70));
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
        }
        else
        {
            chunkDst = outs[i];
            ObjModel_TransformVerticesLinear(mtxs + lastChunk[0x6c] * 0x30, mtxs + lastChunk[0x6d] * 0x30,
                                             gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                             (u8*)(lastChunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                             (u8*)(lastChunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                             *(u16*)(lastChunk + 0x70));
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
        }
        cacheQueueWait(0);
    }
}

void ObjModel_BlendVertexStream(u8* mtxs, u8* job, u8* animData, int* dstOffsets, u8* dstBase)
{
    u16 chunkWords[2];

    setGQR7Packed(job[6], 7, job[6], 7);
    ObjModel_InitScratchBuffers();
    if (((ModelFileHeader*)job)->flags != 0)
    {
        u8* chunk;
        int vtxWords;
        int weightWords;
        u32 i;
        u32 nextSlot;
        u8* chunkDst;

        chunk = *(u8**)(job + 0xc);
        vtxWords = (u32)((chunk[0x73] << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + *(int*)(chunk + 0x60), vtxWords);
        chunkWords[0] = vtxWords;
        weightWords = (u32)(((chunk = *(u8**)(job + 0xc))[0x6f] << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + 4), *(u8**)(chunk + 0x64), weightWords);
        for (i = 0; i < (u32)(((ModelFileHeader*)job)->flags - 1); i++)
        {
            chunk = *(u8**)(job + 0xc) + i * 0x74;
            vtxWords = (u32)((chunk[0xe7] << 5) + 0x1f) >> 5;
            nextSlot = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nextSlot * 2)], animData + *(int*)(chunk + 0xd4), vtxWords);
            chunkWords[(i + 1) & 1] = vtxWords;
            {
                u8* nextChunk;
                int nextWeightWords = (u32)(((nextChunk = *(u8**)(job + 0xc) + i * 0x74)[0xe3] << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nextSlot * 2) + 1)], *(u8**)(nextChunk + 0xd8), nextWeightWords);
            }
            cacheQueueWait(2);
            chunkDst = dstBase + dstOffsets[i];
            ObjModel_TransformVerticesWithTranslation(mtxs + chunk[0x6c] * 0x30, mtxs + chunk[0x6d] * 0x30,
                                                      gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                      (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                      (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                      *(u16*)(chunk + 0x70));
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
        }
        chunk = *(u8**)(job + 0xc) + i * 0x74;
        cacheQueueWait(0);
        chunkDst = dstBase + dstOffsets[i];
        ObjModel_TransformVerticesWithTranslation(mtxs + chunk[0x6c] * 0x30, mtxs + chunk[0x6d] * 0x30,
                                                  gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                                                  (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                  (u8*)(chunk[0x72] + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                                                  *(u16*)(chunk + 0x70));
        memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkWords[i & 1]);
        cacheQueueWait(0);
    }
}

void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count)
{
    f32* ma = (f32*)m1;
    f32* mb = (f32*)m2;
    u8* w = src;
    s16* in = (s16*)d1;
    s16* out = (s16*)d2;
    f32 scale = (f32)(1 << ((sGQR7Config >> 24) & 0x3f));
    f32 invScale = 1.0f / scale;
    f32 x, y, z, w0, w1, ox, oy, oz;
    int i;

    for (i = 0; i < count; i++)
    {
        w0 = __OSu8tof32(w) * (1.0f / 128.0f);
        w1 = __OSu8tof32(w + 1) * (1.0f / 128.0f);
        w += 2;
        x = __OSs16tof32(&in[0]) * invScale;
        y = __OSs16tof32(&in[1]) * invScale;
        z = __OSs16tof32(&in[2]) * invScale;
        in += 3;
        ox = (ma[0] * x + ma[3] * y + ma[6] * z + ma[9]) * w0 +
             (mb[0] * x + mb[3] * y + mb[6] * z + mb[9]) * w1;
        oy = (ma[1] * x + ma[4] * y + ma[7] * z + ma[10]) * w0 +
             (mb[1] * x + mb[4] * y + mb[7] * z + mb[10]) * w1;
        oz = (ma[2] * x + ma[5] * y + ma[8] * z + ma[11]) * w0 +
             (mb[2] * x + mb[5] * y + mb[8] * z + mb[11]) * w1;
        out[0] = __OSf32tos16(ox * scale);
        out[1] = __OSf32tos16(oy * scale);
        out[2] = __OSf32tos16(oz * scale);
        out += 3;
    }
}

void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count)
{
    f32* ma = (f32*)m1;
    f32* mb = (f32*)m2;
    u8* w = src;
    s8* in = (s8*)d1;
    s8* out = (s8*)d2;
    f32 scale = (f32)(1 << ((sGQR7Config >> 24) & 0x3f));
    f32 invScale = 1.0f / scale;
    f32 x, y, z, w0, w1, ox, oy, oz;
    int i;

    for (i = 0; i < count; i++)
    {
        w0 = __OSu8tof32(w) * (1.0f / 128.0f);
        w1 = __OSu8tof32(w + 1) * (1.0f / 128.0f);
        w += 2;
        x = __OSs8tof32(&in[0]) * invScale;
        y = __OSs8tof32(&in[1]) * invScale;
        z = __OSs8tof32(&in[2]) * invScale;
        in += 3;
        ox = (ma[0] * x + ma[3] * y + ma[6] * z) * w0 + (mb[0] * x + mb[3] * y + mb[6] * z) * w1;
        oy = (ma[1] * x + ma[4] * y + ma[7] * z) * w0 + (mb[1] * x + mb[4] * y + mb[7] * z) * w1;
        oz = (ma[2] * x + ma[5] * y + ma[8] * z) * w0 + (mb[2] * x + mb[5] * y + mb[8] * z) * w1;
        out[0] = __OSf32tos8(ox * scale);
        out[1] = __OSf32tos8(oy * scale);
        out[2] = __OSf32tos8(oz * scale);
        out += 3;
    }
}
void ObjModel_TransformQuadVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count)
{
    f32* ma = (f32*)m1;
    f32* mb = (f32*)m2;
    u8* w = src;
    s8* in = (s8*)d1;
    s8* out = (s8*)d2;
    f32 scale = (f32)(1 << ((sGQR7Config >> 24) & 0x3f));
    f32 invScale = 1.0f / scale;
    f32 x, y, z, w0, w1, ox, oy, oz;
    int i;
    int k;

    for (i = 0; i < count; i++)
    {
        w0 = __OSu8tof32(w) * (1.0f / 128.0f);
        w1 = __OSu8tof32(w + 1) * (1.0f / 128.0f);
        w += 2;
        for (k = 0; k < 3; k++)
        {
            x = __OSs8tof32(&in[0]) * invScale;
            y = __OSs8tof32(&in[1]) * invScale;
            z = __OSs8tof32(&in[2]) * invScale;
            in += 3;
            ox = (ma[0] * x + ma[3] * y + ma[6] * z) * w0 + (mb[0] * x + mb[3] * y + mb[6] * z) * w1;
            oy = (ma[1] * x + ma[4] * y + ma[7] * z) * w0 + (mb[1] * x + mb[4] * y + mb[7] * z) * w1;
            oz = (ma[2] * x + ma[5] * y + ma[8] * z) * w0 + (mb[2] * x + mb[5] * y + mb[8] * z) * w1;
            out[0] = __OSf32tos8(ox * scale);
            out[1] = __OSf32tos8(oy * scale);
            out[2] = __OSf32tos8(oz * scale);
            out += 3;
        }
    }
}

void setGQR6(u32 v)
{
}

void setGQR7(u32 v)
{
    sGQR7Config = v;
}
void setGQR7Packed(int a, int b, int c, int d)
{
    setGQR7((((a << 8) + b) << 16) | ((c << 8) + d));
}

void setGQR6_2(int a, int b, int c, int d)
{
    setGQR6((((a << 8) + b) << 16) | ((c << 8) + d));
}
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize)
{
    ModelRenderInstrsState dstState;
    ModelRenderInstrsState srcState;
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
                srcBits = (u8*)modelRenderCopyPackedSamples(&srcState, &dstState, dst[7], vertBits, t);
            }
            else
            {
                srcBits = modelRenderDecodeAdpcm(srcBits, dst[7], &dstState, vertBits, t);
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

int ObjModel_IsPackedResource(u8* resource) { return 0x0; }

int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize)
{
    return baseSize + resource[8] * resource[7];
}

Vec gModelJitterAxis = { 1.0f, 0.0f, 0.0f };

char sModelAnimationBufferOverflowWarning[] = "Warning: Model animation buffer overflow!! size=%d\n";

u8* gModelCacheBuffersA[4];
