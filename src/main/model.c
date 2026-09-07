#include "main/asset_load.h"
#include "dolphin/mtx.h"
#include "track/intersect_texture_api.h"
#include "track/intersect_depth_state_api.h"
#include "main/hud_visibility_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "main/model.h"
#include "main/joint_pose.h"
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

u16 gModelMorphChunkVertexLimit = 0x2A0;
#define MODEL_MORPH_VERTEX_INDEX_MASK 0x1fff
#define MODEL_MORPH_HAS_X             0x2000
#define MODEL_MORPH_HAS_Y             0x4000
#define MODEL_MORPH_HAS_Z             0x8000
void* animLoadFromTable(u8* hdr, int idx, int a, u8* b);
#define LOADCOLOR_BLOCK(SLOT)                                                                                          \
    {                                                                                                                  \
        int idx;                                                                                                       \
        u32 v;                                                                                                         \
        int sz4;                                                                                                       \
        int unusedSize;                                                                                                \
        int sz;                                                                                                        \
        u8* hp;                                                                                                        \
                                                                                                                       \
        v = (u32)(SLOT);                                                                                               \
        idx = *(s16*)((ModelFileHeader*)hdr)->animationHeaderBuffer;                                                   \
        if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) == 0 || *(u16*)(hdr + 4) == 1 ||                      \
            *(u16*)(hdr + 4) == 3) {                                                                                   \
            if (v == 0) {                                                                                              \
                if (ModelList_getHeader(gModelAnimCacheList, idx, &hp) == 0) {                                         \
                    sz4 = gModelAnimDataOffsetTable[idx];                                                              \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, sz4, 0, &sz, idx, 1);                         \
                    hp = mmAlloc(sz, 10, 0);                                                                           \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, hp, sz4, sz, &unusedSize, idx, 0);               \
                    *hp = 1;                                                                                           \
                    modelInitModelList(gModelAnimCacheList, idx, &hp);                                                 \
                } else {                                                                                               \
                    *hp += 1;                                                                                          \
                }                                                                                                      \
            } else {                                                                                                   \
                animLoadFromTable(hdr, idx, 0, (u8*)v);                                                                \
            }                                                                                                          \
        }                                                                                                              \
    }
extern s16 gModelJointScratchBuffer[0xa0];
#define BLENDTBL_ENTRY(FIELD, OFF)                                                                                     \
    if (poseAdjustments->FIELD != 0) {                                                                                 \
        gModelJointScratchBuffer[outPos++] = (s16)(offA + (OFF));                                                      \
        gModelJointScratchBuffer[outPos++] = (s16)(offB + (OFF));                                                      \
        gModelJointScratchBuffer[outPos++] = poseAdjustments->FIELD;                                                   \
        gModelJointScratchBuffer[outPos++] = poseAdjustments->FIELD;                                                   \
    }
extern char sModelAnimationBufferOverflowWarning[];
extern Vec gModelJitterAxis;

void setGQR7Packed(int a, int b, int c, int d);
u16* modelReadMorphDelta(u16* stream, int* dx, int* dy, int* dz);
static inline void* modelGetBoneMtx(ObjModel* model, int idx);
void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformQuadVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void modelBlendMorphTargetChunk(u8* baseVertices, u8* outVertices, u16 vertexCount, u16** targetA, u16** targetB,
                                int weightB, u16 firstVertex) {
    u16* a = *targetA;
    u16* b = *targetB;
    int i = 0;
    u32 weightA = 0x10000u - (u32)weightB;
    int indexA;
    int indexB;
    int ax, ay, az;
    int bx, by, bz;

    while (i < vertexCount) {
        indexA = (*(s16*)a & MODEL_MORPH_VERTEX_INDEX_MASK) - firstVertex;
        indexB = (*(s16*)b & MODEL_MORPH_VERTEX_INDEX_MASK) - firstVertex;
        if (i >= indexA) {
            if (i == indexB) {
                b = modelReadMorphDelta(b, &bx, &by, &bz);
                a = modelReadMorphDelta(a, &ax, &ay, &az);
                *(u16*)outVertices = (((u32)ax * weightA + (u32)bx * (u32)weightB) >> 16) + *(s16*)baseVertices;
                *(u16*)(outVertices + 2) =
                    (((u32)ay * weightA + (u32)by * (u32)weightB) >> 16) + *(s16*)(baseVertices + 2);
                *(u16*)(outVertices + 4) =
                    (((u32)az * weightA + (u32)bz * (u32)weightB) >> 16) + *(s16*)(baseVertices + 4);
            } else {
                a = modelReadMorphDelta(a, &ax, &ay, &az);
                *(u16*)outVertices = (((u32)ax * weightA) >> 16) + *(s16*)baseVertices;
                *(u16*)(outVertices + 2) = (((u32)ay * weightA) >> 16) + *(s16*)(baseVertices + 2);
                *(u16*)(outVertices + 4) = (((u32)az * weightA) >> 16) + *(s16*)(baseVertices + 4);
            }
        } else if (i >= indexB) {
            b = modelReadMorphDelta(b, &bx, &by, &bz);
            *(u16*)outVertices = (((u32)bx * (u32)weightB) >> 16) + *(s16*)baseVertices;
            *(u16*)(outVertices + 2) = (((u32)by * (u32)weightB) >> 16) + *(s16*)(baseVertices + 2);
            *(u16*)(outVertices + 4) = (((u32)bz * (u32)weightB) >> 16) + *(s16*)(baseVertices + 4);
        } else {
            *(u32*)outVertices = *(u32*)baseVertices;
            *(u16*)(outVertices + 4) = *(s16*)(baseVertices + 4);
        }
        baseVertices += 6;
        outVertices += 6;
        i++;
    }
    *targetA = a;
    *targetB = b;
}

u16* modelReadMorphDelta(u16* stream, int* dx, int* dy, int* dz) {
    u16 flags = *stream;

    stream++;
    *dx = 0;
    if (flags & MODEL_MORPH_HAS_X) {
        *dx = *(s16*)stream;
        stream++;
    }
    *dy = 0;
    if (flags & MODEL_MORPH_HAS_Y) {
        *dy = *(s16*)stream;
        stream++;
    }
    *dz = 0;
    if (flags & MODEL_MORPH_HAS_Z) {
        *dz = *(s16*)stream;
        stream++;
    }
    return stream;
}

void modelAnimUpdateChannels(ModelFileHeader* file, ObjAnimState* work, int channelCount) {
    int i;
    u8* mtxSlotRow;
    int frameStride;
    u8* frameStream;
    int boneByteOff;
    int boneIdx;
    int frameIdx;
    int streamOff;
    f32 frameIdxF;

    for (i = 0; i < channelCount; i++) {
        if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
            frameStream = work->cachedMoves[work->cacheSlots[i]];
            mtxSlotRow = frameStream;
            frameStream += 0x80;
        } else {
            mtxSlotRow = file->animationDataSection + work->cacheSlots[i] * (((file->jointCount - 1) & ~7) + 8);
            frameStream = ((u8**)file->animationModelPtrs)[work->cacheSlots[i]];
        }
        frameStride = work->frameData[i]->frameStride;
        boneIdx = 0;
        boneByteOff = 0;
        while (boneIdx < file->jointCount) {
            (file->jointData + boneByteOff)[offsetof(ModelBone, idx) + i + 1] = mtxSlotRow[boneIdx];
            boneByteOff += sizeof(ModelBone);
            boneIdx++;
        }
        frameIdx = (int)work->framePhases[i];
        frameIdxF = frameIdx;
        if (frameIdxF != work->framePhases[i]) {
            work->frameStreamStrides[i] = frameStride;
        } else {
            work->frameStreamStrides[i] = 0;
        }
        if (work->frameTypes[i] != 0 && frameIdxF == work->frameLengths[i] - 1.0f) {
            work->frameStreamStrides[i] = (s16)(-frameStride * frameIdx);
        }
        streamOff = ((ObjAnimMoveData*)frameStream)->frameStreamOffset;
        work->frameStreamCursors[i] = frameStream + streamOff + frameStride * frameIdx;
    }
}

void modelAnimEvalSlotPair(u8* dst, ObjModel* model, ObjAnimState* channel, f32 t, int flags, int slotA, int slotB,
                           int blendSel, int mode, s16 eventVal) {
    ObjAnimState work;
    int mtxBuf;
    ModelFileHeader* file;
    u32 idxA;
    u8 idxB;

    file = model->file;
    mtxBuf = (int)model->jointMatrices[model->bufferFlags & 1];
    if ((u8)mode & 0x10) {
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
    if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
        work.cacheSlots[0] = 0;
        work.cacheSlots[1] = 1;
        work.cachedMoves[0] = channel->cachedMoves[channel->cacheSlots[idxA]];
        if (idxB < 2) {
            work.cachedMoves[1] = channel->cachedMoves[channel->cacheSlots[idxB]];
        } else {
            work.cachedMoves[1] = channel->cachedMoves[2 + channel->cacheSlots[idxB]];
        }
    } else {
        work.cacheSlots[0] = channel->cacheSlots[idxA];
        work.cacheSlots[1] = channel->cacheSlots[idxB];
    }
    if (eventVal == 0) {
        eventVal = 1;
    }
    work.eventCountdown = eventVal;
    modelAnimUpdateChannels(file, &work, 2);
    {
        int modeLow = mode & 0xF;
        mode = modeLow;
        if ((modeLow & 0xC) == 0) {
            int sv = channel->moveControlFlags;
            if (sv & 1) {
                mode = (modeLow | 0x10) & 0xFF;
            }
            if (sv & 4) {
                mode = (mode | 0x20) & 0xFF;
            }
        }
    }
    modelAnimBuildJointMatrices(&mtxBuf, dst, &work, file->jointData, file->jointCount, (u8*)gModelJointScratchBuffer,
                                flags, (u8)mode);
}
void modelAnimEvalChannels(u8* dst, ObjModel* model, ObjAnimState* channel, f32 blend, int flags) {
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
    if (file->flags & 8) {
        work.cachedMoves[0] = channel->cachedMoves[0];
        work.cachedMoves[1] = channel->cachedMoves[1];
        work.cachedMoves[2] = channel->cachedMoves[2];
        work.cachedMoves[3] = channel->cachedMoves[3];
        for (j = 0; j < 2; j++) {
            if (channel->eventCountdown != 0) {
                srcSlot = j;
            } else {
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
        if (ctrlFlags & 1) {
            outFlags |= 0x10;
        }
        if (ctrlFlags & 4) {
            outFlags |= 0x20;
        }
        modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                    (u8*)gModelJointScratchBuffer, flags, outFlags | 0x40);
    } else {
        int i;
        int blendMask;

        for (i = 0; i < 2; i++) {
            if (i != 0) {
                slotEvent = channel->prevEventState;
            } else {
                slotEvent = channel->eventState;
            }
            if (slotEvent != 0) {
                if (channel->eventCountdown != 0) {
                    blendMask = 4 << i;
                } else {
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
                if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
                    work.cacheSlots[0] = 0;
                    work.cacheSlots[1] = 1;
                    work.cachedMoves[0] = channel->cachedMoves[channel->cacheSlots[i]];
                    work.cachedMoves[1] = channel->cachedMoves[2 + channel->cacheSlots[i + 2]];
                } else {
                    work.cacheSlots[0] = channel->cacheSlots[i];
                    work.cacheSlots[1] = channel->cacheSlots[i + 2];
                }
                work.eventCountdown = slotEvent;
                modelAnimUpdateChannels(file, &work, 2);
                modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                            (u8*)gModelJointScratchBuffer, flags, blendMask);
                if (blendMask != 0) {
                    outFlags |= 1 << i;
                }
            }
        }
        if ((channel->eventStates[0] == 0 && channel->eventStates[1] == 0) || outFlags != 0) {
            slotCount = 1;
            if (channel->eventCountdown != 0) {
                slotCount = 2;
            }
            work.cachedMoves[0] = channel->cachedMoves[0];
            work.cachedMoves[1] = channel->cachedMoves[1];
            work.cachedMoves[2] = channel->cachedMoves[2];
            work.cachedMoves[3] = channel->cachedMoves[3];
            j = 0;
            while (j < slotCount) {
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
            if (ctrlFlags & 1) {
                outFlags |= 0x10;
            }
            if (ctrlFlags & 4) {
                outFlags |= 0x20;
            }
            modelAnimBuildJointMatrices((int*)&mtxBuf, dst, &work, file->jointData, file->jointCount,
                                        (u8*)gModelJointScratchBuffer, flags, outFlags);
        }
    }
}

void* ObjAnim_LoadCachedMove(int animId, int moveIndex, u8* cache, ObjAnimDef* animDef) {
    void* out = NULL;
    animationLoad(&out, animId, moveIndex, cache, animDef);
    return out;
}

void modelAnimResetState(void* m, void* data) {
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
    if (((ModelFileHeader*)hdr)->animationCount != 0) {
        if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
            LOADCOLOR_BLOCK(channel->moveCache[0])
            LOADCOLOR_BLOCK(channel->moveCache[1])
            LOADCOLOR_BLOCK(channel->blendMoveCache[0])
            LOADCOLOR_BLOCK(channel->blendMoveCache[1])
            channel->moveCacheSlot = 0;
            mdl = channel->moveCache[channel->moveCacheSlot] + 0x80;
        } else {
            mdl = ((u8**)((ModelFileHeader*)hdr)->animationModelPtrs)[channel->moveCacheSlot];
        }
        channel->moveFrameData = (ObjAnimFrameHeader*)((ObjAnimMoveData*)mdl)->frameCommands;
        channel->frameType = (s8)(*(u8*)(mdl + 1) & 0xf0);
        channel->frameLength = (f32)channel->moveFrameData->frameCount;
        if (channel->frameType == 0) {
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
int modelLoadAnimations(ModelFileHeader* file, int modelId, void* animBase) {
    int modelAnimOffset;
    u8* bufferCursor = animBase;
    s16* offsetTable;
    int modelAnimBytes;
    int animationOffset;
    int groupSlot;
    int i;
    int animIdx;
    int bufferBytes;
    int animId;
    int amapOffset;
    int cacheIndex;
    u8* cacheEntry;
    int unusedSize;
    int animationBytes;
    u8* animation;
    u8* loadedAnimation;
    u8 newRefCount;

    bufferBytes = 0;
    offsetTable = (s16*)gModelAnimOffsetTable;
    fileLoadToBufferOffset(MLDF_FILEID_MODANIM_TAB, offsetTable, modelId << 1, 0x10);
    modelAnimOffset = offsetTable[0];
    if (file->animationCount == 0) {
        return 0;
    }
    modelAnimBytes = (file->animationCount << 1) + 8;
    if (modelAnimBytes > 0x800) {
        debugPrintf(sModelAnimationBufferOverflowWarning, modelAnimBytes);
    }
    fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (modelId & ~3) << 2, 0x20);
    file->animationDataFileOffset = gModelAnimOffsetTable[modelId & 3];
    amapOffset = gModelAnimOffsetTable[modelId & 3];
    modelId = gModelAnimOffsetTable[(modelId & 3) + 1] - amapOffset;
    if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
        file->animationHeaderBuffer = bufferCursor;
        while (modelAnimBytes & 7) {
            modelAnimBytes++;
        }
        bufferBytes = modelAnimBytes;
        bufferCursor += modelAnimBytes;
        fileLoadToBufferOffset(MLDF_FILEID_MODANIM_BIN, file->animationHeaderBuffer, modelAnimOffset, modelAnimBytes);
    } else {
        fileLoadToBufferOffset(MLDF_FILEID_MODANIM_BIN, gModelResourceBuffer, modelAnimOffset, modelAnimBytes);
        file->animationHeaderBuffer = (u8*)gModelResourceBuffer;
    }
    groupSlot = 0;
    file->animGroupBaseIndices[groupSlot++] = 0;
    i = 0;
    for (; i < (int)file->animationCount; i++) {
        if (file->cachedAnimIds[i] == OBJANIM_MISSING_MOVE_ID) {
            file->animGroupBaseIndices[groupSlot++] = (s16)(i + 1);
        }
    }
    if ((file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) == 0) {
        file->animationHeaderBuffer = NULL;
        file->animationModelPtrs = bufferCursor;
        bufferCursor += file->animationCount * (int)sizeof(u8*);
        bufferBytes += file->animationCount * (int)sizeof(u8*);
        while (bufferBytes & 7) {
            bufferCursor++;
            bufferBytes++;
        }
        file->animationDataSection = bufferCursor;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, file->animationDataSection, file->animationDataFileOffset,
                               modelId);
        animIdx = 0;
        do {
            animId = gModelResourceBuffer[animIdx];
            if (animId != OBJANIM_MISSING_MOVE_ID) {
                if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) && file->modelId != 1 && file->modelId != 3) {
                    loadedAnimation = 0;
                } else {
                    if (ModelList_getHeader(gModelAnimCacheList, animId, &animation) == 0) {
                        animationOffset = gModelAnimDataOffsetTable[animId];
                        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animationOffset, 0, &animationBytes,
                                                  animId, 1);
                        animation = mmAlloc(animationBytes, 10, 0);
                        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, animation, animationOffset, animationBytes,
                                                  &unusedSize, animId, 0);
                        *animation = 1;
                        modelInitModelList(gModelAnimCacheList, animId, &animation);
                    } else {
                        *animation += 1;
                    }
                    loadedAnimation = animation;
                }
                ((u8**)file->animationModelPtrs)[animIdx] = loadedAnimation;
                if (((u8**)file->animationModelPtrs)[animIdx] == 0) {
                    int relIdx;

                    relIdx = 0;
                    for (; relIdx < animIdx; relIdx++) {
                        cacheEntry = ((u8**)file->animationModelPtrs)[relIdx];
                        if (cacheEntry != 0) {
                            newRefCount = (*cacheEntry -= 1);
                            if ((s8)newRefCount <= 0) {
                                model_findIdxInModelList(gModelAnimCacheList, &cacheEntry, &cacheIndex);
                                model_adjustModelList(gModelAnimCacheList, cacheIndex);
                                mm_free(cacheEntry);
                            }
                        }
                    }
                    file->animationModelPtrs = NULL;
                    return 1;
                }
            } else {
                ((u8**)file->animationModelPtrs)[animIdx] = NULL;
            }
            animIdx++;
        } while (animIdx < (int)file->animationCount);
    } else {
        file->animationModelPtrs = NULL;
    }
    return 0;
}
int modelGetAmapSize(int modelId, int amapFlag, int animCount) {
    int amapSize;
    int totalSize;
    int index;

    totalSize = 0;
    if (amapFlag != 0) {
        totalSize += animCount * 2 + 8;
        while (totalSize & 7) {
            totalSize++;
        }
    } else {
        totalSize += animCount * (int)sizeof(u8*);
        while (totalSize & 7) {
            totalSize++;
        }
        index = modelId & 3;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (modelId & ~3) << 2, 0x20);
        amapSize = gModelAnimOffsetTable[index + 1] - gModelAnimOffsetTable[index];
        totalSize += amapSize;
    }
    return totalSize;
}

int modelLoad_calcSizes(void* model, int flags, int* sizes, int forceBlendChannels) {
    u8* hdr = model;
    int total;
    int va;

    if (((ModelFileHeader*)hdr)->animationCount != 0) {
        sizes[6] = ((u32)((ModelFileHeader*)hdr)->jointCount + (u32)((ModelFileHeader*)hdr)->extraJointCount) * 0x80;
    } else {
        sizes[6] = 0x80;
    }
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || ((ModelFileHeader*)hdr)->vertexAnimEntries != 0 ||
        (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS) != 0) {
        sizes[0] = (u32)((ModelFileHeader*)hdr)->vertexCount * 0xc + 0x60;
    } else {
        sizes[0] = 0;
    }
    if (((ModelFileHeader*)hdr)->normalAnimEntries != 0) {
        int normalStride;
        if (((ModelFileHeader*)hdr)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE) {
            normalStride = 9;
        } else {
            normalStride = 3;
        }
        sizes[0] += ((ModelFileHeader*)hdr)->normalCount * normalStride + 0x40;
    }
    {
        int hitSphereBytes = ((ModelFileHeader*)hdr)->hitVolumeCount * sizeof(ObjModelHitSphere);
        sizes[1] = hitSphereBytes << 1;
    }
    sizes[3] = 0;
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) != 0) {
        sizes[5] = ((ModelFileHeader*)hdr)->headerSize;
        while ((sizes[5] & 7) != 0) {
            *(int*)((int)sizes + 0x14) = *(int*)((int)sizes + 0x14) + 1;
        }
        sizes[3] = sizes[5] << 2;
    }
    sizes[4] = (int)sizeof(ObjAnimState);
    if ((flags & 0x80) != 0) {
        sizes[4] = sizes[4] << 1;
        sizes[3] = sizes[3] << 1;
    }
    if (((ModelFileHeader*)hdr)->morphTargetCount != 0 || forceBlendChannels != 0) {
        sizes[4] = sizes[4] + sizeof(ObjModelBlendChannel) * 3;
        total = sizes[3] + sizes[4] + (int)sizeof(ObjModel);
        total = (sizes[6] + sizes[1] + 8) + total;
    } else {
        total = sizes[4] + (int)sizeof(ObjModel);
        total = (sizes[3] + sizes[6] + sizes[1] + 8) + total;
    }
    total += sizes[0];
    if (((ModelFileHeader*)hdr)->jointData != 0 && ((ModelFileHeader*)hdr)->jointCount != 0 &&
        ((ModelFileHeader*)hdr)->unk18 != 0) {
        total = ((u32)((ModelFileHeader*)hdr)->jointCount << 1) +
                (((u32)((ModelFileHeader*)hdr)->jointCount * 7) << 2) + (int)sizeof(ModelJointWork) + total;
    }
    if (((ModelFileHeader*)hdr)->vertexAnimEntries != 0) {
        total = (va = (u32)((ModelFileHeader*)hdr)->vertexAnimJob.chunkCount * 4, va + total);
        total += 4;
    }
    if (((ModelFileHeader*)hdr)->normalAnimEntries != 0) {
        total = (va = (u32)((ModelFileHeader*)hdr)->normalAnimJob.chunkCount * 4, va + total);
        total += 4;
    }
    total += (u32)((ModelFileHeader*)hdr)->renderOpCount * (int)sizeof(ModelRenderOpTextureRefs);
    if ((flags & 0x8000) != 0) {
        total += (int)sizeof(GroundShadowQuad);
    }
    return roundUpTo32(((total + 0x2f) & ~0xf) + 0x10);
}

static inline int modelGetJointMatrixCount(const ObjModel* model) {
    const ModelFileHeader* file = model->file;

    if (file->jointCount != 0) {
        return file->jointCount + file->extraJointCount;
    }
    return 1;
}

static inline void* modelGetBoneMtx(ObjModel* model, int idx) {
    int joint = idx;
    u8* base;

    if (joint >= modelGetJointMatrixCount(model)) {
        joint = 0;
    }
    base = model->jointMatrices[model->bufferFlags & 1];
    return base + joint * sizeof(ObjModelJointMatrix);
}

void* modelLoad_layoutBuffers(u8* p, int b, int isType1, u8* c) {
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
    if (p == 0) {
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
    if (((ModelFileHeader*)p)->morphTargetCount != 0 || ((ModelFileHeader*)p)->vertexAnimEntries != NULL ||
        (((ModelFileHeader*)p)->flags & MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS)) {
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
    } else {
        end = *(int*)&((ModelFileHeader*)p)->vertices;
        *(int*)&((ObjModel*)out)->vtxBuf[1] = end;
        *(int*)&((ObjModel*)out2)->vtxBuf[0] = end;
    }
    if (((ModelFileHeader*)p)->normalAnimEntries != NULL) {
        if (((ModelFileHeader*)p)->flags24 & MODEL_FLAGS24_NORMALS_9BYTE) {
            normalStride = 9;
        } else {
            normalStride = 3;
        }
        pos = roundUpTo32(pos);
        *(int*)&((ObjModel*)out2)->normalBuf = pos;
        end = pos + ((ModelFileHeader*)p)->normalCount * normalStride;
        memcpy(((ObjModel*)out2)->normalBuf, ((ModelFileHeader*)p)->normals,
               ((ModelFileHeader*)p)->normalCount * normalStride);
        DCFlushRange(((ObjModel*)out2)->normalBuf, normalStride * ((ModelFileHeader*)p)->normalCount);
        pos = roundUpTo32(end);
    } else {
        ((ObjModel*)out2)->normalBuf = ((ModelFileHeader*)p)->normals;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out2)->animStateA = pos;
    pos += 0x68;
    if (b & 0x80) {
        *(int*)&((ObjModel*)out2)->animStateB = pos;
        pos += 0x68;
    }
    if (((ModelFileHeader*)p)->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
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
        if (q != 0) {
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
    if (((ModelFileHeader*)p)->morphTargetCount != 0) {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->blendChannels = pos;
        pos += sizeof(ObjModelBlendChannel) * 3;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)->morphTargetA = -1;
        ((ObjModelBlendChannel*)q)->morphTargetB = -1;
        f = 0.0f;
        ((ObjModelBlendChannel*)q)->weight = f;
        ((ObjModelBlendChannel*)q)->previousWeight = f;
        ((ObjModelBlendChannel*)q)->weightRate = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)[1].morphTargetA = -1;
        ((ObjModelBlendChannel*)q)[1].morphTargetB = -1;
        ((ObjModelBlendChannel*)q)[1].weight = f;
        ((ObjModelBlendChannel*)q)[1].previousWeight = f;
        ((ObjModelBlendChannel*)q)[1].weightRate = f;
        q = (u8*)((ObjModel*)out2)->blendChannels;
        ((ObjModelBlendChannel*)q)[2].morphTargetA = -1;
        ((ObjModelBlendChannel*)q)[2].morphTargetB = -1;
        ((ObjModelBlendChannel*)q)[2].weight = f;
        ((ObjModelBlendChannel*)q)[2].previousWeight = f;
        ((ObjModelBlendChannel*)q)[2].weightRate = f;
    }
    if (szs[1] > 0) {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[0] = pos;
        o2 = ((ModelFileHeader*)p)->hitVolumeCount;
        pos += o2 * sizeof(ObjModelHitSphere);
        *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[1] = pos;
        pos += ((ModelFileHeader*)p)->hitVolumeCount * sizeof(ObjModelHitSphere);
        *(int*)&((ObjModel*)out2)->activeHitVolumeSpheres = *(int*)&((ObjModel*)out2)->hitVolumeSphereBuffers[0];
    }
    if (((ModelFileHeader*)p)->jointData != NULL && ((ModelFileHeader*)p)->jointCount != 0 &&
        ((ModelFileHeader*)p)->unk18 != NULL && ((ModelFileHeader*)p)->unk1C != NULL) {
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
    } else {
        *(int*)&((ObjModel*)out2)->skeletonJointData = 0;
    }
    if (((ModelFileHeader*)p)->vertexAnimEntries != NULL) {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->vertexAnimOffsets = pos;
        pos += ((ModelFileHeader*)p)->vertexAnimJob.chunkCount * 4;
    }
    if (((ModelFileHeader*)p)->normalAnimEntries != NULL) {
        pos = roundUpTo4(pos);
        *(int*)&((ObjModel*)out2)->normalAnimOutputs = pos;
        pos += ((ModelFileHeader*)p)->normalAnimJob.chunkCount * 4;
    }
    pos = roundUpTo4(pos);
    *(int*)&((ObjModel*)out2)->textureRefs = pos;
    pos += ((ModelFileHeader*)p)->renderOpCount * sizeof(ModelRenderOpTextureRefs);
    k = 0;
    o2 = 0;
    for (; k < (int)((ModelFileHeader*)p)->renderOpCount; k++) {
        ((ObjModel*)out2)->textureRefs[k].swapSelector = 0;
    }
    if (b & 0x8000) {
        pos = alignUp2(pos);
        ((ObjModel*)out2)->groundShadowQuad = (GroundShadowQuad*)pos;
        ((ObjModel*)out2)->groundShadowQuad->status = 0;
    }
    ((ObjModel*)out2)->renderAttachment = NULL;
    ((ObjModel*)out2)->file = (ModelFileHeader*)p;
    ((ObjModel*)out2)->vtxBufDirty = 0;
    return out2;
}

static void modelChainUpdateNodesPassive(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                                         ObjModelChainEntry* entry) {
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
    for (i = 1; i < entry->nodeCount + 1; i++) {
        nextIdx = entry->desc->jointIndices[i];
        PSMTXMultVec(tmp, &entry->nodes[i - 1].localOffset, &out);
        target.x = entry->nodes[i].pos.x + entry->nodes[i].posDelta.x + gMapSavedPlayerOffsetX - playerMapOffsetX;
        target.y = entry->nodes[i].pos.y + entry->nodes[i].posDelta.y;
        target.z = entry->nodes[i].pos.z + entry->nodes[i].posDelta.z + gMapSavedPlayerOffsetZ - playerMapOffsetZ;
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
        if (dot < 0.999f && dot > -0.999f) {
            if (dot < 1.0f && dot > -1.0f) {
                PSVECCrossProduct(&dir2, &dir1, &axis);
                if (dot < -1.0f) {
                    dot = -1.0f;
                } else {
                    f32 sub = 1.0f - dot;
                    dot = sub * chain->stiffness + dot;
                }
                PSMTXTranspose(tmp, mt);
                PSMTXMultVecSR(mt, &axis, &axis);
                PSMTXRotAxisRad(m, &axis, acosf(dot));
            } else {
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
        if (i < entry->nodeCount) {
            m = modelGetBoneMtx(model, nextIdx);
        }
    }
}
static void modelChainUpdateNodes(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                                  ObjModelChainEntry* entry, ObjModelChainUpdateCallback callback, int callbackArg) {
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
    for (i = 1; i < entry->nodeCount + 1; i++) {
        nextIdx = entry->desc->jointIndices[i];
        PSMTXMultVec(tmp, &entry->nodes[i - 1].localOffset, &out);
        target.x = entry->nodes[i].pos.x + entry->nodes[i].posDelta.x + gMapSavedPlayerOffsetX - playerMapOffsetX;
        target.y = entry->nodes[i].pos.y + entry->nodes[i].posDelta.y;
        target.z = entry->nodes[i].pos.z + entry->nodes[i].posDelta.z + gMapSavedPlayerOffsetZ - playerMapOffsetZ;
        work.x = entry->nodes[i - 1].localOffset.x;
        work.y = entry->nodes[i - 1].localOffset.y;
        work.z = entry->nodes[i - 1].localOffset.z;
        if (callback != NULL) {
            callback(file, model, (f32*)&work, callbackArg, i, chain->phase);
        }
        PSVECAdd(&work, &entry->nodes[i].localOffset, &work);
        PSMTXMultVec(tmp, &work, &work);
        PSVECSubtract(&target, &out, &dir1);
        PSVECNormalize(&dir1, &dir1);
        PSVECSubtract(&work, &out, &dir2);
        PSVECNormalize(&dir2, &dir2);
        dot = PSVECDotProduct(&dir2, &dir1);
        if (dot < 0.999f && dot > -0.999f) {
            PSVECCrossProduct(&dir2, &dir1, &axis);
            if (dot < -1.0f) {
                dot = -1.0f;
            } else {
                f32 sub = 1.0f - dot;
                dot = sub * chain->stiffness + dot;
            }
            PSMTXTranspose(tmp, mt);
            PSMTXMultVecSR(mt, &axis, &axis);
            PSMTXRotAxisRad(m, &axis, acosf(dot));
        } else {
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
        if (i < entry->nodeCount) {
            m = modelGetBoneMtx(model, nextIdx);
        }
        entry->nodes[i].posDelta.x = work.x - (gMapSavedPlayerOffsetX + entry->nodes[i].pos.x - playerMapOffsetX);
        entry->nodes[i].posDelta.y = work.y - entry->nodes[i].pos.y;
        entry->nodes[i].posDelta.z = work.z - (gMapSavedPlayerOffsetZ + entry->nodes[i].pos.z - playerMapOffsetZ);
        entry->nodes[i].pos.x = work.x;
        entry->nodes[i].pos.y = work.y;
        entry->nodes[i].pos.z = work.z;
    }
}
static void modelChainApplyDampingAndJitter(ObjModel* model, ModelFileHeader* unused, ObjModelChain* chain,
                                            ObjModelChainEntry* entry) {
    Vec vec;
    int modelIndex;
    ModelFileHeader* hdr;
    u32 count;
    int total;
    ObjModelJointMatrix* jointMtx;
    f32 dot;
    f32 scaled;
    f32 amp;
    int i;

    modelIndex = 0;
    hdr = model->file;
    count = hdr->jointCount;
    if (count != 0) {
        total = count + hdr->extraJointCount;
    } else {
        total = 1;
    }
    if (modelIndex >= total) {
        modelIndex = 0;
    }
    jointMtx = &((ObjModelJointMatrix*)model->jointMatrices[model->bufferFlags & 1])[modelIndex];
    vec.x = jointMtx->row2[0];
    vec.y = jointMtx->row2[1];
    vec.z = jointMtx->row2[2];
    dot = PSVECDotProduct(&vec, &gModelJitterAxis);
    if (dot < 0.0f) {
        dot = 0.0f;
    }
    scaled = gModelChainJitterScale * (1.2f - dot);
    amp = 0.01f * randomGetRange((int)(75.0f * scaled), (int)(100.0f * scaled));
    i = 0;
    while (i < entry->nodeCount + 1) {
        ObjModelChainNode* node = &entry->nodes[i];
        node->posDelta.x = node->posDelta.x * chain->damping + gModelJitterAxis.x * amp;
        node->posDelta.y = gModelJitterAxis.y * amp + (node->posDelta.y * chain->damping + chain->gravityY);
        node->posDelta.z = node->posDelta.z * chain->damping + gModelJitterAxis.z * amp;
        i++;
    }
}

static void modelChainInitNodesFromJoints(ObjModel* model, ModelFileHeader* file, ObjModelChainEntry* entry) {
    int i;

    i = 0;
    for (; i < entry->nodeCount; i++) {
        int jointIdx = entry->desc->jointIndices[i];
        ObjModelChainNode* node = &entry->nodes[i];
        node->localOffset.x = ((ModelBone*)file->jointData)[jointIdx].head[0];
        node->localOffset.y = ((ModelBone*)file->jointData)[jointIdx].head[1];
        node->localOffset.z = ((ModelBone*)file->jointData)[jointIdx].head[2];

        node->pos.x = ((ObjModelJointMatrix*)modelGetBoneMtx(model, jointIdx))->translationX;
        node->pos.y = ((ObjModelJointMatrix*)modelGetBoneMtx(model, jointIdx))->translationY;
        node->pos.z = ((ObjModelJointMatrix*)modelGetBoneMtx(model, jointIdx))->translationZ;
    }
    {
        int lastJointIdx;
        ObjModelChainNode* lastNode = &entry->nodes[i];
        f32 zero = 0.0f;

        lastNode->localOffset.x = zero;
        lastNode->localOffset.y = zero;
        lastNode->localOffset.z = 100.0f;
        {
            s32* jointIdxArr = entry->desc->jointIndices;
            lastJointIdx = jointIdxArr[entry->nodeCount - 1];
        }
        PSMTXMultVec(modelGetBoneMtx(model, lastJointIdx), &lastNode->localOffset, &lastNode->pos);
    }
}

void ObjModelChain_Update(ObjModel* model, ModelFileHeader* file, ObjModelChain* chain,
                          ObjModelChainUpdateCallback callback) {
    int i;

    if (chain->enabled != 0) {
        i = 0;
        for (; i < chain->count; i++) {
            if (chain->firstUpdateDone == 0) {
                modelChainInitNodesFromJoints(model, file, &chain->entries[i]);
            }
            if (getHudHiddenFrameCount() == 0) {
                modelChainApplyDampingAndJitter(model, file, chain, &chain->entries[i]);
                modelChainUpdateNodes(model, file, chain, &chain->entries[i], callback, i);
            } else {
                modelChainUpdateNodesPassive(model, file, chain, &chain->entries[i]);
            }
        }
        chain->updatedThisFrame = 1;
        chain->firstUpdateDone = 1;
    }
}

void ObjModelChain_SetEnabled(ObjModelChain* chain, u8 enabled) {
    chain->enabled = enabled;
}
void ObjModelChain_SetOrigin(ObjModelChain* chain, f32 x, f32 y, f32 z) {
    chain->stiffness = x;
    chain->damping = y;
    chain->gravityY = z;
}
void ObjModelChain_ResetFirstUpdate(ObjModelChain* chain) {
    chain->firstUpdateDone = 0;
}

void ObjModelChain_AdvancePhase(ObjModelChain* chain) {
    chain->updatedThisFrame = 0;
    chain->phase += timeDelta;
    if (chain->phase > 1000.0f) {
        chain->phase -= 1000.0f;
    }
}

extern const f32 gModelVertexScale;

void ObjModelChain_Free(ObjModelChain* chain) {
    int i;
    for (i = 0; i < chain->count; i++) {
        mm_free(chain->entries[i].nodes);
    }
    mm_free(chain->entries);
    mm_free(chain);
}

ObjModelChain* ObjModelChain_Alloc(void* models, int count) {
    ObjModelChainDesc** desc;
    int off;
    ObjModelChain* state;
    int i;

    state = mmAlloc(sizeof(ObjModelChain), 0x1a, 0);
    state->count = count;
    state->firstUpdateDone = 0;
    state->updatedThisFrame = 0;
    state->entries = mmAlloc(count * sizeof(ObjModelChainEntry), 0x1a, 0);
    i = 0;
    desc = models;
    off = 0;
    for (; i < count; i++) {
        ((ObjModelChainEntry*)((u8*)state->entries + off))->desc = *desc;
        ((ObjModelChainEntry*)((u8*)state->entries + off))->nodeCount = (*desc)->nodeCount;
        ((ObjModelChainEntry*)((u8*)state->entries + off))->nodes = mmAlloc(
            (((ObjModelChainEntry*)((u8*)state->entries + off))->nodeCount + 1) * sizeof(ObjModelChainNode), 0x1a, 0);
        desc++;
        off += sizeof(ObjModelChainEntry);
    }
    state->stiffness = 0.12f;
    state->damping = 0.675f;
    state->gravityY = -0.15f;
    state->phase = 0.0f;
    state->enabled = 1;
    return state;
}

void Model_GetVertexPosition(ModelFileHeader* model, int vertexIndex, f32* out) {
    s16* vertex;

    vertex = (s16*)(model->vertices + vertexIndex * 6);
    if ((model->flags & 0x800) != 0) {
        out[0] = vertex[0];
        out[1] = vertex[1];
        out[2] = vertex[2];
    } else {
        out[0] = vertex[0] * gModelVertexScale;
        out[1] = vertex[1] * gModelVertexScale;
        out[2] = vertex[2] * gModelVertexScale;
    }
}

int loadModelAndAnimTabs(void) {
    int* p = getCurrentDataFile(MLDF_FILEID_MODELS_TAB_A);
    if (p == NULL) {
        return 0;
    }
    gModelTabEntryCount = 0;
    while (*p != -1) {
        p++;
        gModelTabEntryCount++;
    }
    gModelTabEntryCount--;
    gModelAnimDataOffsetTable = getCurrentDataFile(MLDF_FILEID_ANIM_TAB_A);
    if (gModelAnimDataOffsetTable == NULL) {
        return 0;
    }
    lbl_803DCB58 = 0;
    return 1;
}

/* Double-buffered DMA-cache vertex transform: stream vtxCount verts through a
   two-slot scratch cache (0x2000 apart, transform output at +0x1000), copying
   worker chunks in via copyToCache while the previous chunk is being processed,
   then writing transformed verts (6 bytes each) back to dstVtx. */
void modelBlendMorphTargets(u8* srcVtx, u8* dstVtx, u16 vtxCount, u16* targetA, u16* targetB, int blendScale) {
    u16 vtxPos;
    u16 chunk;
    u16 cacheBlocks;
    u16 nextChunk;
    u16 nextCacheBlocks;
    u16 bufIdx;
    u8* cache;
    u8* out;
    int curBuf;
    u8* in;
    int sync;

    cache = getCache();
    vtxPos = 0;
    if (vtxCount > gModelMorphChunkVertexLimit) {
        chunk = gModelMorphChunkVertexLimit;
    } else {
        chunk = vtxCount;
    }
    cacheBlocks = (u32)(chunk * 6 + 0x1f & 0xffe0) >> 5;
    copyToCache(cache, srcVtx, cacheBlocks);
    bufIdx = 0;
    sync = 0;
    while (vtxCount != 0) {
        vtxCount -= chunk;
        if (vtxCount != 0) {
            if (vtxCount > gModelMorphChunkVertexLimit) {
                nextChunk = gModelMorphChunkVertexLimit;
            } else {
                nextChunk = vtxCount;
            }
            nextCacheBlocks = (u32)(nextChunk * 6 + 0x1f & 0xffe0) >> 5;
            copyToCache(cache + (bufIdx ^ 1) * 0x2000, srcVtx + (vtxPos + gModelMorphChunkVertexLimit) * 6,
                        nextCacheBlocks);
            sync = 1;
        }
        cacheQueueWait(sync);
        curBuf = bufIdx;
        in = cache + curBuf * 0x2000;
        out = in + 0x1000;
        modelBlendMorphTargetChunk(in, out, chunk, &targetA, &targetB, blendScale, vtxPos);
        memcpyToCache(dstVtx + vtxPos * 6, out, cacheBlocks);
        vtxPos += chunk;
        sync = 1;
        bufIdx = curBuf ^ 1;
        chunk = nextChunk;
        cacheBlocks = nextCacheBlocks;
    }
    cacheQueueWait(0);
}

void model_multMtxs(ObjModel* model, f32* worldMtx) {
    ModelFileHeader* file = model->file;
    u32 i;
    for (i = 0; i < file->jointCount; i++) {
        MtxPtr jointMtx = modelGetBoneMtx(model, i);
        PSMTXConcat((MtxPtr)worldMtx, jointMtx, jointMtx);
    }
}
void modelInitBoneMtxs(ObjModel* model, f32* outReordered) {
    ModelFileHeader* file = model->file;
    u32 i;
    Mtx skinMtx;

    for (i = 0; i < file->jointCount; i++) {
        MtxPtr jointMtx = modelGetBoneMtx(model, i);
        ModelBone* bone = &((ModelBone*)file->jointData)[i];
        PSMTXTrans(skinMtx, -bone->tail[0], -bone->tail[1], -bone->tail[2]);
        PSMTXConcat(jointMtx, skinMtx, skinMtx);
        PSMTXReorder(skinMtx, ((ROMtx*)outReordered)[i]);
    }
}

void modelInitBoneMtxs2(ObjModel* model, f32* worldMtx, f32* outReordered) {
    int boneByteOff;
    ROMtxPtr reorderCursor;
    ModelFileHeader* file;
    u32 i;
    MtxPtr jointMtx;
    ModelBone* bone;
    Mtx transMtx;

    file = model->file;
    if (file->jointCount == 0) {
        u32 cnt;
        int lim;
        int idx;

        idx = 0;
        cnt = file->jointCount;
        if (cnt != 0) {
            lim = cnt + file->extraJointCount;
        } else {
            lim = 1;
        }
        if (lim <= 0) {
            idx = 0;
        }
        jointMtx = (MtxPtr)(model->jointMatrices[model->bufferFlags & 1] + idx * 0x40);
        PSMTXConcat((MtxPtr)worldMtx, jointMtx, jointMtx);
    } else {
        i = 0;
        boneByteOff = 0;
        reorderCursor = (ROMtxPtr)outReordered;
        for (; i < file->jointCount; i++) {
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
const ModelBlendChannelFlags sModelBlendChannelRefreshInit = {{0, 0, 0}};

void ObjModel_ApplyBlendChannels(ObjModel* model) {
    ModelFileHeader* hdr;
    ObjModelBlendChannel* ch;
    int i;
    s16 emptyTarget;
    ModelBlendChannelFlags chanActive = sModelBlendChannelActiveInit;
    ModelBlendChannelFlags chanRefresh = sModelBlendChannelRefreshInit;
    u16* targetA;
    u16* targetB;
    u8* srcVtx;
    u8* dstVtx;
    int refreshBits;

    hdr = model->file;
    if (hdr->morphTargetPtrs == NULL) {
        return;
    }
    emptyTarget = hdr->vertexCount + 1;
    for (i = 0; i < 3; i++) {
        ch = &model->blendChannels[i];
        if (ch->weight != ch->previousWeight) {
            ch->flags &= ~(BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT);
            ch->flags |= BLENDCHAN_FLAG_DIRTY;
        }
        refreshBits = ch->flags & (BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT);
        chanRefresh.values[i] = refreshBits;
        if (ch->morphTargetA != -1 || ch->morphTargetB != -1 || refreshBits != 0) {
            chanActive.values[i] = 1;
        }
        if (chanRefresh.values[i] & BLENDCHAN_FLAG_DIRTY) {
            ch->flags &= ~BLENDCHAN_FLAG_DIRTY;
            ch->flags |= BLENDCHAN_FLAG_REFRESH_NEXT;
        } else if (chanRefresh.values[i] & BLENDCHAN_FLAG_REFRESH_NEXT) {
            ch->flags &= ~BLENDCHAN_FLAG_REFRESH_NEXT;
        }
    }
    if (chanActive.values[0] == 0 && chanActive.values[1] == 0 && chanActive.values[2] == 0) {
        return;
    }
    if (chanActive.values[1]) {
        chanActive.values[0] = 0;
    }
    if (chanRefresh.values[2]) {
        chanRefresh.values[0] = 1;
        chanRefresh.values[1] = 1;
    }
    if ((chanActive.values[0] && chanRefresh.values[0]) || (chanActive.values[1] && chanRefresh.values[1])) {
        if (chanActive.values[2]) {
            chanRefresh.values[2] = 1;
        }
    }
    for (i = 0; i < 3; i++) {
        if (chanActive.values[i] && hdr->vertexAnimEntries) {
            chanRefresh.values[i] = 1;
        }
        ch = &model->blendChannels[i];
        if (ch->flags & BLENDCHAN_FLAG_RESET_WEIGHT) {
            ch->flags &= ~BLENDCHAN_FLAG_RESET_WEIGHT;
            ch->weight = 0.0f;
        }
        if (chanActive.values[i] && chanRefresh.values[i]) {
            f32 weight;
            f32 tw;
            f32 eased;

            if (ch->morphTargetA > -1) {
                targetA = hdr->morphTargetPtrs[ch->morphTargetA];
            } else {
                targetA = (u16*)&emptyTarget;
            }
            if (ch->morphTargetB > -1) {
                targetB = hdr->morphTargetPtrs[ch->morphTargetB];
            } else {
                targetB = (u16*)&emptyTarget;
            }
            if (i == 2) {
                if (chanActive.values[0] == 0 && chanActive.values[1] == 0) {
                    srcVtx = hdr->vertices;
                } else {
                    srcVtx = model->vtxBuf[(model->bufferFlags >> 1) & 1];
                }
            } else {
                srcVtx = hdr->vertices;
            }
            weight = ch->weight;
            if (weight > 1.0f) {
                ch->weight = 1.0f;
            } else if (weight < 0.0f) {
                if (ch->flags & BLENDCHAN_FLAG_ALLOW_NEGATIVE) {
                    if (weight < -1.0f) {
                        ch->weight = -1.0f;
                    }
                } else {
                    ch->weight = 0.0f;
                }
            }
            tw = ch->weight;
            if (tw >= 0.0f) {
                eased = 0.5f * tw + 1.5f * (tw * tw) - tw * (tw * tw);
            } else {
                tw *= -1.0f;
                eased = 0.5f * tw + 1.5f * (tw * tw) - tw * (tw * tw);
                eased *= -1.0f;
            }
            dstVtx = model->vtxBuf[(model->bufferFlags >> 1) & 1];
            modelBlendMorphTargets(srcVtx, dstVtx, hdr->vertexCount, targetA, targetB, (int)(65536.0f * eased));
            model->vtxBufDirty = 1;
        }
        if (ch->previousWeight != ch->weight) {
            ch->previousWeight = ch->weight;
        }
    }
}

void ObjModel_AdvanceBlendChannels(ObjModel* model, f32 dt) {
    int i;
    ObjModelBlendChannel* ch;
    if (model->file->morphTargetPtrs == NULL) {
        return;
    }
    for (i = 0; i < 3; i++) {
        ch = model->blendChannels + i;
        if (ch[0].morphTargetA == -1 && ch[0].morphTargetB == -1) {
            continue;
        }
        if (ch[0].flags & BLENDCHAN_FLAG_MANUAL) {
            continue;
        }
        ch[0].weight = ch[0].weightRate * dt + ch[0].weight;
        if (ch[0].weight >= 0.99f) {
            ch[0].weight = 0.99f;
            ch[0].weightRate = 0.001f;
            ch[0].flags &= ~BLENDCHAN_FLAG_DIRTY;
        } else if (ch[0].weight <= 0.002f) {
            ch[0].weight = 0.002f;
            ch[0].weightRate = 0.001f;
            ch[0].flags &= ~BLENDCHAN_FLAG_DIRTY;
        }
    }
}

int ObjModel_NeedsBlendChannelUpdate(ObjModel* model) {
    ObjModelBlendChannel* ch;

    if (model->file->morphTargetPtrs == NULL) {
        return 0;
    }
    ch = model->blendChannels;
    if (ch[0].weight != ch[0].previousWeight || (ch[0].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    if (ch[1].weight != ch[1].previousWeight || (ch[1].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    if (ch[2].weight != ch[2].previousWeight || (ch[2].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    return 0;
}

void ObjModel_SetBlendChannelWeight(ObjModel* model, int channel, f32 weight) {
    ObjModelBlendChannel* ch;

    if (channel > 2 || model->file->morphTargetPtrs == NULL) {
        return;
    }
    ch = model->blendChannels + channel;
    if (weight != ch->weight) {
        ch->weight = weight;
    }
    ch[0].flags |= BLENDCHAN_FLAG_DIRTY;
}

void ObjModel_SetBlendChannelTargets(ObjModel* model, int channel, int a, int b, f32 weightRate, int flags) {
    ObjModelBlendChannel* ch;
    u8* hdr;
    if (channel > 2 || ((ModelFileHeader*)(hdr = (u8*)model->file))->morphTargetPtrs == NULL) {
        return;
    }
    if (a < -1) {
        return;
    }
    if (b < -1) {
        return;
    }
    if (a >= ((ModelFileHeader*)hdr)->morphTargetCount || b >= ((ModelFileHeader*)hdr)->morphTargetCount) {
        return;
    }
    ch = model->blendChannels + channel;
    if (a == -1 && b == -1) {
        if (ch[0].morphTargetA != -1 || ch[0].morphTargetB != -1) {
            flags |= BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY;
        } else {
            return;
        }
    }
    if (ch[0].morphTargetA == a && ch[0].morphTargetB == b) {
        return;
    }
    ch[0].morphTargetA = a;
    ch[0].morphTargetB = b;
    if (!(flags & BLENDCHAN_FLAG_KEEP_WEIGHT)) {
        ch[0].weight = 0.0f;
    }
    ch[0].previousWeight = -1.0f;
    ch[0].weightRate = weightRate;
    ch[0].flags = flags | BLENDCHAN_FLAG_DIRTY;
}

void ObjModel_ClearBlendChannels(ObjModel* model) {
    if (model->file->morphTargetPtrs != NULL) {
        ObjModel_SetBlendChannelTargets(model, 0, -1, -1, 0.0f, BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
        ObjModel_SetBlendChannelTargets(model, 1, -1, -1, 0.0f, BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
        ObjModel_SetBlendChannelTargets(model, 2, -1, -1, 0.0f, BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
    }
}

void objUpdateHitSpheres(ObjModel* model, ModelFileHeader* file, GameObject* targetObj, u8* boneMtx,
                         GameObject* sourceObj) {
    int off[2];
    ObjModelHitSphere* prevSphere;
    int i;
    u8* mtx;
    ObjHitReactState* hitReact;
    u32 maskWord;
    Vec vec;
    f32 zero;
    f32 motionScale;
    u32 bufSel;
    int idx;
    int maskCount;
    u32 hitMask;
    u32 cnt;
    int lim;
    ObjModel* st;

    hitMask = 0;
    hitReact = sourceObj->anim.hitReactState;
    if (hitReact != NULL) {
        if (sourceObj->anim.modelInstance->hitReactStateCount != 0) {
            maskCount = (int)hitReact->activeEntryByteCount >> 2;
            if (maskCount > 0) {
                maskWord = (u32)hitReact->entries;
                idx = (int)(sourceObj->anim.currentMoveProgress * maskCount);
                if (idx >= maskCount) {
                    idx = maskCount - 1;
                }
                maskWord = ((u32*)maskWord)[idx];
                hitMask = maskWord;
            }
        } else {
            hitMask = ((ObjHitsPriorityState*)hitReact)->objectHitMask;
        }
    }

    if (targetObj->anim.hitReactState != NULL) {
        targetObj->anim.hitReactState->resetHitboxMode -= 1;
        if ((s8)targetObj->anim.hitReactState->resetHitboxMode < 0) {
            targetObj->anim.hitReactState->resetHitboxMode = 0;
        }
        ((ObjHitsPriorityState*)targetObj->anim.hitReactState)->skeletonHitMask =
            ((ObjHitsPriorityState*)targetObj->anim.hitReactState)->objectHitMask;
        ((ObjHitsPriorityState*)targetObj->anim.hitReactState)->objectHitMask = hitMask;
    }

    st = model;
    model->bufferFlags ^= OBJMODEL_BUFFER_FLAG_HITSPHERE_SELECT;
    bufSel = (model->bufferFlags >> 2) & 1;
    st->activeHitVolumeSpheres = st->hitVolumeSphereBuffers[bufSel];
    mtx = boneMtx;
    i = 0;
    off[0] = 0;
    off[1] = off[0];
    prevSphere = (ObjModelHitSphere*)st->hitVolumeSphereBuffers[bufSel ^ 1];
    for (; i < file->hitVolumeCount; i++) {
        if (boneMtx == NULL) {
            idx = ((ModelHitSphereDef*)(file->hitVolumes + off[0]))->jointIdx;
            cnt = model->file->jointCount;
            if (cnt != 0) {
                lim = cnt + model->file->extraJointCount;
            } else {
                lim = 1;
            }
            if (idx >= lim) {
                idx = 0;
            }
            mtx = model->jointMatrices[model->bufferFlags & 1] + idx * sizeof(ObjModelJointMatrix);
        }
        if (i == 0 && sourceObj != targetObj) {
            zero = 0.0f;
            vec.x = zero;
            vec.y = zero;
            vec.z = zero;
            PSMTXMultVec((MtxPtr)mtx, &vec, &vec);
            targetObj->anim.localPosX = vec.x + playerMapOffsetX;
            targetObj->anim.localPosY = vec.y;
            targetObj->anim.localPosZ = vec.z + playerMapOffsetZ;
            Obj_GetWorldPosition(targetObj, &targetObj->anim.worldPosX, &targetObj->anim.worldPosY,
                                 &targetObj->anim.worldPosZ);
        }
        vec.x = ((ModelHitSphereDef*)(file->hitVolumes + off[0]))->center[0];
        vec.y = ((ModelHitSphereDef*)(file->hitVolumes + off[0]))->center[1];
        vec.z = ((ModelHitSphereDef*)(file->hitVolumes + off[0]))->center[2];
        ((ObjModelHitSphere*)(st->activeHitVolumeSpheres + off[1]))->radius =
            ((ModelHitSphereDef*)(file->hitVolumes + off[0]))->radius * (motionScale = sourceObj->anim.rootMotionScale);
        PSMTXMultVec((MtxPtr)mtx, &vec, (Vec*)((ObjModelHitSphere*)(st->activeHitVolumeSpheres + off[1]))->pos);
        prevSphere->pos[0] = (gMapSavedPlayerOffsetX + prevSphere->pos[0]) - playerMapOffsetX;
        prevSphere->pos[2] = (gMapSavedPlayerOffsetZ + prevSphere->pos[2]) - playerMapOffsetZ;
        off[0] += sizeof(ModelHitSphereDef);
        off[1] += sizeof(ObjModelHitSphere);
        prevSphere++;
    }
}

void ObjModel_SampleJointTransform(ObjModel* model, int animState, int frameSource, f32 phase, f32 rootMotionScale,
                                   f32* outPos, s16* outRot) {
    ObjAnimState* state;
    ObjAnimFrameHeader* savedFrameData;
    s16 translationSamples[3];
    int frameStride;
    u8* animationData;

    if (model->file->animationCount == 0) {
        f32 z = 0.0f;
        outPos[0] = z;
        outPos[1] = z;
        outPos[2] = z;
        outRot[0] = 0;
        outRot[1] = 0;
        outRot[2] = 0;
    }
    if (animState != 0) {
        state = model->animStateB;
    } else {
        state = model->animStateA;
    }
    savedFrameData = state->moveFrameData;
    state->moveFrameData = state->frameData[frameSource];
    if (model->file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
        if (frameSource > 1) {
            u8** cache = state->blendMoveCache;
            u16* cacheSlots = state->cacheSlots;
            animationData = cache[cacheSlots[frameSource]] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
        } else {
            u8** cache = state->moveCache;
            u16* cacheSlots = state->cacheSlots;
            animationData = cache[cacheSlots[frameSource]] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
        }
    } else {
        u16* cacheSlots = state->cacheSlots;
        animationData = ((u8**)model->file->animationModelPtrs)[cacheSlots[frameSource]];
    }
    state->framePhase = phase * state->frameLength;
    frameStride = state->moveFrameData->frameStride;
    {
        f32 framePhase = state->framePhase;
        int frameIndex = framePhase;
        f32 frameIndexF = frameIndex;
        if (frameIndexF != framePhase) {
            state->frameStreamStrides[0] = frameStride;
        } else {
            state->frameStreamStrides[0] = 0;
        }
        if (state->frameType != 0 && frameIndexF == state->frameLength - 1.0f) {
            state->frameStreamStrides[0] = (s16)(-frameStride * frameIndex);
        }
        state->frameStreamCursors[0] =
            animationData + ((ObjAnimMoveData*)animationData)->frameStreamOffset + frameStride * frameIndex;
    }
    modelRenderInterpolateRootTransform(state, translationSamples, outRot);
    state->moveFrameData = savedFrameData;
    {
        f32 translationScale = 0.001953125f;
        outPos[0] = translationScale * translationSamples[0];
        outPos[1] = translationScale * translationSamples[1];
        outPos[2] = translationScale * translationSamples[2];
    }
    outPos[0] = outPos[0] + ((ModelBone*)model->file->jointData)->head[0];
    outPos[1] = outPos[1] + ((ModelBone*)model->file->jointData)->head[1];
    outPos[2] = outPos[2] + ((ModelBone*)model->file->jointData)->head[2];
    outPos[0] *= rootMotionScale;
    outPos[1] *= rootMotionScale;
    outPos[2] *= rootMotionScale;
}

void* animLoadFromTable(u8* hdr, int id, int idx, u8* out) {
    int size;
    int flags;
    int out2;
    u8* buf;
    int stride;

    flags = 0;
    fileLoadToBufferOffset(MLDF_FILEID_PREANIM_TAB, &flags, id * sizeof(u32), 4);
    if (flags & 0x10000000) {
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, 0, flags, 0, &size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    } else {
        flags = gModelAnimDataOffsetTable[id];
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, flags, 0, &size, id, 1);
        buf = out + 0x80;
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    return buf;
}
void* loadAnimation(ModelFileHeader* hdr, s16 id, int b, u8* bufout) {
    int tmp;
    int size;
    u8* ptr;
    int animOffset;
    int i;
    u32 ftype;

    if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) != 0 && (ftype = hdr->modelId) != 1 && ftype != 3) {
        return 0;
    }
    if (bufout == 0) {
        if (ModelList_getHeader(gModelAnimCacheList, (i = id), &ptr) == 0) {
            u8* np;
            animOffset = gModelAnimDataOffsetTable[id];
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animOffset, 0, &size, i, 1);
            ptr = np = mmAlloc(size, 10, 0);
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, np, animOffset, size, &tmp, i, 0);
            *ptr = 1;
            modelInitModelList(gModelAnimCacheList, id, &ptr);
        } else {
            u8* p = ptr;
            *p += 1;
        }
        return ptr;
    }
    return animLoadFromTable((u8*)hdr, id, (s16)b, bufout);
}

ModelCollisionTriangle* modelFileGetCollisionTriangle(ModelFileHeader* modelFile, int index) {
    return &modelFile->collisionTriangles[index];
}

CollisionPolygonGroup* modelFileGetCollisionBlock(ModelFileHeader* modelFile, int index) {
    return &modelFile->collisionBlocks[index];
}

ModelDisplayListEntry* modelFileGetDisplayList(ModelFileHeader* modelFile, int displayListIndex) {
    return &modelFile->displayLists[displayListIndex];
}

void ObjModel_CopyJointTranslation(u8* modelBytes, int jointIndex, f32* out) {
    ObjModel* model;
    u32 jointCount;
    u8* jointMtx;

    model = (ObjModel*)modelBytes;
    jointCount = model->file->jointCount;
    if (jointIndex >= (int)(jointCount != 0 ? jointCount + model->file->extraJointCount : 1)) {
        jointIndex = 0;
    }

    jointMtx = model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40;
    out[0] = *(f32*)(jointMtx + 0xc);
    out[1] = *(f32*)(jointMtx + 0x1c);
    out[2] = *(f32*)(jointMtx + 0x2c);
}

Texture* ObjModel_GetTexture(ModelFileHeader* model, int textureIndex) {
    return textureIdxToPtr(model->textureIds[textureIndex]);
}

s16* ObjModel_GetBaseVertexCoords(ModelFileHeader* modelFile, int vertexIndex) {
    return (s16*)(modelFile->vertices + vertexIndex * 6);
}

Shader* ObjModel_GetRenderOp(ModelFileHeader* model, int renderOpIndex) {
    return &model->renderOps[renderOpIndex];
}

extern u8* gModelCacheBuffersA[4];
u8* gModelCacheBuffersB[6];

u16 modelFileHeaderGetCullDistance(ModelFileHeader* modelFile) {
    return modelFile->cullDistance;
}

void ObjModel_ClearRenderAttachment(ObjModel* model) {
    if (model->renderAttachment != NULL) {
        mm_free(model->renderAttachment);
        model->renderAttachment = NULL;
    } else {
        model->renderCallback = NULL;
    }
}

void ObjModel_EnableDefaultRenderCallback(void* object, ObjModel* model, f32* mtx, int enabled, f32 scale) {
    if (model->renderAttachment == NULL) {
        model->renderCallback = objFrozenRenderCb;
    }
}

s16* ObjModel_GetCurrentVertexCoords(ObjModel* model, int vertexIndex) {
    return (s16*)(model->vtxBuf[(model->bufferFlags >> 1) & 1] + vertexIndex * 6);
}

void* ObjModel_GetPostRenderCallback(ObjModel* model) {
    return model->postRenderCallback;
}

void postRenderSetAlphaBlendState(void) {
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void ObjModel_SetPostRenderCallback(ObjModel* model, void* callback) {
    model->postRenderCallback = callback;
}

void* ObjModel_GetRenderCallback(ObjModel* model) {
    return model->renderCallback;
}

void ObjModel_SetRenderCallback(u8* model, void* callback) {
    ((ObjModel*)model)->renderCallback = callback;
}

void ObjModel_ToggleVertexBuffer(ObjModel* model) {
    model->bufferFlags ^= 2;
}

/* Per-bone delta-transform opcode bits: a set bit means the X/Y/Z
   component is present (as an s16) in the stream, else it is 0. */

void ObjModel_ToggleMatrixBuffer(ObjModel* model) {
    model->bufferFlags ^= 1;
}

ObjModelJointMatrix* ObjModel_GetJointMatrix(u8* modelBytes, int jointIndex) {
    ObjModel* model;
    u32 jointCount;

    model = (ObjModel*)modelBytes;
    jointCount = model->file->jointCount;
    if (jointIndex >= (int)(jointCount != 0 ? jointCount + model->file->extraJointCount : 1)) {
        jointIndex = 0;
    }

    return (ObjModelJointMatrix*)(model->jointMatrices[model->bufferFlags & 1] + jointIndex * 0x40);
}

s16 gModelJointScratchBuffer[0xa0];
ModelRenderOpTextureRefs* ObjModel_GetRenderOpTextureRefs(ObjModel* model, int renderOpIndex) {
    return &model->textureRefs[renderOpIndex];
}

void ObjModel_LoadRenderOpTextures(u8* model, GameObject* object) {
    int i;
    u8* hdr = (u8*)((ObjModel*)model)->file;
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED) {
        return;
    }
    ((ObjModel*)model)->bufferFlags |= OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
    for (i = 0; i < ((ObjModel*)model)->file->renderOpCount; i++) {
        shaderInit((u8*)&((ModelFileHeader*)hdr)->renderOps[i], &((ObjModel*)model)->textureRefs[i], object,
                   ((ModelFileHeader*)hdr)->shaderFlags);
    }
}

extern s16 gModelRootRotX;
extern s16 gModelRootRotY;
extern s16 gModelRootRotZ;

static void ObjModel_BuildAnimBlendTable(ObjAnimComponent* objAnim, ObjAnimState* channel, ModelFileHeader* file) {
    int poseOff;
    ObjModelInstance* modelDef;
    int defOff;
    int i;
    u32 jointRemap;
    int offA;
    int offB;
    int outPos;
    ObjJointPose* poseAdjustments;
    u8* rowA;
    u8* rowB;

    if (file->flags & MODEL_FLAG_VERTEX_ANIM_AREA) {
        rowA = channel->moveCache[channel->moveCacheSlot];
        rowB = channel->moveCache[channel->prevMoveCacheSlot];
    } else {
        rowA = file->animationDataSection + channel->moveCacheSlot * (((file->jointCount - 1) & ~7) + 8);
        rowB = file->animationDataSection + channel->prevMoveCacheSlot * (((file->jointCount - 1) & ~7) + 8);
    }
    modelDef = objAnim->modelInstance;
    defOff = 0;
    outPos = 0;
    i = 0;
    poseOff = 0;
    for (; i < modelDef->jointCount; i++) {
        jointRemap = *(u8*)(modelDef->jointData + defOff + objAnim->bankIndex + 1);
        if (jointRemap != 0xff) {
            poseAdjustments = (ObjJointPose*)(objAnim->jointPoseData + poseOff);
            offA = *(s8*)(rowA + jointRemap) << 6;
            offB = *(s8*)(rowB + jointRemap) << 6;
            BLENDTBL_ENTRY(rotation[0], 0)
            BLENDTBL_ENTRY(rotation[1], 2)
            BLENDTBL_ENTRY(rotation[2], 4)
            BLENDTBL_ENTRY(scale[0], 0xc)
            BLENDTBL_ENTRY(scale[1], 0xe)
            BLENDTBL_ENTRY(scale[2], 0x10)
            BLENDTBL_ENTRY(translation[0], 0x18)
            BLENDTBL_ENTRY(translation[1], 0x1a)
            BLENDTBL_ENTRY(translation[2], 0x1c)
        }
        defOff += modelDef->modelCount + 1;
        poseOff += sizeof(ObjJointPose);
    }
    gModelJointScratchBuffer[outPos++] = 0x1000;
    gModelJointScratchBuffer[outPos] = 0x1000;
}

void ObjModel_UpdateAnimMatrices(ObjModel* model, ModelFileHeader* blend, GameObject* obj, f32* dst) {
    ObjAnimState* ch;
    ObjAnimState* ch2;
    f32 pos[3];
    s16 rot[3];

    ObjModel_BuildAnimBlendTable(&obj->anim, model->animStateA, blend);
    model->bufferFlags ^= 1;
    ch = model->animStateA;
    if (ch->moveControlFlags & 4) {
        ObjModel_SampleJointTransform(model, 0, 0, obj->anim.currentMoveProgress, obj->anim.rootMotionScale, pos, rot);
        gModelRootRotX = rot[0];
        gModelRootRotY = rot[1];
        gModelRootRotZ = rot[2];
    }
    if (model->file->flags & 8) {
        modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateA, obj->anim.currentMoveProgress, 0x7f);
    } else if (((ObjAnimState*)model->animStateA)->moveControlFlags & OBJANIM_MOVE_CONTROL_REFRESH_SAVED_STEP) {
        ch2 = model->animStateB;
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 0, 2, 0x14,
                              (s16)ch->eventState);
        modelAnimEvalSlotPair((u8*)dst, model, ch2, obj->anim.activeMoveProgress, 0x7f, 0, 0, 2, 0x18,
                              (s16)ch2->eventState);
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 0, 0, 7,
                              (s16)ch2->eventCountdown);
        modelAnimEvalSlotPair((u8*)dst, model, ch, obj->anim.currentMoveProgress, 0x7f, 0, 1, 1, 1,
                              (s16)ch->eventCountdown);
    } else {
        modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateA, obj->anim.currentMoveProgress, 0x7f);
        ch2 = model->animStateB;
        if (ch2 != NULL && obj->anim.activeMove > -1) {
            ObjModel_BuildAnimBlendTable(&obj->anim, model->animStateB, blend);
            modelAnimEvalChannels((u8*)dst, model, (ObjAnimState*)model->animStateB, obj->anim.activeMoveProgress, -1);
        }
    }
}
void ObjModel_RelocateAnimData(ModelFileHeader* file, ObjModel* model);

void ObjModel_ResolveRenderOpTextures(u8* m) {
    int j, k;
    u8* op;
    for (j = 0; j < ((ModelFileHeader*)m)->renderOpCount; j++) {
        op = (u8*)&((ModelFileHeader*)m)->renderOps[j];
        for (k = 0; k < ((Shader*)op)->layerCount; k++) {
            ShaderLayer* e = &((Shader*)op)->layers[k];
            if (e->textureIndex != -1) {
                e->textureIndex = ((ModelFileHeader*)m)->textureIds[e->textureIndex];
            } else {
                e->texture = NULL;
            }
        }
        if (*(int*)(op + 0x34) != -1) {
            *(int*)(op + 0x34) = ((ModelFileHeader*)m)->textureIds[*(int*)(op + 0x34)];
        } else {
            ((Shader*)op)->auxTexture = NULL;
        }
        if (((Shader*)op)->indTextureId != -1) {
            ((Shader*)op)->indTextureId = ((ModelFileHeader*)m)->textureIds[((Shader*)op)->indTextureId];
        } else {
            ((Shader*)op)->indTexture = NULL;
        }
        if (*(int*)(op + 0x1c) != -1) {
            if (*(int*)(op + 0x1c) == -2) {
                ((Shader*)op)->unk1C = 0;
            } else {
                ((Shader*)op)->unk1C = 1;
            }
        } else {
            ((Shader*)op)->unk1C = 0;
        }
        if (((Shader*)op)->textureId != -1) {
            ((Shader*)op)->textureId = ((ModelFileHeader*)m)->textureIds[((Shader*)op)->textureId];
        } else {
            ((Shader*)op)->textureId = 0;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xc)) {
            ((Shader*)op)->reg1Texture = NULL;
        }
        if (!(((ModelFileHeader*)m)->shaderFlags & 0xe00)) {
            ((Shader*)op)->reg2Texture = NULL;
        }
    }
}

void* ObjModel_LoadModelData(int id);

void ObjModel_RelocateAnimData(ModelFileHeader* file, ObjModel* model) {
    int i;
    file->vertexAnimJob.chunks = file->vertexAnimEntries;
    for (i = 0; i < file->vertexAnimJob.chunkCount; i++) {
        model->vertexAnimOffsets[i] = file->vertexAnimEntries[i].srcDataOffset;
        if (file->vertexAnimEntries[i].weightStream < file->vertexAnimBase) {
            file->vertexAnimEntries[i].weightStream =
                file->vertexAnimBase + (u32)file->vertexAnimEntries[i].weightStream;
        }
    }
    file->normalAnimJob.chunks = file->normalAnimEntries;
    for (i = 0; i < file->normalAnimJob.chunkCount; i++) {
        model->normalAnimOutputs[i] = model->normalBuf + file->normalAnimEntries[i].srcDataOffset;
        if (file->normalAnimEntries[i].weightStream < file->normalAnimBase) {
            file->normalAnimEntries[i].weightStream =
                file->normalAnimBase + (u32)file->normalAnimEntries[i].weightStream;
        }
    }
}

void ObjModel_RelocateModelData(u8* m) {
    int i;
    if (*(u32*)&((ModelFileHeader*)m)->hitVolumes) {
        ((ModelFileHeader*)m)->hitVolumes = m + *(u32*)&((ModelFileHeader*)m)->hitVolumes;
    }
    if (*(u32*)&((ModelFileHeader*)m)->jointData) {
        ((ModelFileHeader*)m)->jointData = m + *(u32*)&((ModelFileHeader*)m)->jointData;
        if (*(u32*)&((ModelFileHeader*)m)->unk18) {
            ((ModelFileHeader*)m)->unk18 = m + *(u32*)&((ModelFileHeader*)m)->unk18;
        }
        if (*(u32*)&((ModelFileHeader*)m)->unk1C) {
            ((ModelFileHeader*)m)->unk1C = m + *(u32*)&((ModelFileHeader*)m)->unk1C;
        }
        if (*(u32*)&((ModelFileHeader*)m)->jointFuzzScales) {
            ((ModelFileHeader*)m)->jointFuzzScales =
                (ModelFuzzScaleDef*)(m + *(u32*)&((ModelFileHeader*)m)->jointFuzzScales);
        }
    }
    if (*(u32*)&((ModelFileHeader*)m)->extraJointDefs) {
        ((ModelFileHeader*)m)->extraJointDefs =
            (ModelExtraJointDef*)(m + *(u32*)&((ModelFileHeader*)m)->extraJointDefs);
    }
    if (*(u32*)&((ModelFileHeader*)m)->textureIds) {
        *(u8**)&((ModelFileHeader*)m)->textureIds = m + *(u32*)&((ModelFileHeader*)m)->textureIds;
    }
    ((ModelFileHeader*)m)->vertices = m + *(u32*)&((ModelFileHeader*)m)->vertices;
    if (*(u32*)&((ModelFileHeader*)m)->normals) {
        ((ModelFileHeader*)m)->normals = m + *(u32*)&((ModelFileHeader*)m)->normals;
    }
    if (*(u32*)&((ModelFileHeader*)m)->colors) {
        ((ModelFileHeader*)m)->colors = m + *(u32*)&((ModelFileHeader*)m)->colors;
    }
    if (*(u32*)&((ModelFileHeader*)m)->texCoords) {
        ((ModelFileHeader*)m)->texCoords = m + *(u32*)&((ModelFileHeader*)m)->texCoords;
    }
    if (*(u32*)&((ModelFileHeader*)m)->instrs) {
        ((ModelFileHeader*)m)->instrs = m + *(u32*)&((ModelFileHeader*)m)->instrs;
    }
    if (*(u32*)&((ModelFileHeader*)m)->displayLists) {
        ((ModelFileHeader*)m)->displayLists = (ModelDisplayListEntry*)(m + *(u32*)&((ModelFileHeader*)m)->displayLists);
    }
    if (*(u32*)&((ModelFileHeader*)m)->morphTargetPtrs) {
        ((ModelFileHeader*)m)->morphTargetPtrs = (u16**)(m + *(u32*)&((ModelFileHeader*)m)->morphTargetPtrs);
    }
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries) {
        ((ModelFileHeader*)m)->vertexAnimEntries =
            (ModelVtxAnimChunk*)(m + *(u32*)&((ModelFileHeader*)m)->vertexAnimEntries);
    }
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimBase) {
        ((ModelFileHeader*)m)->vertexAnimBase = m + *(u32*)&((ModelFileHeader*)m)->vertexAnimBase;
    }
    if (*(u32*)&((ModelFileHeader*)m)->normalAnimEntries) {
        ((ModelFileHeader*)m)->normalAnimEntries =
            (ModelVtxAnimChunk*)(m + *(u32*)&((ModelFileHeader*)m)->normalAnimEntries);
    }
    if (*(u32*)&((ModelFileHeader*)m)->normalAnimBase) {
        ((ModelFileHeader*)m)->normalAnimBase = m + *(u32*)&((ModelFileHeader*)m)->normalAnimBase;
    }
    if (*(u32*)&((ModelFileHeader*)m)->renderOps) {
        ((ModelFileHeader*)m)->renderOps = (Shader*)(m + *(u32*)&((ModelFileHeader*)m)->renderOps);
    }
    for (i = 0; i < ((ModelFileHeader*)m)->displayListCount + ((ModelFileHeader*)m)->shadowDisplayListCount; i++) {
        ((ModelFileHeader*)m)->displayLists[i].dlist = m + *(u32*)&((ModelFileHeader*)m)->displayLists[i].dlist;
    }
    for (i = 0; i < ((ModelFileHeader*)m)->morphTargetCount; i++) {
        ((ModelFileHeader*)m)->morphTargetPtrs[i] = (u16*)(m + *(u32*)&((ModelFileHeader*)m)->morphTargetPtrs[i]);
    }
    if (*(u32*)&((ModelFileHeader*)m)->collisionTriangles) {
        ((ModelFileHeader*)m)->collisionTriangles =
            (ModelCollisionTriangle*)(m + *(u32*)&((ModelFileHeader*)m)->collisionTriangles);
    }
    if (*(u32*)&((ModelFileHeader*)m)->collisionBlocks) {
        ((ModelFileHeader*)m)->collisionBlocks =
            (CollisionPolygonGroup*)(m + *(u32*)&((ModelFileHeader*)m)->collisionBlocks);
    }
}

void* ObjModel_LoadModelData(int id) {
    int fileOffset, dataLen, animCount, headerSize, amapFlag;
    int amapSize;
    void* model;
    if (getTableFileEntry(MLDF_FILEID_MODELS_TAB_A, id, &fileOffset) == 0) {
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
    if (((ModelFileHeader*)model)->animationCount == 0) {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_NO_ANIMATIONS;
    }
    if (amapFlag != 0) {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_VERTEX_ANIM_AREA;
    }
    return model;
}

void ObjModel_TouchModelCache(void) {
    u8 buf[8];
    gModelList->iter = gModelList->entries;
    while (gModelList->iter != gModelList->end) {
        s16* iter = gModelList->iter;
        if (*iter == -1) {
            memset(buf, 0, gModelList->dataSize);
        } else {
            memcpy(buf, iter + 1, gModelList->dataSize);
        }
        gModelList->iter += gModelList->strideShorts;
    }
}

void ObjModel_Release(u8* model) {
    u8* header;
    int z[2];
    if (((ObjModel*)model)->bufferFlags & OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED) {
        ((ObjModel*)model)->bufferFlags &= ~OBJMODEL_BUFFER_FLAG_TEXTURES_LOADED;
        z[0] = 0;
        for (z[1] = z[0]; z[0] < ((ObjModel*)model)->file->renderOpCount; z[1] += 0xc, z[0]++) {
            ShaderDef_free((void**)&((ObjModel*)model)->textureRefs[z[0]]);
        }
    }
    header = (u8*)((ObjModel*)model)->file;
    if (((ObjModel*)model)->renderAttachment != NULL) {
        mm_free(((ObjModel*)model)->renderAttachment);
    }
    if (--((ModelFileHeader*)header)->refCount == 0) {
        model_adjustModelList(gModelList, ((ModelFileHeader*)header)->modelId); /* modelId */
        z[0] = 0;
        for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->textureCount; z[1] += 4, z[0]++) {
            textureFree((Texture*)(textureIdxToPtr(*(s32*)((u8*)((ModelFileHeader*)header)->textureIds + z[1]))));
        }
        if (((ModelFileHeader*)header)->animationModelPtrs != NULL && ((ModelFileHeader*)header)->animationCount != 0) {
            z[0] = 0;
            for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->animationCount; z[1] += 4, z[0]++) {
                int idx;
                void* tex = *(void**)(((ModelFileHeader*)header)->animationModelPtrs + z[1]);
                if (tex != NULL && (s8)-- * (u8*)tex <= 0) {
                    model_findIdxInModelList(gModelAnimCacheList, &tex, &idx);
                    model_adjustModelList(gModelAnimCacheList, idx);
                    mm_free(tex);
                }
            }
        }
        mm_free(header);
    }
}

void* ObjModel_LoadAnimData(u8* p, int b, u8* c) {
    void* m = modelLoad_layoutBuffers(p, b, p[0] == 1, c);
    modelAnimResetState(m, ((ObjModel*)m)->animStateA);
    if (((ObjModel*)m)->animStateB != NULL) {
        modelAnimResetState(m, ((ObjModel*)m)->animStateB);
    }
    ObjModel_RelocateAnimData((ModelFileHeader*)p, (ObjModel*)m);
    *(int*)(p + 8) = 0;
    DCStoreRange(p, ((ModelFileHeader*)p)->dataSize);
    return m;
}

void* ObjModel_Load(int id, int loadFlag, int* outSize) {
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
    if (idc < 0) {
        realId[0] = -idc;
    } else {
        fileLoadToBufferOffset(MLDF_FILEID_MODELIND_BIN, gModelResourceBuffer, idc * 2, 8);
        realId[0] = gModelResourceBuffer[0];
    }
    if (ModelList_getHeader(gModelList, realId[0], &header) == 0) {
        header = ObjModel_LoadModelData(realId[0]);
        ObjModel_RelocateModelData(header);
        h[0] = header;
        i[0] = 0;
        off[0] = i[0];
        for (; i[0] < h[0][0xf2]; i[0]++) {
            tex = textureLoad(-(*(int*)(*(int*)(h[0] + 0x20) + off[0]) | 0x8000), 1);
            *(void**)(*(int*)(h[0] + 0x20) + off[0]) = tex;
            off[0] += 4;
        }
        ObjModel_ResolveRenderOpTextures(header);
        modelLoadAnimations((ModelFileHeader*)header, realId[0], header + ((ModelFileHeader*)header)->dataSize);
        modelInitModelList(gModelList, realId[0], &header);
    } else {
        (*header)++;
    }
    *outSize = modelLoad_calcSizes(header, loadFlag, sizes, 0);
    return header;
}

void* loadModelInstance(int resourceId, int arg, void* buffer) {
    return NULL;
}

void ObjModel_InitResourceCaches(void) {
    void* m;
    int* p;
    gModelList = allocModelStruct(0x8c, (int)sizeof(u8*));
    gModelAnimCacheList = allocModelStruct(0xc4, (int)sizeof(u8*));
    m = mmAlloc(0x830, 0xa, 0);
    gModelResourceBuffer = m;
    gModelAnimOffsetTable = (int*)((u8*)m + 0x800);
    lbl_803DCB5C = (int*)((u8*)m + 0x810);
    p = getCurrentDataFile(MLDF_FILEID_MODELS_TAB_A);
    if (p == NULL) {
        return;
    }
    gModelTabEntryCount = 0;
    while (*p != -1) {
        p++;
        gModelTabEntryCount++;
    }
    gModelTabEntryCount--;
    gModelAnimDataOffsetTable = getCurrentDataFile(MLDF_FILEID_ANIM_TAB_A);
    if (gModelAnimDataOffsetTable == NULL) {
        return;
    }
    lbl_803DCB58 = 0;
}

void ObjModel_InitScratchBuffers(void) {
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

void ObjModel_InitRenderBuffers(void) {
    if ((PPCMfhid2() & 0x10000000) == 0) {
        void* cache = getCache();
        DCInvalidateRange(cache, 0x4000);
        LCEnable();
    }
    ObjModel_InitScratchBuffers();
    setGQR6_2(7, 4, 7, 4);
}

void ObjModel_BlendNormalStream(u8* mtxs, ModelVtxAnimJob* job, u8* animData, u8** outs, int quad) {
    u16 chunkBlocks[2];

    setGQR7Packed(job->quantShift, 6, job->quantShift, 6);
    ObjModel_InitScratchBuffers();
    if (job->chunkCount != 0) {
        ModelVtxAnimChunk* chunk;
        int vtxBlocks;
        int weightBlocks;
        u32 i;
        u32 nextSlot;
        u8* chunkDst;
        ModelVtxAnimChunk* lastChunk;

        chunk = job->chunks;
        vtxBlocks = (u32)((chunk->vtxBlocks << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + chunk->srcDataOffset, vtxBlocks);
        chunkBlocks[0] = vtxBlocks;
        weightBlocks = (u32)(((chunk = job->chunks)->weightBlocks << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + sizeof(gModelCacheBuffersA[0])), chunk->weightStream,
                    weightBlocks);
        for (i = 0; i < (u32)(job->chunkCount - 1); i++) {
            int nextVtxBlocks;

            chunk = job->chunks + i;
            nextVtxBlocks = (u32)((chunk[1].vtxBlocks << 5) + 0x1f) >> 5;
            nextSlot = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nextSlot * 2)], animData + chunk[1].srcDataOffset, nextVtxBlocks);
            chunkBlocks[(i + 1) & 1] = nextVtxBlocks;
            {
                ModelVtxAnimChunk* nextChunk;
                int nextWeightBlocks = (u32)(((nextChunk = job->chunks + i)[1].weightBlocks << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nextSlot * 2) + 1)], nextChunk[1].weightStream,
                            nextWeightBlocks);
            }
            cacheQueueWait(2);
            if ((u8)quad) {
                chunkDst = outs[i];
                ObjModel_TransformQuadVerticesLinear(
                    mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
                    gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                    (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                    (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), chunk->vtxCount);
                memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
            } else {
                chunkDst = outs[i];
                ObjModel_TransformVerticesLinear(
                    mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
                    gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                    (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                    (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), chunk->vtxCount);
                memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
            }
        }
        lastChunk = job->chunks + i;
        cacheQueueWait(0);
        if ((u8)quad) {
            chunkDst = outs[i];
            ObjModel_TransformQuadVerticesLinear(
                mtxs + lastChunk->mtxIdxA * sizeof(ROMtx), mtxs + lastChunk->mtxIdxB * sizeof(ROMtx),
                gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                (u8*)(lastChunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                (u8*)(lastChunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), lastChunk->vtxCount);
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
        } else {
            chunkDst = outs[i];
            ObjModel_TransformVerticesLinear(
                mtxs + lastChunk->mtxIdxA * sizeof(ROMtx), mtxs + lastChunk->mtxIdxB * sizeof(ROMtx),
                gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                (u8*)(lastChunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                (u8*)(lastChunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), lastChunk->vtxCount);
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
        }
        cacheQueueWait(0);
    }
}

void ObjModel_BlendVertexStream(u8* mtxs, ModelVtxAnimJob* job, u8* animData, s32* dstOffsets, u8* dstBase) {
    u16 chunkBlocks[2];

    setGQR7Packed(job->quantShift, 7, job->quantShift, 7);
    ObjModel_InitScratchBuffers();
    if (job->chunkCount != 0) {
        ModelVtxAnimChunk* chunk;
        int vtxBlocks;
        int weightBlocks;
        u32 i;
        u32 nextSlot;
        u8* chunkDst;

        chunk = job->chunks;
        vtxBlocks = (u32)((chunk->vtxBlocks << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + chunk->srcDataOffset, vtxBlocks);
        chunkBlocks[0] = vtxBlocks;
        weightBlocks = (u32)(((chunk = job->chunks)->weightBlocks << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((int)gModelCacheBuffersA + sizeof(gModelCacheBuffersA[0])), chunk->weightStream,
                    weightBlocks);
        for (i = 0; i < (u32)(job->chunkCount - 1); i++) {
            chunk = job->chunks + i;
            vtxBlocks = (u32)((chunk[1].vtxBlocks << 5) + 0x1f) >> 5;
            nextSlot = (i + 1) & 1;
            copyToCache(gModelCacheBuffersA[(u8)(nextSlot * 2)], animData + chunk[1].srcDataOffset, vtxBlocks);
            chunkBlocks[(i + 1) & 1] = vtxBlocks;
            {
                ModelVtxAnimChunk* nextChunk;
                int nextWeightBlocks = (u32)(((nextChunk = job->chunks + i)[1].weightBlocks << 5) + 0x1f) >> 5;
                copyToCache(gModelCacheBuffersA[(u8)((u8)(nextSlot * 2) + 1)], nextChunk[1].weightStream,
                            nextWeightBlocks);
            }
            cacheQueueWait(2);
            chunkDst = dstBase + dstOffsets[i];
            ObjModel_TransformVerticesWithTranslation(
                mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
                gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
                (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
                (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), chunk->vtxCount);
            memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
        }
        chunk = job->chunks + i;
        cacheQueueWait(0);
        chunkDst = dstBase + dstOffsets[i];
        ObjModel_TransformVerticesWithTranslation(
            mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
            gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
            (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
            (u8*)(chunk->dstByteOffset + (int)gModelCacheBuffersA[(u8)((i & 1) * 2)]), chunk->vtxCount);
        memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
        cacheQueueWait(0);
    }
}

void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count) {
    f32* ma = (f32*)m1;
    f32* mb = (f32*)m2;
    u8* w = src;
    s16* in = (s16*)d1;
    s16* out = (s16*)d2;
    f32 scale = (f32)(1 << ((sGQR7Config >> 24) & 0x3f));
    f32 invScale = 1.0f / scale;
    f32 x, y, z, w0, w1, ox, oy, oz;
    int i;

    for (i = 0; i < count; i++) {
        w0 = __OSu8tof32(w) * (1.0f / 128.0f);
        w1 = __OSu8tof32(w + 1) * (1.0f / 128.0f);
        w += 2;
        x = __OSs16tof32(&in[0]) * invScale;
        y = __OSs16tof32(&in[1]) * invScale;
        z = __OSs16tof32(&in[2]) * invScale;
        in += 3;
        ox = (ma[0] * x + ma[3] * y + ma[6] * z + ma[9]) * w0 + (mb[0] * x + mb[3] * y + mb[6] * z + mb[9]) * w1;
        oy = (ma[1] * x + ma[4] * y + ma[7] * z + ma[10]) * w0 + (mb[1] * x + mb[4] * y + mb[7] * z + mb[10]) * w1;
        oz = (ma[2] * x + ma[5] * y + ma[8] * z + ma[11]) * w0 + (mb[2] * x + mb[5] * y + mb[8] * z + mb[11]) * w1;
        out[0] = __OSf32tos16(ox * scale);
        out[1] = __OSf32tos16(oy * scale);
        out[2] = __OSf32tos16(oz * scale);
        out += 3;
    }
}

void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count) {
    f32* ma = (f32*)m1;
    f32* mb = (f32*)m2;
    u8* w = src;
    s8* in = (s8*)d1;
    s8* out = (s8*)d2;
    f32 scale = (f32)(1 << ((sGQR7Config >> 24) & 0x3f));
    f32 invScale = 1.0f / scale;
    f32 x, y, z, w0, w1, ox, oy, oz;
    int i;

    for (i = 0; i < count; i++) {
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
void ObjModel_TransformQuadVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count) {
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

    for (i = 0; i < count; i++) {
        w0 = __OSu8tof32(w) * (1.0f / 128.0f);
        w1 = __OSu8tof32(w + 1) * (1.0f / 128.0f);
        w += 2;
        for (k = 0; k < 3; k++) {
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

void setGQR6(u32 v) {
}

void setGQR7(u32 v) {
    sGQR7Config = v;
}
void setGQR7Packed(int a, int b, int c, int d) {
    setGQR7((((a << 8) + b) << 16) | ((c << 8) + d));
}

void setGQR6_2(int a, int b, int c, int d) {
    setGQR6((((a << 8) + b) << 16) | ((c << 8) + d));
}
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize) {
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
    while (p < end) {
        v = *(s16*)p;
        p += 2;
        t = v & 0xF;
        if (t != 0) {
            if (t < 0) {
                srcBits = (u8*)modelRenderCopyPackedSamples(&srcState, &dstState, dst[7], vertBits, t);
            } else {
                srcBits = modelRenderDecodeAdpcm(srcBits, dst[7], &dstState, vertBits, t);
            }
        }
    }
    *(u16*)dst &= ~0x20;
    if (*(u16*)(dst + 4) != 0) {
        u32 oldOff = *(u16*)(dst + 4);
        *(u16*)(dst + 4) = *(u16*)(dst + 2) + (vertBits >> 3) * (dst[7] + 2);
        *(u16*)(dst + 4) = (*(u16*)(dst + 4) + 7) & ~7;
        memcpy(dst + *(u16*)(dst + 4), src + *(u16*)(src + 4), srcSize - oldOff);
    }
}

int ObjModel_IsPackedResource(u8* resource) {
    return 0x0;
}

int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize) {
    return baseSize + resource[8] * resource[7];
}

Vec gModelJitterAxis = {1.0f, 0.0f, 0.0f};

char sModelAnimationBufferOverflowWarning[] = "Warning: Model animation buffer overflow!! size=%d\n";

u8* gModelCacheBuffersA[4];
