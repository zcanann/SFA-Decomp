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
#include "MSL_C/PPCEABI/bare/H/inverse_trig_api.h"
#include "main/render_internal.h"
#include "string.h"
#include "main/vecmath.h"
#include "dolphin/os/OSFastCast.h"

typedef union ModelAnimationOffsetScratch {
    s16 modelAnimationOffsets[8];
    int animationMapOffsets[8];
    struct {
        u8 prefix[0x10];
        u8 tail[0x20];
    } opaque;
} ModelAnimationOffsetScratch;

typedef struct ModelResourceScratch {
    s16 ids[0x400];
    ModelAnimationOffsetScratch offsets;
} ModelResourceScratch;

STATIC_ASSERT(sizeof(ModelAnimationOffsetScratch) == 0x30);
STATIC_ASSERT(sizeof(ModelResourceScratch) == 0x830);
STATIC_ASSERT(offsetof(ModelResourceScratch, offsets) == 0x800);
STATIC_ASSERT(offsetof(ModelResourceScratch, offsets.opaque.tail) == 0x810);

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
void* animLoadFromTable(u8* hdr, int idx, int a, ObjAnimCachedMove* b);
#define MODEL_LOAD_INITIAL_MOVE(SLOT)                                                                                  \
    {                                                                                                                  \
        int animationId;                                                                                               \
        u32 cacheAddress;                                                                                              \
        int animationOffset;                                                                                           \
        int unusedSize;                                                                                                \
        int animationBytes;                                                                                            \
        ObjAnimMoveData* animation;                                                                                    \
                                                                                                                       \
        cacheAddress = (u32)(SLOT);                                                                                    \
        animationId = ((ModelFileHeader*)hdr)->cachedAnimIds[0];                                                       \
        if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) == 0 || ((ModelFileHeader*)hdr)->modelId == 1 ||      \
            ((ModelFileHeader*)hdr)->modelId == 3) {                                                                   \
            if (cacheAddress == 0) {                                                                                   \
                if (ModelList_getHeader(gModelAnimCacheList, animationId, &animation) == 0) {                          \
                    animationOffset = gModelAnimDataOffsetTable[animationId];                                          \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animationOffset, 0, &animationBytes,          \
                                              animationId, 1);                                                         \
                    animation = mmAlloc(animationBytes, 10, 0);                                                        \
                    loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, animation, animationOffset, animationBytes,      \
                                              &unusedSize, animationId, 0);                                            \
                    animation->refCount = 1;                                                                           \
                    modelInitModelList(gModelAnimCacheList, animationId, &animation);                                  \
                } else {                                                                                               \
                    animation->refCount += 1;                                                                          \
                }                                                                                                      \
            } else {                                                                                                   \
                animLoadFromTable(hdr, animationId, 0, (ObjAnimCachedMove*)cacheAddress);                              \
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

void setGQR7Packed(int loadScale, int loadType, int storeScale, int storeType);
asm void modelReadMorphDelta(void);
static inline void* modelGetBoneMtx(ObjModel* model, int idx);
void ObjModel_TransformVerticesWithTranslation(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformVerticesLinear(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
void ObjModel_TransformNormalTriplets(u8* m1, u8* m2, u8* src, u8* d1, u8* d2, int count);
/* Register ABI: r3/r4 are vertex buffers, r5 is the chunk count, r6/r7
 * point to stream cursors, r8 is weight B and r9 is the first vertex.
 * r17 holds weight A; r18/r19 hold pending relative indices; r23/r24 are
 * stream cursors and r25 is the current relative vertex. The private
 * decoder uses r20 and returns X/Y/Z through r10/r12/r15. */
asm void modelBlendMorphTargetChunk(u8* baseVertices, u8* outVertices, u16 vertexCount, u16** targetA, u16** targetB,
                                    int weightB, u16 firstVertex) {
    // clang-format off
    nofralloc
    mflr r0
    stwu r1, -0x50(r1)
    stw r0, 0x54(r1)
    stmw r14, 8(r1)
    lwz r23, 0(r6)
    lwz r24, 0(r7)
    li r25, 0
    lis r17, 1
    subf r17, r8, r17

readPendingIndices:
    lha r18, 0(r23)
    lha r19, 0(r24)
    andi. r18, r18, MODEL_MORPH_VERTEX_INDEX_MASK
    andi. r19, r19, MODEL_MORPH_VERTEX_INDEX_MASK
    subf r18, r9, r18
    subf r19, r9, r19

checkVertex:
    cmpw r25, r5
    bge finishChunk
    cmpw r25, r18
    bge targetAPresent
    cmpw r25, r19
    bge blendTargetB

    lwz r20, 0(r3)
    lha r22, 4(r3)
    addi r3, r3, 6
    stw r20, 0(r4)
    addi r25, r25, 1
    sth r22, 4(r4)
    addi r4, r4, 6
    b checkVertex

targetAPresent:
    cmpw r25, r19
    bne blendTargetA
    mr r20, r24
    bl modelReadMorphDelta
    mr r24, r20
    mr r11, r10
    mr r14, r12
    mr r16, r15
    mr r20, r23
    bl modelReadMorphDelta
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
    b readPendingIndices

blendTargetA:
    mr r20, r23
    bl modelReadMorphDelta
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
    b readPendingIndices

blendTargetB:
    mr r20, r24
    bl modelReadMorphDelta
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
    b readPendingIndices

finishChunk:
    stw r23, 0(r6)
    stw r24, 0(r7)
    lwz r0, 0x54(r1)
    mtlr r0
    lmw r14, 8(r1)
    addi r1, r1, 0x50
    blr
    // clang-format on
}

/* Private entry: cursor in/out r20, signed X/Y/Z in r10/r12/r15.
 * Clobbers r21, r22 and CR0. This is not an ordinary C-callable function. */
asm void modelReadMorphDelta(void) {
    // clang-format off
    nofralloc
    lhz r21, 0(r20)
    addi r20, r20, 2
    andi. r22, r21, MODEL_MORPH_HAS_X
    li r10, 0
    beq readY
    lha r10, 0(r20)
    addi r20, r20, 2
readY:
    andi. r22, r21, MODEL_MORPH_HAS_Y
    li r12, 0
    beq readZ
    lha r12, 0(r20)
    addi r20, r20, 2
readZ:
    andi. r22, r21, MODEL_MORPH_HAS_Z
    li r15, 0
    beqlr
    lha r15, 0(r20)
    addi r20, r20, 2
    blr
    // clang-format on
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
        if (file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
            mtxSlotRow = work->cachedMoves[work->cacheSlots[i]]->jointMatrixSlots;
            frameStream = (u8*)&work->cachedMoves[work->cacheSlots[i]]->moveData;
        } else {
            mtxSlotRow = file->animationDataSection + work->cacheSlots[i] * (((file->jointCount - 1) & ~7) + 8);
            frameStream = (u8*)file->moveData[work->cacheSlots[i]];
        }
        frameStride = work->frameData[i]->frameStride;
        boneIdx = 0;
        boneByteOff = 0;
        while (boneIdx < file->jointCount) {
            (file->jointData + boneByteOff)[offsetof(ModelBone, animationMatrixSlots) + i] = mtxSlotRow[boneIdx];
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
    if (file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
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
                if (file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
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

void* ObjAnim_LoadCachedMove(int animId, int moveIndex, ObjAnimCachedMove* cache, ObjAnimDef* animDef) {
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
        if (((ModelFileHeader*)hdr)->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
            MODEL_LOAD_INITIAL_MOVE(channel->moveCache[0])
            MODEL_LOAD_INITIAL_MOVE(channel->moveCache[1])
            MODEL_LOAD_INITIAL_MOVE(channel->blendMoveCache[0])
            MODEL_LOAD_INITIAL_MOVE(channel->blendMoveCache[1])
            channel->moveCacheSlot = 0;
            mdl = (u8*)&channel->moveCache[channel->moveCacheSlot]->moveData;
        } else {
            mdl = (u8*)((ModelFileHeader*)hdr)->moveData[channel->moveCacheSlot];
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
int modelLoadAnimations(ModelFileHeader* file, int resourceId, u8* bufferCursor) {
    int modelAnimOffset;
    int modelId = resourceId;
    ModelAnimationOffsetScratch* offsetTable;
    int modelAnimBytes;
    int animationOffset;
    int groupSlot;
    int i;
    int animIdx;
    int bufferBytes;
    int animId;
    int amapOffset;
    int cacheIndex;
    ObjAnimMoveData* cacheEntry;
    int unusedSize;
    int animationBytes;
    ObjAnimMoveData* animation;
    ObjAnimMoveData* loadedAnimation;
    u8 newRefCount;

    bufferBytes = 0;
    offsetTable = (ModelAnimationOffsetScratch*)gModelAnimOffsetTable;
    fileLoadToBufferOffset(MLDF_FILEID_MODANIM_TAB, offsetTable->modelAnimationOffsets, modelId << 1,
                           sizeof(offsetTable->modelAnimationOffsets));
    modelAnimOffset = offsetTable->modelAnimationOffsets[0];
    if (file->animationCount == 0) {
        return 0;
    }
    modelAnimBytes = (file->animationCount << 1) + 8;
    if (modelAnimBytes > (int)sizeof(((ModelResourceScratch*)0)->ids)) {
        debugPrintf(sModelAnimationBufferOverflowWarning, modelAnimBytes);
    }
    fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (modelId & ~3) << 2,
                           sizeof(((ModelAnimationOffsetScratch*)0)->animationMapOffsets));
    file->animationDataFileOffset = gModelAnimOffsetTable[modelId & 3];
    amapOffset = gModelAnimOffsetTable[modelId & 3];
    modelId = gModelAnimOffsetTable[(modelId & 3) + 1] - amapOffset;
    if (file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
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
    if ((file->flags & MODEL_FLAG_CACHED_ANIMATIONS) == 0) {
        file->animationHeaderBuffer = NULL;
        file->moveData = (ObjAnimMoveData**)bufferCursor;
        bufferCursor += file->animationCount * (int)sizeof(ObjAnimMoveData*);
        bufferBytes += file->animationCount * (int)sizeof(ObjAnimMoveData*);
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
                        animation->refCount = 1;
                        modelInitModelList(gModelAnimCacheList, animId, &animation);
                    } else {
                        animation->refCount += 1;
                    }
                    loadedAnimation = animation;
                }
                file->moveData[animIdx] = loadedAnimation;
                if (file->moveData[animIdx] == 0) {
                    int relIdx;

                    relIdx = 0;
                    for (; relIdx < animIdx; relIdx++) {
                        cacheEntry = file->moveData[relIdx];
                        if (cacheEntry != 0) {
                            newRefCount = (cacheEntry->refCount -= 1);
                            if ((s8)newRefCount <= 0) {
                                model_findIdxInModelList(gModelAnimCacheList, &cacheEntry, &cacheIndex);
                                model_adjustModelList(gModelAnimCacheList, cacheIndex);
                                mm_free(cacheEntry);
                            }
                        }
                    }
                    file->moveData = NULL;
                    return 1;
                }
            } else {
                file->moveData[animIdx] = NULL;
            }
            animIdx++;
        } while (animIdx < (int)file->animationCount);
    } else {
        file->moveData = NULL;
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
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_TAB, gModelAnimOffsetTable, (modelId & ~3) << 2,
                               sizeof(((ModelAnimationOffsetScratch*)0)->animationMapOffsets));
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
        if (((ModelFileHeader*)hdr)->flags24 & MODEL_FLAGS24_NBT_NORMALS) {
            normalStride = sizeof(ModelNormalTriplet);
        } else {
            normalStride = sizeof(ModelPackedNormal);
        }
        sizes[0] += ((ModelFileHeader*)hdr)->normalCount * normalStride + 0x40;
    }
    {
        int hitSphereBytes = ((ModelFileHeader*)hdr)->hitVolumeCount * sizeof(ObjModelHitSphere);
        sizes[1] = hitSphereBytes << 1;
    }
    sizes[3] = 0;
    if ((((ModelFileHeader*)hdr)->flags & MODEL_FLAG_CACHED_ANIMATIONS) != 0) {
        sizes[5] = ((ModelFileHeader*)hdr)->animationCacheSize;
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
        if (((ModelFileHeader*)p)->flags24 & MODEL_FLAGS24_NBT_NORMALS) {
            normalStride = sizeof(ModelNormalTriplet);
        } else {
            normalStride = sizeof(ModelPackedNormal);
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
    if (((ModelFileHeader*)p)->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
        pos = roundUpTo8(pos);
        q = ((ObjModel*)out2)->animStateA;
        ((ObjAnimState*)q)->moveCache[0] = (ObjAnimCachedMove*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->moveCache[1] = (ObjAnimCachedMove*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->blendMoveCache[0] = (ObjAnimCachedMove*)pos;
        pos += szs[5];
        ((ObjAnimState*)q)->blendMoveCache[1] = (ObjAnimCachedMove*)pos;
        pos += szs[5];
        q = ((ObjModel*)out2)->animStateB;
        if (q != 0) {
            ((ObjAnimState*)q)->moveCache[0] = (ObjAnimCachedMove*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->moveCache[1] = (ObjAnimCachedMove*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->blendMoveCache[0] = (ObjAnimCachedMove*)pos;
            pos += szs[5];
            ((ObjAnimState*)q)->blendMoveCache[1] = (ObjAnimCachedMove*)pos;
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
    if ((model->flags & MODEL_FLAG_INTEGER_VERTEX_COORDS) != 0) {
        out[0] = vertex[0];
        out[1] = vertex[1];
        out[2] = vertex[2];
    } else {
        out[0] = vertex[0] / 256.0f;
        out[1] = vertex[1] / 256.0f;
        out[2] = vertex[2] / 256.0f;
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
static inline void* modelJointMtxPtr(ObjModel* model, int joint) {
    void* mtx = model->jointMatrices[model->bufferFlags & 1] + joint * sizeof(ObjModelJointMatrix);
    return mtx;
}

void modelInitBoneMtxs(ObjModel* model, f32* outReordered) {
    ModelFileHeader* file = model->file;
    u32 i;
    Mtx skinMtx;

    for (i = 0; i < file->jointCount; i++) {
        int joint = i;
        u8 jointCount = model->file->jointCount;
        MtxPtr jointMtx;
        ModelBone* bone;

        if (joint >= (jointCount != 0 ? jointCount + model->file->extraJointCount : 1)) {
            joint = 0;
        }
        jointMtx = modelJointMtxPtr(model, joint);
        bone = &((ModelBone*)file->jointData)[i];
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
    if (hdr->morphTargets == NULL) {
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
                targetA = hdr->morphTargets[ch->morphTargetA].stream;
            } else {
                targetA = (u16*)&emptyTarget;
            }
            if (ch->morphTargetB > -1) {
                targetB = hdr->morphTargets[ch->morphTargetB].stream;
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
    if (model->file->morphTargets == NULL) {
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

    if (model->file->morphTargets == NULL) {
        return 0;
    }
    ch = model->blendChannels;
    if (ch[0].weight != ch[0].previousWeight ||
        (ch[0].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    if (ch[1].weight != ch[1].previousWeight ||
        (ch[1].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    if (ch[2].weight != ch[2].previousWeight ||
        (ch[2].flags & (BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY | BLENDCHAN_FLAG_REFRESH_NEXT))) {
        return 1;
    }
    return 0;
}

void ObjModel_SetBlendChannelWeight(ObjModel* model, int channel, f32 weight) {
    ObjModelBlendChannel* ch;

    if (channel > 2 || model->file->morphTargets == NULL) {
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
    if (channel > 2 || ((ModelFileHeader*)(hdr = (u8*)model->file))->morphTargets == NULL) {
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
    if (model->file->morphTargets != NULL) {
        ObjModel_SetBlendChannelTargets(model, 0, -1, -1, 0.0f,
                                        BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
        ObjModel_SetBlendChannelTargets(model, 1, -1, -1, 0.0f,
                                        BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
        ObjModel_SetBlendChannelTargets(model, 2, -1, -1, 0.0f,
                                        BLENDCHAN_FLAG_MANUAL | BLENDCHAN_FLAG_RESET_WEIGHT | BLENDCHAN_FLAG_DIRTY);
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
    if (model->file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
        if (frameSource > 1) {
            ObjAnimCachedMove** cache = state->blendMoveCache;
            u16* cacheSlots = state->cacheSlots;
            animationData = (u8*)&cache[cacheSlots[frameSource]]->moveData;
        } else {
            ObjAnimCachedMove** cache = state->moveCache;
            u16* cacheSlots = state->cacheSlots;
            animationData = (u8*)&cache[cacheSlots[frameSource]]->moveData;
        }
    } else {
        u16* cacheSlots = state->cacheSlots;
        animationData = (u8*)model->file->moveData[cacheSlots[frameSource]];
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

void* animLoadFromTable(u8* hdr, int id, int idx, ObjAnimCachedMove* out) {
    int size;
    int flags;
    int out2;
    u8* buf;
    int stride;

    flags = 0;
    fileLoadToBufferOffset(MLDF_FILEID_PREANIM_TAB, &flags, id * sizeof(u32), 4);
    if (flags & 0x10000000) {
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, 0, flags, 0, &size, id, 1);
        buf = (u8*)&out->moveData;
        loadAndDecompressDataFile(MLDF_FILEID_PREANIM_BIN, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out->jointMatrixSlots,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    } else {
        flags = gModelAnimDataOffsetTable[id];
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, flags, 0, &size, id, 1);
        buf = (u8*)&out->moveData;
        loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, buf, flags, size, &out2, id, 0);
        stride = ((((ModelFileHeader*)hdr)->jointCount - 1) & ~7) + 8;
        fileLoadToBufferOffset(MLDF_FILEID_AMAP_BIN, out->jointMatrixSlots,
                               ((ModelFileHeader*)hdr)->animationDataFileOffset + idx * stride, stride);
    }
    return buf;
}
void* loadAnimation(ModelFileHeader* file, s16 animationId, int moveIndex, ObjAnimCachedMove* cachedMove) {
    int unusedSize;
    int animationBytes;
    ObjAnimMoveData* animation;
    int animationOffset;
    int cacheId;
    u32 modelId;

    if ((getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) != 0 && (modelId = file->modelId) != 1 && modelId != 3) {
        return 0;
    }
    if (cachedMove == 0) {
        if (ModelList_getHeader(gModelAnimCacheList, (cacheId = animationId), &animation) == 0) {
            ObjAnimMoveData* newAnimation;
            animationOffset = gModelAnimDataOffsetTable[animationId];
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, 0, animationOffset, 0, &animationBytes, cacheId, 1);
            animation = newAnimation = mmAlloc(animationBytes, 10, 0);
            loadAndDecompressDataFile(MLDF_FILEID_ANIM_BIN_A, newAnimation, animationOffset, animationBytes,
                                      &unusedSize, cacheId, 0);
            animation->refCount = 1;
            modelInitModelList(gModelAnimCacheList, animationId, &animation);
        } else {
            ObjAnimMoveData* cachedAnimation = animation;
            cachedAnimation->refCount += 1;
        }
        return animation;
    }
    return animLoadFromTable((u8*)file, animationId, (s16)moveIndex, cachedMove);
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
    return textureIdxToPtr(model->textureEntries[textureIndex].reference);
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

    if (file->flags & MODEL_FLAG_CACHED_ANIMATIONS) {
        rowA = channel->moveCache[channel->moveCacheSlot]->jointMatrixSlots;
        rowB = channel->moveCache[channel->prevMoveCacheSlot]->jointMatrixSlots;
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

void ObjModel_ResolveRenderOpTextures(ModelFileHeader* file) {
    int j, k;
    Shader* op;
    for (j = 0; j < file->renderOpCount; j++) {
        op = &file->renderOps[j];
        for (k = 0; k < op->layerCount; k++) {
            ShaderLayer* e = &op->layers[k];
            if (e->textureIndex != -1) {
                e->textureIndex = file->textureEntries[e->textureIndex].reference;
            } else {
                e->texture = NULL;
            }
        }
        if ((s32)op->auxTextureIndex != -1) {
            op->auxTextureIndex = file->textureEntries[(s32)op->auxTextureIndex].reference;
        } else {
            op->auxTexture = NULL;
        }
        if (op->indTextureId != -1) {
            op->indTextureId = file->textureEntries[op->indTextureId].reference;
        } else {
            op->indTexture = NULL;
        }
        if ((s32)op->unk1C != -1) {
            if ((s32)op->unk1C == -2) {
                op->unk1C = 0;
            } else {
                op->unk1C = 1;
            }
        } else {
            op->unk1C = 0;
        }
        if (op->textureId != -1) {
            op->textureId = file->textureEntries[op->textureId].reference;
        } else {
            op->textureId = 0;
        }
        if (!(file->shaderFlags & 0xc)) {
            op->reg1Texture = NULL;
        }
        if (!(file->shaderFlags & 0xe00)) {
            op->reg2Texture = NULL;
        }
    }
}

void* ObjModel_LoadModelData(int id);

void ObjModel_RelocateAnimData(ModelFileHeader* file, ObjModel* model) {
    int i;
    file->vertexAnimJob.chunks = file->vertexAnimEntries;
    for (i = 0; i < file->vertexAnimJob.chunkCount; i++) {
        model->vertexAnimOffsets[i] = file->vertexAnimEntries[i].srcDataOffset;
        if (file->vertexAnimEntries[i].weightStream < file->vertexWeightData) {
            file->vertexAnimEntries[i].weightStream =
                file->vertexWeightData + (u32)file->vertexAnimEntries[i].weightStream;
        }
    }
    file->normalAnimJob.chunks = file->normalAnimEntries;
    for (i = 0; i < file->normalAnimJob.chunkCount; i++) {
        model->normalAnimOutputs[i] = model->normalBuf + file->normalAnimEntries[i].srcDataOffset;
        if (file->normalAnimEntries[i].weightStream < file->normalWeightData) {
            file->normalAnimEntries[i].weightStream =
                file->normalWeightData + (u32)file->normalAnimEntries[i].weightStream;
        }
    }
}

void ObjModel_RelocateModelData(ModelFileHeader* file) {
    int i;
    u8* base = (u8*)file;
    if (file->hitVolumesOffset) {
        file->hitVolumes = base + file->hitVolumesOffset;
    }
    if (file->jointDataOffset) {
        file->jointData = base + file->jointDataOffset;
        if (file->unk18Offset) {
            file->unk18 = base + file->unk18Offset;
        }
        if (file->unk1COffset) {
            file->unk1C = base + file->unk1COffset;
        }
        if (file->jointFuzzScalesOffset) {
            file->jointFuzzScales = (ModelFuzzScaleDef*)(base + file->jointFuzzScalesOffset);
        }
    }
    if (file->extraJointDefsOffset) {
        file->extraJointDefs = (ModelExtraJointDef*)(base + file->extraJointDefsOffset);
    }
    if (file->textureEntriesOffset) {
        file->textureEntries = (ModelTextureEntry*)(base + file->textureEntriesOffset);
    }
    file->vertices = base + file->verticesOffset;
    if (file->normalsOffset) {
        file->normals = base + file->normalsOffset;
    }
    if (file->colorsOffset) {
        file->colors = base + file->colorsOffset;
    }
    if (file->texCoordsOffset) {
        file->texCoords = base + file->texCoordsOffset;
    }
    if (file->instrsOffset) {
        file->instrs = base + file->instrsOffset;
    }
    if (file->displayListsOffset) {
        file->displayLists = (ModelDisplayListEntry*)(base + file->displayListsOffset);
    }
    if (file->morphTargetsOffset) {
        file->morphTargets = (ModelMorphTargetRef*)(base + file->morphTargetsOffset);
    }
    if (file->vertexAnimEntriesOffset) {
        file->vertexAnimEntries = (ModelVtxAnimChunk*)(base + file->vertexAnimEntriesOffset);
    }
    if (file->vertexWeightDataOffset) {
        file->vertexWeightData = base + file->vertexWeightDataOffset;
    }
    if (file->normalAnimEntriesOffset) {
        file->normalAnimEntries = (ModelVtxAnimChunk*)(base + file->normalAnimEntriesOffset);
    }
    if (file->normalWeightDataOffset) {
        file->normalWeightData = base + file->normalWeightDataOffset;
    }
    if (file->renderOpsOffset) {
        file->renderOps = (Shader*)(base + file->renderOpsOffset);
    }
    for (i = 0; i < file->displayListCount + file->shadowDisplayListCount; i++) {
        file->displayLists[i].dlist = base + file->displayLists[i].dlistOffset;
    }
    for (i = 0; i < file->morphTargetCount; i++) {
        file->morphTargets[i].stream = (u16*)(base + file->morphTargets[i].offset);
    }
    if (file->collisionTrianglesOffset) {
        file->collisionTriangles = (ModelCollisionTriangle*)(base + file->collisionTrianglesOffset);
    }
    if (file->collisionBlocksOffset) {
        file->collisionBlocks = (CollisionPolygonGroup*)(base + file->collisionBlocksOffset);
    }
}

void* ObjModel_LoadModelData(int id) {
    int fileOffset, dataLen, animCount, cacheSize, amapFlag;
    int amapSize;
    int totalSize;
    void* model;
    if (getTableFileEntry(MLDF_FILEID_MODELS_TAB_A, id, &fileOffset) == 0) {
        return NULL;
    }
    loadModelsBin(fileOffset, &animCount, &cacheSize, &amapFlag, &dataLen, id);
    cacheSize = roundUpTo8(cacheSize);
    cacheSize += 0xb0;
    amapSize = modelGetAmapSize(id, amapFlag, animCount);
    totalSize = dataLen + amapSize + 0x1f4;
    model = (void*)roundUpTo16((int)mmAlloc(totalSize, 9, 0));
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
    DCInvalidateRange(model, totalSize);
#endif
    loadAndDecompressDataFile(MLDF_FILEID_MODELS_BIN_A, model, fileOffset, dataLen, 0, id, 0);
    ((ModelFileHeader*)model)->animationCacheSize = cacheSize;
    ((ModelFileHeader*)model)->modelId = id;
    ((ModelFileHeader*)model)->animationCount = animCount;
    ((ModelFileHeader*)model)->flags &= ~MODEL_FLAG_CACHED_ANIMATIONS;
    ((ModelFileHeader*)model)->refCount = 1;
    if (((ModelFileHeader*)model)->animationCount == 0) {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_NO_ANIMATIONS;
    }
    if (amapFlag != 0) {
        ((ModelFileHeader*)model)->flags |= MODEL_FLAG_CACHED_ANIMATIONS;
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
        for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->textureCount; z[1] += sizeof(ModelTextureEntry), z[0]++) {
            textureFree((Texture*)(textureIdxToPtr(
                ((ModelTextureEntry*)((u8*)((ModelFileHeader*)header)->textureEntries + z[1]))->reference)));
        }
        if (((ModelFileHeader*)header)->moveData != NULL && ((ModelFileHeader*)header)->animationCount != 0) {
            z[0] = 0;
            for (z[1] = z[0]; z[0] < ((ModelFileHeader*)header)->animationCount; z[1] += 4, z[0]++) {
                int idx;
                ObjAnimMoveData* animation = *(ObjAnimMoveData**)((u8*)((ModelFileHeader*)header)->moveData + z[1]);
                if (animation != NULL && (s8)--animation->refCount <= 0) {
                    model_findIdxInModelList(gModelAnimCacheList, &animation, &idx);
                    model_adjustModelList(gModelAnimCacheList, idx);
                    mm_free(animation);
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
    ModelFileHeader* header;
    int i[1];
    ModelFileHeader* loaded[1];
    int textureOffset[1];
    void* textureRef;
    int requestedId;
    realId[0] = 0;
    i[0] = 0;
    requestedId = id;
    if (requestedId < 0) {
        realId[0] = -requestedId;
    } else {
        fileLoadToBufferOffset(MLDF_FILEID_MODELIND_BIN, gModelResourceBuffer, requestedId * 2, 8);
        realId[0] = gModelResourceBuffer[0];
    }
    if (ModelList_getHeader(gModelList, realId[0], &header) == 0) {
        header = ObjModel_LoadModelData(realId[0]);
        ObjModel_RelocateModelData(header);
        loaded[0] = header;
        i[0] = 0;
        textureOffset[0] = i[0];
        for (; i[0] < loaded[0]->textureCount; i[0]++) {
            textureRef = textureLoad(
                -(((ModelTextureEntry*)((u8*)loaded[0]->textureEntries + textureOffset[0]))->assetId | 0x8000), 1);
            ((ModelTextureEntry*)((u8*)loaded[0]->textureEntries + textureOffset[0]))->loadResult = textureRef;
            textureOffset[0] += sizeof(ModelTextureEntry);
        }
        ObjModel_ResolveRenderOpTextures(header);
        modelLoadAnimations(header, realId[0], (u8*)header + header->dataSize);
        modelInitModelList(gModelList, realId[0], &header);
    } else {
        header->refCount++;
    }
    *outSize = modelLoad_calcSizes((u8*)header, loadFlag, sizes, 0);
    return header;
}

void* loadModelInstance(int resourceId, int arg, void* buffer) {
    return NULL;
}

void ObjModel_InitResourceCaches(void) {
    ModelResourceScratch* scratch;
    int* p;
    gModelList = allocModelStruct(0x8c, (int)sizeof(u8*));
    gModelAnimCacheList = allocModelStruct(0xc4, (int)sizeof(u8*));
    scratch = mmAlloc(sizeof(*scratch), 0xa, 0);
    gModelResourceBuffer = scratch->ids;
    gModelAnimOffsetTable = scratch->offsets.animationMapOffsets;
    lbl_803DCB5C = (int*)scratch->offsets.opaque.tail;
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

/* Integer address addition preserves MWCC's offset-before-buffer load order.
 * Keep the address wide enough for native pointers as well as the target. */
STATIC_ASSERT(sizeof(size_t) == sizeof(void*));

static inline void modelConsumeNormalChunk(u8* mtxs, ModelVtxAnimChunk* chunk, u32 i, u16* chunkBlocks, u8* chunkDst,
                                           void (*transform)(u8*, u8*, u8*, u8*, u8*, int)) {
    transform(mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
              gModelCacheBuffersA[(u8)((i & 1) * 2) + 1],
              (u8*)(chunk->dstByteOffset + (size_t)gModelCacheBuffersA[(u8)((i & 1) * 2)]),
              (u8*)(chunk->dstByteOffset + (size_t)gModelCacheBuffersA[(u8)((i & 1) * 2)]), chunk->vtxCount);
    memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((i & 1) * 2)], chunkBlocks[i & 1]);
}

void ObjModel_BlendNormalStream(u8* mtxs, ModelVtxAnimJob* job, u8* animData, u8** outs, int normalTriplets) {
    u16 chunkBlocks[2];

    setGQR7Packed(job->quantShift, 6, job->quantShift, 6);
    ObjModel_InitScratchBuffers();
    if (job->chunkCount != 0) {
        ModelVtxAnimChunk* chunk;
        int vtxBlocks;
        int weightBlocks;
        u32 i;
        u32 nextSlot;
        ModelVtxAnimChunk* lastChunk;

        chunk = job->chunks;
        vtxBlocks = (u32)((chunk->vtxBlocks << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + chunk->srcDataOffset, vtxBlocks);
        chunkBlocks[0] = vtxBlocks;
        weightBlocks = (u32)(((chunk = job->chunks)->weightBlocks << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((u8*)gModelCacheBuffersA + sizeof(gModelCacheBuffersA[0])), chunk->weightStream,
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
            if ((u8)normalTriplets) {
                modelConsumeNormalChunk(mtxs, chunk, i, chunkBlocks, outs[i], ObjModel_TransformNormalTriplets);
            } else {
                modelConsumeNormalChunk(mtxs, chunk, i, chunkBlocks, outs[i], ObjModel_TransformVerticesLinear);
            }
        }
        lastChunk = job->chunks + i;
        cacheQueueWait(0);
        if ((u8)normalTriplets) {
            modelConsumeNormalChunk(mtxs, lastChunk, i, chunkBlocks, outs[i], ObjModel_TransformNormalTriplets);
        } else {
            modelConsumeNormalChunk(mtxs, lastChunk, i, chunkBlocks, outs[i], ObjModel_TransformVerticesLinear);
        }
        cacheQueueWait(0);
    }
}

static inline ModelVtxAnimChunk* modelPrefetchNextVertexChunk(ModelVtxAnimJob* job, u32 i, u8* animData,
                                                              u16* chunkBlocks, int* work) {
    ModelVtxAnimChunk* chunks;
    u32 nextBufferIndex;
    chunks = job->chunks;
    *work = (u32)((chunks[i + 1].vtxBlocks << 5) + 0x1f) >> 5;
    nextBufferIndex = ((i + 1) & 1) * 2;
    copyToCache(gModelCacheBuffersA[(u8)(nextBufferIndex)], animData + chunks[i + 1].srcDataOffset, *work);
    chunkBlocks[(i + 1) & 1] = *work;
    {
        ModelVtxAnimChunk* nextChunk;
        int nextWeightBlocks = (u32)(((nextChunk = job->chunks + i)[1].weightBlocks << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[(u8)((u8)(nextBufferIndex) + 1)], nextChunk[1].weightStream, nextWeightBlocks);
    }
    return chunks + i;
}

static inline void modelConsumeVertexChunk(u8* mtxs, ModelVtxAnimChunk* chunk, u32 i, u16* chunkBlocks, u8* chunkDst,
                                           int* work) {
    *work = i & 1;
    ObjModel_TransformVerticesWithTranslation(
        mtxs + chunk->mtxIdxA * sizeof(ROMtx), mtxs + chunk->mtxIdxB * sizeof(ROMtx),
        gModelCacheBuffersA[(u8)((u32)*work * 2) + 1],
        (u8*)(chunk->dstByteOffset + (size_t)gModelCacheBuffersA[(u8)((u32)*work * 2)]),
        (u8*)(chunk->dstByteOffset + (size_t)gModelCacheBuffersA[(u8)((u32)*work * 2)]), chunk->vtxCount);
    memcpyToCache(chunkDst, gModelCacheBuffersA[(u8)((u32)*work * 2)], chunkBlocks[(u32)*work]);
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
        int work;

        chunk = job->chunks;
        vtxBlocks = (u32)((chunk->vtxBlocks << 5) + 0x1f) >> 5;
        copyToCache(gModelCacheBuffersA[0], animData + chunk->srcDataOffset, vtxBlocks);
        chunkBlocks[0] = vtxBlocks;
        weightBlocks = (u32)(((chunk = job->chunks)->weightBlocks << 5) + 0x1f) >> 5;
        copyToCache(*(u8**)((u8*)gModelCacheBuffersA + sizeof(gModelCacheBuffersA[0])), chunk->weightStream,
                    weightBlocks);
        for (i = 0; i < (u32)(job->chunkCount - 1); i++) {
            chunk = modelPrefetchNextVertexChunk(job, i, animData, chunkBlocks, &work);
            cacheQueueWait(2);
            modelConsumeVertexChunk(mtxs, chunk, i, chunkBlocks, dstBase + dstOffsets[i], &work);
        }
        chunk = job->chunks + i;
        cacheQueueWait(0);
        modelConsumeVertexChunk(mtxs, chunk, i, chunkBlocks, dstBase + dstOffsets[i], &work);
        cacheQueueWait(0);
    }
}

/* Register ABI: r3/r4 are 3x4 matrices A and B, r5 walks the u8 weight pairs
 * through GQR6, r6/r7 walk the source/destination vertices through GQR7 and
 * r8 is the vertex count, which must be nonzero. The loop is software
 * pipelined: each pass stores the previous vertex and reads one vertex ahead. */
asm void ObjModel_TransformVerticesWithTranslation(u8* matrixA, u8* matrixB, u8* weightPairs, u8* source,
                                                   u8* destination, int count) {
    // clang-format off
    nofralloc
    stwu r1, -0xa0(r1)
    stfd f14, 0x8(r1)
    addi r9, r8, -1
    stfd f15, 0x10(r1)
    stfd f16, 0x18(r1)
    stfd f17, 0x20(r1)
    stfd f18, 0x28(r1)
    stfd f19, 0x30(r1)
    stfd f20, 0x38(r1)
    stfd f21, 0x40(r1)
    stfd f22, 0x48(r1)
    stfd f23, 0x50(r1)
    stfd f24, 0x58(r1)
    stfd f25, 0x60(r1)
    stfd f26, 0x68(r1)
    stfd f27, 0x70(r1)
    mtctr r9
    psq_l f0, 0x0(r3), 0, 0
    addi r6, r6, -2
    psq_l f1, 0x8(r3), 1, 0
    addi r7, r7, -2
    psq_l f6, 0x24(r3), 0, 0
    addi r5, r5, -2
    psq_lu f8, 0x2(r6), 0, 7
    psq_l f7, 0x2c(r3), 1, 0
    psq_lu f9, 0x4(r6), 1, 7
    psq_lu f27, 0x2(r5), 0, 6
    ps_madds0 f15, f0, f8, f6
    psq_l f2, 0xc(r3), 0, 0
    ps_madds0 f16, f1, f8, f7
    psq_l f3, 0x14(r3), 1, 0
    psq_l f5, 0x20(r3), 1, 0
    ps_madds1 f15, f2, f8, f15
    psq_l f19, 0x0(r4), 0, 0
    ps_madds1 f16, f3, f8, f16
    psq_l f4, 0x18(r3), 0, 0
    psq_l f20, 0x8(r4), 1, 0
    psq_l f21, 0xc(r4), 0, 0
    ps_madds0 f15, f4, f9, f15
    psq_l f22, 0x14(r4), 1, 0
    ps_madds0 f16, f5, f9, f16
    psq_l f23, 0x18(r4), 0, 0
    psq_l f24, 0x20(r4), 1, 0
    psq_l f25, 0x24(r4), 0, 0
    ps_muls0 f15, f15, f27
    psq_l f26, 0x2c(r4), 1, 0
    ps_muls0 f16, f16, f27
    ps_madds0 f11, f19, f8, f25
    ps_madds0 f12, f20, f8, f26
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x2(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x4(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
loop:
    ps_madds0 f15, f0, f8, f6
    psq_stu f11, 0x2(r7), 0, 7
    ps_madds0 f16, f1, f8, f7
    psq_stu f12, 0x4(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    psq_lu f27, 0x2(r5), 0, 6
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_madds0 f11, f19, f8, f25
    ps_madds0 f12, f20, f8, f26
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x2(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x4(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    bdnz loop
    psq_stu f11, 0x2(r7), 0, 7
    psq_stu f12, 0x4(r7), 1, 7
    lfd f14, 0x8(r1)
    lfd f15, 0x10(r1)
    lfd f16, 0x18(r1)
    lfd f17, 0x20(r1)
    lfd f18, 0x28(r1)
    lfd f19, 0x30(r1)
    lfd f20, 0x38(r1)
    lfd f21, 0x40(r1)
    lfd f22, 0x48(r1)
    lfd f23, 0x50(r1)
    lfd f24, 0x58(r1)
    lfd f25, 0x60(r1)
    lfd f26, 0x68(r1)
    lfd f27, 0x70(r1)
    addi r1, r1, 160
    blr
    // clang-format on
}

/* Register ABI: r3/r4 are 3x4 matrices A and B, r5 walks the u8 weight pairs
 * through GQR6, r6/r7 walk the source/destination vertices through GQR7 and
 * r8 is the vertex count, which must be nonzero. The loop is software
 * pipelined: each pass stores the previous vertex and reads one vertex ahead. */
asm void ObjModel_TransformVerticesLinear(u8* matrixA, u8* matrixB, u8* weightPairs, u8* source, u8* destination,
                                          int count) {
    // clang-format off
    nofralloc
    stwu r1, -0xa0(r1)
    stfd f14, 0x8(r1)
    addi r9, r8, -1
    stfd f15, 0x10(r1)
    stfd f16, 0x18(r1)
    stfd f17, 0x20(r1)
    stfd f18, 0x28(r1)
    stfd f19, 0x30(r1)
    stfd f20, 0x38(r1)
    stfd f21, 0x40(r1)
    stfd f22, 0x48(r1)
    stfd f23, 0x50(r1)
    stfd f24, 0x58(r1)
    stfd f25, 0x60(r1)
    stfd f26, 0x68(r1)
    stfd f27, 0x70(r1)
    mtctr r9
    psq_l f0, 0x0(r3), 0, 0
    addi r6, r6, -1
    psq_l f1, 0x8(r3), 1, 0
    addi r7, r7, -1
    addi r5, r5, -2
    psq_lu f8, 0x1(r6), 0, 7
    psq_lu f9, 0x2(r6), 1, 7
    psq_lu f27, 0x2(r5), 0, 6
    ps_muls0 f15, f0, f8
    psq_l f2, 0xc(r3), 0, 0
    ps_muls0 f16, f1, f8
    psq_l f3, 0x14(r3), 1, 0
    psq_l f5, 0x20(r3), 1, 0
    ps_madds1 f15, f2, f8, f15
    psq_l f19, 0x0(r4), 0, 0
    ps_madds1 f16, f3, f8, f16
    psq_l f4, 0x18(r3), 0, 0
    psq_l f20, 0x8(r4), 1, 0
    psq_l f21, 0xc(r4), 0, 0
    ps_madds0 f15, f4, f9, f15
    psq_l f22, 0x14(r4), 1, 0
    ps_madds0 f16, f5, f9, f16
    psq_l f23, 0x18(r4), 0, 0
    psq_l f24, 0x20(r4), 1, 0
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
loop:
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    psq_lu f27, 0x2(r5), 0, 6
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    bdnz loop
    psq_stu f11, 0x1(r7), 0, 7
    psq_stu f12, 0x2(r7), 1, 7
    lfd f14, 0x8(r1)
    lfd f15, 0x10(r1)
    lfd f16, 0x18(r1)
    lfd f17, 0x20(r1)
    lfd f18, 0x28(r1)
    lfd f19, 0x30(r1)
    lfd f20, 0x38(r1)
    lfd f21, 0x40(r1)
    lfd f22, 0x48(r1)
    lfd f23, 0x50(r1)
    lfd f24, 0x58(r1)
    lfd f25, 0x60(r1)
    lfd f26, 0x68(r1)
    lfd f27, 0x70(r1)
    addi r1, r1, 160
    blr
    // clang-format on
}

/* Same register ABI as the vertex loops; each weight pair covers three consecutive
 * normals, so the weight load is scheduled once per three stores. */
asm void ObjModel_TransformNormalTriplets(u8* matrixA, u8* matrixB, u8* weightPairs, u8* source, u8* destination,
                                          int count) {
    // clang-format off
    nofralloc
    stwu r1, -0xa0(r1)
    stfd f14, 0x8(r1)
    addi r9, r8, -1
    stfd f15, 0x10(r1)
    stfd f16, 0x18(r1)
    stfd f17, 0x20(r1)
    stfd f18, 0x28(r1)
    stfd f19, 0x30(r1)
    stfd f20, 0x38(r1)
    stfd f21, 0x40(r1)
    stfd f22, 0x48(r1)
    stfd f23, 0x50(r1)
    stfd f24, 0x58(r1)
    stfd f25, 0x60(r1)
    stfd f26, 0x68(r1)
    stfd f27, 0x70(r1)
    mtctr r9
    psq_l f0, 0x0(r3), 0, 0
    addi r6, r6, -1
    psq_l f1, 0x8(r3), 1, 0
    addi r7, r7, -1
    addi r5, r5, -2
    psq_lu f8, 0x1(r6), 0, 7
    psq_lu f9, 0x2(r6), 1, 7
    psq_lu f27, 0x2(r5), 0, 6
    ps_muls0 f15, f0, f8
    psq_l f2, 0xc(r3), 0, 0
    ps_muls0 f16, f1, f8
    psq_l f3, 0x14(r3), 1, 0
    psq_l f5, 0x20(r3), 1, 0
    ps_madds1 f15, f2, f8, f15
    psq_l f19, 0x0(r4), 0, 0
    ps_madds1 f16, f3, f8, f16
    psq_l f4, 0x18(r3), 0, 0
    psq_l f20, 0x8(r4), 1, 0
    psq_l f21, 0xc(r4), 0, 0
    ps_madds0 f15, f4, f9, f15
    psq_l f22, 0x14(r4), 1, 0
    ps_madds0 f16, f5, f9, f16
    psq_l f23, 0x18(r4), 0, 0
    psq_l f24, 0x20(r4), 1, 0
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
loop:
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    psq_lu f27, 0x2(r5), 0, 6
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    ps_muls0 f15, f0, f8
    psq_stu f11, 0x1(r7), 0, 7
    ps_muls0 f16, f1, f8
    psq_stu f12, 0x2(r7), 1, 7
    ps_madds1 f15, f2, f8, f15
    ps_madds1 f16, f3, f8, f16
    ps_madds0 f15, f4, f9, f15
    ps_madds0 f16, f5, f9, f16
    ps_muls0 f15, f15, f27
    ps_muls0 f16, f16, f27
    ps_muls0 f11, f19, f8
    ps_muls0 f12, f20, f8
    ps_madds1 f11, f21, f8, f11
    ps_madds1 f12, f22, f8, f12
    psq_lu f8, 0x1(r6), 0, 7
    ps_madds0 f11, f23, f9, f11
    ps_madds0 f12, f24, f9, f12
    psq_lu f9, 0x2(r6), 1, 7
    ps_madds1 f11, f11, f27, f15
    ps_madds1 f12, f12, f27, f16
    bdnz loop
    psq_stu f11, 0x1(r7), 0, 7
    psq_stu f12, 0x2(r7), 1, 7
    lfd f14, 0x8(r1)
    lfd f15, 0x10(r1)
    lfd f16, 0x18(r1)
    lfd f17, 0x20(r1)
    lfd f18, 0x28(r1)
    lfd f19, 0x30(r1)
    lfd f20, 0x38(r1)
    lfd f21, 0x40(r1)
    lfd f22, 0x48(r1)
    lfd f23, 0x50(r1)
    lfd f24, 0x58(r1)
    lfd f25, 0x60(r1)
    lfd f26, 0x68(r1)
    lfd f27, 0x70(r1)
    addi r1, r1, 160
    blr
    // clang-format on
}

void setGQR6(register u32 config) {
    asm {
        mtspr GQR6, config
    }
}

void setGQR7(register u32 config) {
    asm {
        mtspr GQR7, config
    }
}
void setGQR7Packed(int loadScale, int loadType, int storeScale, int storeType) {
    setGQR7((((loadScale << 8) + loadType) << 16) | ((storeScale << 8) + storeType));
}

void setGQR6_2(int loadScale, int loadType, int storeScale, int storeType) {
    setGQR6((((loadScale << 8) + loadType) << 16) | ((storeScale << 8) + storeType));
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
