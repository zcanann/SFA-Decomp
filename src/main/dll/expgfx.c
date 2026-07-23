#include "main/dll/partfx_interface.h"
#include "dolphin/mtx.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_fog_api.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_geom_api.h"
#include "main/hud_visibility_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/object.h"
#include "main/camera.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/expgfx_internal.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/mm.h"
#include "main/sky.h"
#include "main/tex_dolphin.h"
#include "main/texture.h"
#include "main/dll/objfx_api.h"
#include "dolphin/os/OSFastCast.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/render_mode_api.h"
#include "main/dll/objfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "main/dll/viewfinder.h"
#include "main/dll/dll_000B_dll0b.h"
#include "track/intersect_api.h"
#include "main/lightmap.h"
#include "main/dll/dll_80136a40.h"

int gExpgfxSlotType1Average;
int lbl_803DD274;
int gExpgfxSlotType1Count;
int gExpgfxLastAddedSlot;
u16 gExpgfxPhaseAngleB;
u16 gExpgfxPhaseAngleA;
f32 gExpgfxFrameTimerC;
f32 gExpgfxFrameTimerB;
f32 gExpgfxFrameTimerA;
int gExpgfxTextureFreeInProgress;
u8 gExpgfxRenderResetPending;
u8 lbl_803DD253;
u8 gExpgfxFrameParityBit;
s16 gExpgfxSequenceCounter;

f32 gExpgfxNearFadeDepth = -50.0f;

typedef union ExpgfxWGPipe
{
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
    f64 f64;
} ExpgfxWGPipe;

typedef struct ExpgfxRotateParams
{
    s16 angleX;
    s16 angleY;
    s16 angleZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ExpgfxRotateParams;

typedef struct ExpgfxBillboardAngles
{
    s16 pitch;
    s16 yaw;
} ExpgfxBillboardAngles;

typedef union Dll0BDescriptorTable
{
    u32 words[30];
    u64 align8;
} Dll0BDescriptorTable;

#define GX_BM_NONE        0
#define GX_BM_BLEND       1
#define GX_BL_ZERO        0
#define GX_BL_ONE         1
#define GX_BL_SRCALPHA    4
#define GX_BL_INVSRCALPHA 5
#define GX_LO_NOOP        5
#define GX_GREATER        4
#define GX_ALWAYS         7
#define GX_AOP_AND        0
#define GX_CULL_NONE      0
#define GX_VA_POS         9
#define GX_VA_CLR0        11
#define GX_VA_TEX0        13
#define GX_DIRECT         1
#define GX_QUADS          0x80
#define GX_VTXFMT4        4
#define GX_PNMTX0         0
#define GX_COLOR0         0
#define GX_ALPHA0         2
#define GX_FALSE          0
#define GX_SRC_REG        0
#define GX_SRC_VTX        1
#define GX_DF_NONE        0
#define GX_AF_NONE        2

#define GXWGFifo (*(volatile ExpgfxWGPipe*)0xCC008000)

extern u8 lbl_803DD253;
extern f32 gExpgfxYVelocityPositiveLimit;
extern f32 gExpgfxYVelocityFastStep;
extern f32 gExpgfxYVelocitySlowStep;
extern f32 gExpgfxYVelocityNegativeLimit;
extern const f32 gExpgfxSlotMotionStep;

extern const f32 gExpgfxBoundsInitMin;
extern const f32 gExpgfxBoundsInitMax;
extern const f32 gExpgfxU16ToUnitScale;
extern int gExpgfxSlotType1Count;
extern int lbl_803DD274;
extern int gExpgfxSlotType1Average;

static inline ExpgfxTableEntry* Expgfx_GetTableEntry(int tableIndex)
{
    return &gExpgfxTableEntries[tableIndex];
}

static inline u32 Expgfx_GetSlotTableIndex(const ExpgfxSlot* slot)
{
    return ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;
}

static inline void Expgfx_SetSlotTableIndex(ExpgfxSlot* slot, u8 tableIndex)
{
    slot->encodedTableIndex = (u8)((tableIndex << 1) | (slot->encodedTableIndex & 1));
}

static inline ExpgfxSlot* Expgfx_GetSlot(int poolIndex, int slotIndex)
{
    return (ExpgfxSlot*)(gExpgfxSlotPoolBases[poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
}

static inline ExpgfxBounds* Expgfx_GetBoundsTemplate(int templateIndex)
{
    return &((ExpgfxBounds*)gExpgfxStaticData)[templateIndex];
}

#define EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, poolIndex) \
    ((u32*)((u8*)(runtime)->poolActiveMasks + (poolIndex) * sizeof(u32)))

void expgfxRemove(u32 slotPoolBase, int poolIndex, int slotIndex, int skipTextureFree, int flushSlot)
{
    ExpgfxRuntimeDataLayout* runtime;
    int activeBit[1];
    u32* resources[1];
    ExpgfxSlot* slot;
    u32 inactiveBitMask;

    runtime = EXPGFX_RUNTIME_DATA;
    resources[0] = NULL;
    activeBit[0] = 1 << slotIndex;
    if ((activeBit[0] & runtime->poolActiveMasks[poolIndex]) == 0)
    {
        return;
    }

    slot = (ExpgfxSlot*)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;

    if (skipTextureFree == 0)
    {
        resources[0] = &runtime->expTab[0].resource;

        if (resources[0][Expgfx_GetSlotTableIndex(slot) * 4] != 0)
        {
            gExpgfxTextureFreeInProgress = 1;
            textureFree((Texture*)(void*)resources[0][Expgfx_GetSlotTableIndex(slot) * 4]);
            gExpgfxTextureFreeInProgress = 0;
        }

        {
            u32 tableIndex = Expgfx_GetSlotTableIndex(slot);

            if (runtime->expTab[tableIndex].refCount != 0)
            {
                runtime->expTab[tableIndex].refCount--;
                if (runtime->expTab[tableIndex].refCount == 0)
                {
                    resources[0][tableIndex * 4] = 0;
                    runtime->expTab[tableIndex].sourceId = 0;
                }
            }
            else
            {
                debugPrintf(sExpgfxMismatchInAddRemove);
            }
        }
    }

    slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
    if ((u8)flushSlot != 0)
    {
        DCFlushRange(slot, EXPGFX_SLOT_SIZE);
    }

    {
        u32 currentMaskValue = runtime->poolActiveMasks[poolIndex];
        inactiveBitMask = ~activeBit[0];
        runtime->poolActiveMasks[poolIndex] = currentMaskValue & inactiveBitMask;
    }
    runtime->poolActiveCounts[poolIndex]--;
    if (runtime->poolActiveCounts[poolIndex] == 0)
    {
        gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
    }
}

static inline void expgfxRemoveAllBody(void)
{
    ExpgfxTableEntry* expTabEntry;
    u16* refCountPtr;
    ExpgfxSlot* slot;
    int slotIndex;
    int poolIndex;
    int activeBit;
    s16* poolSlotTypeIds;
    s8* poolActiveCountPtrs;
    u32* poolActiveMasks;
    u32* slotPoolBases;
    ExpgfxRuntimeDataLayout* runtime;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotPoolBases = runtime->slotPoolBases;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCountPtrs = runtime->poolActiveCounts;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        slot = (ExpgfxSlot*)*slotPoolBases;
        slotIndex = 0;
        while (slotIndex < EXPGFX_SLOTS_PER_POOL)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & *poolActiveMasks) != 0)
            {
                if (((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0 &&
                    ((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0)
                {
                    gExpgfxTextureFreeInProgress = 1;
                    textureFree((Texture*)((void*)((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))
                                    ->resource));
                    gExpgfxTextureFreeInProgress = 0;
                }

                expTabEntry = (ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16);
                refCountPtr = &expTabEntry->refCount;
                if (*refCountPtr != 0)
                {
                    (*refCountPtr)--;
                    if (*refCountPtr == 0)
                    {
                        expTabEntry->resource = 0;
                        expTabEntry->sourceId = 0;
                    }
                }
                else
                {
                    debugPrintf(sExpgfxMismatchInAddRemove);
                }

                slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
                *poolActiveMasks &= ~activeBit;
            }

            slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
            slotIndex++;
        }

        *poolActiveCountPtrs = 0;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        DCFlushRange((void*)*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases++;
        poolActiveMasks++;
        poolActiveCountPtrs++;
        poolSlotTypeIds++;
        poolIndex++;
    }
}

void expgfxRemoveAll(void)
{
    expgfxRemoveAllBody();
}

void expgfxRemoveAll(void);

static inline void expgfxSetSlotResult(s16* poolIndexOut, s16* slotIndexOut,
                                       s16 poolIndex, s16 slotIndex)
{
    *slotIndexOut = slotIndex;
    *poolIndexOut = poolIndex;
}

int expgfxGetSlot(short* poolIndexOut, short* slotIndexOut, short slotType, int preferredPoolIndex, u32 sourceId)
{
    u32 currentMask;
    u32* activeMaskPtr;
    int chosenPool;
    s16* poolSlotTypeIds;
    u32* sourceIdWalk;
    s8* activeCountWalk;
    u32 activeBit;
    ExpgfxRuntimeDataLayout* runtime;
    short foundPoolIndex;
    short found;
    s8* poolActiveCounts;
    int slotIndex;
    int batchGroup;
    int batchSlot;
    int searchIndex;
    runtime = EXPGFX_RUNTIME_DATA;
    foundPoolIndex = EXPGFX_INVALID_POOL_INDEX;
    found = 0;
    searchIndex = 0;
    sourceIdWalk = runtime->poolSourceIds;
    poolSlotTypeIds = &gExpgfxStaticPoolSlotTypeIds[0];
    poolActiveCounts = runtime->poolActiveCounts;
    activeCountWalk = poolActiveCounts;
    for (batchGroup = 0; batchGroup < EXPGFX_POOL_SEARCH_BATCH_COUNT;
         activeCountWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE,
             sourceIdWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE, batchGroup++)
    {
        for (batchSlot = 0; batchSlot < EXPGFX_POOL_SEARCH_BATCH_SIZE;
             poolSlotTypeIds++, searchIndex++, batchSlot++)
        {
            u32 bs = batchSlot;
            if ((sourceIdWalk[bs] == sourceId) && (slotType == *poolSlotTypeIds) &&
                (activeCountWalk[bs] < EXPGFX_SLOTS_PER_POOL))
            {
                foundPoolIndex = searchIndex;
                found = 1;
                break;
            }
        }
        if (found)
        {
            break;
        }
    }

    if (found)
    {
        slotIndex = 0;
        chosenPool = foundPoolIndex;
        activeMaskPtr = EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, chosenPool);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & currentMask) == 0)
            {
                expgfxSetSlotResult(poolIndexOut, slotIndexOut, foundPoolIndex, slotIndex);
                *activeMaskPtr |= activeBit;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
    }

    found = 0;
    if (preferredPoolIndex == EXPGFX_INVALID_POOL_INDEX)
    {
        for (searchIndex = 0; searchIndex < EXPGFX_POOL_COUNT - 1; poolActiveCounts++, searchIndex++)
        {
            if (*poolActiveCounts <= 0)
            {
                foundPoolIndex = searchIndex;
                found = 1;
                runtime->poolActiveCounts[searchIndex] = 0;
                break;
            }
        }
    }
    else if (preferredPoolIndex != EXPGFX_INVALID_POOL_INDEX)
    {
        searchIndex = preferredPoolIndex;
        if (runtime->poolActiveCounts[preferredPoolIndex] < EXPGFX_SLOTS_PER_POOL)
        {
            foundPoolIndex = preferredPoolIndex;
            found = 1;
        }
    }

    if (found)
    {
        slotIndex = 0;
        chosenPool = foundPoolIndex;
        activeMaskPtr = EXPGFX_POOL_ACTIVE_MASK_PTR(runtime, chosenPool);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & currentMask) == 0)
            {
                expgfxSetSlotResult(poolIndexOut, slotIndexOut, foundPoolIndex, slotIndex);
                *activeMaskPtr |= activeBit;
                gExpgfxStaticPoolSlotTypeIds[searchIndex] = slotType;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
        return EXPGFX_INVALID_POOL_INDEX;
    }

    return EXPGFX_INVALID_POOL_INDEX;
}

void expgfx_initSlotQuad(void* slotPtr)
{
    ExpgfxStaticDataLayout* staticData;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* entry;
    ExpgfxQuadVertex* quad;
    ExpgfxQuadTemplateVertex* quadTemplate;
    u32 resource;
    u32 behaviorFlags;
    s16 texT1;
    s16 texT0;
    s16 texS1;
    s16 texS0;
    f32 step;
    slot = (ExpgfxSlot*)slotPtr;
    staticData = EXPGFX_STATIC_DATA;
    entry = gExpgfxTableEntries;
    entry += ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;
    resource = entry->resource;

    slot->stateBits.bits.frameParity = 0;
    slot->stateBits.bits.quadReady = 1;

    behaviorFlags = slot->behaviorFlags;
    if ((behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0)
    {
        quadTemplate = staticData->quadTemplateA;
    }
    else
    {
        quadTemplate = staticData->quadTemplateB;
    }

    if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 && slot->velocityY < gExpgfxYVelocityPositiveLimit)
    {
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 && slot->velocityY < gExpgfxYVelocityPositiveLimit)
        {
            slot->velocityY -= gExpgfxYVelocityFastStep * timeDelta;
        }
        else
        {
            slot->velocityY -= gExpgfxYVelocitySlowStep * timeDelta;
        }
    }
    else if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 && slot->velocityY > gExpgfxYVelocityNegativeLimit)
    {
        slot->velocityY += gExpgfxYVelocityFastStep * timeDelta;
    }
    else if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
             slot->velocityY > gExpgfxYVelocityNegativeLimit)
    {
        slot->velocityY += gExpgfxYVelocitySlowStep * timeDelta;
    }

    slot->posX.value += slot->velocityX * (step = gExpgfxSlotMotionStep);
    slot->posY.value += slot->velocityY * step;
    slot->posZ.value += slot->velocityZ * step;

    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0)
    {
        *(u16*)&slot->scaleCurrent = ((f32)(u16)slot->scaleStep * step + (f32)(u16)slot->scaleCurrent);
    }
    else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0)
    {
        *(u16*)&slot->scaleCurrent = ((f32)(u16)slot->scaleCurrent - (f32)(u16)slot->scaleStep * step);
    }

    if (resource == 0)
    {
        debugPrintf(staticData->noTextureString);
        return;
    }

    texT0 = 0;
    texT1 = 0;
    texS0 = 0;
    texS1 = 0;
    if (resource != 0)
    {
        texS0 = EXPGFX_QUAD_TEXCOORD_MAX;
        texT0 = EXPGFX_QUAD_TEXCOORD_MAX;
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0)
        {
            texS1 = EXPGFX_QUAD_TEXCOORD_MAX;
            texS0 = 0;
        }
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0)
        {
            texT1 = EXPGFX_QUAD_TEXCOORD_MAX;
            texT0 = 0;
        }
    }

    quad = (ExpgfxQuadVertex*)slot;
    quad[0].x = quadTemplate[0].x;
    quad[0].y = quadTemplate[0].y;
    quad[0].z = quadTemplate[0].z;
    quad[0].texS = texS0;
    quad[0].texT = texT0;
    quad[1].x = quadTemplate[1].x;
    quad[1].y = quadTemplate[1].y;
    quad[1].z = quadTemplate[1].z;
    quad[1].texS = texS1;
    quad[1].texT = texT0;
    quad[2].x = quadTemplate[2].x;
    quad[2].y = quadTemplate[2].y;
    quad[2].z = quadTemplate[2].z;
    quad[2].texS = texS1;
    quad[2].texT = texT1;
    quad[3].x = quadTemplate[3].x;
    quad[3].y = quadTemplate[3].y;
    quad[3].z = quadTemplate[3].z;
    quad[3].texS = texS0;
    quad[3].texT = texT1;
}

void expgfx_updateActivePools(u8 sourceMode, int sourceId, int resetSourceFrameState)
{
    ExpgfxBounds* bounds;
    ExpgfxRuntimeDataLayout* runtime;
    int nextActivePool;
    f32* maxXPtr;
    f32* minYPtr;
    f32* maxYPtr;
    f32* minZPtr;
    f32* maxZPtr;
    int pool;
    int sky;
    ExpgfxStaticDataLayout* staticData;
    s16 slotIdx;
    ExpgfxSlot* slot;
    ExpgfxQuadTemplateVertex* quadTemplate;
    s16 texT1;
    s16 texT0;
    s16 texS1;
    s16 texS0;
    GameObject* player;
    GameObject* tricky;
    u8* nextCacheBuf;
    u8 cacheParity;
    u32 resource;
    s8* activeCountScan;
    int curPool;
    int poolByteOffset;
    u32* maskPtr;
    void* cache;
    u8* curCacheBuf;
    u8* curPoolBuf;
    ExpgfxSourceObject* srcObj;
    u8 cacheQueued;
    int ambRPlus1;
    int ambGPlus1;
    int ambBPlus1;
    u8 ambientScaled[3]; /* BGR order: [2]=R, [1]=G, [0]=B */
    ExpgfxRotateParams rotParams;
    f32 workVec[3];
    f32 skyLightDir[3];
    f32 rotatedPos[3];
    f32 srcWorldPos[3];
    u8 ambB8;
    u8 ambG8;
    u8 ambR8;
    f32 boundsMax;
    f32 boundsMin;
    f32 trailPrevX;
    f32 trailPrevY;
    f32 trailPrevZ;
    f32 workB; /* player dist-sq; reused as cross-product lane in the trail block */
    f32 workA; /* tricky dist-sq; reused as cross-product lane in the trail block */
    f32 ambientScale;
    f32 playerRange;
    f32 trickyRange;
    f32 attractRatio; /* attract speed ratio; reused as cross-product Z lane and trail inv-scale */
    staticData = EXPGFX_STATIC_DATA;
    runtime = EXPGFX_RUNTIME_DATA;
    attractRatio = 1.0f;
    trickyRange = 0.0f;
    playerRange = trickyRange;
    player = (GameObject*)Obj_GetPlayerObject();
    tricky = (GameObject*)getTrickyObject();
    cache = getCache();
    gExpgfxPhaseAngleA += (u16)(120.0f * timeDelta);
    gExpgfxPhaseAngleB += (u16)(480.0f * timeDelta);
    sky = getSkyStructField24C();
    skyGetSunLightDirection(sky, &skyLightDir[0], &skyLightDir[1], &skyLightDir[2]);
    PSMTXMultVec((void*)Camera_GetViewRotationMatrix(), (void*)skyLightDir, (void*)skyLightDir);
    ambientScale = -skyLightDir[2];
    if (ambientScale < 0.75f)
    {
        ambientScale = 0.75f;
    }
    getAmbientColor(sky, &ambR8, &ambG8, &ambB8);
    ambientScaled[2] = (f32)ambR8 * ambientScale;
    ambientScaled[1] = (f32)ambG8 * ambientScale;
    ambientScaled[0] = (f32)ambB8 * ambientScale;

    activeCountScan = runtime->poolActiveCounts;
    for (nextActivePool = 0; nextActivePool < EXPGFX_POOL_COUNT || (nextActivePool = -1, 0); nextActivePool++)
    {
        if (activeCountScan[nextActivePool] != 0)
        {
            break;
        }
    }
    pool = nextActivePool;
    if (pool != -1)
    {
        copyToCache(cache, (void*)runtime->slotPoolBases[pool], EXPGFX_POOL_CACHE_LINE_COUNT);
        cacheParity = 1;
        curCacheBuf = cache;
        Camera_GetCurrentViewSlot();
        if (tricky != NULL)
        {
            trickyRange = fn_80138F78(tricky);
        }
        if (player != NULL)
        {
            playerRange = fn_8029610C(player);
        }
        cacheQueued = 0;
        ambRPlus1 = ambientScaled[2] + 1;
        ambGPlus1 = ambientScaled[1] + 1;
        ambBPlus1 = ambientScaled[0] + 1;
        boundsMin = gExpgfxBoundsInitMin;
        boundsMax = gExpgfxBoundsInitMax;
        while (pool > -1)
        {
            curPoolBuf = (u8*)runtime + pool * sizeof(ExpgfxBounds);
            bounds = (ExpgfxBounds*)(curPoolBuf + EXPGFX_POOL_BOUNDS_OFFSET);
            bounds->minX = boundsMin;
            maxXPtr = &bounds->maxX;
            *maxXPtr = boundsMax;
            minYPtr = &bounds->minY;
            *minYPtr = boundsMin;
            maxYPtr = &bounds->maxY;
            *maxYPtr = boundsMax;
            minZPtr = &bounds->minZ;
            *minZPtr = boundsMin;
            maxZPtr = &bounds->maxZ;
            *maxZPtr = boundsMax;
            curPool = pool;
            nextActivePool = pool + 1;
            curPoolBuf = (u8*)runtime + nextActivePool;
            activeCountScan = (s8*)(curPoolBuf + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
            for (; nextActivePool < EXPGFX_POOL_COUNT || (nextActivePool = -1, 0); nextActivePool++)
            {
                if (*activeCountScan != 0)
                {
                    break;
                }
                activeCountScan++;
            }
            slot = (ExpgfxSlot*)curCacheBuf;
            if (nextActivePool > -1)
            {
                nextCacheBuf = (u8*)cache + cacheParity * 0x1000;
                copyToCache(nextCacheBuf, (void*)*(u32*)((u8*)runtime->slotPoolBases + nextActivePool * 4),
                            EXPGFX_POOL_CACHE_LINE_COUNT);
                curCacheBuf = nextCacheBuf;
                cacheQueued = 1;
            }
            cacheParity ^= 1;
            cacheQueueWait(cacheQueued);
            slot--;
            slotIdx = 0;
            poolByteOffset = pool * 4;
            maskPtr = (u32*)((u8*)runtime + poolByteOffset);
            maskPtr = (u32*)((u8*)maskPtr + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
            curPoolBuf = (u8*)cache + cacheParity * 0x1000;
            for (; slotIdx < EXPGFX_SLOTS_PER_POOL; slotIdx++)
            {
                ExpgfxQuadVertex* quad;
                ExpgfxTableEntry* entry;
                u32 phase;

                slot++;
                if ((1 << slotIdx & *maskPtr) == 0)
                {
                    continue;
                }
                if (slot->sequenceId == -1)
                {
                    continue;
                }
                entry = (ExpgfxTableEntry*)((u8*)runtime->expTab +
                                            (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16);
                srcObj = (ExpgfxSourceObject*)entry->sourceId;
                resource = entry->resource;
                slot->stateBits.bits.frameParity = 0;
                slot->stateBits.bits.quadReady = 1;
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_HOLD_LIFETIME_TIMER) == 0)
                {
                    slot->lifetimeFrame -= framesThisStep;
                }
                phase = slot->stateBits.bits.initPhase;
                if (phase == 2)
                {
                    slot->stateBits.bits.initPhase = 1;
                    continue;
                }
                if (phase == 1)
                {
                    expgfxRemove((u32)curPoolBuf, curPool, slotIdx, 0, 0);
                    continue;
                }
                if (slot->lifetimeFrame <= 0 || slot->lifetimeFrame > slot->lifetimeFrameLimit)
                {
                    slot->stateBits.bits.initPhase = 2;
                    continue;
                }
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0)
                {
                    quadTemplate = staticData->quadTemplateA;
                }
                else
                {
                    quadTemplate = staticData->quadTemplateB;
                }
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                    (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                {
                    rotParams.x = 0.0f;
                    rotParams.y = 0.0f;
                    rotParams.z = 0.0f;
                    rotParams.scale = 1.0f;
                    rotParams.angleZ = (f32)slot->sourceVecZ * timeDelta;
                    rotParams.angleY = (f32)slot->sourceVecY * timeDelta;
                    rotParams.angleX = (f32)slot->sourceVecX * timeDelta;
                    vecRotateZXY(&rotParams.angleX, &slot->posX.value);
                }
                if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) != 0)
                {
                    workB = 1000000.0f;
                    workA = workB;
                    if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_PLAYER) != 0 && player != NULL &&
                        srcObj != NULL && playerRange > 0.2f)
                    {
                        workVec[0] = player->anim.worldPosX - (slot->startPosX.value + srcObj->localPosX);
                        workVec[2] = player->anim.worldPosZ - (slot->startPosZ.value + srcObj->localPosZ);
                        workB = workVec[0] * workVec[0] + workVec[2] * workVec[2];
                        attractRatio = playerRange / workB;
                    }
                    if (workB > 300.0f && (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_TRICKY) != 0 &&
                        tricky != NULL && srcObj != NULL && trickyRange > 0.2f)
                    {
                        workVec[0] = tricky->anim.worldPosX - (slot->startPosX.value + srcObj->localPosX);
                        workVec[2] = tricky->anim.worldPosZ - (slot->startPosZ.value + srcObj->localPosZ);
                        workA = workVec[0] * workVec[0] + workVec[2] * workVec[2];
                        attractRatio = trickyRange / workB;
                    }
                    if (workA < workB)
                    {
                        workB = workA;
                    }
                    if (workB < 300.0f)
                    {
                        if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_PLAYER) != 0)
                        {
                            slot->renderFlags ^= EXPGFX_RENDER_ATTRACT_TO_PLAYER | 0LL;
                        }
                        if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_TRICKY) != 0)
                        {
                            slot->renderFlags ^= EXPGFX_RENDER_ATTRACT_TO_TRICKY | 0LL;
                        }
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED) != 0)
                        {
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED | 0LL;
                        }
                        slot->lifetimeFrame = randomGetRange(0, 0x28) + 0xdc;
                        slot->lifetimeFrameLimit = randomGetRange(0, 0x28) + 0xdc;
                        slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        slot->renderFlags |= EXPGFX_RENDER_IMPACT_POSITION_LOCKED | 0LL;
                        slot->velocityX = -workVec[0] * attractRatio;
                        slot->velocityZ = -workVec[2] * attractRatio;
                    }
                }
                else
                {
                    if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_A) != 0)
                    {
                        slot->velocityX += 0.01f * slot->velocityX;
                        slot->velocityY += 0.01f * slot->velocityY;
                        slot->velocityZ += 0.01f * slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_B) != 0)
                    {
                        slot->velocityX += 0.02f * slot->velocityX;
                        slot->velocityY += 0.02f * slot->velocityY;
                        slot->velocityZ += 0.02f * slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_C) != 0)
                    {
                        slot->velocityX += 0.04f * slot->velocityX;
                        slot->velocityY += 0.04f * slot->velocityY;
                        slot->velocityZ += 0.04f * slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_DAMP) != 0)
                    {
                        slot->velocityX = 0.99f * slot->velocityX;
                        slot->velocityY = 0.99f * slot->velocityY;
                        slot->velocityZ = 0.99f * slot->velocityZ;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
                        slot->velocityY < gExpgfxYVelocityPositiveLimit)
                    {
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                            slot->velocityY < gExpgfxYVelocityPositiveLimit)
                        {
                            slot->velocityY -= gExpgfxYVelocityFastStep * timeDelta;
                        }
                        else
                        {
                            slot->velocityY -= gExpgfxYVelocitySlowStep * timeDelta;
                        }
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                             slot->velocityY > gExpgfxYVelocityNegativeLimit)
                    {
                        slot->velocityY += gExpgfxYVelocityFastStep * timeDelta;
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
                             slot->velocityY > gExpgfxYVelocityNegativeLimit)
                    {
                        slot->velocityY += gExpgfxYVelocitySlowStep * timeDelta;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_IMPACT_POSITION_LOCKED) != 0)
                    {
                        if (slot->velocityY * timeDelta + slot->posY.value < 0.0f)
                        {
                            slot->velocityX = 0.0f;
                            slot->velocityY = 0.0f;
                            slot->velocityZ = 0.0f;
                            slot->sourceVecX = 0;
                            slot->sourceVecY = 0;
                            slot->sourceVecZ = 0;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0)
                            {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B | 0LL;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0)
                            {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A | 0LL;
                            }
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED | 0LL;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0)
                            {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_FAST_Y_RESPONSE | 0LL;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0)
                            {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY | 0LL;
                            }
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER) != 0)
                            {
                                slot->behaviorFlags ^= EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER;
                            }
                            slot->renderFlags ^= EXPGFX_RENDER_IMPACT_POSITION_LOCKED | 0LL;
                        }
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK) != 0 &&
                        slot->velocityY * timeDelta + slot->posY.value < 0.0f)
                    {
                        u32 rnd;
                        f32 fade;

                        rnd = randomGetRange(0, 5);
                        fade = -((f32)(int)rnd * 0.01f + 0.25f);
                        slot->velocityY *= fade;
                        if (slot->velocityY > 0.3f)
                        {
                            slot->velocityY = 0.3f;
                        }
                        rotParams.scale = 1.0f;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = 0;
                        if (srcObj != NULL)
                        {
                            rotParams.x = slot->posX.value + srcObj->localPosX;
                            rotParams.y = slot->posY.value + srcObj->localPosY;
                            rotParams.z = slot->posZ.value + srcObj->localPosZ;
                        }
                        else
                        {
                            rotParams.x = slot->posX.value + slot->sourcePosY.value;
                            rotParams.y = slot->posY.value + slot->sourcePosZ.value;
                            rotParams.z = slot->posZ.value + slot->sourcePosW.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT) != 0 &&
                            (slot->renderFlags & EXPGFX_RENDER_IMPACT_POSITION_LOCKED) == 0)
                        {
                            slot->velocityX *= gExpgfxSlotMotionStep;
                            slot->velocityZ *= gExpgfxSlotMotionStep;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT | 0LL;
                            if (slot->impactEffectId != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                                slot->impactEffectId = -1;
                            }
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1) != 0)
                        {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent = (f32)slot->scaleCurrent * 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1 | 0LL;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2) != 0)
                        {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent = (f32)slot->scaleCurrent * 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3) != 0)
                        {
                            slot->velocityX *= 0.5f;
                            slot->velocityZ *= 0.5f;
                            slot->scaleCurrent = (f32)slot->scaleCurrent * 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2;
                            if (slot->impactEffectId != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                            }
                            slot->impactEffectId = -1;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4) != 0)
                        {
                            {
                                f32 v;
                                f32 st;
                                v = slot->velocityX;
                                st = gExpgfxSlotMotionStep;
                                slot->velocityX = v * (st - v);
                                v = slot->velocityZ;
                                slot->velocityZ = v * (st - v);
                            }
                            slot->scaleCurrent = (f32)slot->scaleCurrent * 0.65f;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3;
                            if (slot->impactEffectId != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, 0);
                            }
                        }
                        gExpgfxFrameParityBit = 0;
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) != 0 &&
                             slot->velocityY * timeDelta + slot->posY.value < 0.0f)
                    {
                        if (slot->impactEffectId != -1)
                        {
                            rotParams.scale = 1.0f;
                            rotParams.angleZ = 0;
                            rotParams.angleY = 0;
                            rotParams.angleX = 0;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0)
                            {
                                rotParams.x = slot->posX.value;
                                rotParams.y = 0.0f;
                                rotParams.z = slot->posZ.value;
                            }
                            else if (srcObj != NULL)
                            {
                                rotParams.x = slot->posX.value + srcObj->worldPosX;
                                rotParams.y = srcObj->worldPosY;
                                rotParams.z = slot->posZ.value + srcObj->worldPosZ;
                            }
                            else
                            {
                                rotParams.x = slot->posX.value;
                                rotParams.y = 0.0f;
                                rotParams.z = slot->posZ.value;
                            }
                            gExpgfxFrameParityBit = 1;
                            (*gWaterfxInterface)->spawnRipple(
                                rotParams.x, rotParams.y, rotParams.z, 0, 0.0f, 4);
                            (*gWaterfxInterface)->spawnSplashBurst(NULL, rotParams.x, rotParams.y, rotParams.z, gExpgfxSlotMotionStep);
                            if (srcObj != NULL && coordsToMapCell(srcObj->localPosX, srcObj->localPosZ) == 0x10)
                            {
                                Sfx_PlayFromObject((u32)srcObj, SFXTRIG_blkscrp6);
                            }
                            slot->impactEffectId = -1;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT | 0LL;
                            slot->lifetimeFrame = 0;
                            gExpgfxFrameParityBit = 0;
                        }
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK) == 0 &&
                             (slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) == 0 &&
                             slot->impactEffectId != -1)
                    {
                        rotParams.scale = 1.0f;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = 0;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0)
                        {
                            rotParams.x = slot->posX.value;
                            rotParams.y = slot->posY.value;
                            rotParams.z = slot->posZ.value;
                        }
                        else if (srcObj != NULL)
                        {
                            rotParams.x = slot->posX.value + srcObj->worldPosX;
                            rotParams.y = slot->posY.value + srcObj->worldPosY;
                            rotParams.z = slot->posZ.value + srcObj->worldPosZ;
                        }
                        else
                        {
                            rotParams.x = slot->posX.value;
                            rotParams.y = slot->posY.value;
                            rotParams.z = slot->posZ.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        (*gPartfxInterface)->spawnObject(srcObj, slot->impactEffectId, &rotParams, 0x200001, -1, NULL);
                        gExpgfxFrameParityBit = 0;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER) != 0 && randomGetRange(0, 4) == 1)
                    {
                        slot->velocityX += 0.045f - (f32)(int)randomGetRange(0, 9) / 100.0f;
                        slot->velocityZ += 0.045f - (f32)(int)randomGetRange(0, 9) / 100.0f;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_RANDOM_VELOCITY_BURST) != 0 && randomGetRange(0, 10) == 1)
                    {
                        if (slot->lifetimeFrameLimit > (f32)slot->lifetimeFrame)
                        {
                            slot->velocityX += 0.0004f * (f32)(int)randomGetRange(-800, 800) + 0.02f;
                            slot->velocityY += 0.0004f * (f32)(int)randomGetRange(-800, 800) + 0.02f;
                            slot->velocityZ += 0.0004f * (f32)(int)randomGetRange(-800, 800) + 0.02f;
                        }
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH) != 0)
                    {
                        if (0.25f * slot->lifetimeFrameLimit > (f32)slot->lifetimeFrame)
                        {
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH | 0LL;
                            slot->velocityX *= -3.0f;
                            slot->velocityY *= -3.0f;
                            slot->velocityZ *= -3.0f;
                        }
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_STRETCHED_TRAIL) != 0)
                    {
                        trailPrevX = slot->posX.value;
                        trailPrevY = slot->posY.value;
                        trailPrevZ = slot->posZ.value;
                    }
                    slot->posX.value += slot->velocityX * timeDelta;
                    slot->posY.value += slot->velocityY * timeDelta;
                    slot->posZ.value += slot->velocityZ * timeDelta;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0)
                    {
                        slot->scaleCurrent = (f32)slot->scaleStep * timeDelta + (f32)slot->scaleCurrent;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0)
                    {
                        slot->scaleCurrent = slot->scaleCurrent - slot->scaleStep * framesThisStep;
                    }
                }
                quad = (ExpgfxQuadVertex*)slot;
                if (resource == 0)
                {
                    debugPrintf(staticData->noTextureString);
                }
                else
                {
                    GameObject* attached;

                    texT0 = 0;
                    texT1 = 0;
                    texS0 = 0;
                    texS1 = 0;
                    if (resource != 0)
                    {
                        texS0 = 0x80;
                        texT0 = 0x80;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0)
                        {
                            texS1 = 0x80;
                            texS0 = 0;
                        }
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0)
                        {
                            texT1 = 0x80;
                            texT0 = 0;
                        }
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0)
                    {
                        int colR;
                        int colG;
                        int colB;
                        f32 ratio;

                        ratio = (f32)slot->lifetimeFrame / slot->lifetimeFrameLimit;
                        colR = (int)(ratio * (f32)(quad[1].alpha - slot->colorByte0) + slot->colorByte0);
                        colG = (int)(ratio * (f32)(quad[2].alpha - slot->colorByte1) + slot->colorByte1);
                        colB = (int)(ratio * (f32)(quad[3].alpha - slot->colorByte2) + slot->colorByte2);
                        if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_DIRECT) != 0)
                        {
                            quad[0].colorR = (s16)colR * (ambR8 + 1) >> 8;
                            quad[0].colorG = (s16)colG * (ambG8 + 1) >> 8;
                            quad[0].colorB = (s16)colB * (ambB8 + 1) >> 8;
                        }
                        else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_SCALED) != 0)
                        {
                            quad[0].colorR = (s16)colR * ambRPlus1 >> 8;
                            quad[0].colorG = (s16)colG * ambGPlus1 >> 8;
                            quad[0].colorB = (s16)colB * ambBPlus1 >> 8;
                        }
                        else
                        {
                            quad[0].colorR = colR;
                            quad[0].colorG = colG;
                            quad[0].colorB = colB;
                        }
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_DIRECT) != 0)
                    {
                        quad[0].colorR = ambR8;
                        quad[0].colorG = ambG8;
                        quad[0].colorB = ambB8;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_AMBIENT_COLOR_SCALED) != 0)
                    {
                        quad[0].colorR = ambientScaled[2];
                        quad[0].colorG = ambientScaled[1];
                        quad[0].colorB = ambientScaled[0];
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_STRETCHED_TRAIL) != 0)
                    {
                        f32 sx;
                        f32 sy;
                        f32 sz;
                        f32 dirX;
                        f32 dirY;
                        f32 dirZ;
                        f32 prevDX;
                        f32 prevDY;
                        f32 prevDZ;
                        f32 normSq;
                        f32 norm;
                        f32 axisX;
                        f32 axisY;
                        f32 axisZ;

                        sx = 0.0f;
                        sy = sx;
                        sz = sx;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) == 0)
                        {
                            if (srcObj != NULL)
                            {
                                sx = srcObj->worldPosX;
                                sy = srcObj->worldPosY;
                                sz = srcObj->worldPosZ;
                            }
                            else
                            {
                                sx = slot->sourcePosY.value;
                                sy = slot->sourcePosZ.value;
                                sz = slot->sourcePosW.value;
                            }
                        }
                        dirX = sx - slot->posX.value;
                        dirY = sy - slot->posY.value;
                        dirZ = sz - slot->posZ.value;
                        prevDX = trailPrevX - slot->posX.value;
                        prevDY = trailPrevY - slot->posY.value;
                        prevDZ = trailPrevZ - slot->posZ.value;
                        workA = prevDY * dirZ - prevDZ * dirY;
                        workB = -(prevDX * dirZ - prevDZ * dirX);
                        attractRatio = prevDX * dirY - prevDY * dirX;
                        normSq = attractRatio * attractRatio + (workA * workA + workB * workB);
                        if (0.0f != normSq)
                        {
                            norm = sqrtf(normSq);
                        }
                        else
                        {
                            norm = 1.0f;
                        }
                        axisX = 250.0f * (workA / norm);
                        axisY = 250.0f * (workB / norm);
                        axisZ = 250.0f * (attractRatio / norm);
                        attractRatio = 2.0f / (gExpgfxU16ToUnitScale * (f32)(u16)slot->scaleTarget);
                        quad[0].x = (s16)axisX;
                        quad[0].y = (s16)axisY;
                        quad[0].z = (s16)axisZ;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = attractRatio * (slot->posX.value - trailPrevX) + axisX;
                        quad[1].y = attractRatio * (slot->posY.value - trailPrevY) + axisY;
                        quad[1].z = attractRatio * (slot->posZ.value - trailPrevZ) + axisZ;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = attractRatio * (slot->posX.value - trailPrevX) - axisX;
                        quad[2].y = attractRatio * (slot->posY.value - trailPrevY) - axisY;
                        quad[2].z = attractRatio * (slot->posZ.value - trailPrevZ) - axisZ;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = -(s16)axisX;
                        quad[3].y = -(s16)axisY;
                        quad[3].z = -(s16)axisZ;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0 &&
                             (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rotParams.x = 0.0f;
                        rotParams.y = 0.0f;
                        rotParams.z = 0.0f;
                        slot->sourceVecX = slot->sourceVecX + (int)slot->sourcePosY.value * framesThisStep;
                        slot->sourceVecY = slot->sourceVecY + (int)slot->sourcePosZ.value * framesThisStep;
                        slot->sourceVecZ = slot->sourceVecZ + (int)slot->sourcePosW.value * framesThisStep;
                        rotParams.scale = 1.0f;
                        workVec[0] = (f32) quadTemplate[0].x;
                        workVec[1] = (f32) quadTemplate[0].y;
                        workVec[2] = (f32) quadTemplate[0].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[0].x = workVec[0];
                        quad[0].y = workVec[1];
                        quad[0].z = workVec[2];
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        workVec[0] = (f32) quadTemplate[1].x;
                        workVec[1] = (f32) quadTemplate[1].y;
                        workVec[2] = (f32) quadTemplate[1].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[1].x = workVec[0];
                        quad[1].y = workVec[1];
                        quad[1].z = workVec[2];
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        workVec[0] = (f32) quadTemplate[2].x;
                        workVec[1] = (f32) quadTemplate[2].y;
                        workVec[2] = (f32) quadTemplate[2].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[2].x = workVec[0];
                        quad[2].y = workVec[1];
                        quad[2].z = workVec[2];
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        workVec[0] = (f32) quadTemplate[3].x;
                        workVec[1] = (f32) quadTemplate[3].y;
                        workVec[2] = (f32) quadTemplate[3].z;
                        rotParams.angleZ = 0;
                        rotParams.angleY = 0;
                        rotParams.angleX = slot->sourceVecX;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        rotParams.angleZ = slot->sourceVecY;
                        rotParams.angleY = slot->sourceVecZ;
                        rotParams.angleX = 0;
                        vecRotateZXY(&rotParams.angleX, workVec);
                        quad[3].x = workVec[0];
                        quad[3].y = workVec[1];
                        quad[3].z = workVec[2];
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0)
                    {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_Y8) != 0)
                    {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].y <<= 3;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].y <<= 3;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].y <<= 3;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].y <<= 3;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SWAP_XZ_SCALE_Z32) != 0)
                    {
                        quad[0].z = quadTemplate[0].x;
                        quad[0].z <<= 5;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].x = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].z = quadTemplate[1].x;
                        quad[1].z <<= 5;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].x = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].z = quadTemplate[2].x;
                        quad[2].z <<= 5;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].x = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].z = quadTemplate[3].x;
                        quad[3].z <<= 5;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].x = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_X32) != 0)
                    {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].x <<= 5;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].x <<= 5;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].x <<= 5;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].x <<= 5;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else
                    {
                        quad[0].x = quadTemplate[0].x;
                        quad[0].y = quadTemplate[0].y;
                        quad[0].z = quadTemplate[0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x = quadTemplate[1].x;
                        quad[1].y = quadTemplate[1].y;
                        quad[1].z = quadTemplate[1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x = quadTemplate[2].x;
                        quad[2].y = quadTemplate[2].y;
                        quad[2].z = quadTemplate[2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = quadTemplate[3].x;
                        quad[3].y = quadTemplate[3].y;
                        quad[3].z = quadTemplate[3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    attached = (GameObject*)((ExpgfxTableEntry*)((u8*)runtime->expTab +
                                                                 (((u32)slot->encodedTableIndex >> 1) &
                                                                  EXPGFX_SLOT_TABLE_INDEX_MASK) *
                                                                     16))
                                   ->attachedTableKey;
                    rotParams.x = 0.0f;
                    rotParams.y = 0.0f;
                    rotParams.z = 0.0f;
                    rotParams.scale = 1.0f;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rotParams.x = slot->posX.value;
                        rotParams.y = slot->posY.value;
                        rotParams.z = slot->posZ.value;
                    }
                    rotParams.angleZ = 0;
                    rotParams.angleY = 0;
                    rotParams.angleX = 0;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0)
                    {
                        if (srcObj != NULL)
                        {
                            rotParams.angleX = srcObj->rotX;
                            rotParams.angleY = srcObj->rotY;
                            rotParams.angleZ = srcObj->rotZ;
                        }
                        else
                        {
                            rotParams.angleX = slot->sourceVecX;
                            rotParams.angleY = slot->sourceVecY;
                            rotParams.angleZ = slot->sourceVecZ;
                        }
                    }
                    rotatedPos[0] = slot->posX.value;
                    rotatedPos[1] = slot->posY.value;
                    rotatedPos[2] = slot->posZ.value;
                    if ((rotParams.angleX | rotParams.angleY | rotParams.angleZ) != 0)
                    {
                        vecRotateZXY(&rotParams.angleX, rotatedPos);
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) == 0)
                    {
                        if (srcObj != NULL)
                        {
                            srcWorldPos[0] = srcObj->worldPosX;
                            srcWorldPos[1] = srcObj->worldPosY;
                            srcWorldPos[2] = srcObj->worldPosZ;
                        }
                        else
                        {
                            srcWorldPos[0] = slot->sourcePosY.value;
                            srcWorldPos[1] = slot->sourcePosZ.value;
                            srcWorldPos[2] = slot->sourcePosW.value;
                            if (attached != NULL)
                            {
                                Obj_RotateLocalOffsetByYaw(&slot->sourcePosY.value, srcWorldPos,
                                                           attached->anim.transformMatrixIndex);
                            }
                        }
                    }
                    else
                    {
                        srcWorldPos[0] = 0.0f;
                        srcWorldPos[1] = 0.0f;
                        srcWorldPos[2] = 0.0f;
                    }
                    rotParams.angleZ = 0;
                    rotParams.angleY = 0;
                    rotParams.angleX = 0;
                    rotParams.x = srcWorldPos[0] + rotatedPos[0];
                    rotParams.y = srcWorldPos[1] + rotatedPos[1];
                    rotParams.z = srcWorldPos[2] + rotatedPos[2];
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rotParams.x = rotParams.x + slot->sourcePosY.value;
                        rotParams.y = rotParams.y + slot->sourcePosZ.value;
                        rotParams.z = rotParams.z + slot->sourcePosW.value;
                    }
                    slot->renderX = rotParams.x;
                    slot->renderY = rotParams.y;
                    slot->renderZ = rotParams.z;
                    if (rotParams.x < bounds->minX)
                    {
                        bounds->minX = rotParams.x;
                    }
                    if (rotParams.x > *maxXPtr)
                    {
                        *maxXPtr = rotParams.x;
                    }
                    if (rotParams.y < *minYPtr)
                    {
                        *minYPtr = rotParams.y;
                    }
                    if (rotParams.y > *maxYPtr)
                    {
                        *maxYPtr = rotParams.y;
                    }
                    if (rotParams.z < *minZPtr)
                    {
                        *minZPtr = rotParams.z;
                    }
                    if (rotParams.z > *maxZPtr)
                    {
                        *maxZPtr = rotParams.z;
                    }
                }
            }
            memcpyToCache((void*)*(u32*)((u8*)runtime->slotPoolBases + poolByteOffset), curPoolBuf, EXPGFX_POOL_CACHE_LINE_COUNT);
            cacheQueued = 1;
            pool = nextActivePool;
        }
        cacheQueueWait(0);
    }
}

u8 gExpgfxRuntimeData[0x980];
ExpgfxTableEntry gExpgfxTableEntries[0x550 / sizeof(ExpgfxTableEntry)];
ExpgfxSourceObject* gExpgfxTrackedPoolSourceIds[0x50];
u64 gExpgfxTrackedSourceFrameMasks[0xB0 / sizeof(u64)];
u32 gExpgfxSlotActiveMasks[0x50];
u32 gExpgfxSlotPoolBases[0x50];

char sExpgfxMismatchInAddRemove[] = "expgfx.c: mismatch in add/remove in exptab\n";

char sExpgfxNoTexture[11] = "notexture \n";

char sExpgfxAddToTableUsageOverflow[] = "expgfx.c: addToTable usage overflow\n";

char sExpgfxExpTabIsFull[] = "expgfx.c: exptab is FULL\n";

char sExpgfxInvalidTabIndex[] = "expgfx.c: invalid tabindex\n";

char sExpgfxScaleOverflow[] = "expgfx.c: scale overflow\n";

Dll0BDescriptorTable lbl_8030FCA8 = {{0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x00180000,
                                      (u32)dll_0B_initialise,
                                      (u32)dll_0B_release,
                                      0x00000000,
                                      (u32)dll_0B_onMapSetup,
                                      (u32)dll_0B_func04,
                                      (u32)dll_0B_func05,
                                      (u32)dll_0B_func06,
                                      (u32)dll_0B_func07,
                                      (u32)dll_0B_func08,
                                      (u32)dll_0B_func09,
                                      (u32)dll_0B_func0A,
                                      (u32)dll_0B_func0B,
                                      (u32)dll_0B_func0C,
                                      (u32)dll_0B_func0D,
                                      (u32)dll_0B_func0E,
                                      (u32)dll_0B_func0F,
                                      (u32)dll_0B_func10,
                                      (u32)dll_0B_func11,
                                      (u32)dll_0B_func12,
                                      (u32)dll_0B_func13,
                                      (u32)dll_0B_func14,
                                      (u32)dll_0B_func15,
                                      (u32)dll_0B_func16,
                                      (u32)dll_0B_func17,
                                      (u32)dll_0B_func18,
                                      0x00000000}};
