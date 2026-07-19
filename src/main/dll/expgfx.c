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
#include "main/sky_state.h"
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

typedef struct ExpgfxCameraViewSlot
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad06[0x0C - 0x06];
    f32 x;
    f32 y;
    f32 z;
} ExpgfxCameraViewSlot;

STATIC_ASSERT(offsetof(ExpgfxCameraViewSlot, x) == 0x0C);

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

extern ExpgfxBounds gExpgfxPoolBounds[];
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

static inline ExpgfxBounds* Expgfx_GetPoolBounds(int poolIndex)
{
    return &gExpgfxPoolBounds[poolIndex];
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
    activeCountWalk = runtime->poolActiveCounts;
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
                goto poolSearchDone;
            }
        }
    }
poolSearchDone:

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
                *slotIndexOut = slotIndex;
                *poolIndexOut = foundPoolIndex;
                *activeMaskPtr |= activeBit;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
    }

    found = 0;
    if (preferredPoolIndex == EXPGFX_INVALID_POOL_INDEX)
    {
        poolActiveCounts = runtime->poolActiveCounts;
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
                *slotIndexOut = slotIndex;
                *poolIndexOut = foundPoolIndex;
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
    fn_800897D4(sky, &skyLightDir[0], &skyLightDir[1], &skyLightDir[2]);
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
    for (nextActivePool = 0; nextActivePool < EXPGFX_POOL_COUNT; nextActivePool++)
    {
        if (activeCountScan[nextActivePool] != 0)
        {
            break;
        }
    }
    if (nextActivePool == EXPGFX_POOL_COUNT)
    {
        nextActivePool = -1;
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
            for (; nextActivePool < EXPGFX_POOL_COUNT; nextActivePool++)
            {
                if (*activeCountScan != 0)
                {
                    break;
                }
                activeCountScan++;
            }
            if (nextActivePool == EXPGFX_POOL_COUNT)
            {
                nextActivePool = -1;
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

int expgfx_addToTable(u32 resourceHandle, u32 sourceId, u32 attachedTableKey, s16 resourceId)
{
    ExpgfxTableEntry* entry;
    int tableIndex;
    int freeIndex;

    for (tableIndex = 0; tableIndex < EXPGFX_EXPTAB_ENTRY_COUNT; tableIndex++)
    {
        entry = &gExpgfxTableEntries[tableIndex];
        if ((entry->refCount != 0) && (entry->resource == resourceHandle) && (entry->sourceId == sourceId) &&
            (entry->attachedTableKey == attachedTableKey))
        {
            if (gExpgfxTableEntries[tableIndex].refCount >= EXPGFX_REFCOUNT_OVERFLOW)
            {
                debugPrintf(sExpgfxAddToTableUsageOverflow);
                return EXPGFX_INVALID_TABLE_INDEX;
            }
            gExpgfxTableEntries[tableIndex].refCount++;
            return (s16)tableIndex;
        }
    }

    for (freeIndex = 0; freeIndex < EXPGFX_EXPTAB_ENTRY_COUNT; freeIndex++)
    {
        if (gExpgfxTableEntries[freeIndex].refCount == 0)
        {
            gExpgfxTableEntries[freeIndex].refCount = 1;
            gExpgfxTableEntries[freeIndex].resource = resourceHandle;
            gExpgfxTableEntries[freeIndex].sourceId = sourceId;
            gExpgfxTableEntries[freeIndex].attachedTableKey = attachedTableKey;
            gExpgfxTableEntries[freeIndex].resourceId = resourceId;
            return (s16)freeIndex;
        }
    }

    debugPrintf(sExpgfxExpTabIsFull);
    return EXPGFX_INVALID_TABLE_INDEX;
}

int expgfx_addToTable(u32 resourceHandle, u32 sourceId, u32 attachedTableKey, s16 resourceId);

int expgfx_updateSourceFrameFlags(void* sourceObject)
{
    s16 signedPoolIndex;
    int result;
    void** poolSourceIds;
    int poolIndex;
    u8* frameFlags;
    result = EXPGFX_SOURCE_FRAME_STATE_NONE;
    lbl_803DD253 = 0;
    poolIndex = 0;
    poolSourceIds = gExpgfxTrackedPoolSourceIds;
    frameFlags = gExpgfxStaticPoolFrameFlags;

    for (; (s16)poolIndex < EXPGFX_POOL_COUNT; poolSourceIds++, frameFlags++, poolIndex++)
    {
        if ((((ExpgfxSourceObject*)sourceObject)->objType == EXPGFX_SOURCE_OBJTYPE_MATCH_ALL) ||
            (*poolSourceIds == sourceObject))
        {
            signedPoolIndex = poolIndex;
            if (((s64)(1 << (signedPoolIndex >> 1)) & gExpgfxTrackedSourceFrameMasks[signedPoolIndex & 1]) != 0)
            {
                *frameFlags = EXPGFX_SOURCE_FRAME_STATE_B;
                if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_A)
                {
                    result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
                }
                else
                {
                    result = EXPGFX_SOURCE_FRAME_STATE_B;
                }
            }
            else
            {
                *frameFlags = EXPGFX_SOURCE_FRAME_STATE_A;
                if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_B)
                {
                    result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
                }
                else
                {
                    result = EXPGFX_SOURCE_FRAME_STATE_A;
                }
            }
        }
        else
        {
            *frameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }
    }

    return result;
}

void expgfx_ownerFree3(u32 sourceId)
{
    expgfx_free(sourceId);
    return;
}

void expgfx_func0B_nop(void)
{
}

void expgfx_func0A_nop(void)
{
}

int expgfx_func09(void)
{
    return 0;
}

void expgfx_renderSourcePools(int sourceId, int sourceMode)
{
    ExpgfxRuntimeDataLayout* runtime;
    ExpgfxBounds* boundsTemplate;
    s8* poolActiveCounts;
    u32* poolSourceIds;
    u8* poolSourceModes;
    u8* poolBoundsTemplateIds;
    ExpgfxBounds* poolBounds;
    u32* slotPoolBases;
    int poolIndex;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSourceIds = runtime->poolSourceIds;
    poolSourceModes = runtime->poolSourceModes;
    poolBoundsTemplateIds = runtime->poolBoundsTemplateIds;
    poolBounds = runtime->poolBounds;
    slotPoolBases = runtime->slotPoolBases;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        if ((*poolActiveCounts != 0) && (*poolSourceIds == sourceId) &&
            (*poolSourceModes == sourceMode + EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET))
        {
            boundsTemplate = Expgfx_GetBoundsTemplate(*poolBoundsTemplateIds);
            if ((u8)frustumTestAabbWithPlaneOffsets(poolBounds->minX - playerMapOffsetX,
                                                    poolBounds->maxX - playerMapOffsetX, poolBounds->minY,
                                                    poolBounds->maxY, poolBounds->minZ - playerMapOffsetZ,
                                                    poolBounds->maxZ - playerMapOffsetZ, &boundsTemplate->minX) != 0)
            {
                drawGlow(*slotPoolBases, poolIndex);
            }
        }
        poolActiveCounts++;
        poolSourceIds++;
        poolSourceModes++;
        poolBoundsTemplateIds++;
        poolBounds++;
        slotPoolBases++;
        poolIndex++;
    }
}

void drawGlow(u32 slotPoolBase, int poolIndex)
{
    s16 pitchAngle;
    s16 yawAngle;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* tabBase;
    ExpgfxTableEntry* tabEntry;
    f32 sinB, cosB;
    int slotIndex;
    int alpha;
    ExpgfxSourceObject* sourceObject;
    u32 renderFlags;
    u32 stateBitsValue;
    ExpgfxCameraViewSlot* cameraSlot;
    f32 halfLifeFrames;
    f32 scaleSize;
    f32 centerX, centerY, centerZ;
    f32 scaleFactor;
    u32 texture;
    MtxPtr viewMatrix;
    f32 sinA, cosA;
    u32 behaviorFlags;
    f32 sinC, cosC;
    f32 worldX, worldY, worldZ;
    f32 cC, sC, cB, sB, cA, ay_cosB, sA, pz_sinB;
    f32 px, nx, py, pz, ny;
    f32 aimDelta[3];
    ExpgfxQuadVertex* quad;
    ExpgfxQuadVertex* vertexStream;
    int vertexIndex;
    f32 viewDepth;
    int hudHiddenFrameCount;
    u32* activeMasks;
    s8 alphaMode;
    s8 blendMode;
    s8 zMode;
    s8 zCompLoc;
    u32 currentTexture;
    u8 lastOverrideColorFlag;
    ExpgfxSlot* cachedSlots;
    cachedSlots = getCache();
    lastOverrideColorFlag = 0;
    hudHiddenFrameCount = getHudHiddenFrameCount();
    Camera_GetProjectionMatrix();
    copyToCache(cachedSlots, (void*)slotPoolBase, EXPGFX_POOL_CACHE_LINE_COUNT);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_NONE);
    viewMatrix = (MtxPtr)Camera_GetViewMatrix();
    GXLoadPosMtxImm(viewMatrix, GX_PNMTX0);
    PSMTXCopy(viewMatrix, lbl_803967C0);
    fn_8007D670();
    _gxSetFogParams();
    if ((short)renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    cameraSlot = (ExpgfxCameraViewSlot*)Camera_GetCurrentViewSlot();
    _textSetColor(0, 0xff, 0xff, 0xff, 0xff);
    alphaMode = -1;
    blendMode = -1;
    zMode = -1;
    zCompLoc = -1;
    currentTexture = 0;
    cacheQueueWait(0);

    slot = cachedSlots - 1;
    slotIndex = 0;
    activeMasks = &gExpgfxSlotActiveMasks[poolIndex];
    tabBase = gExpgfxTableEntries;
    do
    {
        slot++;
        tabEntry = &tabBase[((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK];
        sourceObject = (ExpgfxSourceObject*)tabEntry->sourceId;
        texture = tabEntry->resource;
        if ((1U << slotIndex & *activeMasks) != 0)
        {
            stateBitsValue = slot->stateBits.value;
            if (((stateBitsValue >> 2) & 3) == 0 && ((stateBitsValue >> 1) & 1) != 0 &&
                slot->sequenceId != EXPGFX_INVALID_SEQUENCE_ID && (stateBitsValue & 1) == 0)
            {
                halfLifeFrames = 0.5f * (f32)slot->lifetimeFrameLimit;
                behaviorFlags = slot->behaviorFlags;
                if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_TO_OPAQUE) != 0)
                {
                    f32 ratio = (f32)slot->lifetimeFrame / (f32)slot->lifetimeFrameLimit;
                    if (ratio < 0.0f)
                    {
                        ratio = 0.0f;
                    }
                    else if (ratio > 1.0f)
                    {
                        ratio = 1.0f;
                    }
                    {
                        u32 baseAlpha = slot->initialAlpha;
                        alpha = (int)((f32)((s32)baseAlpha - 0xff) * ratio + (f32)baseAlpha);
                    }
                }
                else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_OUT) != 0)
                {
                    f32 ratio = (f32)slot->lifetimeFrame / (f32)slot->lifetimeFrameLimit;
                    if (ratio < 0.0f)
                    {
                        ratio = 0.0f;
                    }
                    else if (ratio > 1.0f)
                    {
                        ratio = 1.0f;
                    }
                    alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                }
                else if ((slot->renderFlags & EXPGFX_RENDER_ALPHA_FADE_IN) != 0 &&
                         (f32)slot->lifetimeFrame <= halfLifeFrames)
                {
                    f32 ratio = (f32)slot->lifetimeFrame / halfLifeFrames;
                    if (ratio < 0.0f)
                    {
                        ratio = 0.0f;
                    }
                    else if (ratio > 1.0f)
                    {
                        ratio = 1.0f;
                    }
                    alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                }
                else
                {
                    u32 pulse = behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_PULSE;
                    if (pulse != 0 && (f32)slot->lifetimeFrame <= halfLifeFrames)
                    {
                        f32 ratio = (f32)slot->lifetimeFrame / halfLifeFrames;
                        if (ratio < 0.0f)
                        {
                            ratio = 0.0f;
                        }
                        else if (ratio > 1.0f)
                        {
                            ratio = 1.0f;
                        }
                        alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                    }
                    else if (pulse != 0)
                    {
                        f32 ratio = (halfLifeFrames - ((f32)slot->lifetimeFrame - halfLifeFrames)) / halfLifeFrames;
                        if (ratio < 0.0f)
                        {
                            ratio = 0.0f;
                        }
                        else if (ratio > 1.0f)
                        {
                            ratio = 1.0f;
                        }
                        alpha = (int)((f32)(u32)slot->initialAlpha * ratio);
                    }
                    else
                    {
                        alpha = slot->initialAlpha;
                    }
                }

                pitchAngle = 0;
                yawAngle = pitchAngle;
                centerX = slot->renderX;
                centerY = slot->renderY;
                centerZ = slot->renderZ;
                scaleSize = gExpgfxU16ToUnitScale * (f32)(u32)slot->scaleCurrent;
                if ((behaviorFlags & EXPGFX_BEHAVIOR_RANDOMIZE_SCALE) != 0 && hudHiddenFrameCount == 0)
                {
                    f32 base = 0.5f * scaleSize;
                    f32 rnd = (f32)randomGetRange(1, 10);
                    scaleFactor = base + base / rnd;
                }
                else
                {
                    scaleFactor = scaleSize;
                }

                {
                    u32 behavior = slot->behaviorFlags;
                    if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0)
                    {
                        pitchAngle = 0;
                        if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A) != 0)
                        {
                            yawAngle = pitchAngle;
                        }
                        else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH) != 0)
                        {
                            if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_SOURCE_OBJECT) != 0 && sourceObject != NULL)
                            {
                                aimDelta[0] = cameraSlot->x - sourceObject->worldPosX;
                                aimDelta[1] = cameraSlot->y - sourceObject->worldPosY;
                                aimDelta[2] = cameraSlot->z - sourceObject->worldPosZ;
                                PSVECNormalize((Vec*)aimDelta, (Vec*)aimDelta);
                                {
                                    f32 absX = __fabsf(aimDelta[0]);
                                    f32 absZ = __fabsf(aimDelta[2]);
                                    if (absX > absZ)
                                    {
                                        getAngle(absX, aimDelta[1]);
                                        pitchAngle = (s16)(getAngle(absX, aimDelta[1]) - 0x3800);
                                    }
                                    else
                                    {
                                        getAngle(absZ, aimDelta[1]);
                                        pitchAngle = (s16)(getAngle(absZ, aimDelta[1]) - 0x3800);
                                    }
                                    yawAngle = (s16)getAngle(aimDelta[0], aimDelta[2]);
                                }
                            }
                            else
                            {
                                yawAngle = (s16)(0x10000 - cameraSlot->yaw);
                                pitchAngle = cameraSlot->pitch;
                            }
                        }
                        else
                        {
                            yawAngle = (s16)(0x10000 - cameraSlot->yaw);
                        }
                    }
                }

                angleToVec2((u16)yawAngle, &cosA, &sinA);
                angleToVec2((u16)pitchAngle, &cosB, &sinB);
                if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_A) != 0)
                {
                    angleToVec2((u16)(gExpgfxPhaseAngleA + (((u32)slot << 8) & 0xFF00)), &sinC, &cosC);
                }
                else if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_B) != 0)
                {
                    angleToVec2((u16)(gExpgfxPhaseAngleB + (((u32)slot << 8) & 0xFF00)), &sinC, &cosC);
                }
                if (sourceObject != NULL && (slot->renderFlags & EXPGFX_RENDER_MODULATE_ALPHA_SOURCE) != 0)
                {
                    alpha = (alpha * sourceObject->alpha) >> 8;
                }

                if (currentTexture != texture)
                {
                    selectTexture((Texture*)texture, 0);
                    currentTexture = texture;
                }

                {
                    u32 flags = slot->renderFlags;
                    if ((flags & EXPGFX_RENDER_ALPHA_TEXTURE_SETUP) != 0)
                    {
                        if (alphaMode != 0)
                        {
                            textureSetupFn_800799c0();
                            fn_80079180();
                            textRenderSetupFn_80079804();
                            alphaMode = 0;
                        }
                    }
                    else if ((flags & EXPGFX_RENDER_ALT_ALPHA_SETUP) != 0)
                    {
                        if (!(alphaMode == 4 && ((lastOverrideColorFlag != flags) & EXPGFX_RENDER_OVERRIDE_COLORS) == 0))
                        {
                            int masked;
                            setupReflectionIndirectTev(flags & EXPGFX_RENDER_OVERRIDE_COLORS);
                            alphaMode = 4;
                            masked = slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS;
                            lastOverrideColorFlag = masked;
                        }
                    }
                    else if (alphaMode != 1)
                    {
                        textureSetupFn_800799c0();
                        geomDrawFn_800796f0();
                        textRenderSetupFn_80079804();
                        alphaMode = 1;
                    }
                }
                if ((slot->renderFlags & EXPGFX_RENDER_DEPTH_BLEND_MODE) != 0)
                {
                    if (blendMode != 0)
                    {
                        Camera_ApplyFullViewport();
                        gxSetZMode_(1, 3, 1);
                        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                        gxSetPeControl_ZCompLoc_(0);
                        GXSetAlphaCompare(GX_GREATER, 0xfe, GX_AOP_AND, GX_GREATER, 0xfe);
                        blendMode = 0;
                        zMode = 0;
                        zCompLoc = 0;
                    }
                }
                else
                {
                    if (zCompLoc != 1)
                    {
                        gxSetPeControl_ZCompLoc_(1);
                        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                        zCompLoc = 1;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_DEPTH_MODE_OVERRIDE) != 0)
                    {
                        if (zMode != 1)
                        {
                            fn_8000F83C();
                            gxSetZMode_(1, 3, 0);
                            zMode = 1;
                        }
                    }
                    else if (zMode != 2)
                    {
                        Camera_ApplyFullViewport();
                        gxSetZMode_(1, 3, 0);
                        zMode = 2;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_BLEND_ADDITIVE) != 0)
                    {
                        if (blendMode != 1)
                        {
                            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
                            blendMode = 1;
                        }
                    }
                    else if (blendMode != 2)
                    {
                        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                        blendMode = 2;
                    }
                }

                centerX -= playerMapOffsetX;
                centerZ -= playerMapOffsetZ;
                quad = (ExpgfxQuadVertex*)slot;
                vertexStream = quad;
                GXBegin(GX_QUADS, GX_VTXFMT4, 4);
                for (vertexIndex = 0; vertexIndex < 4; vertexIndex++)
                {
                    px = scaleFactor * __OSs16tof32(&vertexStream->x);
                    py = scaleFactor * __OSs16tof32(&vertexStream->y);
                    pz = scaleFactor * __OSs16tof32(&vertexStream->z);
                    if ((slot->renderFlags & (EXPGFX_RENDER_PHASE_ROTATE_A | EXPGFX_RENDER_PHASE_ROTATE_B)) != 0)
                    {
                        cC = cosC;
                        sC = sinC;
                        nx = px * cC - py * sC;
                        ny = px * sC + py * cC;
                        cA = cosA;
                        sB = sinB;
                        pz_sinB = pz * sB;
                        sA = sinA;
                        cB = cosB;
                        ay_cosB = ny * cB;
                        worldX = centerX + (nx * sA + cA * ay_cosB + cA * pz_sinB);
                        worldY = centerY + (ny * sB + (-pz) * cB);
                        worldZ = centerZ + ((-nx) * cA + sA * ay_cosB + sA * pz_sinB);
                    }
                    else
                    {
                        cA = cosA;
                        sB = sinB;
                        pz_sinB = pz * sB;
                        sA = sinA;
                        cB = cosB;
                        ay_cosB = py * cB;
                        worldX = centerX + (px * sA + cA * ay_cosB + cA * pz_sinB);
                        worldY = centerY + (py * sB + (-pz) * cB);
                        worldZ = centerZ + ((-px) * cA + sA * ay_cosB + sA * pz_sinB);
                    }
                    viewDepth = viewMatrix[2][0] * worldX + viewMatrix[2][1] * worldY + viewMatrix[2][2] * worldZ +
                                viewMatrix[2][3];
                    if (viewDepth > gExpgfxNearFadeDepth)
                    {
                        alpha = (int)((f32)alpha * ((-viewDepth) - 2.5f) / ((-gExpgfxNearFadeDepth) - 2.5f));
                    }
                    GXWGFifo.f32 = worldX;
                    GXWGFifo.f32 = worldY;
                    GXWGFifo.f32 = worldZ;
                    {
                        u8 colorR;
                        u8 colorG;
                        u8 colorB;
                        colorB = quad->colorB;
                        colorG = quad->colorG;
                        colorR = quad->colorR;
                        GXWGFifo.u8 = colorR;
                        GXWGFifo.u8 = colorG;
                        GXWGFifo.u8 = colorB;
                    }
                    GXWGFifo.u8 = alpha;
                    {
                        s16 texU;
                        s16 texV;
                        texV = vertexStream->texT;
                        texU = vertexStream->texS;
                        GXWGFifo.s16 = texU;
                        GXWGFifo.s16 = texV;
                    }
                    vertexStream++;
                }
            }
        }

        slotIndex++;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);

    if (gExpgfxRenderResetPending != 0)
    {
        expgfx_updateResourceEntries(0);
        gExpgfxRenderResetPending = 0;
    }
}

static inline void renderParticlesBody(void)
{
    float queuePosition[3];
    f32* currentMatrix;
    int poolIndex;
    u32* slotPoolBases;
    ExpgfxRuntimeDataLayout* runtime;
    register s16* poolSlotTypeIds;
    u32* poolSourceIds;
    ExpgfxBounds* poolBounds;
    u8* poolBoundsTemplateIds;
    u8* poolSourceModes;
    s8* poolActiveCounts;
    ExpgfxPoolSourcePosition* sourcePosition;
    ExpgfxBounds* boundsTemplate;

    runtime = EXPGFX_RUNTIME_DATA;
    currentMatrix = Camera_GetViewMatrix();
    poolIndex = 0;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSourceModes = runtime->poolSourceModes;
    poolBoundsTemplateIds = runtime->poolBoundsTemplateIds;
    poolBounds = runtime->poolBounds;
    poolSourceIds = runtime->poolSourceIds;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    slotPoolBases = runtime->slotPoolBases;
    do
    {
        if ((*poolActiveCounts != 0) && (*poolSourceModes == EXPGFX_POOL_SOURCE_MODE_STANDALONE))
        {
            boundsTemplate = Expgfx_GetBoundsTemplate(*poolBoundsTemplateIds);
            if ((u8)frustumTestAabbWithPlaneOffsets(
                    (double)(poolBounds->minX - playerMapOffsetX), (double)(poolBounds->maxX - playerMapOffsetX),
                    (double)poolBounds->minY, (double)poolBounds->maxY, (double)(poolBounds->minZ - playerMapOffsetZ),
                    (double)(poolBounds->maxZ - playerMapOffsetZ), &boundsTemplate->minX) != 0)
            {
                sourcePosition = (ExpgfxPoolSourcePosition*)*poolSourceIds;
                if (sourcePosition != (ExpgfxPoolSourcePosition*)0x0)
                {
                    queuePosition[0] = sourcePosition->x - playerMapOffsetX;
                    queuePosition[1] = sourcePosition->y;
                    queuePosition[2] = sourcePosition->z - playerMapOffsetZ;
                }
                else
                {
                    queuePosition[0] = 0.5f * (poolBounds->minX + poolBounds->maxX) - playerMapOffsetX;
                    queuePosition[1] = 0.5f * (poolBounds->minY + poolBounds->maxY);
                    queuePosition[2] = 0.5f * (poolBounds->minZ + poolBounds->maxZ) - playerMapOffsetZ;
                }
                PSMTXMultVec((float (*)[4])currentMatrix, (Vec*)queuePosition, (Vec*)queuePosition);
                if (*poolSourceIds != 0)
                {
                    queuePosition[2] = queuePosition[2] - (float)(*poolSlotTypeIds & EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK);
                }
                lightmap_queueExternalRenderEntry(*slotPoolBases, poolIndex, queuePosition);
            }
        }
        poolActiveCounts = poolActiveCounts + 1;
        poolSourceModes = poolSourceModes + 1;
        poolBoundsTemplateIds = poolBoundsTemplateIds + 1;
        poolBounds = poolBounds + 1;
        poolSourceIds = poolSourceIds + 1;
        poolSlotTypeIds = poolSlotTypeIds + 1;
        slotPoolBases = slotPoolBases + 1;
        poolIndex = poolIndex + 1;
    } while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

void renderParticles(void)
{
    renderParticlesBody();
}

void expgfx_free2(u32 sourceId)
{
    expgfx_free(sourceId);
    return;
}

void expgfx_free(u32 sourceId)
{
    s8* poolActiveCounts[1];
    int slotIndex;
    ExpgfxTableEntry* tableEntry;
    u32* slotPoolBases[1];
    ExpgfxRuntimeDataLayout* runtime;
    int tableIndex;
    u32* poolSourceIds[1];
    int poolIndex;
    ExpgfxSlot* slot;

    runtime = EXPGFX_RUNTIME_DATA;
    if (sourceId == 0)
    {
        return;
    }

    poolIndex = 0;
    slotPoolBases[0] = runtime->slotPoolBases;
    poolSourceIds[0] = runtime->poolSourceIds;
    poolActiveCounts[0] = runtime->poolActiveCounts;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        slot = (ExpgfxSlot*)*slotPoolBases[0];
        if (sourceId == *poolSourceIds[0])
        {
            for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
            {
                if (slot != NULL)
                {
                    tableEntry =
                        (ExpgfxTableEntry*)((u8*)runtime->expTab +
                                            (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16);
                    if (tableEntry->sourceId == sourceId)
                    {
                        expgfxRemove(*slotPoolBases[0], poolIndex, slotIndex, 0, 1);
                    }
                }
                slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
                if (*poolActiveCounts[0] == 0)
                {
                    gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
                }
            }
            *poolSourceIds[0] = 0;
            gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }

        slotPoolBases[0]++;
        poolSourceIds[0]++;
        poolActiveCounts[0]++;
        poolIndex++;
    }
}

static inline void expgfx_clearResourceTable(ExpgfxResourceEntry* resourceEntry, s32 zeroFlag, s32 zeroResource,
                                             s32 zeroId, s32 zeroScore, s32 zeroReserved)
{
    int resourceIndex;
    for (resourceIndex = 0; resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT; resourceEntry++, resourceIndex++)
    {
        gExpgfxTextureFreeInProgress = 1;
        if (resourceEntry->resource != NULL)
        {
            textureFree((Texture*)(resourceEntry->resource));
        }
        gExpgfxTextureFreeInProgress = zeroFlag;
        resourceEntry->resource = (void*)zeroResource;
        resourceEntry->resourceId = zeroId;
        resourceEntry->evictionScore = zeroScore;
        resourceEntry->reserved = zeroReserved;
    }
}

void expgfx_resetAllPools(void)
{
    u16* refCountPtr;
    u32* poolActiveMasks[1];
    s8* poolActiveCounts[1];
    s16* poolSlotTypeIds[1];
    u32* poolSourceIds[1];
    u8* poolFrameFlags[1];
    int resourceIndex;
    int activeBit;
    int poolIndex;
    ExpgfxResourceEntry* resourceEntry;
    ExpgfxTableEntry* tableEntry;
    ExpgfxStaticDataLayout* staticData;
    u32* slotPoolBases[1];
    int tableIndex;
    ExpgfxRuntimeDataLayout* runtime[1];
    int slotIndex;
    ExpgfxSlot* slot;
    staticData = EXPGFX_STATIC_DATA;
    slotPoolBases[0] = NULL;
    poolActiveMasks[0] = NULL;
    poolActiveCounts[0] = NULL;
    poolSlotTypeIds[0] = NULL;
    poolSourceIds[0] = NULL;
    poolFrameFlags[0] = NULL;
    runtime[0] = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotPoolBases[0] = runtime[0]->slotPoolBases;
    poolActiveMasks[0] = runtime[0]->poolActiveMasks;
    poolActiveCounts[0] = runtime[0]->poolActiveCounts;
    poolSlotTypeIds[0] = staticData->poolSlotTypeIds;
    poolSourceIds[0] = runtime[0]->poolSourceIds;
    poolFrameFlags[0] = staticData->poolFrameFlags;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        slot = (ExpgfxSlot*)*slotPoolBases[0];
        for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & *poolActiveMasks[0]) != 0)
            {
                if (((ExpgfxTableEntry*)((u8*)runtime[0]->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0)
                {
                    gExpgfxTextureFreeInProgress = 1;
                    textureFree((Texture*)((void*)((ExpgfxTableEntry*)((u8*)runtime[0]->expTab + Expgfx_GetSlotTableIndex(slot) * 16))
                                    ->resource));
                    gExpgfxTextureFreeInProgress = 0;
                }

                tableEntry = (ExpgfxTableEntry*)((u8*)runtime[0]->expTab + Expgfx_GetSlotTableIndex(slot) * 16);
                refCountPtr = &tableEntry->refCount;
                if (*refCountPtr != 0)
                {
                    (*refCountPtr)--;
                    if (*refCountPtr == 0)
                    {
                        tableEntry->resource = 0;
                        tableEntry->sourceId = 0;
                    }
                }
                else
                {
                    debugPrintf(staticData->mismatchInAddRemoveString);
                }

                slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
                *poolActiveMasks[0] &= ~activeBit;
            }

            slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
        }

        *poolActiveCounts[0] = 0;
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        *poolSourceIds[0] = 0;
        *poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        DCFlushRange((void*)*slotPoolBases[0], EXPGFX_POOL_BYTES);

        slotPoolBases[0]++;
        poolActiveMasks[0]++;
        poolActiveCounts[0]++;
        poolSlotTypeIds[0]++;
        poolSourceIds[0]++;
        poolFrameFlags[0]++;
        poolIndex++;
    }

    resourceEntry = runtime[0]->resourceTable;
    {
        expgfx_clearResourceTable(resourceEntry, 0, 0, 0, 0, 0);
    }
}

void expgfx_updateFrameState(int sourceMode, int sourceId)
{
    int renderMode;
    int poolIndex;
    f32 frameStep;
    f32 frameValue;

    renderMode = renderModeSetOrGet(EXPGFX_INVALID_SLOT_TYPE);
    if ((short)renderMode != 1)
    {
        frameValue = gExpgfxFrameTimerA + (frameStep = timeDelta);
        gExpgfxFrameTimerA = frameValue;
        if (frameValue >= 1024.0f)
        {
            gExpgfxFrameTimerA = 0.0f;
        }
        frameValue = gExpgfxFrameTimerB + frameStep;
        gExpgfxFrameTimerB = frameValue;
        if (frameValue >= 10.0f)
        {
            gExpgfxFrameTimerB = 0.0f;
        }
        frameValue = gExpgfxFrameTimerC + frameStep;
        gExpgfxFrameTimerC = frameValue;
        if (frameValue >= 1.0f)
        {
            gExpgfxFrameTimerC = 0.0f;
        }
        gExpgfxUpdatingActivePools = 1;
        expgfx_updateActivePools((u8)sourceMode, sourceId, 0);
        gExpgfxUpdatingActivePools = 0;
        poolIndex = EXPGFX_POOL_COUNT;
        while ((u8)poolIndex > 0)
        {
            poolIndex--;
            gExpgfxStaticPoolFrameFlags[(u8)poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }
        (*gPartfxInterface)->updateFrameState(0);
        gExpgfxRenderResetPending = 1;
    }
    return;
}

int expgfx_addremove(ExpgfxSpawnConfig* config, int preferredPoolIndex, int slotType, int boundsTemplateId)
{
    u32 behaviorFlags;
    ExpgfxSlot* slot;
    ExpgfxSourceObject* attachedSource;
    ExpgfxResourceHandle* resourceHandle;
    ExpgfxRuntimeDataLayout* runtime;
    GameObject* playerObj;
    s16 texT1 = 0;
    int expTabIndex;
    int attachedTableKey;
    short poolIndex;
    short slotIndex;
    s16 texT0 = 0;
    int resourceTableIndex;
    s16 texS1 = 0;
    s16 texS0 = 0;
    f32 scaleVal;
    u8* poolSourceModesByte;
    u8 sourceModeValue;

    ExpgfxQuadVertex* quadVertices;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotIndex = 0;
    texT1 = 0;
    texT0 = 0;
    texS1 = 0;
    texS0 = 0;
    if (getHudHiddenFrameCount() != 0)
    {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    if (expgfxGetSlot(&poolIndex, &slotIndex, (int)slotType, preferredPoolIndex, (u32)(int)config->attachedSource) ==
        EXPGFX_INVALID_POOL_INDEX)
    {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    {
        int poolIdx = poolIndex;

        if (poolIdx < EXPGFX_POOL_COUNT)
        {
            runtime->poolSourceIds[poolIdx] = (int)config->attachedSource;
        }
        if (poolIdx < EXPGFX_POOL_COUNT && (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0)
        {
            runtime->trackedSourceFrameMasks[poolIdx & 1] |= (s64)(1 << (poolIdx >> 1));
        }
        else
        {
            runtime->trackedSourceFrameMasks[poolIdx & 1] &= (s64)~(1 << (poolIdx >> 1));
        }
        slot = (ExpgfxSlot*)runtime->slotPoolBases[poolIdx];
        slot += slotIndex;
        quadVertices = (ExpgfxQuadVertex*)slot;
        gExpgfxSequenceCounter++;
        if (gExpgfxSequenceCounter > EXPGFX_SEQUENCE_COUNTER_MAX)
        {
            gExpgfxSequenceCounter = 0;
        }
        slot->sequenceId = gExpgfxSequenceCounter;
        slot->behaviorFlags = config->behaviorFlags;
        slot->renderFlags = config->renderFlags;
        slot->stateBits.bits.initPhase = 0;

        resourceTableIndex = (int)(short)expgfx_acquireResourceEntry(config->texture.parts.textureId);
        if (resourceTableIndex < 0)
        {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        resourceHandle = (ExpgfxResourceHandle*)runtime->resourceTable[resourceTableIndex].resource;
        if (resourceHandle != NULL)
        {
            if (resourceHandle->refCount >= EXPGFX_REFCOUNT_OVERFLOW)
            {
                expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
                return EXPGFX_INVALID_POOL_INDEX;
            }
            resourceHandle->refCount++;
            resourceHandle->linkGroup = config->linkGroup;
        }
        else
        {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }

        behaviorFlags = slot->behaviorFlags;
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_S) != 0)
        {
            texS1 = 0;
            texS0 = 0;
        }
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX_T) != 0)
        {
            texT1 = 0;
            texT0 = 0;
        }

        attachedSource = (ExpgfxSourceObject*)config->attachedSource;
        attachedTableKey = 0;
        if (attachedSource == NULL)
        {
            slot->sourcePosY.value = config->sourcePosY.value;
            slot->sourcePosZ.value = config->sourcePosZ.value;
            slot->sourcePosW.value = config->sourcePosW.value;
            slot->sourcePosX.value = config->sourcePosX.value;
            slot->sourceVecZ = config->sourceVecZ;
            slot->sourceVecY = config->sourceVecY;
            slot->sourceVecX = config->sourceVecX;
        }
        else if ((behaviorFlags & EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE) != 0)
        {
            slot->sourcePosY.value = attachedSource->worldPosX;
            slot->sourcePosZ.value = attachedSource->worldPosY;
            slot->sourcePosW.value = attachedSource->worldPosZ;
            slot->sourcePosX.value = attachedSource->sourcePosX;
            slot->sourceVecZ = attachedSource->rotZ;
            slot->sourceVecY = attachedSource->rotY;
            slot->sourceVecX = attachedSource->rotX;
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A) != 0 ||
                (slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0)
            {
                config->velocityX = config->velocityX + attachedSource->velocityX;
                config->velocityY = config->velocityY + attachedSource->velocityY;
                config->velocityZ = config->velocityZ + attachedSource->velocityZ;
            }
        }

        if (attachedSource != NULL)
        {
            attachedTableKey = attachedSource->attachedTableKey;
            attachedSource = NULL;
        }

        expTabIndex = expgfx_addToTable((u32)resourceHandle, (u32)attachedSource, attachedTableKey,
                                        config->texture.parts.textureId);
        if ((short)expTabIndex == EXPGFX_INVALID_TABLE_INDEX)
        {
            debugPrintf(sExpgfxInvalidTabIndex);
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        ((struct {
             u8 tableIndex : 7;
             u8 lowBit : 1;
         }*)&slot->encodedTableIndex)
            ->tableIndex = (u8)expTabIndex;

        slot->posX.value = slot->startPosX.value = config->startPosX.value;
        slot->posY.value = slot->startPosY.value = config->startPosY.value;
        slot->posZ.value = slot->startPosZ.value = config->startPosZ.value;
        slot->velocityX = config->velocityX;
        slot->velocityY = config->velocityY;
        slot->velocityZ = config->velocityZ;
        slot->initialAlpha = config->initialAlpha;
        quadVertices[3].pad06 = config->quadVertex3Pad06;
        slot->lifetimeFrame = config->lifetimeFrames;
        slot->lifetimeFrameLimit = config->lifetimeFrames;

        if (config->scale > 1.0f)
        {
            debugPrintf(sExpgfxScaleOverflow);
        }
        scaleVal = 65535.0f * config->scale;

        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0)
        {
            slot->scaleCurrent = 0;
            *(u16*)&slot->scaleStep = (scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
            *(u16*)&slot->scaleTarget = scaleVal;
        }
        else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0)
        {
            *(u16*)&slot->scaleCurrent = scaleVal;
            *(u16*)&slot->scaleStep = (scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
            *(u16*)&slot->scaleTarget = scaleVal;
        }
        else
        {
            *(u16*)&slot->scaleCurrent = scaleVal;
            slot->scaleTarget = slot->scaleCurrent;
            slot->scaleStep = 0;
        }

        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 ||
            (slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B) != 0)
        {
            slot->sourcePosY.value = config->sourcePosY.value;
            slot->sourcePosZ.value = config->sourcePosZ.value;
            slot->sourcePosW.value = config->sourcePosW.value;
            slot->sourcePosX.value = config->sourcePosX.value;
            slot->sourceVecZ = config->sourceVecZ;
            slot->sourceVecY = config->sourceVecY;
            slot->sourceVecX = config->sourceVecX;
        }
        slot->stateBits.bits.frameParity = *(u8*)&gExpgfxFrameParityBit;

        if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0)
        {
            slot->renderFlags = slot->renderFlags ^ (EXPGFX_RENDER_BACKDATE_MOTION + 0LL);
            slot->posX.value = slot->velocityX * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posX.value;
            slot->posY.value = slot->velocityY * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posY.value;
            slot->posZ.value = slot->velocityZ * (1.5f * (f32)(s32)slot->lifetimeFrame) + slot->posZ.value;
            slot->velocityX = slot->velocityX * -1.0f;
            slot->velocityY = slot->velocityY * -1.0f;
            slot->velocityZ = slot->velocityZ * -1.0f;
        }

        if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_ACTOR) != 0)
        {
            f32 dx;
            f32 dz;
            f32 distSq;
            f32 inv;
            playerObj = (GameObject*)Obj_GetPlayerObject();
            slot->renderFlags = slot->renderFlags ^ (EXPGFX_RENDER_AIM_AT_ACTOR + 0LL);
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0)
            {
                dx = playerObj->anim.worldPosX - slot->startPosX.value;
                dz = playerObj->anim.worldPosZ - slot->startPosZ.value;
                distSq = dx * dx + dz * dz;
                if (distSq < 3600.0f && 0.0f != playerObj->anim.velocityX &&
                    0.0f != playerObj->anim.velocityZ)
                {
                    slot->velocityX = slot->velocityX + dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY =
                        slot->velocityY + ((30.0f + playerObj->anim.worldPosY) - slot->startPosY.value) /
                                              (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ = slot->velocityZ + (playerObj->anim.worldPosZ - slot->startPosZ.value) /
                                                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            }
            else
            {
                dx = playerObj->anim.worldPosX - (slot->startPosX.value + attachedSource->localPosX);
                dz = playerObj->anim.worldPosZ - (slot->startPosZ.value + attachedSource->localPosZ);
                distSq = dx * dx + dz * dz;
                if (distSq < 3600.0f && 0.0f != playerObj->anim.velocityX &&
                    0.0f != playerObj->anim.velocityZ)
                {
                    slot->velocityX = slot->velocityX - dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY =
                        slot->velocityY - ((30.0f + playerObj->anim.worldPosY) -
                                           (slot->startPosY.value + attachedSource->localPosY)) /
                                              (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ =
                        slot->velocityZ -
                        (playerObj->anim.worldPosZ - (slot->startPosZ.value + attachedSource->localPosZ)) /
                            (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            }
        }

        if (slotType == 1)
        {
            gExpgfxSlotType1Count = gExpgfxSlotType1Count + 1;
            gExpgfxSlotType1Average = lbl_803DD274 / gExpgfxSlotType1Count;
        }

        slot->colorByte0 = (u8)((int)*(u16*)&config->colorByte0 >> 8);
        slot->colorByte1 = (u8)((int)*(u16*)&config->colorByte1 >> 8);
        slot->colorByte2 = (u8)((int)*(u16*)&config->colorByte2 >> 8);

        if ((config->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0)
        {
            quadVertices[1].alpha = (u8)((int)config->overrideColor0 >> 8);
            quadVertices[2].alpha = (u8)((int)config->overrideColor1 >> 8);
            quadVertices[3].alpha = (u8)((int)config->overrideColor2 >> 8);
        }

        quadVertices[0].colorR = 0xff;
        quadVertices[0].colorG = 0xff;
        quadVertices[0].colorB = 0xff;

        quadVertices[0].texS = texS0;
        quadVertices[0].texT = texT0;
        quadVertices[1].texS = texS1;
        quadVertices[1].texT = texT0;
        quadVertices[2].texS = texS1;
        quadVertices[2].texT = texT1;
        quadVertices[3].texS = texS0;
        quadVertices[3].texT = texT1;

        if ((slot->renderFlags & EXPGFX_RENDER_INIT_QUAD) != 0)
        {
            expgfx_initSlotQuad(slot);
        }

        {
            sourceModeValue = (config->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0 ? 1 : 0;
            poolSourceModesByte = (u8*)runtime + poolIndex;
            poolSourceModesByte += EXPGFX_POOL_SOURCE_MODES_OFFSET;
            *poolSourceModesByte = sourceModeValue;
            if (*poolSourceModesByte != 0 &&
                (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0)
            {
                (*poolSourceModesByte)++;
            }
            runtime->poolBoundsTemplateIds[poolIndex] = (u8)boundsTemplateId;
        }

        DCFlushRange(slot, EXPGFX_SLOT_SIZE);
        gExpgfxLastAddedSlot = (int)slot;
        return slot->sequenceId;
    }
}

void expgfx_onMapSetup(void)
{
    ExpgfxRuntimeDataLayout* runtime[1];
    ExpgfxResourceEntry* resourceEntry;
    s64* trackedFrameMasks;
    u32* poolActiveMasks[1];
    s8* poolActiveCounts[1];
    s16* poolSlotTypeIds[1];
    u8* poolFrameFlags[1];
    u8* poolSourceModes;
    u32* poolSourceIds;
    int poolIndex;

    runtime[0] = EXPGFX_RUNTIME_DATA;
    expgfxRemoveAll();

    poolActiveMasks[0] = runtime[0]->poolActiveMasks;
    poolActiveCounts[0] = runtime[0]->poolActiveCounts;
    poolSlotTypeIds[0] = gExpgfxStaticPoolSlotTypeIds;
    poolFrameFlags[0] = gExpgfxStaticPoolFrameFlags;
    poolSourceModes = runtime[0]->poolSourceModes;
    poolSourceIds = runtime[0]->poolSourceIds;

    for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++)
    {
        *poolActiveMasks[0] = 0;
        *poolActiveCounts[0] = 0;
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        *poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        *poolSourceModes = EXPGFX_POOL_SOURCE_MODE_STANDALONE;
        *poolSourceIds = 0;

        poolActiveMasks[0]++;
        poolActiveCounts[0]++;
        poolSlotTypeIds[0]++;
        poolFrameFlags[0]++;
        poolSourceModes++;
        poolSourceIds++;
    }

    trackedFrameMasks = runtime[0]->trackedSourceFrameMasks;
    trackedFrameMasks[0] = 0;
    trackedFrameMasks[1] = 0;

    gExpgfxTextureFreeInProgress = 1;
    poolIndex = 0;
    resourceEntry = runtime[0]->resourceTable;
    while (poolIndex < EXPGFX_RESOURCE_TABLE_COUNT)
    {
        if (resourceEntry->resource != NULL)
        {
            textureFree((Texture*)(resourceEntry->resource));
        }
        resourceEntry->resource = NULL;
        resourceEntry->resourceId = 0;
        resourceEntry->evictionScore = 0;
        resourceEntry->reserved = 0;
        resourceEntry++;
        poolIndex++;
    }
    gExpgfxTextureFreeInProgress = 0;
}

void expgfx_release(void)
{
    int poolIndex;

    expgfxRemoveAll();
    poolIndex = 0;
    do
    {
        mm_free((void*)gExpgfxSlotPoolBases[poolIndex]);
        poolIndex = poolIndex + 1;
    } while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

void expgfx_initialise(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    s16* poolSlotTypeIds[1];
    u32* slotPoolBases[1];
    int poolIndex[1];
    int groupCount;

    runtime = EXPGFX_RUNTIME_DATA;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    slotPoolBases[0] = NULL;
    poolSlotTypeIds[0] = gExpgfxStaticPoolSlotTypeIds;
    for (groupCount = EXPGFX_POOL_GROUP_COUNT; groupCount != 0; groupCount--)
    {
        poolIndex[0] = 0;
        *poolActiveMasks = poolIndex[0];
        *poolActiveCounts = poolIndex[0];
        *poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[1] = poolIndex[0];
        poolActiveCounts[1] = poolIndex[0];
        poolSlotTypeIds[0][1] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[2] = poolIndex[0];
        poolActiveCounts[2] = poolIndex[0];
        poolSlotTypeIds[0][2] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[3] = poolIndex[0];
        poolActiveCounts[3] = poolIndex[0];
        poolSlotTypeIds[0][3] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[4] = poolIndex[0];
        poolActiveCounts[4] = poolIndex[0];
        poolSlotTypeIds[0][4] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[5] = poolIndex[0];
        poolActiveCounts[5] = poolIndex[0];
        poolSlotTypeIds[0][5] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[6] = poolIndex[0];
        poolActiveCounts[6] = poolIndex[0];
        poolSlotTypeIds[0][6] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[7] = poolIndex[0];
        poolActiveCounts[7] = poolIndex[0];
        poolSlotTypeIds[0][7] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks += 8;
        poolActiveCounts += 8;
        poolSlotTypeIds[0] += 8;
    }

    slotPoolBases[0] = runtime->slotPoolBases;
    do
    {
        *slotPoolBases[0] = (u32)mmAlloc(EXPGFX_POOL_BYTES, EXPGFX_POOL_ALLOC_HEAP, 0);
        memset((void*)*slotPoolBases[0], 0, EXPGFX_POOL_BYTES);
        DCFlushRange((void*)*slotPoolBases[0], EXPGFX_POOL_BYTES);
        slotPoolBases[0]++;
        poolIndex[0]++;
    } while (poolIndex[0] < EXPGFX_POOL_COUNT);
    memset(runtime->expTab, 0, EXPGFX_EXPTAB_BYTES);
    return;
}

u8 gExpgfxRuntimeData[0x980];
ExpgfxTableEntry gExpgfxTableEntries[0x550 / sizeof(ExpgfxTableEntry)];
void* gExpgfxTrackedPoolSourceIds[0x50];
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
