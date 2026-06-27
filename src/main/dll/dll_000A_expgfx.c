#include "dolphin/mtx.h"
#include "math.h"
#include "main/camera.h"
#include "main/dll_000A_expgfx.h"
#include "main/expgfx_internal.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/lightmap.h"
#include "main/mm.h"
#include "main/sky_state.h"
#include "main/tex_dolphin.h"
#include "main/texture.h"
#include "dolphin/os/OSFastCast.h"

#define GX_BM_NONE 0
#define GX_BM_BLEND 1
#define GX_BL_ZERO 0
#define GX_BL_ONE 1
#define GX_BL_SRCALPHA 4
#define GX_BL_INVSRCALPHA 5
#define GX_LO_NOOP 5
#define GX_GREATER 4
#define GX_ALWAYS 7
#define GX_AOP_AND 0
#define GX_CULL_NONE 0
#define GX_VA_POS 9
#define GX_VA_CLR0 11
#define GX_VA_TEX0 13
#define GX_DIRECT 1
#define GX_QUADS 0x80
#define GX_VTXFMT4 4

extern s16 renderModeSetOrGet(int mode);
extern void debugPrintf(char* fmt, ...);
extern u64 FUN_80286830();
extern ExpgfxBounds gExpgfxPoolBounds[];
extern u8 lbl_803DD253;
extern volatile f32 timeDelta;
extern volatile f32 gExpgfxFrameTimerA;
extern volatile f32 gExpgfxFrameTimerB;
extern volatile f32 gExpgfxFrameTimerC;
extern const f32 lbl_803DF354;
extern const f32 lbl_803DF35C;
extern volatile f32 lbl_803DF384;
extern volatile f32 lbl_803DF418;
extern const f32 lbl_803DF358;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f64 gExpgfxU16ToDoubleBias;
extern f32 gExpgfxYVelocityPositiveLimit;
extern f32 gExpgfxYVelocityFastStep;
extern f32 gExpgfxYVelocitySlowStep;
extern f32 gExpgfxYVelocityNegativeLimit;
extern const f32 gExpgfxSlotMotionStep;

ObjectDescriptor14 expgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,
    (ObjectDescriptorCallback)expgfx_initialise,
    (ObjectDescriptorCallback)expgfx_release,
    0,
    (ObjectDescriptorCallback)expgfx_onMapSetup,
    (ObjectDescriptorCallback)expgfx_addremove,
    (ObjectDescriptorCallback)expgfx_updateFrameState,
    (ObjectDescriptorCallback)expgfx_resetAllPools,
    (ObjectDescriptorCallback)expgfx_free,
    (ObjectDescriptorCallback)expgfx_free2,
    (ObjectDescriptorCallback)expgfx_func09,
    (ObjectDescriptorCallback)expgfx_func0A_nop,
    (ObjectDescriptorCallback)expgfx_func0B_nop,
    (ObjectDescriptorCallback)expgfx_ownerFree3,
    (ObjectDescriptorCallback)expgfx_updateSourceFrameFlags,
};

extern f32 fn_80138F78(void* tricky);
extern f32 fn_8029610C(void* player);
extern void vecRotateZXY(void* params, void* vec);
extern u8 framesThisStep;
extern u16 gExpgfxPhaseAngleA;
extern u16 gExpgfxPhaseAngleB;
extern f32 lbl_803DF38C;
extern f32 lbl_803DF390;
extern f32 lbl_803DF3B0;
extern const f32 lbl_803DF3C8;
extern const f32 lbl_803DF3CC;
extern const f32 lbl_803DF3D0;
extern const f32 gExpgfxBoundsInitMin;
extern const f32 gExpgfxBoundsInitMax;
extern const f32 lbl_803DF3DC;
extern const f32 lbl_803DF3E0;
extern const f32 lbl_803DF3E4;
extern const f32 lbl_803DF3E8;
extern const f32 lbl_803DF3EC;
extern const f32 lbl_803DF3F0;
extern const f32 lbl_803DF3F4;
extern const f32 lbl_803DF3F8;
extern const f32 lbl_803DF3FC;
extern const f32 lbl_803DF400;
extern const f32 lbl_803DF404;
extern const f32 lbl_803DF408;
extern const f32 lbl_803DF40C;
extern const f32 gExpgfxU16ToUnitScale;
extern int getHudHiddenFrameCount(void);
extern int Camera_GetProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void _textSetColor(int unused, int a, int b, int c, int d);
extern void fn_8000F83C(void);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern float __fabsf(float);
extern void angleToVec2(int angle, f32* cosOut, f32* sinOut);
extern void selectTexture(int handle, int slot);
extern void setupReflectionIndirectTev(u8 flag);
extern void gxSetPeControl_ZCompLoc_(u32 zcomploc);
extern void gxSetZMode_(u32 compEnable, int func, u32 updateEnable);
extern void _gxSetFogParams(void);
extern void fn_80079180(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void textureSetupFn_800799c0(void);
extern void fn_8007D670(void);
extern f32 lbl_803967C0[3][4];
extern const f32 lbl_803DF414;
extern f32 lbl_803DB790;
extern f32 lbl_803DF350;
extern const f32 lbl_803DF41C;
extern const f32 lbl_803DF420;
extern const f32 lbl_803DF424;
extern const f32 lbl_803DF428;
extern int lbl_803DD270;
extern int lbl_803DD274;
extern int lbl_803DD278;

static inline ExpgfxTableEntry* Expgfx_GetTableEntry(int tableIndex)
{
    return &gExpgfxTableEntries[tableIndex];
}

static inline u8 Expgfx_GetSlotTableIndex(const ExpgfxSlot* slot)
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

static inline f64 Expgfx_U16AsDouble(u16 value)
{
    u64 bits;

    bits = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)(value)));
    return *(f64*)&bits - gExpgfxU16ToDoubleBias;
}

static inline ExpgfxCurrentSource Expgfx_GetCurrentSource(void)
{
    u64 rawSource;
    ExpgfxCurrentSource currentSource;

    rawSource = FUN_80286830();
    currentSource.sourceId = (int)((u64)rawSource >> 0x20);
    currentSource.sourceMode = rawSource;
    return currentSource;
}

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void expgfxRemove(u32 slotPoolBase, int poolIndex, int slotIndex, int skipTextureFree, int flushSlot)
{
    ExpgfxRuntimeDataLayout* runtime;
    u32 activeBit;
    u8* resBase;
    ExpgfxSlot* slot;
    u32 inactiveBitMask;

    runtime = EXPGFX_RUNTIME_DATA;
    activeBit = 1 << slotIndex;
    if ((activeBit & runtime->poolActiveMasks[poolIndex]) == 0)
    {
        return;
    }

    slot = (ExpgfxSlot*)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;

    if (skipTextureFree == 0)
    {
        resBase = (u8*)&runtime->expTab[0].resource;

        if (*(u32*)(resBase + (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16) != 0)
        {
            gExpgfxTextureFreeInProgress = 1;
            textureFree((void*)*(u32*)(resBase + (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16));
            gExpgfxTextureFreeInProgress = 0;
        }

        {
            u32 tableIndex = ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;

            if (runtime->expTab[tableIndex].refCount != 0)
            {
                runtime->expTab[tableIndex].refCount--;
                if (runtime->expTab[tableIndex].refCount == 0)
                {
                    *(u32*)(resBase + tableIndex * 16) = 0;
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
        inactiveBitMask = ~activeBit;
        runtime->poolActiveMasks[poolIndex] = currentMaskValue & inactiveBitMask;
    }
    runtime->poolActiveCounts[poolIndex]--;
    if (runtime->poolActiveCounts[poolIndex] == 0)
    {
        gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
    }
}
#pragma opt_propagation reset

#pragma opt_propagation off
void expgfxRemoveAll(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    u32* slotPoolBases;
    u32* poolActiveMasks;
    s8* poolActiveCountPtrs;
    s16* poolSlotTypeIds;
    u16* refCountPtr;
    ExpgfxTableEntry* expTabEntry;
    u32 activeBit;
    u32 inactiveBitMask;
    int poolIndex;
    int slotIndex;
    ExpgfxSlot* slot;

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
                    textureFree((void*)((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource);
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
                {
                    u32 currentMaskValue = *poolActiveMasks;
                    inactiveBitMask = ~activeBit;
                    *poolActiveMasks = currentMaskValue & inactiveBitMask;
                }
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
#pragma opt_propagation reset

#pragma ppc_unroll_speculative on
#pragma ppc_unroll_factor_limit 5
#pragma ppc_unroll_instructions_limit 120
#pragma opt_strength_reduction off
int expgfxGetSlot(short* poolIndexOut, short* slotIndexOut, short slotType,
                  int preferredPoolIndex, u32 sourceId)
{
    u32 currentMask;
    s8* poolActiveCounts;
    u32* poolActiveMasks;
    int searchIndex;
    u32* sourceIdWalk;
    s16* poolSlotTypeIds;
    s8* activeCountWalk;
    u32 activeBit;
    ExpgfxRuntimeDataLayout* runtime;
    u32* activeMaskPtr;
    short foundPool;
    int foundPoolIndex;
    int poolIndex;
    int slotIndex;
    int batchGroup;
    int batchSlot;
    int chosenPool;

    runtime = EXPGFX_RUNTIME_DATA;
    foundPoolIndex = EXPGFX_INVALID_POOL_INDEX;
    foundPool = 0;
    searchIndex = 0;
    sourceIdWalk = runtime->poolSourceIds;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    poolActiveCounts = runtime->poolActiveCounts;
    activeCountWalk = runtime->poolActiveCounts;
    for (batchGroup = 0; batchGroup < EXPGFX_POOL_SEARCH_BATCH_COUNT; batchGroup++)
    {
        for (batchSlot = 0; batchSlot < EXPGFX_POOL_SEARCH_BATCH_SIZE; batchSlot++)
        {
            if ((sourceIdWalk[batchSlot] == sourceId) &&
                (slotType == *poolSlotTypeIds) &&
                (activeCountWalk[batchSlot] < EXPGFX_SLOTS_PER_POOL))
            {
                foundPoolIndex = (s16)searchIndex;
                foundPool = 1;
                goto poolSearchDone;
            }
            poolSlotTypeIds++;
            searchIndex++;
        }
        sourceIdWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE;
        activeCountWalk += EXPGFX_POOL_SEARCH_BATCH_SIZE;
    }
poolSearchDone:

    if (foundPool)
    {
        slotIndex = 0;
        chosenPool = (s16)foundPoolIndex;
        activeMaskPtr = (u32*)((u8*)runtime->poolActiveMasks + chosenPool * 4);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & currentMask) == 0)
            {
                *slotIndexOut = slotIndex;
                *poolIndexOut = chosenPool;
                *activeMaskPtr |= activeBit;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
    }

    foundPool = 0;
    if (preferredPoolIndex == EXPGFX_INVALID_POOL_INDEX)
    {
        for (poolIndex = 0;
             poolIndex < EXPGFX_POOL_COUNT - 1;
             poolActiveCounts++, poolIndex++)
        {
            if (*poolActiveCounts <= 0)
            {
                foundPoolIndex = (s16)poolIndex;
                foundPool = 1;
                runtime->poolActiveCounts[poolIndex] = 0;
                break;
            }
        }
    }
    if (preferredPoolIndex != EXPGFX_INVALID_POOL_INDEX)
    {
        foundPoolIndex = preferredPoolIndex;
        if (runtime->poolActiveCounts[preferredPoolIndex] < EXPGFX_SLOTS_PER_POOL)
        {
            foundPoolIndex = (s16)preferredPoolIndex;
            foundPool = 1;
        }
    }

    if (foundPool)
    {
        slotIndex = 0;
        chosenPool = (s16)foundPoolIndex;
        activeMaskPtr = (u32*)((u8*)runtime->poolActiveMasks + chosenPool * 4);
        currentMask = *activeMaskPtr;
        for (; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & currentMask) == 0)
            {
                *slotIndexOut = slotIndex;
                *poolIndexOut = chosenPool;
                *activeMaskPtr |= activeBit;
                gExpgfxStaticPoolSlotTypeIds[chosenPool] = slotType;
                runtime->poolActiveCounts[chosenPool]++;
                return 1;
            }
        }
        return EXPGFX_INVALID_POOL_INDEX;
    }

    return EXPGFX_INVALID_POOL_INDEX;
}
#pragma ppc_unroll_factor_limit 4
#pragma ppc_unroll_instructions_limit 256

void expgfx_initSlotQuad(void* slotPtr)
{
    ExpgfxStaticDataLayout* staticData;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* entry;
    ExpgfxQuadVertex* quad;
    ExpgfxQuadTemplateVertex *
    template
    ;
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
        template
        =
        staticData->quadTemplateA;
    }
    else
    {
        template
        =
        staticData->quadTemplateB;
    }

    if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
        slot->velocityY < gExpgfxYVelocityPositiveLimit)
    {
        if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
            slot->velocityY < gExpgfxYVelocityPositiveLimit)
        {
            slot->velocityY -= gExpgfxYVelocityFastStep * timeDelta;
        }
        else
        {
            slot->velocityY -= gExpgfxYVelocitySlowStep * timeDelta;
        }
    }
    else if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
        slot->velocityY > gExpgfxYVelocityNegativeLimit)
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
        *(u16*)&slot->scaleCurrent =
        ((f32)(u16)
        slot->scaleStep * step + (f32)(u16)
        slot->scaleCurrent
        )
        ;
    }
    else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0)
    {
        *(u16*)&slot->scaleCurrent =
        ((f32)(u16)
        slot->scaleCurrent - (f32)(u16)
        slot->scaleStep * step
        )
        ;
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
    quad[0].x =
    template
    [0].x;
    quad[0].y =
    template
    [0].y;
    quad[0].z =
    template
    [0].z;
    quad[0].texS = texS0;
    quad[0].texT = texT0;
    quad[1].x =
    template
    [1].x;
    quad[1].y =
    template
    [1].y;
    quad[1].z =
    template
    [1].z;
    quad[1].texS = texS1;
    quad[1].texT = texT0;
    quad[2].x =
    template
    [2].x;
    quad[2].y =
    template
    [2].y;
    quad[2].z =
    template
    [2].z;
    quad[2].texS = texS1;
    quad[2].texT = texT1;
    quad[3].x =
    template
    [3].x;
    quad[3].y =
    template
    [3].y;
    quad[3].z =
    template
    [3].z;
    quad[3].texS = texS0;
    quad[3].texT = texT1;
}

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

void expgfx_updateActivePools(u8 sourceMode, int sourceId, int resetSourceFrameState)
{
    ExpgfxStaticDataLayout* staticData;
    ExpgfxRuntimeDataLayout* runtime;
    int next;
    GameObject* player;
    GameObject* tricky;
    int pool;
    int sky;
    ExpgfxBounds* bounds;
    f32* maxYPtr;
    f32* minZPtr;
    f32* maxZPtr;
    s16 slotIdx;
    ExpgfxSlot* slot;
    ExpgfxQuadTemplateVertex* template;
    s16 texT1;
    s16 texT0;
    s16 texS1;
    u8* nextBuf;
    f32* minYPtr;
    ExpgfxSourceObject* srcObj;
    u32 resource;
    s16 texS0;
    s8* scan;
    int batch;
    int curPool;
    u32* maskPtr;
    void* cache;
    u8* curCache;
    u8* curPoolBuf;
    f32* maxXPtr;
    u8 parity;
    u8 prefetched;
    int ambRPlus1;
    int ambGPlus1;
    int ambBPlus1;
    u8 ambScaled[3];
    ExpgfxRotateParams rot;
    f32 vecBuf[3];
    f32 camDir[3];
    f32 rotPos[3];
    f32 srcVel[3];
    u8 ambB8;
    u8 ambG8;
    u8 ambR8;
    f32 boundsMax;
    f32 boundsMin;
    f32 prevX;
    f32 prevY;
    f32 prevZ;
    f32 workA;
    f32 workB;
    f32 camScale;
    f32 playerRange;
    f32 trickyRange;
    f32 attractRatio;

    staticData = EXPGFX_STATIC_DATA;
    runtime = EXPGFX_RUNTIME_DATA;
    attractRatio = lbl_803DF354;
    trickyRange = lbl_803DF35C;
    playerRange = trickyRange;
    player = (GameObject*)Obj_GetPlayerObject();
    tricky = (GameObject*)getTrickyObject();
    cache = getCache();
    gExpgfxPhaseAngleA += (int)(lbl_803DF3C8 * timeDelta);
    gExpgfxPhaseAngleB += (int)(lbl_803DF3CC * timeDelta);
    sky = getSkyStructField24C();
    fn_800897D4(sky, &camDir[0], &camDir[1], &camDir[2]);
    PSMTXMultVec((void*)Camera_GetViewRotationMatrix(), (void*)camDir, (void*)camDir);
    camScale = -camDir[2];
    if (camScale < lbl_803DF3D0)
    {
        camScale = lbl_803DF3D0;
    }
    getAmbientColor(sky, &ambR8, &ambG8, &ambB8);
    ambScaled[2] = (f32)ambR8 * camScale;
    ambScaled[1] = (f32)ambG8 * camScale;
    ambScaled[0] = (f32)ambB8 * camScale;

    next = 0;
    scan = runtime->poolActiveCounts;
    for (batch = 8; batch != 0; batch--)
    {
        switch (scan[0])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[1])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[2])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[3])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[4])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[5])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[6])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[7])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[8])
        {
        case 0: break;
        default: goto foundFirst;
        }
        next++;
        switch (scan[9])
        {
        case 0: break;
        default: goto foundFirst;
        }
        scan += 10;
        next++;
    }
    next = -1;
foundFirst:
    pool = next;
    if (pool != -1)
    {
        copyToCache(cache, (void*)runtime->slotPoolBases[pool], EXPGFX_POOL_CACHE_LINE_COUNT);
        parity = 1;
        curCache = cache;
        Camera_GetCurrentViewSlot();
        if (tricky != NULL)
        {
            trickyRange = fn_80138F78(tricky);
        }
        if (player != NULL)
        {
            playerRange = fn_8029610C(player);
        }
        prefetched = 0;
        ambRPlus1 = ambScaled[2] + 1;
        ambGPlus1 = ambScaled[1] + 1;
        ambBPlus1 = ambScaled[0] + 1;
        boundsMin = gExpgfxBoundsInitMin;
        boundsMax = gExpgfxBoundsInitMax;
        while (pool > -1)
        {
            bounds = &runtime->poolBounds[pool];
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
            next = pool + 1;
            scan = &runtime->poolActiveCounts[next];
            for (; next < EXPGFX_POOL_COUNT; next++)
            {
                switch (*scan)
                {
                case 0: break;
                default: goto foundNext;
                }
                scan++;
            }
            next = -1;
        foundNext:
            slot = (ExpgfxSlot*)curCache;
            if (next > -1)
            {
                nextBuf = (u8*)cache + parity * 0x1000;
                copyToCache(nextBuf, (void*)*(u32*)((u8*)runtime->slotPoolBases + next * 4), EXPGFX_POOL_CACHE_LINE_COUNT);
                curCache = nextBuf;
                prefetched = 1;
            }
            parity ^= 1;
            cacheQueueWait(prefetched);
            slot--;
            maskPtr = &runtime->poolActiveMasks[pool];
            curPoolBuf = (u8*)cache + parity * 0x1000;
            for (slotIdx = 0; slotIdx < EXPGFX_SLOTS_PER_POOL; slotIdx++)
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
                    template
                    =
                    staticData->quadTemplateA;
                }
                else
                {
                    template
                    =
                    staticData->quadTemplateB;
                }
                if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                    (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                {
                    rot.x = lbl_803DF35C;
                    rot.y = lbl_803DF35C;
                    rot.z = lbl_803DF35C;
                    rot.scale = lbl_803DF354;
                    *(s16*)&rot.angleZ = ((f32)slot->sourceVecZ * timeDelta);
                    *(s16*)&rot.angleY = ((f32)slot->sourceVecY * timeDelta);
                    *(s16*)&rot.angleX = ((f32)slot->sourceVecX * timeDelta);
                    vecRotateZXY(&rot, &slot->posX.value);
                }
                if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) != 0)
                {
                    workB = lbl_803DF3DC;
                    workA = workB;
                    if ((slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_PLAYER) != 0 && player != NULL && srcObj != NULL
                        &&
                        playerRange > lbl_803DF3E0)
                    {
                        vecBuf[0] = player->anim.worldPosX -
                            (slot->startPosX.value + srcObj->localPosX);
                        vecBuf[2] = player->anim.worldPosZ -
                            (slot->startPosZ.value + srcObj->localPosZ);
                        workB = vecBuf[0] * vecBuf[0] + vecBuf[2] * vecBuf[2];
                        attractRatio = playerRange / workB;
                    }
                    if (workB > lbl_803DF3B0 && (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TO_TRICKY) != 0 &&
                        tricky != NULL && srcObj != NULL && trickyRange > lbl_803DF3E0)
                    {
                        vecBuf[0] = tricky->anim.worldPosX -
                            (slot->startPosX.value + srcObj->localPosX);
                        vecBuf[2] = tricky->anim.worldPosZ -
                            (slot->startPosZ.value + srcObj->localPosZ);
                        workA = vecBuf[0] * vecBuf[0] + vecBuf[2] * vecBuf[2];
                        attractRatio = trickyRange / workB;
                    }
                    if (workA < workB)
                    {
                        workB = workA;
                    }
                    if (workB < lbl_803DF3B0)
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
                        slot->velocityX = -(vecBuf[0] * attractRatio);
                        slot->velocityZ = -(vecBuf[2] * attractRatio);
                    }
                }
                else
                {
                    if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_A) != 0)
                    {
                        slot->velocityX = lbl_803DF3E4 * slot->velocityX + slot->velocityX;
                        slot->velocityY = lbl_803DF3E4 * slot->velocityY + slot->velocityY;
                        slot->velocityZ = lbl_803DF3E4 * slot->velocityZ + slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_B) != 0)
                    {
                        slot->velocityX = lbl_803DF3E8 * slot->velocityX + slot->velocityX;
                        slot->velocityY = lbl_803DF3E8 * slot->velocityY + slot->velocityY;
                        slot->velocityZ = lbl_803DF3E8 * slot->velocityZ + slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_BOOST_C) != 0)
                    {
                        slot->velocityX = lbl_803DF3EC * slot->velocityX + slot->velocityX;
                        slot->velocityY = lbl_803DF3EC * slot->velocityY + slot->velocityY;
                        slot->velocityZ = lbl_803DF3EC * slot->velocityZ + slot->velocityZ;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_VELOCITY_DAMP) != 0)
                    {
                        slot->velocityX = lbl_803DF3F0 * slot->velocityX;
                        slot->velocityY = lbl_803DF3F0 * slot->velocityY;
                        slot->velocityZ = lbl_803DF3F0 * slot->velocityZ;
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
                        f32 zero = lbl_803DF35C;
                        if (slot->velocityY * timeDelta + slot->posY.value < zero)
                        {
                            slot->velocityX = zero;
                            slot->velocityY = zero;
                            slot->velocityZ = zero;
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
                        slot->velocityY * timeDelta + slot->posY.value < lbl_803DF35C)
                    {
                        u32 rnd;
                        f32 fade;

                        rnd = randomGetRange(0, 5);
                        slot->velocityY *= -(lbl_803DF3E4 * (f32)(int)
                        rnd + lbl_803DF38C
                        )
                        ;
                        if (slot->velocityY > lbl_803DF390)
                        {
                            slot->velocityY = lbl_803DF390;
                        }
                        rot.scale = lbl_803DF354;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = 0;
                        if (srcObj != NULL)
                        {
                            rot.x = slot->posX.value + srcObj->localPosX;
                            rot.y = slot->posY.value + srcObj->localPosY;
                            rot.z = slot->posZ.value + srcObj->localPosZ;
                        }
                        else
                        {
                            rot.x = slot->posX.value + slot->sourcePosY.value;
                            rot.y = slot->posY.value + slot->sourcePosZ.value;
                            rot.z = slot->posZ.value + slot->sourcePosW.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT) != 0 &&
                            (slot->renderFlags & EXPGFX_RENDER_IMPACT_POSITION_LOCKED) == 0)
                        {
                            slot->velocityX *= gExpgfxSlotMotionStep;
                            slot->velocityZ *= gExpgfxSlotMotionStep;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT | 0LL;
                            if (slot->soundHandle != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->soundHandle, &rot, 0x200001,
                                                                 -1, 0);
                                slot->soundHandle = -1;
                            }
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1) != 0)
                        {
                            slot->velocityX *= lbl_803DF358;
                            slot->velocityZ *= lbl_803DF358;
                            *(u16*)&slot->scaleCurrent =
                            ((f32)(u16)
                            slot->scaleCurrent * lbl_803DF3F4
                            )
                            ;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1 | 0LL;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2) != 0)
                        {
                            slot->velocityX *= lbl_803DF358;
                            slot->velocityZ *= lbl_803DF358;
                            *(u16*)&slot->scaleCurrent =
                            ((f32)(u16)
                            slot->scaleCurrent * lbl_803DF3F4
                            )
                            ;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3) != 0)
                        {
                            slot->velocityX *= lbl_803DF358;
                            slot->velocityZ *= lbl_803DF358;
                            *(u16*)&slot->scaleCurrent =
                            ((f32)(u16)
                            slot->scaleCurrent * lbl_803DF3F4
                            )
                            ;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2;
                            if (slot->soundHandle != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->soundHandle, &rot, 0x200001,
                                                                 -1, 0);
                            }
                            slot->soundHandle = -1;
                        }
                        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4) != 0)
                        {
                            slot->velocityX = slot->velocityX * (gExpgfxSlotMotionStep - slot->velocityX);
                            slot->velocityZ = slot->velocityZ * (gExpgfxSlotMotionStep - slot->velocityZ);
                            *(u16*)&slot->scaleCurrent =
                            ((f32)(u16)
                            slot->scaleCurrent * lbl_803DF3F4
                            )
                            ;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4 | 0LL;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3;
                            if (slot->soundHandle != -1)
                            {
                                (*gPartfxInterface)->spawnObject(srcObj, slot->soundHandle, &rot, 0x200001,
                                                                 -1, 0);
                            }
                        }
                        gExpgfxFrameParityBit = 0;
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) != 0 &&
                        slot->velocityY * timeDelta + slot->posY.value < lbl_803DF35C)
                    {
                        if (slot->soundHandle != -1)
                        {
                            rot.scale = lbl_803DF354;
                            rot.angleZ = 0;
                            rot.angleY = 0;
                            rot.angleX = 0;
                            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0)
                            {
                                rot.x = slot->posX.value;
                                rot.y = lbl_803DF35C;
                                rot.z = slot->posZ.value;
                            }
                            else if (srcObj != NULL)
                            {
                                rot.x = slot->posX.value + srcObj->worldPosX;
                                rot.y = srcObj->worldPosY;
                                rot.z = slot->posZ.value + srcObj->worldPosZ;
                            }
                            else
                            {
                                rot.x = slot->posX.value;
                                rot.y = lbl_803DF35C;
                                rot.z = slot->posZ.value;
                            }
                            gExpgfxFrameParityBit = 1;
                            ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                                rot.x, rot.y, rot.z, 0, lbl_803DF35C, 4);
                            (*gWaterfxInterface)->spawnSplashBurst(NULL, rot.x, rot.y, rot.z,
                                                                   gExpgfxSlotMotionStep);
                            if (srcObj != NULL &&
                                coordsToMapCell(srcObj->localPosX, srcObj->localPosZ) == 0x10)
                            {
                                Sfx_PlayFromObject((u32)srcObj, 0x285);
                            }
                            slot->soundHandle = -1;
                            slot->behaviorFlags |= EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT | 0LL;
                            slot->lifetimeFrame = 0;
                            gExpgfxFrameParityBit = 0;
                        }
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK) == 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT) == 0 && slot->soundHandle != -1)
                    {
                        rot.scale = lbl_803DF354;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = 0;
                        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0)
                        {
                            rot.x = slot->posX.value;
                            rot.y = slot->posY.value;
                            rot.z = slot->posZ.value;
                        }
                        else if (srcObj != NULL)
                        {
                            rot.x = slot->posX.value + srcObj->localPosX;
                            rot.y = slot->posY.value + srcObj->localPosY;
                            rot.z = slot->posZ.value + srcObj->localPosZ;
                        }
                        else
                        {
                            rot.x = slot->posX.value;
                            rot.y = slot->posY.value;
                            rot.z = slot->posZ.value;
                        }
                        gExpgfxFrameParityBit = 1;
                        (*gPartfxInterface)->spawnObject(srcObj, slot->soundHandle, &rot, 0x200001, -1, NULL);
                        gExpgfxFrameParityBit = 0;
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER) != 0 && randomGetRange(0, 4) == 1)
                    {
                        slot->velocityX +=
                            lbl_803DF3F8 - (f32)(int)
                        randomGetRange(0, 9) / lbl_803DF3FC;
                        slot->velocityZ +=
                            lbl_803DF3F8 - (f32)(int)
                        randomGetRange(0, 9) / lbl_803DF3FC;
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_RANDOM_VELOCITY_BURST) != 0 && randomGetRange(0, 10) ==
                        1)
                    {
                        if ((f32)slot->lifetimeFrame < slot->lifetimeFrameLimit)
                        {
                            slot->velocityX +=
                                lbl_803DF400 * (f32)(int)
                            randomGetRange(-800, 800) + lbl_803DF3E8;
                            slot->velocityY +=
                                lbl_803DF400 * (f32)(int)
                            randomGetRange(-800, 800) + lbl_803DF3E8;
                            slot->velocityZ +=
                                lbl_803DF400 * (f32)(int)
                            randomGetRange(-800, 800) + lbl_803DF3E8;
                        }
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH) != 0)
                    {
                        if ((f32)slot->lifetimeFrame < lbl_803DF38C * slot->lifetimeFrameLimit)
                        {
                            f32 boost = lbl_803DF404;
                            slot->behaviorFlags ^= EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH | 0LL;
                            slot->velocityX *= boost;
                            slot->velocityY *= boost;
                            slot->velocityZ *= boost;
                        }
                    }
                    if ((slot->renderFlags & EXPGFX_RENDER_STRETCHED_TRAIL) != 0)
                    {
                        prevX = slot->posX.value;
                        prevY = slot->posY.value;
                        prevZ = slot->posZ.value;
                    }
                    slot->posX.value += slot->velocityX * timeDelta;
                    slot->posY.value += slot->velocityY * timeDelta;
                    slot->posZ.value += slot->velocityZ * timeDelta;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0)
                    {
                        *(u16*)&slot->scaleCurrent =
                        ((f32)(u16)
                        slot->scaleStep * timeDelta +
                            (f32)(u16)
                        slot->scaleCurrent
                        )
                        ;
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
                    u8* attached;

                    texT0 = 0;
                    texT1 = 0;
                    texS0 = 0;
                    texS1 = 0;
                    if (resource != 0)
                    {
                        texS0 = 0x80;
                        texT0 = 0x80;
                        texS1 = 0;
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
                        colR = (int)(ratio * (f32)(quad[1].alpha - slot->colorByte0) +
                            slot->colorByte0);
                        colG = (int)(ratio * (f32)(quad[2].alpha - slot->colorByte1) +
                            slot->colorByte1);
                        colB = (int)(ratio * (f32)(quad[3].alpha - slot->colorByte2) +
                            slot->colorByte2);
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
                        quad[0].colorR = ambScaled[2];
                        quad[0].colorG = ambScaled[1];
                        quad[0].colorB = ambScaled[0];
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
                        s16 baseX;
                        s16 baseY;
                        s16 baseZ;

                        sx = lbl_803DF35C;
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
                        prevDX = prevX - slot->posX.value;
                        prevDY = prevY - slot->posY.value;
                        prevDZ = prevZ - slot->posZ.value;
                        workA = prevDY * dirZ - prevDZ * dirY;
                        workB = -(prevDX * dirZ - prevDZ * dirX);
                        attractRatio = prevDX * dirY - prevDY * dirX;
                        normSq = attractRatio * attractRatio + (workA * workA + workB * workB);
                        if (lbl_803DF35C != normSq)
                        {
                            norm = sqrtf(normSq);
                        }
                        else
                        {
                            norm = lbl_803DF354;
                        }
                        axisX = lbl_803DF408 * (workA / norm);
                        axisY = lbl_803DF408 * (workB / norm);
                        axisZ = lbl_803DF408 * (attractRatio / norm);
                        attractRatio = lbl_803DF40C / (gExpgfxU16ToUnitScale * (f32)(u16)
                        slot->scaleTarget
                        )
                        ;
                        baseX = axisX;
                        quad[0].x = baseX;
                        baseY = axisY;
                        quad[0].y = baseY;
                        baseZ = axisZ;
                        quad[0].z = baseZ;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        *(s16*)&quad[1].x = (attractRatio * (slot->posX.value - prevX) + axisX);
                        *(s16*)&quad[1].y = (attractRatio * (slot->posY.value - prevY) + axisY);
                        *(s16*)&quad[1].z = (attractRatio * (slot->posZ.value - prevZ) + axisZ);
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        *(s16*)&quad[2].x = (attractRatio * (slot->posX.value - prevX) - axisX);
                        *(s16*)&quad[2].y = (attractRatio * (slot->posY.value - prevY) - axisY);
                        *(s16*)&quad[2].z = (attractRatio * (slot->posZ.value - prevZ) - axisZ);
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x = -baseX;
                        quad[3].y = -baseY;
                        quad[3].z = -baseZ;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rot.x = lbl_803DF35C;
                        rot.y = lbl_803DF35C;
                        rot.z = lbl_803DF35C;
                        slot->sourceVecX = slot->sourceVecX + (int)slot->sourcePosY.value * framesThisStep;
                        slot->sourceVecY = slot->sourceVecY + (int)slot->sourcePosZ.value * framesThisStep;
                        slot->sourceVecZ = slot->sourceVecZ + (int)slot->sourcePosW.value * framesThisStep;
                        rot.scale = lbl_803DF354;
                        vecBuf[0] = (f32)
                        template
                        [0].x;
                        vecBuf[1] = (f32)
                        template
                        [0].y;
                        vecBuf[2] = (f32)
                        template
                        [0].z;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = slot->sourceVecX;
                        vecRotateZXY(&rot, vecBuf);
                        rot.angleZ = slot->sourceVecY;
                        rot.angleY = slot->sourceVecZ;
                        rot.angleX = 0;
                        vecRotateZXY(&rot, vecBuf);
                        quad[0].x = vecBuf[0];
                        quad[0].y = vecBuf[1];
                        quad[0].z = vecBuf[2];
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        vecBuf[0] = (f32)
                        template
                        [1].x;
                        vecBuf[1] = (f32)
                        template
                        [1].y;
                        vecBuf[2] = (f32)
                        template
                        [1].z;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = slot->sourceVecX;
                        vecRotateZXY(&rot, vecBuf);
                        rot.angleZ = slot->sourceVecY;
                        rot.angleY = slot->sourceVecZ;
                        rot.angleX = 0;
                        vecRotateZXY(&rot, vecBuf);
                        quad[1].x = vecBuf[0];
                        quad[1].y = vecBuf[1];
                        quad[1].z = vecBuf[2];
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        vecBuf[0] = (f32)
                        template
                        [2].x;
                        vecBuf[1] = (f32)
                        template
                        [2].y;
                        vecBuf[2] = (f32)
                        template
                        [2].z;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = slot->sourceVecX;
                        vecRotateZXY(&rot, vecBuf);
                        rot.angleZ = slot->sourceVecY;
                        rot.angleY = slot->sourceVecZ;
                        rot.angleX = 0;
                        vecRotateZXY(&rot, vecBuf);
                        quad[2].x = vecBuf[0];
                        quad[2].y = vecBuf[1];
                        quad[2].z = vecBuf[2];
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        vecBuf[0] = (f32)
                        template
                        [3].x;
                        vecBuf[1] = (f32)
                        template
                        [3].y;
                        vecBuf[2] = (f32)
                        template
                        [3].z;
                        rot.angleZ = 0;
                        rot.angleY = 0;
                        rot.angleX = slot->sourceVecX;
                        vecRotateZXY(&rot, vecBuf);
                        rot.angleZ = slot->sourceVecY;
                        rot.angleY = slot->sourceVecZ;
                        rot.angleX = 0;
                        vecRotateZXY(&rot, vecBuf);
                        quad[3].x = vecBuf[0];
                        quad[3].y = vecBuf[1];
                        quad[3].z = vecBuf[2];
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0)
                    {
                        quad[0].x =
                        template
                        [0].x;
                        quad[0].y =
                        template
                        [0].y;
                        quad[0].z =
                        template
                        [0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x =
                        template
                        [1].x;
                        quad[1].y =
                        template
                        [1].y;
                        quad[1].z =
                        template
                        [1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x =
                        template
                        [2].x;
                        quad[2].y =
                        template
                        [2].y;
                        quad[2].z =
                        template
                        [2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x =
                        template
                        [3].x;
                        quad[3].y =
                        template
                        [3].y;
                        quad[3].z =
                        template
                        [3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_Y8) != 0)
                    {
                        quad[0].x =
                        template
                        [0].x;
                        quad[0].y =
                        template
                        [0].y;
                        quad[0].y <<= 3;
                        quad[0].z =
                        template
                        [0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x =
                        template
                        [1].x;
                        quad[1].y =
                        template
                        [1].y;
                        quad[1].y <<= 3;
                        quad[1].z =
                        template
                        [1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x =
                        template
                        [2].x;
                        quad[2].y =
                        template
                        [2].y;
                        quad[2].y <<= 3;
                        quad[2].z =
                        template
                        [2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x =
                        template
                        [3].x;
                        quad[3].y =
                        template
                        [3].y;
                        quad[3].y <<= 3;
                        quad[3].z =
                        template
                        [3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SWAP_XZ_SCALE_Z32) != 0)
                    {
                        quad[0].z =
                        template
                        [0].x;
                        quad[0].z <<= 5;
                        quad[0].y =
                        template
                        [0].y;
                        quad[0].x =
                        template
                        [0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].z =
                        template
                        [1].x;
                        quad[1].z <<= 5;
                        quad[1].y =
                        template
                        [1].y;
                        quad[1].x =
                        template
                        [1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].z =
                        template
                        [2].x;
                        quad[2].z <<= 5;
                        quad[2].y =
                        template
                        [2].y;
                        quad[2].x =
                        template
                        [2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].z =
                        template
                        [3].x;
                        quad[3].z <<= 5;
                        quad[3].y =
                        template
                        [3].y;
                        quad[3].x =
                        template
                        [3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else if ((slot->renderFlags & EXPGFX_RENDER_QUAD_SCALE_X32) != 0)
                    {
                        quad[0].x =
                        template
                        [0].x;
                        quad[0].x <<= 5;
                        quad[0].y =
                        template
                        [0].y;
                        quad[0].z =
                        template
                        [0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x =
                        template
                        [1].x;
                        quad[1].x <<= 5;
                        quad[1].y =
                        template
                        [1].y;
                        quad[1].z =
                        template
                        [1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x =
                        template
                        [2].x;
                        quad[2].x <<= 5;
                        quad[2].y =
                        template
                        [2].y;
                        quad[2].z =
                        template
                        [2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x =
                        template
                        [3].x;
                        quad[3].x <<= 5;
                        quad[3].y =
                        template
                        [3].y;
                        quad[3].z =
                        template
                        [3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    else
                    {
                        quad[0].x =
                        template
                        [0].x;
                        quad[0].y =
                        template
                        [0].y;
                        quad[0].z =
                        template
                        [0].z;
                        quad[0].texS = texS0;
                        quad[0].texT = texT0;
                        quad[1].x =
                        template
                        [1].x;
                        quad[1].y =
                        template
                        [1].y;
                        quad[1].z =
                        template
                        [1].z;
                        quad[1].texS = texS1;
                        quad[1].texT = texT0;
                        quad[2].x =
                        template
                        [2].x;
                        quad[2].y =
                        template
                        [2].y;
                        quad[2].z =
                        template
                        [2].z;
                        quad[2].texS = texS1;
                        quad[2].texT = texT1;
                        quad[3].x =
                        template
                        [3].x;
                        quad[3].y =
                        template
                        [3].y;
                        quad[3].z =
                        template
                        [3].z;
                        quad[3].texS = texS0;
                        quad[3].texT = texT1;
                    }
                    attached = (u8*)((ExpgfxTableEntry*)((u8*)runtime->expTab +
                        (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16))->attachedTableKey;
                    rot.x = lbl_803DF35C;
                    rot.y = lbl_803DF35C;
                    rot.z = lbl_803DF35C;
                    rot.scale = lbl_803DF354;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rot.x = slot->posX.value;
                        rot.y = slot->posY.value;
                        rot.z = slot->posZ.value;
                    }
                    rot.angleZ = 0;
                    rot.angleY = 0;
                    rot.angleX = 0;
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 && (slot->behaviorFlags &
                        EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0)
                    {
                        if (srcObj != NULL)
                        {
                            rot.angleX = srcObj->rotX;
                            rot.angleY = srcObj->rotY;
                            rot.angleZ = srcObj->rotZ;
                        }
                        else
                        {
                            rot.angleX = slot->sourceVecX;
                            rot.angleY = slot->sourceVecY;
                            rot.angleZ = slot->sourceVecZ;
                        }
                    }
                    rotPos[0] = slot->posX.value;
                    rotPos[1] = slot->posY.value;
                    rotPos[2] = slot->posZ.value;
                    if ((rot.angleZ | rot.angleX | rot.angleY) != 0)
                    {
                        vecRotateZXY(&rot, rotPos);
                    }
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) == 0)
                    {
                        if (srcObj != NULL)
                        {
                            srcVel[0] = srcObj->worldPosX;
                            srcVel[1] = srcObj->worldPosY;
                            srcVel[2] = srcObj->worldPosZ;
                        }
                        else
                        {
                            srcVel[0] = slot->sourcePosY.value;
                            srcVel[1] = slot->sourcePosZ.value;
                            srcVel[2] = slot->sourcePosW.value;
                            if (attached != NULL)
                            {
                                Obj_RotateLocalOffsetByYaw(&slot->sourcePosY.value, srcVel, *(attached + 0x35));
                            }
                        }
                    }
                    else
                    {
                        srcVel[0] = lbl_803DF35C;
                        srcVel[1] = lbl_803DF35C;
                        srcVel[2] = lbl_803DF35C;
                    }
                    rot.angleZ = 0;
                    rot.angleY = 0;
                    rot.angleX = 0;
                    rot.x = srcVel[0] + rotPos[0];
                    rot.y = srcVel[1] + rotPos[1];
                    rot.z = srcVel[2] + rotPos[2];
                    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 &&
                        (slot->behaviorFlags & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) == 0 &&
                        (slot->renderFlags & EXPGFX_RENDER_ATTRACT_TARGET_MASK) == 0)
                    {
                        rot.x = rot.x + slot->sourcePosY.value;
                        rot.y = rot.y + slot->sourcePosZ.value;
                        rot.z = rot.z + slot->sourcePosW.value;
                    }
                    slot->renderX = rot.x;
                    slot->renderY = rot.y;
                    slot->renderZ = rot.z;
                    if (rot.x < bounds->minX)
                    {
                        bounds->minX = rot.x;
                    }
                    if (rot.x > *maxXPtr)
                    {
                        *maxXPtr = rot.x;
                    }
                    if (rot.y < *minYPtr)
                    {
                        *minYPtr = rot.y;
                    }
                    if (rot.y > *maxYPtr)
                    {
                        *maxYPtr = rot.y;
                    }
                    if (rot.z < *minZPtr)
                    {
                        *minZPtr = rot.z;
                    }
                    if (rot.z > *maxZPtr)
                    {
                        *maxZPtr = rot.z;
                    }
                }
            }
            memcpyToCache((void*)runtime->slotPoolBases[pool], curPoolBuf, EXPGFX_POOL_CACHE_LINE_COUNT);
            prefetched = 1;
            pool = next;
        }
        cacheQueueWait(0);
    }
}

#pragma dont_inline on
#pragma opt_strength_reduction on
int expgfx_addToTable(u32 resourceHandle, u32 sourceId, u32 attachedTableKey, s16 resourceId)
{
    ExpgfxTableEntry* entry;
    int tableIndex;
    int freeIndex;

    for (tableIndex = 0; tableIndex < EXPGFX_EXPTAB_ENTRY_COUNT; tableIndex++)
    {
        entry = &gExpgfxTableEntries[tableIndex];
        if ((entry->refCount != 0) && (entry->resource == resourceHandle) &&
            (entry->sourceId == sourceId) && (entry->attachedTableKey == attachedTableKey))
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
#pragma opt_strength_reduction off
#pragma dont_inline reset

#pragma opt_propagation off
int expgfx_updateSourceFrameFlags(void* sourceObject)
{
    ExpgfxSourceObject* source;
    ExpgfxTrackedSourceFrameMask* mask;
    int signedPoolIndex;
    u32 highBits;
    int result;
    u32* poolSourceIds;
    int poolIndex;
    u8* poolFrameFlags;
    u32 bit;

    result = EXPGFX_SOURCE_FRAME_STATE_NONE;
    lbl_803DD253 = 0;
    poolIndex = 0;
    source = (ExpgfxSourceObject*)sourceObject;
    poolSourceIds = gExpgfxTrackedPoolSourceIds;

    while ((s16)poolIndex < EXPGFX_POOL_COUNT)
    {
        poolFrameFlags = &gExpgfxStaticPoolFrameFlags[poolIndex];
        if ((source->objType == EXPGFX_SOURCE_OBJTYPE_MATCH_ALL) ||
            (*poolSourceIds == (u32)sourceObject))
        {
            signedPoolIndex = (s16)poolIndex;
            bit = 1 << (signedPoolIndex >> 1);
            highBits = (u32)((s32)bit >> 31);
            mask = &gExpgfxTrackedSourceFrameMasks[signedPoolIndex & 1];
            if ((((u64)(((u64)(u32)(highBits) << 32) | (u32)(bit))) & ((u64)(((u64)(u32)(mask->highWord) << 32) | (u32)(mask->lowWord)))) != 0)
            {
                *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_B;
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
                *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_A;
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
            *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }
        poolSourceIds++;
        poolIndex++;
    }

    return result;
}
#pragma opt_propagation reset

#pragma scheduling on
#pragma peephole on
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

#pragma scheduling off
#pragma peephole off
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
                                                poolBounds->maxX - playerMapOffsetX,
                                                poolBounds->minY, poolBounds->maxY,
                                                poolBounds->minZ - playerMapOffsetZ,
                                                poolBounds->maxZ - playerMapOffsetZ,
                                                &boundsTemplate->minX) != 0)
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

#pragma optimization_level 2
void drawGlow(u32 slotPoolBase, int poolIndex)
{
    void* dstBuf;
    int trackedFlags;
    int zCompLoc;
    int zMode;
    int blendMode;
    int alphaMode;
    void* viewMatrix;
    ExpgfxCameraViewSlot* cameraSlot;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* tabBase;
    ExpgfxTableEntry* tabEntry;
    ExpgfxSourceObject* sourceObject;
    u32 texture;
    u32 currentTexture;
    int slotIndex;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 state;
    int alpha;
    f32 lifeFraction;
    f32 scaleSize;
    f32 sx, sy, sz;
    f32 scaleFactor;
    s16 angleA;
    s16 angleB;
    f32 cosA, sinA;
    f32 cosB, sinB;
    f32 cosC, sinC;
    f32 worldX, worldY, worldZ;
    f32 aimDelta[3];
    s16* vtxStream;
    int vertexIndex;
    f32 viewProjW;
    volatile int dummy;
    u32* activeMasks;

    dstBuf = getCache();
    trackedFlags = 0;
    dummy = getHudHiddenFrameCount();
    Camera_GetProjectionMatrix();
    copyToCache(dstBuf, (void*)slotPoolBase, EXPGFX_POOL_CACHE_LINE_COUNT);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCurrentMtx(0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_NONE);
    viewMatrix = Camera_GetViewMatrix();
    GXLoadPosMtxImm((void*)viewMatrix, 0);
    PSMTXCopy((void*)viewMatrix, lbl_803967C0);
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

    slot = (ExpgfxSlot*)((char*)dstBuf - EXPGFX_SLOT_SIZE);
    slotIndex = 0;
    activeMasks = &gExpgfxSlotActiveMasks[poolIndex];
    tabBase = gExpgfxTableEntries;
    do
    {
        slot = (ExpgfxSlot*)((char*)slot + EXPGFX_SLOT_SIZE);
        tabEntry = &tabBase[((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK];
        sourceObject = (ExpgfxSourceObject*)tabEntry->sourceId;
        texture = tabEntry->resource;
        if ((1U << slotIndex & *activeMasks) == 0) goto next_slot;
        state = slot->stateBits.value;
        if (((state >> 2) & 3) != 0) goto next_slot;
        if (((state >> 1) & 1) == 0) goto next_slot;
        if (slot->sequenceId == EXPGFX_INVALID_SEQUENCE_ID) goto next_slot;
        if ((state & 1) != 0) goto next_slot;

        lifeFraction = lbl_803DF358 * (f32)(s32)
        slot->lifetimeFrameLimit;
        behaviorFlags = slot->behaviorFlags;
        if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_TO_OPAQUE) != 0)
        {
            f32 ratio = (f32)(s32)slot->lifetimeFrame
            /
            (f32)(s32)
            slot->lifetimeFrameLimit;
            if (ratio < lbl_803DF35C)
            {
                ratio = lbl_803DF35C;
            }
            else if (ratio > lbl_803DF354)
            {
                ratio = lbl_803DF354;
            }
            {
                u32 baseAlpha = slot->initialAlpha;
                alpha = (int)
                ((f32)((s32)baseAlpha - 0xff) * ratio + (f32)baseAlpha)
                ;
            }
        }
        else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_OUT) != 0)
        {
            f32 ratio = (f32)(s32)slot->lifetimeFrame
            /
            (f32)(s32)
            slot->lifetimeFrameLimit;
            if (ratio < lbl_803DF35C)
            {
                ratio = lbl_803DF35C;
            }
            else if (ratio > lbl_803DF354)
            {
                ratio = lbl_803DF354;
            }
            alpha = (int)
            ((f32)(u32)
            slot->initialAlpha * ratio
            )
            ;
        }
        else if ((slot->renderFlags & EXPGFX_RENDER_ALPHA_FADE_IN) != 0 &&
            (f32)(s32)
                slot->lifetimeFrame <= lifeFraction
        )
        {
            f32 ratio = (f32)(s32)slot->lifetimeFrame
            /
            lifeFraction;
            if (ratio < lbl_803DF35C)
            {
                ratio = lbl_803DF35C;
            }
            else if (ratio > lbl_803DF354)
            {
                ratio = lbl_803DF354;
            }
            alpha = (int)
            ((f32)(u32)
            slot->initialAlpha * ratio
            )
            ;
        }
        else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_PULSE) != 0 &&
            (f32)(s32)slot->lifetimeFrame <= lifeFraction)
        {
            f32 ratio = (f32)(s32)slot->lifetimeFrame / lifeFraction;
            if (ratio < lbl_803DF35C)
            {
                ratio = lbl_803DF35C;
            }
            else if (ratio > lbl_803DF354)
            {
                ratio = lbl_803DF354;
            }
            alpha = (int)
            ((f32)(u32)
            slot->initialAlpha * ratio
            )
            ;
        }
        else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_PULSE) != 0)
        {
            f32 ratio = (lifeFraction - ((f32)(s32)
            slot->lifetimeFrame - lifeFraction
            )
            )
            /
            lifeFraction;
            if (ratio < lbl_803DF35C)
            {
                ratio = lbl_803DF35C;
            }
            else if (ratio > lbl_803DF354)
            {
                ratio = lbl_803DF354;
            }
            alpha = (int)
            ((f32)(u32)
            slot->initialAlpha * ratio
            )
            ;
        }
        else
        {
            alpha = slot->initialAlpha;
        }

        angleA = 0;
        angleB = 0;
        sx = slot->renderX;
        sy = slot->renderY;
        sz = slot->renderZ;
        scaleSize = gExpgfxU16ToUnitScale * (f32)(u32)
        slot->scaleCurrent;
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOMIZE_SCALE) != 0 && dummy == 0)
        {
            f32 base = lbl_803DF358 * scaleSize;
            f32 rnd = (f32)(s32)randomGetRange(1, 10);
            scaleFactor = base + base / rnd;
        }
        else
        {
            scaleFactor = scaleSize;
        }

        {
            u32 behavior = slot->behaviorFlags;
            if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0)
            {
                angleA = 0;
                angleB = 0;
            }
            else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A) != 0)
            {
                angleA = 0;
                angleB = 0;
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
                            angleB = (s16)(getAngle(absX, aimDelta[1]) - 0x3800);
                        }
                        else
                        {
                            getAngle(absZ, aimDelta[1]);
                            angleB = (s16)(getAngle(absZ, aimDelta[1]) - 0x3800);
                        }
                        angleA = getAngle(aimDelta[0], aimDelta[2]);
                    }
                }
                else
                {
                    angleA = (s16)(0x10000 - cameraSlot->yaw);
                    angleB = cameraSlot->pitch;
                }
            }
            else
            {
                angleA = (s16)(0x10000 - cameraSlot->yaw);
            }
        }

        angleToVec2((u16)angleA, &cosA, &sinA);
        angleToVec2((u16)angleB, &cosB, &sinB);
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
            selectTexture(texture, 0);
            currentTexture = texture;
        }

        {
            u32 flags = slot->renderFlags;
            if ((flags & EXPGFX_RENDER_ALPHA_TEXTURE_SETUP) != 0)
            {
                if ((s8)alphaMode != 0)
                {
                    textureSetupFn_800799c0();
                    fn_80079180();
                    textRenderSetupFn_80079804();
                    alphaMode = 0;
                }
            }
            else if ((flags & EXPGFX_RENDER_ALT_ALPHA_SETUP) != 0)
            {
                if (!((s8)alphaMode == 4 && trackedFlags == (int)(flags & EXPGFX_RENDER_OVERRIDE_COLORS)))
                {
                    setupReflectionIndirectTev(flags & EXPGFX_RENDER_OVERRIDE_COLORS);
                    alphaMode = 4;
                    trackedFlags = (int)(slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS);
                }
            }
            else if ((s8)alphaMode != 1)
            {
                textureSetupFn_800799c0();
                geomDrawFn_800796f0();
                textRenderSetupFn_80079804();
                alphaMode = 1;
            }
        }
        if ((slot->renderFlags & EXPGFX_RENDER_DEPTH_BLEND_MODE) != 0)
        {
            if ((s8)blendMode != 0)
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
            if ((s8)zCompLoc != 1)
            {
                gxSetPeControl_ZCompLoc_(1);
                GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                zCompLoc = 1;
            }
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_DEPTH_MODE_OVERRIDE) != 0)
            {
                if ((s8)zMode != 1)
                {
                    fn_8000F83C();
                    gxSetZMode_(1, 3, 0);
                    zMode = 1;
                }
            }
            else if ((s8)zMode != 2)
            {
                Camera_ApplyFullViewport();
                gxSetZMode_(1, 3, 0);
                zMode = 2;
            }
            if ((slot->renderFlags & EXPGFX_RENDER_BLEND_ADDITIVE) != 0)
            {
                if ((s8)blendMode != 1)
                {
                    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
                    blendMode = 1;
                }
            }
            else if ((s8)blendMode != 2)
            {
                GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                blendMode = 2;
            }
        }

        sx -= playerMapOffsetX;
        sz -= playerMapOffsetZ;
        vtxStream = (s16*)slot;
        GXBegin(GX_QUADS, GX_VTXFMT4, 4);
        for (vertexIndex = 0; vertexIndex < 4; vertexIndex++)
        {
            f32 px = scaleFactor * __OSs16tof32(&vtxStream[0]);
            f32 py = scaleFactor * __OSs16tof32(&vtxStream[1]);
            f32 pz = scaleFactor * __OSs16tof32(&vtxStream[2]);
            f32 outX, outY, outZ;
            f32 ax, ay;
            f32 ay_cosB, pz_sinB;
            if ((slot->renderFlags & (EXPGFX_RENDER_PHASE_ROTATE_A | EXPGFX_RENDER_PHASE_ROTATE_B)) != 0)
            {
                f32 nx = px * cosC - py * sinC;
                f32 ny = px * sinC + py * cosC;
                ay_cosB = ny * cosB;
                pz_sinB = pz * sinB;
                outX = sx + (cosA * ay_cosB + nx * sinA + cosA * pz_sinB);
                outY = sy + (ny * sinB + (-pz) * cosB);
                outZ = sz + (sinA * ay_cosB + (-nx) * cosA + sinA * pz_sinB);
            }
            else
            {
                ay_cosB = py * cosB;
                pz_sinB = pz * sinB;
                outX = sx + (cosA * ay_cosB + px * sinA + cosA * pz_sinB);
                outY = sy + (py * sinB + (-pz) * cosB);
                outZ = sz + (sinA * ay_cosB + (-px) * cosA + sinA * pz_sinB);
            }
            viewProjW = ((f32*)viewMatrix)[8] * outX
                + ((f32*)viewMatrix)[9] * outY
                + ((f32*)viewMatrix)[10] * outZ
                + ((f32*)viewMatrix)[11];
            if (viewProjW > lbl_803DB790)
            {
                alpha = (int)((f32)(s32)alpha * ((-viewProjW) - lbl_803DF414) /
                    ((-lbl_803DB790) - lbl_803DF414));
            }
            *(volatile f32*)0xCC008000 = outX;
            *(volatile f32*)0xCC008000 = outY;
            *(volatile f32*)0xCC008000 = outZ;
            {
                u8 colorR = ((u8*)slot)[12];
                u8 colorG = ((u8*)slot)[13];
                u8 colorB = ((u8*)slot)[14];
                *(volatile u8*)0xCC008000 = colorR;
                *(volatile u8*)0xCC008000 = colorG;
                *(volatile u8*)0xCC008000 = colorB;
            }
            *(volatile u8*)0xCC008000 = alpha;
            {
                s16 texU = vtxStream[4];
                s16 texV = vtxStream[5];
                *(volatile s16*)0xCC008000 = texU;
                *(volatile s16*)0xCC008000 = texV;
            }
            vtxStream += 8;
        }

    next_slot:
        slotIndex++;
    }
    while (slotIndex < EXPGFX_SLOTS_PER_POOL);

    if (gExpgfxRenderResetPending != 0)
    {
        expgfx_updateResourceEntries(0);
        gExpgfxRenderResetPending = 0;
    }
}
#pragma optimization_level reset

void renderParticles(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    ExpgfxBounds* boundsTemplate;
    ExpgfxPoolSourcePosition* sourcePosition;
    s8* poolActiveCounts;
    u8* poolSourceModes;
    u8* poolBoundsTemplateIds;
    ExpgfxBounds* poolBounds;
    u32* poolSourceIds;
    register s16* poolSlotTypeIds;
    u32* slotPoolBases;
    int poolIndex;
    f32* currentMatrix;
    float queuePosition[3];

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
        if ((*poolActiveCounts != 0) &&
            (*poolSourceModes == EXPGFX_POOL_SOURCE_MODE_STANDALONE))
        {
            boundsTemplate = Expgfx_GetBoundsTemplate(*poolBoundsTemplateIds);
            if ((u8)frustumTestAabbWithPlaneOffsets((double)(poolBounds->minX - playerMapOffsetX),
                                                (double)(poolBounds->maxX - playerMapOffsetX),
                                                (double)poolBounds->minY, (double)poolBounds->maxY,
                                                (double)(poolBounds->minZ - playerMapOffsetZ),
                                                (double)(poolBounds->maxZ - playerMapOffsetZ),
                                                &boundsTemplate->minX) != 0)
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
                    queuePosition[0] =
                        lbl_803DF358 * (poolBounds->minX + poolBounds->maxX) - playerMapOffsetX;
                    queuePosition[1] = lbl_803DF358 * (poolBounds->minY + poolBounds->maxY);
                    queuePosition[2] =
                        lbl_803DF358 * (poolBounds->minZ + poolBounds->maxZ) - playerMapOffsetZ;
                }
                PSMTXMultVec((float (*)[4])currentMatrix, (Vec*)queuePosition, (Vec*)queuePosition);
                if (*poolSourceIds != 0)
                {
                    queuePosition[2] =
                        queuePosition[2] - (float)(*poolSlotTypeIds & EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK);
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
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

#pragma scheduling on
#pragma peephole on
void expgfx_free2(u32 sourceId)
{
    expgfx_free(sourceId);
    return;
}

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void expgfx_free(u32 sourceId)
{
    s8* poolActiveCounts;
    int slotIndex;
    ExpgfxTableEntry* tableEntry;
    u32* slotPoolBases;
    ExpgfxRuntimeDataLayout* runtime;
    int tableIndex;
    u32* poolSourceIds;
    int poolIndex;
    ExpgfxSlot* slot;

    runtime = EXPGFX_RUNTIME_DATA;
    if (sourceId == 0)
    {
        return;
    }

    poolIndex = 0;
    slotPoolBases = runtime->slotPoolBases;
    poolSourceIds = runtime->poolSourceIds;
    poolActiveCounts = runtime->poolActiveCounts;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        slot = (ExpgfxSlot*)*slotPoolBases;
        if (sourceId == *poolSourceIds)
        {
            for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
            {
                if (slot != NULL)
                {
                    tableEntry = (ExpgfxTableEntry*)((u8*)runtime->expTab +
                        (((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK) * 16);
                    if (tableEntry->sourceId == sourceId)
                    {
                        expgfxRemove(*slotPoolBases, poolIndex, slotIndex, 0, 1);
                    }
                }
                slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
                if (*poolActiveCounts == 0)
                {
                    gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
                }
            }
            *poolSourceIds = 0;
            gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
        }

        poolSourceIds++;
        slotPoolBases++;
        poolActiveCounts++;
        poolIndex++;
    }
}
#pragma dont_inline reset

#pragma opt_propagation off
void expgfx_resetAllPools(void)
{
    u32* slotPoolBases;
    u16* refCountPtr;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    s16* poolSlotTypeIds;
    u32* poolSourceIds;
    u8* poolFrameFlags;
    int resourceIndex;
    int poolIndex;
    ExpgfxResourceEntry* resourceEntry;
    ExpgfxTableEntry* tableEntry;
    ExpgfxStaticDataLayout* staticData;
    u32 activeBit;
    u32 inactiveBitMask;
    int tableIndex;
    ExpgfxRuntimeDataLayout* runtime;
    int slotIndex;
    ExpgfxSlot* slot;

    staticData = EXPGFX_STATIC_DATA;
    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotPoolBases = runtime->slotPoolBases;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSlotTypeIds = staticData->poolSlotTypeIds;
    poolSourceIds = runtime->poolSourceIds;
    poolFrameFlags = staticData->poolFrameFlags;

    while (poolIndex < EXPGFX_POOL_COUNT)
    {
        slot = (ExpgfxSlot*)*slotPoolBases;
        for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++)
        {
            activeBit = 1 << slotIndex;
            if ((activeBit & *poolActiveMasks) != 0)
            {
                if (((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource != 0)
                {
                    gExpgfxTextureFreeInProgress = 1;
                    textureFree((void*)((ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16))->resource);
                    gExpgfxTextureFreeInProgress = 0;
                }

                tableEntry = (ExpgfxTableEntry*)((u8*)runtime->expTab + Expgfx_GetSlotTableIndex(slot) * 16);
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
                {
                    u32 currentMaskValue = *poolActiveMasks;
                    inactiveBitMask = ~activeBit;
                    *poolActiveMasks = currentMaskValue & inactiveBitMask;
                }
            }

            slot = (ExpgfxSlot*)((u8*)slot + EXPGFX_SLOT_SIZE);
        }

        *poolActiveCounts = 0;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        *poolSourceIds = 0;
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
        DCFlushRange((void*)*slotPoolBases, EXPGFX_POOL_BYTES);

        slotPoolBases++;
        poolActiveMasks++;
        poolActiveCounts++;
        poolSlotTypeIds++;
        poolSourceIds++;
        poolFrameFlags++;
        poolIndex++;
    }

    resourceEntry = runtime->resourceTable;
    for (resourceIndex = 0; resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT; resourceEntry++,
         resourceIndex++)
    {
        s32 zero = 0;

        gExpgfxTextureFreeInProgress = 1;
        if (resourceEntry->resource != NULL)
        {
            textureFree(resourceEntry->resource);
        }
        gExpgfxTextureFreeInProgress = zero;
        resourceEntry->resource = (void*)zero;
        resourceEntry->resourceId = zero;
        resourceEntry->evictionScore = zero;
        resourceEntry->reserved = zero;
    }
}
#pragma opt_propagation reset

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
        if (frameValue >= lbl_803DF418)
        {
            gExpgfxFrameTimerA = lbl_803DF35C;
        }
        frameValue = gExpgfxFrameTimerB + frameStep;
        gExpgfxFrameTimerB = frameValue;
        if (frameValue >= lbl_803DF384)
        {
            gExpgfxFrameTimerB = lbl_803DF35C;
        }
        frameValue = gExpgfxFrameTimerC + frameStep;
        gExpgfxFrameTimerC = frameValue;
        if (frameValue >= lbl_803DF354)
        {
            gExpgfxFrameTimerC = lbl_803DF35C;
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

#pragma dont_inline on
int expgfx_addremove(ExpgfxSpawnConfig* config, int preferredPoolIndex, int slotType,
                     u8 boundsTemplateId)
{
    u32 behaviorFlags;
    ExpgfxSourceObject* attachedSource;
    ExpgfxResourceHandle* resourceHandle;
    ExpgfxRuntimeDataLayout* runtime;
    GameObject* playerObj;
    ExpgfxSlot* slot;
    s16 texS0 = 0;
    int expTabIndex;
    int attachedTableKey;
    u32 bit;
    u32 maskHighWord;
    u32 maskLowWord;
    u32 inverseBit;
    short poolIndex;
    short slotIndex;
    s16 texT1 = 0;
    int resourceTableIndex;
    s16 texT0 = 0;
    s16 texS1 = 0;
    f32 scaleVal;
    u8* poolSourceModesByte;
    u8 modeFlag;

    ExpgfxQuadVertex* quadVertices;

    runtime = EXPGFX_RUNTIME_DATA;
    poolIndex = 0;
    slotIndex = 0;
    texS1 = 0;
    texS0 = 0;
    texT0 = 0;
    texT1 = 0;
    if (getHudHiddenFrameCount() != 0)
    {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    if (expgfxGetSlot(&poolIndex, &slotIndex, (int)slotType,
                      preferredPoolIndex, (u32)(int)config->attachedSource)
        == EXPGFX_INVALID_POOL_INDEX)
    {
        return EXPGFX_INVALID_POOL_INDEX;
    }
    {
        int pi = poolIndex;

        if (pi < EXPGFX_POOL_COUNT)
        {
            runtime->poolSourceIds[pi] = (int)config->attachedSource;
        }
        if (pi < EXPGFX_POOL_COUNT &&
            (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0)
        {
            u8* mb = (u8*)runtime + (pi & 1) * 8;
            maskHighWord = *(u32*)(mb + 4112);
            maskLowWord = *(u32*)(mb + 4116);
            bit = 1 << (pi >> 1);
            maskHighWord = maskHighWord | (u32)((int)bit >> 0x1f);
            maskLowWord = maskLowWord | bit;
            *(u32*)(mb + 4116) = maskLowWord;
            *(u32*)(mb + 4112) = maskHighWord;
        }
        else
        {
            u8* mb = (u8*)runtime + (pi & 1) * 8;
            maskHighWord = *(u32*)(mb + 4112);
            maskLowWord = *(u32*)(mb + 4116);
            inverseBit = ~(u32)(1 << (pi >> 1));
            maskHighWord = maskHighWord & (u32)((int)inverseBit >> 0x1f);
            maskLowWord = maskLowWord & inverseBit;
            *(u32*)(mb + 4116) = maskLowWord;
            *(u32*)(mb + 4112) = maskHighWord;
        }
        slot = (ExpgfxSlot*)(runtime->slotPoolBases[pi] + slotIndex * EXPGFX_SLOT_SIZE);
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
        if (resourceHandle == NULL)
        {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        if (resourceHandle->refCount >= EXPGFX_REFCOUNT_OVERFLOW)
        {
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        resourceHandle->refCount++;
        resourceHandle->linkGroup = config->linkGroup;

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
            if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A) != 0 ||
                (behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0)
            {
                config->velocityX = config->velocityX + attachedSource->velocityX;
                config->velocityY = config->velocityY + attachedSource->velocityY;
                config->velocityZ = config->velocityZ + attachedSource->velocityZ;
            }
        }

        if (attachedSource != NULL)
        {
            attachedTableKey = attachedSource->attachedTableKey;
        }
        attachedSource = NULL;

        expTabIndex = expgfx_addToTable((u32)resourceHandle, (u32)attachedSource, attachedTableKey,
                                        config->texture.parts.textureId);
        if ((short)expTabIndex == EXPGFX_INVALID_TABLE_INDEX)
        {
            debugPrintf(sExpgfxInvalidTabIndex);
            expgfxRemove(runtime->slotPoolBases[poolIndex], poolIndex, slotIndex, 1, 1);
            return EXPGFX_INVALID_POOL_INDEX;
        }
        ((struct { u8 tableIndex : 7; u8 lowBit : 1; }*)&slot->encodedTableIndex)->tableIndex = (u8)expTabIndex;

        slot->posX.value = config->startPosX.value;
        slot->startPosX.value = config->startPosX.value;
        slot->posY.value = config->startPosY.value;
        slot->startPosY.value = config->startPosY.value;
        slot->posZ.value = config->startPosZ.value;
        slot->startPosZ.value = config->startPosZ.value;
        slot->velocityX = config->velocityX;
        slot->velocityY = config->velocityY;
        slot->velocityZ = config->velocityZ;
        slot->initialAlpha = config->initialAlpha;
        quadVertices[3].pad06 = config->quadVertex3Pad06;
        slot->lifetimeFrame = config->lifetimeFrames;
        slot->lifetimeFrameLimit = config->lifetimeFrames;

        if (config->scale > lbl_803DF354)
        {
            debugPrintf(sExpgfxScaleOverflow);
        }
        scaleVal = lbl_803DF350 * config->scale;

        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0)
        {
            slot->scaleCurrent = 0;
            *(u16*)&slot->scaleStep =
            (scaleVal / (f32)(s32)
            slot->lifetimeFrameLimit
            )
            ;
            *(u16*)&slot->scaleTarget = scaleVal;
        }
        else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0)
        {
            *(u16*)&slot->scaleCurrent = scaleVal;
            *(u16*)&slot->scaleStep =
            (scaleVal / (f32)(s32)
            slot->lifetimeFrameLimit
            )
            ;
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
        slot->stateBits.bits.frameParity = gExpgfxFrameParityBit;

        if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0)
        {
            slot->renderFlags = slot->renderFlags ^ (EXPGFX_RENDER_BACKDATE_MOTION + 0LL);
            slot->posX.value = slot->velocityX * (lbl_803DF41C * (f32)(s32)
            slot->lifetimeFrame) + slot->posX.value;
            slot->posY.value = slot->velocityY * (lbl_803DF41C * (f32)(s32)
            slot->lifetimeFrame) + slot->posY.value;
            slot->posZ.value = slot->velocityZ * (lbl_803DF41C * (f32)(s32)
            slot->lifetimeFrame) + slot->posZ.value;
            slot->velocityX = slot->velocityX * lbl_803DF420;
            slot->velocityY = slot->velocityY * lbl_803DF420;
            slot->velocityZ = slot->velocityZ * lbl_803DF420;
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
                if (distSq < lbl_803DF424
                    && lbl_803DF35C != playerObj->anim.velocityX
                    && lbl_803DF35C != playerObj->anim.velocityZ)
                {
                    slot->velocityX = slot->velocityX + dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY = slot->velocityY +
                        ((lbl_803DF428 + playerObj->anim.worldPosY) - slot->startPosY.value) /
                        (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ = slot->velocityZ +
                        (playerObj->anim.worldPosZ - slot->startPosZ.value) /
                        (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            }
            else
            {
                dx = playerObj->anim.worldPosX -
                    (slot->startPosX.value + config->actorAimOffset.localOffsetX);
                dz = playerObj->anim.worldPosZ -
                    (slot->startPosZ.value + config->actorAimOffset.localOffsetZ);
                distSq = dx * dx + dz * dz;
                if (distSq < lbl_803DF424
                    && lbl_803DF35C != playerObj->anim.velocityX
                    && lbl_803DF35C != playerObj->anim.velocityZ)
                {
                    slot->velocityX = slot->velocityX - dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityY = slot->velocityY -
                        ((lbl_803DF428 + playerObj->anim.worldPosY) -
                            (slot->startPosY.value + config->actorAimOffset.localOffsetY)) /
                        (f32)(s32)((int)slot->lifetimeFrame << 1);
                    slot->velocityZ = slot->velocityZ -
                        (playerObj->anim.worldPosZ -
                            (slot->startPosZ.value + config->actorAimOffset.localOffsetZ)) /
                        (f32)(s32)((int)slot->lifetimeFrame << 1);
                }
            }
        }

        if (slotType == 1)
        {
            lbl_803DD270 = lbl_803DD270 + 1;
            lbl_803DD278 = lbl_803DD274 / lbl_803DD270;
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
            ExpgfxRuntimeDataLayout* poolModeBase =
                (ExpgfxRuntimeDataLayout*)((u8*)runtime + poolIndex);
            modeFlag = (config->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0 ? 1 : 0;
            poolModeBase->poolSourceModes[0] = modeFlag;
            if (poolModeBase->poolSourceModes[0] != 0 &&
                (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0)
            {
                poolModeBase->poolSourceModes[0] = poolModeBase->poolSourceModes[0] + 1;
            }
        }
        runtime->poolBoundsTemplateIds[poolIndex] = boundsTemplateId;

        DCFlushRange(slot, EXPGFX_SLOT_SIZE);
        gExpgfxLastAddedSlot = (int)slot;
        return slot->sequenceId;
    }
}
#pragma dont_inline reset

#pragma ppc_unroll_speculative off
#pragma ppc_unroll_factor_limit 1
#pragma ppc_unroll_instructions_limit 120
void expgfx_onMapSetup(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    ExpgfxResourceEntry* resourceEntry;
    ExpgfxTrackedSourceFrameMask* trackedFrameMasks;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    s16* poolSlotTypeIds;
    u8* poolFrameFlags;
    u8* poolSourceModes;
    u32* poolSourceIds;
    int poolIndex;
    int resourceIndex;

    runtime = EXPGFX_RUNTIME_DATA;
    expgfxRemoveAll();

    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    poolFrameFlags = gExpgfxStaticPoolFrameFlags;
    poolSourceModes = runtime->poolSourceModes;
    poolSourceIds = runtime->poolSourceIds;

    for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++)
    {
        *poolActiveMasks = 0;
        *poolActiveCounts = 0;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
        *poolSourceModes = EXPGFX_POOL_SOURCE_MODE_STANDALONE;
        *poolSourceIds = 0;

        poolActiveMasks++;
        poolActiveCounts++;
        poolSlotTypeIds++;
        poolFrameFlags++;
        poolSourceModes++;
        poolSourceIds++;
    }

    trackedFrameMasks = runtime->trackedSourceFrameMasks;
    trackedFrameMasks[0].lowWord = 0;
    trackedFrameMasks[0].highWord = 0;
    trackedFrameMasks[1].lowWord = 0;
    trackedFrameMasks[1].highWord = 0;

    gExpgfxTextureFreeInProgress = 1;
    resourceEntry = runtime->resourceTable;
    for (resourceIndex = 0; resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT; resourceEntry++,
         resourceIndex++)
    {
        if (resourceEntry->resource != NULL)
        {
            textureFree(resourceEntry->resource);
        }
        resourceEntry->resource = NULL;
        resourceEntry->resourceId = 0;
        resourceEntry->evictionScore = 0;
        resourceEntry->reserved = 0;
    }
    gExpgfxTextureFreeInProgress = 0;
}
#pragma ppc_unroll_speculative on
#pragma ppc_unroll_factor_limit 5
#pragma ppc_unroll_instructions_limit 120

void expgfx_release(void)
{
    int poolIndex;

    expgfxRemoveAll();
    poolIndex = 0;
    do
    {
        mm_free((void*)gExpgfxSlotPoolBases[poolIndex]);
        poolIndex = poolIndex + 1;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    return;
}

#pragma ppc_unroll_speculative off
#pragma ppc_unroll_factor_limit 1
#pragma ppc_unroll_instructions_limit 120
void expgfx_initialise(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    s16* poolSlotTypeIds;
    u32* slotPoolBases;
    int poolIndex;
    int groupCount;

    runtime = EXPGFX_RUNTIME_DATA;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    poolIndex = 0;
    for (groupCount = EXPGFX_POOL_GROUP_COUNT; groupCount != 0; groupCount--)
    {
        *poolActiveMasks = poolIndex;
        *poolActiveCounts = poolIndex;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[1] = poolIndex;
        poolActiveCounts[1] = poolIndex;
        poolSlotTypeIds[1] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[2] = poolIndex;
        poolActiveCounts[2] = poolIndex;
        poolSlotTypeIds[2] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[3] = poolIndex;
        poolActiveCounts[3] = poolIndex;
        poolSlotTypeIds[3] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[4] = poolIndex;
        poolActiveCounts[4] = poolIndex;
        poolSlotTypeIds[4] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[5] = poolIndex;
        poolActiveCounts[5] = poolIndex;
        poolSlotTypeIds[5] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[6] = poolIndex;
        poolActiveCounts[6] = poolIndex;
        poolSlotTypeIds[6] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[7] = poolIndex;
        poolActiveCounts[7] = poolIndex;
        poolSlotTypeIds[7] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks += 8;
        poolActiveCounts += 8;
        poolSlotTypeIds += 8;
    }

    slotPoolBases = runtime->slotPoolBases;
    do
    {
        *slotPoolBases = (u32)mmAlloc(EXPGFX_POOL_BYTES, EXPGFX_POOL_ALLOC_HEAP, 0);
        memset((void*)*slotPoolBases, 0, EXPGFX_POOL_BYTES);
        DCFlushRange((void*)*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases++;
        poolIndex++;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    memset(runtime->expTab, 0, EXPGFX_EXPTAB_BYTES);
    return;
}
#pragma ppc_unroll_speculative on
#pragma ppc_unroll_factor_limit 5
#pragma ppc_unroll_instructions_limit 120
