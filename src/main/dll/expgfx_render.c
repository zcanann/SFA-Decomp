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

extern u16 gExpgfxPhaseAngleB;
extern u16 gExpgfxPhaseAngleA;
extern f32 gExpgfxFrameTimerC;
extern f32 gExpgfxFrameTimerB;
extern f32 gExpgfxFrameTimerA;
extern f32 gExpgfxNearFadeDepth;

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
    ExpgfxSourceObject* source;
    s16 signedPoolIndex;
    int result;
    ExpgfxSourceObject** poolSourceIds;
    int poolIndex;
    s64 frameBit;
    u8* frameFlags;
    source = sourceObject;
    result = EXPGFX_SOURCE_FRAME_STATE_NONE;
    lbl_803DD253 = 0;
    poolIndex = 0;
    poolSourceIds = gExpgfxTrackedPoolSourceIds;
    frameFlags = gExpgfxStaticPoolFrameFlags;

    for (; (s16)poolIndex < EXPGFX_POOL_COUNT; poolSourceIds++, frameFlags++, poolIndex++)
    {
        if ((source->objType == EXPGFX_SOURCE_OBJTYPE_MATCH_ALL) ||
            (poolSourceIds[0] == source))
        {
            signedPoolIndex = poolIndex;
            frameBit = 1 << (signedPoolIndex >> 1);
            if ((frameBit & gExpgfxTrackedSourceFrameMasks[signedPoolIndex & 1]) != 0)
            {
                frameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_B;
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
                frameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_A;
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
            frameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
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
    ExpgfxBillboardAngles angles;
    ExpgfxSlot* slot;
    ExpgfxTableEntry* tabBase;
    ExpgfxTableEntry* tabEntry;
    f32 sinB, cosB;
    int slotIndex;
    int alpha;
    ExpgfxSourceObject* sourceObject;
    u32 renderFlags;
    u32 stateBitsValue;
    CameraViewSlot* cameraSlot;
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
    f32 px, nx, py, pz, ny;
    Vec aimDelta;
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
    cameraSlot = Camera_GetCurrentViewSlot();
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

                angles.pitch = 0;
                angles.yaw = angles.pitch;
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
                        angles.pitch = 0;
                        if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A) != 0)
                        {
                            angles.yaw = angles.pitch;
                        }
                        else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH) != 0)
                        {
                            if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_SOURCE_OBJECT) != 0 && sourceObject != NULL)
                            {
                                aimDelta.x = cameraSlot->x - sourceObject->worldPosX;
                                aimDelta.y = cameraSlot->y - sourceObject->worldPosY;
                                aimDelta.z = cameraSlot->z - sourceObject->worldPosZ;
                                PSVECNormalize(&aimDelta, &aimDelta);
                                {
                                    f32 absX = __fabsf(aimDelta.x);
                                    f32 absZ = __fabsf(aimDelta.z);
                                    if (absX > absZ)
                                    {
                                        getAngle(absX, aimDelta.y);
                                        angles.pitch = (s16)(getAngle(absX, aimDelta.y) - 0x3800);
                                    }
                                    else
                                    {
                                        getAngle(absZ, aimDelta.y);
                                        angles.pitch = (s16)(getAngle(absZ, aimDelta.y) - 0x3800);
                                    }
                                    angles.yaw = (s16)getAngle(aimDelta.x, aimDelta.z);
                                }
                            }
                            else
                            {
                                angles.yaw = (s16)(0x10000 - cameraSlot->yaw);
                                angles.pitch = cameraSlot->pitch;
                            }
                        }
                        else
                        {
                            angles.yaw = (s16)(0x10000 - cameraSlot->yaw);
                        }
                    }
                }

                angleToVec2((u16)angles.yaw, &cosA, &sinA);
                angleToVec2((u16)angles.pitch, &cosB, &sinB);
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
                            Camera_ApplyEffectDepthViewport();
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
                        nx = px * cosC - py * sinC;
                        ny = px * sinC + py * cosC;
                        worldX = centerX + (nx * sinA + cosA * (ny * cosB) + cosA * (pz * sinB));
                        worldY = centerY + (ny * sinB + (-pz) * cosB);
                        worldZ = centerZ + ((-nx) * cosA + sinA * (ny * cosB) + sinA * (pz * sinB));
                    }
                    else
                    {
                        worldX = centerX + (px * sinA + cosA * (py * cosB) + cosA * (pz * sinB));
                        worldY = centerY + (py * sinB + (-pz) * cosB);
                        worldZ = centerZ + ((-px) * cosA + sinA * (py * cosB) + sinA * (pz * sinB));
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
            slot->velocityX *= -1.0f;
            slot->velocityY *= -1.0f;
            slot->velocityZ *= -1.0f;
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
