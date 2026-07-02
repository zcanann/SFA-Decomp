/*
 * effect9 (DLL 0x22) - particle / model-graphics effects support DLL.
 *
 * Three subsystems share this object:
 *  - modgfx: per-vertex animation of an active model effect. Double-buffered
 *    vertex tables (active/inactive) drive texcoord scrolling, RGB/alpha/scale
 *    blends and rotation/position stepping over a frame countdown
 *    (modgfx_* functions). modgfx_alloc/releaseExpgfxPools own the expgfx slot
 *    pools (EXPGFX_POOL_COUNT) and the active-effect registry
 *    (MODGFX_ACTIVE_EFFECT_COUNT entries).
 *  - projgfx: an ObjectDescriptor11 (projgfx_funcs) whose callbacks are mostly
 *    no-ops; the spawner-side lives in projgfx_spawnPresetEffect, a switch over
 *    preset effect ids 0x422-0x42d (decimal 1058-1069) that fills an
 *    ExpgfxSpawnConfig (random
 *    velocity/scale/lifetime/color per preset) and hands it to
 *    gExpgfxInterface->spawnEffect.
 *  - Effect9: preset-effect spawner (Effect9_func04, switch over effectId-949)
 *    plus a per-frame animation tick (Effect9_func05).
 */
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/dll/DR/dr_shared.h"

STATIC_ASSERT(offsetof(ModgfxState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(ModgfxState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(ModgfxState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(ModgfxState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(ModgfxState, posCurX) == 0x60);
STATIC_ASSERT(offsetof(ModgfxState, activeChannel) == 0xFC);
STATIC_ASSERT(offsetof(ModgfxState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(ModgfxState, rotOffsetZ) == 0x106);

static inline int* Modgfx_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32
#define PARTFX_STAGE_COUNT 7

STATIC_ASSERT(sizeof(ModgfxSpawnContext) == 0x60);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, vecX) == 0x20);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, posX) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, sequenceParams) == 0x46);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, flags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, pendingSpawnCount) == 0x5D);

typedef struct PartfxEffectState
{
    void* instanceObject;
    void* sourceObject;
    void* auxSequenceBuffer;
    s16 sourceRotX;
    s16 sourceRotY;
    s16 sourceRotZ;
    f32 sourceScale;
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 posStepX;
    f32 posStepY;
    f32 posStepZ;
    ModgfxScaleChannel scaleChannels[2];
    f32 drawPosX;
    f32 drawPosY;
    f32 drawPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* vertexBuffers[3];
    void* colorBuffers[3];
    void* baseVertexBuffer;
    void* baseColorBuffer;
    void* textureResource;
    void* emitterCommands;
    void* auxAllocation;
    u32 flags;
    s32 initialDelayFrames;
    ModgfxAlphaChannel alphaChannels[2];
    f32 blendColorR;
    f32 blendColorG;
    f32 blendColorB;
    f32 blendColorStepR;
    f32 blendColorStepG;
    f32 blendColorStepB;
    f32 renderScale;
    u8 padD8[0xE6 - 0xD8];
    s16 soundHandle;
    u8 padE8[0xEA - 0xE8];
    s16 vertexCount;
    s16 colorVertexCount;
    s16 stageDurations[PARTFX_STAGE_COUNT];
    s16 currentStage;
    s16 stageFrameCountdown;
    u8 pad100[0x106 - 0x100];
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 sequenceId;
    s16 nextStage;
    s16 stageTimer;
    u8 pad112[0x114 - 0x112];
    int unk114;
    int unk118;
    int unk11C;
    s16 vec120;
    s16 vec122;
    s16 vec124;
    s8 byte126;
    u8 pad127[0x12C - 0x127];
    void* inlineData;
    u8 activeVertexBufferIndex;
    u8 textureFrame;
    u8 textureFrameTimer;
    u8 textureFrameStep;
    u8 textureFrameFadeStep;
    s8 sourceYawIndex;
    u8 drawGroupCount;
    u8 drawGroupStride;
    u8 initialStateByte;
    s8 emitterCount;
    u8 releaseRequested;
    char unk13B;
    u8 requestedStage;
    u8 unk13D;
    u8 frameUpdated;
    u8 textureIsBorrowed;
} PartfxEffectState;

STATIC_ASSERT(sizeof(PartfxEffectState) == 0x140);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(PartfxEffectState, textureResource) == 0x98);
STATIC_ASSERT(offsetof(PartfxEffectState, flags) == 0xA4);
STATIC_ASSERT(offsetof(PartfxEffectState, drawPosX) == 0x60);
STATIC_ASSERT(offsetof(PartfxEffectState, velocityX) == 0x6C);
STATIC_ASSERT(offsetof(PartfxEffectState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(PartfxEffectState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(PartfxEffectState, renderScale) == 0xD4);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(PartfxEffectState, colorVertexCount) == 0xEC);
STATIC_ASSERT(offsetof(PartfxEffectState, stageDurations) == 0xEE);
STATIC_ASSERT(offsetof(PartfxEffectState, sequenceId) == 0x10C);
STATIC_ASSERT(offsetof(PartfxEffectState, inlineData) == 0x12C);
STATIC_ASSERT(offsetof(PartfxEffectState, activeVertexBufferIndex) == 0x130);
STATIC_ASSERT(offsetof(PartfxEffectState, emitterCount) == 0x139);
STATIC_ASSERT(offsetof(PartfxEffectState, textureIsBorrowed) == 0x13F);

#define gModgfxActiveEffectRegistry DAT_8039ce58

extern ModgfxActiveEffect*gModgfxActiveEffectRegistry[];

static ModgfxVertexData* modgfx_getActiveVertexBuffer(ModgfxState* state)
{
    return state->vertexBuffers[state->activeVertexBufferIndex];
}

static ModgfxVertexData* modgfx_getInactiveVertexBuffer(ModgfxState* state)
{
    return state->vertexBuffers[1 - state->activeVertexBufferIndex];
}

static ModgfxActiveEffect** modgfx_getActiveEffectRegistry(void)
{
    return gModgfxActiveEffectRegistry;
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-u8 spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */
extern ExpgfxSpawnConfig gExpgfxSpawnConfig;
extern f64 DOUBLE_803e00c0;
extern f64 DOUBLE_803e00c8;
extern f32 lbl_803DC450;
extern f32 lbl_803DC454;
extern f32 lbl_803DDF04;
extern f32 lbl_803E00B0;
extern f32 lbl_803E00B4;
extern f32 lbl_803E00B8;
extern f32 lbl_803E00BC;
extern f32 lbl_803E0900;
extern f32 lbl_803E0904;
extern f32 lbl_803E0908;
extern f32 lbl_803E090C;
extern f32 lbl_803E0910;
extern f32 lbl_803E0914;
extern f32 lbl_803E0918;
extern f32 lbl_803E091C;
extern f32 lbl_803E0920;
extern f32 lbl_803E0924;
extern f32 lbl_803E0928;
extern f32 lbl_803E092C;
extern f32 lbl_803E0930;
extern f32 lbl_803E0934;
extern f32 lbl_803E0938;
extern f32 lbl_803E093C;
extern f32 lbl_803E0940;
extern f32 lbl_803E0944;

void modgfx_releaseExpgfxPools(void)
{
    int poolIndex;
    u32* slotPoolBases;

    expgfxRemoveAll();
    poolIndex = 0;
    slotPoolBases = gExpgfxSlotPoolBases;
    do
    {
        FUN_80017814(*slotPoolBases);
        slotPoolBases = slotPoolBases + 1;
        poolIndex = poolIndex + 1;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
}

void modgfx_allocExpgfxPools(void)
{
    ExpgfxRuntimeDataLayout* runtime;
    s16* poolSlotTypeIds;
    u32 allocatedPool;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    int poolIndex;
    u32* slotPoolBases;
    int groupCount;

    runtime = EXPGFX_RUNTIME_DATA;
    poolActiveMasks = runtime->poolActiveMasks;
    poolActiveCounts = runtime->poolActiveCounts;
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    groupCount = EXPGFX_POOL_GROUP_COUNT;
    do
    {
        poolIndex = 0;
        *poolActiveMasks = 0;
        *poolActiveCounts = 0;
        *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[1] = 0;
        poolActiveCounts[1] = 0;
        poolSlotTypeIds[1] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[2] = 0;
        poolActiveCounts[2] = 0;
        poolSlotTypeIds[2] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[3] = 0;
        poolActiveCounts[3] = 0;
        poolSlotTypeIds[3] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[4] = 0;
        poolActiveCounts[4] = 0;
        poolSlotTypeIds[4] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[5] = 0;
        poolActiveCounts[5] = 0;
        poolSlotTypeIds[5] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[6] = 0;
        poolActiveCounts[6] = 0;
        poolSlotTypeIds[6] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks[7] = 0;
        poolActiveCounts[7] = 0;
        poolSlotTypeIds[7] = EXPGFX_INVALID_SLOT_TYPE;
        poolActiveMasks = poolActiveMasks + 8;
        poolActiveCounts = poolActiveCounts + 8;
        poolSlotTypeIds = poolSlotTypeIds + 8;
        groupCount = groupCount + -1;
    }
    while (groupCount != 0);
    slotPoolBases = gExpgfxSlotPoolBases;
    do
    {
        allocatedPool = FUN_80017830(EXPGFX_POOL_BYTES, 0x14);
        *slotPoolBases = allocatedPool;
        FUN_800033a8(*slotPoolBases, 0, EXPGFX_POOL_BYTES);
        FUN_802420e0(*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases = slotPoolBases + 1;
        poolIndex = poolIndex + 1;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    FUN_800033a8(-0x7fc63ec8, 0, 0x500);
}

void modgfx_initExpgfxSpawnConfig(u32 arg0, u32 arg1, u8 colorLowByte,
                                  u32 textureWord, u32 scaleBits)
{
    u32 setupWord;
    u16 setupValue;

    setupWord = FUN_80286840();
    FUN_800033a8((int)&gExpgfxSpawnConfig, 0, EXPGFX_SPAWN_CONFIG_PREFIX_BYTES);
    gExpgfxSpawnConfig.colorByte0.value = setupValue;
    gExpgfxSpawnConfig.behaviorFlags = setupValue & 0xff;
    gExpgfxSpawnConfig.velocityZ = lbl_803E00B0;
    gExpgfxSpawnConfig.startPosX.value = lbl_803E00B0;
    gExpgfxSpawnConfig.startPosY.value = lbl_803E00B0;
    gExpgfxSpawnConfig.sourcePosW.value = lbl_803E00B0;
    gExpgfxSpawnConfig.velocityX = lbl_803E00B0;
    gExpgfxSpawnConfig.velocityY = lbl_803E00B0;
    gExpgfxSpawnConfig.startPosZ.value = lbl_803E00B4;
    gExpgfxSpawnConfig.colorByte1.value = 0;
    gExpgfxSpawnConfig.colorByte1.lowByte = 0;
    gExpgfxSpawnConfig.quadVertex3Pad06 = setupWord;
    *(u32*)&gExpgfxSpawnConfig.scale = scaleBits;
    gExpgfxSpawnConfig.texture.word = textureWord;
    gExpgfxSpawnConfig.colorByte0.lowByte = colorLowByte;
    FUN_8028688c();
}

void modgfx_scrollVertexTexcoords(int stateArg, int command)
{
    ModgfxState* state;
    short coord;
    f32 stepS;
    f32 stepT;
    int i;
    ModgfxVertexData* activeVertexData;
    ModgfxVertexData* inactiveVertexData;
    u32 wrapCountS;
    u32 wrapCountT;

    state = (ModgfxState*)stateArg;
    stepS = lbl_803E00B8 * ((ModgfxVertexGroupCmd*)command)->valueX * lbl_803DDF04;
    stepT = lbl_803E00B8 * ((ModgfxVertexGroupCmd*)command)->valueY * lbl_803DDF04;
    activeVertexData = modgfx_getActiveVertexBuffer(state);
    inactiveVertexData = modgfx_getInactiveVertexBuffer(state);
    wrapCountS = 0;
    wrapCountT = 0;
    for (i = 0; i < state->vertexCount; i = i + 1)
    {
        activeVertexData->texCoordS = inactiveVertexData->texCoordS;
        activeVertexData->texCoordT = inactiveVertexData->texCoordT;
        activeVertexData->texCoordS = activeVertexData->texCoordS + (short)(int)stepS;
        if (0x100 < activeVertexData->texCoordS)
        {
            wrapCountS = wrapCountS + 1 & 0xff;
        }
        if (activeVertexData->texCoordS < -0x100)
        {
            wrapCountS = wrapCountS + 1 & 0xff;
        }
        activeVertexData->texCoordT = activeVertexData->texCoordT + (short)(int)stepT;
        if (0x100 < activeVertexData->texCoordT)
        {
            wrapCountT = wrapCountT + 1 & 0xff;
        }
        if (activeVertexData->texCoordT < -0x100)
        {
            wrapCountT = wrapCountT + 1 & 0xff;
        }
        activeVertexData = activeVertexData + 1;
        inactiveVertexData = inactiveVertexData + 1;
    }
    activeVertexData = modgfx_getActiveVertexBuffer(state);
    for (i = 0; i < state->vertexCount; i = i + 1)
    {
        if (wrapCountS == state->vertexCount)
        {
            coord = activeVertexData->texCoordS;
            if (coord < 0x101)
            {
                activeVertexData->texCoordS = coord + 0x100;
            }
            else
            {
                activeVertexData->texCoordS = coord + -0x100;
            }
        }
        if (wrapCountT == state->vertexCount)
        {
            coord = activeVertexData->texCoordT;
            if (coord < 0x101)
            {
                activeVertexData->texCoordT = coord + 0x100;
            }
            else
            {
                activeVertexData->texCoordT = coord + -0x100;
            }
        }
        activeVertexData = activeVertexData + 1;
    }
}

void modgfx_resetBaseVertexState(int stateArg)
{
    ModgfxState* state;
    f32 zero;
    f32 one;
    int i;
    ModgfxVertexData* baseVertexData;
    ModgfxVertexData* inactiveVertexData;

    state = (ModgfxState*)stateArg;
    inactiveVertexData = modgfx_getInactiveVertexBuffer(state);
    baseVertexData = state->baseVertexData;
    for (i = 0; one = lbl_803E00B4, i < state->vertexCount; i = i + 1)
    {
        baseVertexData->posX = inactiveVertexData->posX;
        baseVertexData->posY = inactiveVertexData->posY;
        baseVertexData->posZ = inactiveVertexData->posZ;
        baseVertexData->colorR = inactiveVertexData->colorR;
        baseVertexData->colorG = inactiveVertexData->colorG;
        baseVertexData->colorB = inactiveVertexData->colorB;
        baseVertexData->alpha = inactiveVertexData->alpha;
        baseVertexData = baseVertexData + 1;
        inactiveVertexData = inactiveVertexData + 1;
    }
    state->scaleChannels[0].cur[0] = lbl_803E00B4;
    state->scaleChannels[0].cur[1] = one;
    state->scaleChannels[0].cur[2] = one;
    zero = lbl_803E00B0;
    state->scaleChannels[0].step[0] = lbl_803E00B0;
    state->scaleChannels[0].step[1] = zero;
    state->scaleChannels[0].step[2] = zero;
    state->scaleChannels[1].cur[0] = one;
    state->scaleChannels[1].cur[1] = one;
    state->scaleChannels[1].cur[2] = one;
    state->scaleChannels[1].step[0] = zero;
    state->scaleChannels[1].step[1] = zero;
    state->scaleChannels[1].step[2] = zero;
}

void modgfx_updateVertexRgb(int state, int command, int mode)
{
    f32 targetR;
    f32 targetG;
    f32 targetB;
    f64 biasU;
    f64 biasS;
    int vtxData;
    int idxOff;
    int i;
    u64 convFrames;
    u64 convBlueBase;
    u64 convFrames2;

    biasU = DOUBLE_803e00c0;
    vtxData = *(int*)(state + (u32) * (u8*)(state + 0x130) * 4 + 0x78);
    if (mode == 1)
    {
        targetR = ((ModgfxVertexGroupCmd*)command)->valueX;
        targetG = ((ModgfxVertexGroupCmd*)command)->valueY;
        targetB = ((ModgfxVertexGroupCmd*)command)->valueZ;
        if (((ModgfxState*)state)->blendFrameCount == 0)
        {
            ((ModgfxState*)state)->blendColorR = targetR;
            ((ModgfxState*)state)->blendColorG = targetG;
            ((ModgfxState*)state)->blendColorB = targetB;
            targetR = lbl_803E00B0;
            ((ModgfxState*)state)->blendColorStepR = lbl_803E00B0;
            ((ModgfxState*)state)->blendColorStepG = targetR;
            ((ModgfxState*)state)->blendColorStepB = targetR;
        }
        else
        {
            ((ModgfxState*)state)->blendColorR =
                (f32)((f64)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xc));
            ((ModgfxState*)state)->blendColorG =
                (f32)((f64)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xd));
            ((ModgfxState*)state)->blendColorB =
                (f32)((f64)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xe));
            biasS = DOUBLE_803e00c8;
            ((ModgfxState*)state)->blendColorStepR =
                (targetR - (f32)((f64)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xc))) /
                (f32)((f64)(int)((ModgfxState*)state)->blendFrameCount);
            convFrames = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000)));
            ((ModgfxState*)state)->blendColorStepG =
                (targetG - (f32)((f64)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xd))) /
                (f32)(convFrames - biasS);
            convBlueBase = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10
                                                + 0xe))));
            convFrames2 = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000)));
            ((ModgfxState*)state)->blendColorStepB = (targetB - (f32)(convBlueBase - biasU)) / (f32)(convFrames2 -
                biasS);
        }
    }
    ((ModgfxState*)state)->blendColorR = ((ModgfxState*)state)->blendColorR + ((ModgfxState*)state)->blendColorStepR;
    ((ModgfxState*)state)->blendColorG = ((ModgfxState*)state)->blendColorG + ((ModgfxState*)state)->blendColorStepG;
    ((ModgfxState*)state)->blendColorB = ((ModgfxState*)state)->blendColorB + ((ModgfxState*)state)->blendColorStepB;
    if (lbl_803E00B0 <= ((ModgfxState*)state)->blendColorR)
    {
        if (lbl_803E00BC < ((ModgfxState*)state)->blendColorR)
        {
            ((ModgfxState*)state)->blendColorR = lbl_803E00BC;
        }
    }
    else
    {
        ((ModgfxState*)state)->blendColorR = lbl_803E00B0;
    }
    if (lbl_803E00B0 <= ((ModgfxState*)state)->blendColorG)
    {
        if (lbl_803E00BC < ((ModgfxState*)state)->blendColorG)
        {
            ((ModgfxState*)state)->blendColorG = lbl_803E00BC;
        }
    }
    else
    {
        ((ModgfxState*)state)->blendColorG = lbl_803E00B0;
    }
    if (lbl_803E00B0 <= ((ModgfxState*)state)->blendColorB)
    {
        if (lbl_803E00BC < ((ModgfxState*)state)->blendColorB)
        {
            ((ModgfxState*)state)->blendColorB = lbl_803E00BC;
        }
    }
    else
    {
        ((ModgfxState*)state)->blendColorB = lbl_803E00B0;
    }
    idxOff = 0;
    for (i = 0; i < ((ModgfxVertexGroupCmd*)command)->indexCount; i = i + 1)
    {
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xc) =
            (char)(int)((ModgfxState*)state)->blendColorR;
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xd) =
            (char)(int)((ModgfxState*)state)->blendColorG;
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xe) =
            (char)(int)((ModgfxState*)state)->blendColorB;
        idxOff = idxOff + 2;
    }
}

void modgfx_updateEffectPosition(int stateArg, int command, int mode)
{
    ModgfxState* state;
    f64 biasS;
    u16 rotAngle0;

    state = (ModgfxState*)stateArg;
    biasS = DOUBLE_803e00c8;
    if (mode == 1)
    {
        if (*(s16*)((u8*)state + state->activeChannel * 2 + 0xee) == 0)
        {
            if (((state->flags & 4) != 0) || ((state->flags & 0x80000) != 0))
            {
                rotAngle0 = *(u16*)state->unk04;
                FUN_80017748(&rotAngle0, (f32*)(command + 4));
            }
            *(u32*)&state->posStepX = *(u32*)(command + 4);
            *(u32*)&state->posStepY = *(u32*)&((ModgfxVertexGroupCmd*)command)->valueY;
            *(u32*)&state->posStepZ = *(u32*)&((ModgfxVertexGroupCmd*)command)->valueZ;
        }
        else
        {
            state->posStepX =
                *(f32*)(command + 4) /
                (f32)((f64)(int)state->blendFrameCount);
            state->posStepY =
                ((ModgfxVertexGroupCmd*)command)->valueY /
                (f32)((f64)(int)state->blendFrameCount
                );
            state->posStepZ =
                ((ModgfxVertexGroupCmd*)command)->valueZ /
                (f32)((f64)(int)state->blendFrameCount
                );
        }
        state->posCurX = state->posCurX + state->posStepX;
        state->posCurY = state->posCurY + state->posStepY;
        state->posCurZ = state->posCurZ + state->posStepZ;
    }
    else
    {
        state->posCurX =
            state->posStepX * lbl_803DDF04 + state->posCurX;
        state->posCurY =
            state->posStepY * lbl_803DDF04 + state->posCurY;
        state->posCurZ =
            state->posStepZ * lbl_803DDF04 + state->posCurZ;
    }
}

void modgfx_updateEffectRotation(int stateArg, int command, int mode)
{
    ModgfxState* state;
    short targetRotZ;
    short targetRotY;
    short targetRotX;

    state = (ModgfxState*)stateArg;
    if (mode == 1)
    {
        targetRotZ = (short)(int)((ModgfxVertexGroupCmd*)command)->valueX;
        targetRotY = (short)(int)((ModgfxVertexGroupCmd*)command)->valueY;
        targetRotX = (short)(int)((ModgfxVertexGroupCmd*)command)->valueZ;
        if (state->blendFrameCount == 0)
        {
            state->rotOffsetZ = targetRotZ;
            state->rotStepZ = 0;
            state->rotOffsetY = targetRotY;
            state->rotStepY = 0;
            state->rotOffsetX = targetRotX;
            state->rotStepX = 0;
        }
        else
        {
            state->rotStepZ =
                (short)(((int)targetRotZ - state->rotOffsetZ) / state->blendFrameCount
                );
            state->rotStepY =
                (short)(((int)targetRotY - state->rotOffsetY) / state->blendFrameCount
                );
            state->rotStepX =
                (short)(((int)targetRotX - state->rotOffsetX) / state->blendFrameCount
                );
        }
    }
    state->rotOffsetZ = state->rotOffsetZ + state->rotStepZ;
    state->rotOffsetY = state->rotOffsetY + state->rotStepY;
    state->rotOffsetX = state->rotOffsetX + state->rotStepX;
}

void modgfx_updateVertexAlpha(int state, int command, int mode, u32 channel)
{
    f32 targetAlpha;
    f64 biasU;
    int work0;
    int vtxOff;
    int curVtxData;
    int baseVtxData;
    int work1;
    int work2;
    u64 convAlphaBase;

    biasU = DOUBLE_803e00c0;
    curVtxData = *(int*)(state + (u32) * (u8*)(state + 0x130) * 4 + 0x78);
    baseVtxData = (int)((ModgfxState*)state)->baseVertexData;
    if (mode == 1)
    {
        targetAlpha = ((ModgfxVertexGroupCmd*)command)->valueX;
        if ((int)((ModgfxState*)state)->blendFrameCount == 0)
        {
            work1 = 0;
            for (work0 = 0; work0 < ((ModgfxVertexGroupCmd*)command)->indexCount; work0 = work0 + 1)
            {
                *(char*)(baseVtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 0xf) =
                    (char)(int)targetAlpha;
                work2 = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 0xf;
                *(u8*)(curVtxData + work2) = *(u8*)(baseVtxData + work2);
                work1 = work1 + 2;
            }
            return;
        }
        work1 = state + (channel & 0xff) * 8;
        *(f32*)(work1 + 0xac) =
            (targetAlpha - (f32)((f64)(u32) * (u8*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xf)))
            / (f32)((f64)(int)((ModgfxState*)state)->blendFrameCount);
        convAlphaBase = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((u32) * (u8*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->indices *
                                             0x10 + 0xf))));
        *(f32*)(work1 + 0xb0) = (f32)(convAlphaBase - biasU);
    }
    work1 = (channel & 0xff) * 8;
    work0 = state + work1;
    *(f32*)(work0 + 0xb0) = *(f32*)(work0 + 0xac) * lbl_803DDF04 + *(f32*)(work0 + 0xb0);
    if (lbl_803E00B0 <= *(f32*)(work0 + 0xb0))
    {
        if (lbl_803E00BC < *(f32*)(work0 + 0xb0))
        {
            *(f32*)(work0 + 0xb0) = lbl_803E00BC;
        }
    }
    else
    {
        *(f32*)(work0 + 0xb0) = lbl_803E00B0;
    }
    work0 = 0;
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2 = work2 + 1)
    {
        *(char*)(curVtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf) =
            (char)(int)*(f32*)(state + work1 + 0xb0);
        vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf;
        *(u8*)(baseVtxData + vtxOff) = *(u8*)(curVtxData + vtxOff);
        work0 = work0 + 2;
    }
}

void modgfx_updateVertexScale(int state, int command, int mode, u32 channel)
{
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f64 biasS;
    int work0;
    int work1;
    int vtxBufA;
    int work2;
    int vtxOff;
    int off;
    u64 convFrames;
    u64 convA;
    u64 convB;

    biasS = DOUBLE_803e00c8;
    if (mode == 1)
    {
        targetX = ((ModgfxVertexGroupCmd*)command)->valueX;
        targetY = ((ModgfxVertexGroupCmd*)command)->valueY;
        targetZ = ((ModgfxVertexGroupCmd*)command)->valueZ;
        if ((int)((ModgfxState*)state)->blendFrameCount == 0)
        {
            work2 = (int)((ModgfxState*)state)->baseVertexData;
            vtxBufA = *(int*)(state + (u32) * (u8*)(state + 0x130) * 4 + 0x78);
            work1 = 0;
            for (work0 = 0; work0 < ((ModgfxVertexGroupCmd*)command)->indexCount; work0 = work0 + 1)
            {
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10;
                *(short*)(work2 + off) =
                    (short)(int)((f32)((f64)(int)*(short*)(work2 + off)) * targetX);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 2;
                *(short*)(work2 + off) =
                    (short)(int)((f32)((f64)(int)*(short*)(work2 + off)) * targetY);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 4;
                convA = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)*(short*)(work2 + off) ^ 0x80000000)));
                *(short*)(work2 + off) = (short)(int)((f32)(convA - biasS) * targetZ);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10;
                *(u16*)(vtxBufA + off) = *(u16*)(work2 + off);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 2;
                *(u16*)(vtxBufA + off) = *(u16*)(work2 + off);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 4;
                *(u16*)(vtxBufA + off) = *(u16*)(work2 + off);
                work1 = work1 + 2;
            }
            return;
        }
        work1 = state + (channel & 0xff) * 0x18;
        *(f32*)(work1 + 0x3c) =
            (targetX - *(f32*)(work1 + 0x30)) /
            (f32)((f64)(int)((ModgfxState*)state)->blendFrameCount);
        convFrames = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000)));
        *(f32*)(work1 + 0x40) = (targetY - *(f32*)(work1 + 0x34)) / (f32)(convFrames - biasS);
        *(f32*)(work1 + 0x44) =
            (targetZ - *(f32*)(work1 + 0x38)) /
            (f32)((f64)(int)((ModgfxState*)state)->blendFrameCount);
    }
    work0 = state + (channel & 0xff) * 0x18;
    *(f32*)(work0 + 0x30) = *(f32*)(work0 + 0x3c) * lbl_803DDF04 + *(f32*)(work0 + 0x30);
    *(f32*)(work0 + 0x34) = *(f32*)(work0 + 0x40) * lbl_803DDF04 + *(f32*)(work0 + 0x34);
    *(f32*)(work0 + 0x38) = *(f32*)(work0 + 0x44) * lbl_803DDF04 + *(f32*)(work0 + 0x38);
    targetX = lbl_803E00B4;
    vtxBufA = (int)((ModgfxState*)state)->baseVertexData;
    work1 = *(int*)(state + (u32) * (u8*)(state + 0x130) * 4 + 0x78);
    off = 0;
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2 = work2 + 1)
    {
        if (targetX != *(f32*)(work0 + 0x30))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10;
            convB = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000)));
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(f32*)(work0 + 0x30) * (f32)(convB - DOUBLE_803e00c8));
        }
        if (targetX != *(f32*)(work0 + 0x34))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 2;
            convB = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000)));
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(f32*)(work0 + 0x34) * (f32)(convB - DOUBLE_803e00c8));
        }
        if (targetX != *(f32*)(work0 + 0x38))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 4;
            convB = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)((int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000)));
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(f32*)(work0 + 0x38) * (f32)(convB - DOUBLE_803e00c8));
        }
        off = off + 2;
    }
}

void modgfx_restoreActiveVertexState(int stateArg)
{
    ModgfxState* state;
    int i;
    ModgfxVertexData* activeVertexData;
    ModgfxVertexData* baseVertexData;

    state = (ModgfxState*)stateArg;
    activeVertexData = modgfx_getActiveVertexBuffer(state);
    baseVertexData = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i = i + 1)
    {
        activeVertexData->posX = baseVertexData->posX;
        activeVertexData->posY = baseVertexData->posY;
        activeVertexData->posZ = baseVertexData->posZ;
        activeVertexData->colorR = baseVertexData->colorR;
        activeVertexData->colorG = baseVertexData->colorG;
        activeVertexData->colorB = baseVertexData->colorB;
        activeVertexData->alpha = baseVertexData->alpha;
        activeVertexData = activeVertexData + 1;
        baseVertexData = baseVertexData + 1;
    }
}

void modgfx_releaseActiveEffectsByType(u64 argReg1, u64 argReg2, u64 argReg3,
                                       u64 argReg4, u64 argReg5, u64 argReg6,
                                       u64 argReg7, u64 argReg8, short effectType,
                                       int releaseAll)
{
    ModgfxActiveEffect* activeEffect;
    ModgfxActiveEffect** activeEffects;
    int i;

    activeEffects = modgfx_getActiveEffectRegistry();
    i = 0;
    do
    {
        activeEffect = activeEffects[i];
        if ((activeEffect != (ModgfxActiveEffect*)0x0) &&
            ((effectType == activeEffect->effectType || (releaseAll != 0))))
        {
            if (activeEffect->releaseTransformSource != 0)
            {
                argReg1 = FUN_80017814(activeEffect->releaseTransformSource);
            }
            if (activeEffect->instanceHandle != 0)
            {
                FUN_80017ac8(argReg1, argReg2, argReg3, argReg4, argReg5, argReg6, argReg7, argReg8,
                             activeEffect->instanceHandle);
            }
            activeEffect->state = 0;
            if ((activeEffect->keepSharedResource == 0) && (activeEffect->sharedResourceHandle != 0))
            {
                FUN_80053754();
            }
            if (activeEffect->keepSharedResource == 0)
            {
                activeEffect->sharedResourceHandle = 0;
            }
            argReg1 = FUN_80017814(activeEffect);
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
}

void modgfx_releaseActiveEffectsByOwner(u64 argReg1, u64 argReg2, u64 argReg3,
                                        u64 argReg4, u64 argReg5, u64 argReg6,
                                        u64 argReg7, u64 argReg8, int ownerToken)
{
    ModgfxActiveEffect* activeEffect;
    ModgfxActiveEffect** activeEffects;
    int i;

    activeEffects = modgfx_getActiveEffectRegistry();
    i = 0;
    do
    {
        activeEffect = activeEffects[i];
        if ((activeEffect != (ModgfxActiveEffect*)0x0) && (activeEffect->ownerToken == ownerToken))
        {
            if (activeEffect->instanceHandle != 0)
            {
                FUN_80017ac8(argReg1, argReg2, argReg3, argReg4, argReg5, argReg6, argReg7, argReg8,
                             activeEffect->instanceHandle);
            }
            activeEffect->state = 0;
            if ((activeEffect->keepSharedResource == 0) && (activeEffect->sharedResourceHandle != 0))
            {
                FUN_80053754();
            }
            if (activeEffect->keepSharedResource == 0)
            {
                activeEffect->sharedResourceHandle = 0;
            }
            argReg1 = FUN_80017814(activeEffect);
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
}

void modgfx_releaseAllActiveEffects(u64 argReg1, u64 argReg2, u64 argReg3,
                                    u64 argReg4, u64 argReg5, u64 argReg6,
                                    u64 argReg7, u64 argReg8)
{
    modgfx_releaseActiveEffectsByType(argReg1, argReg2, argReg3, argReg4, argReg5, argReg6, argReg7, argReg8,
                                      0, 1);
}

void modgfx_resetActiveEffectRegistry(u64 argReg1, u64 argReg2, u64 argReg3,
                                      u64 argReg4, u64 argReg5, u64 argReg6,
                                      u64 argReg7, u64 argReg8)
{
    ModgfxActiveEffect** activeEffects;
    int i;

    modgfx_releaseActiveEffectsByType(argReg1, argReg2, argReg3, argReg4, argReg5, argReg6, argReg7, argReg8,
                                      0, 1);
    activeEffects = modgfx_getActiveEffectRegistry();
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i = i + 1)
    {
        activeEffects[i] = (ModgfxActiveEffect*)0x0;
    }
    i = 2;
    {
        ModgfxActiveEffect** tailEffects;

        tailEffects = &activeEffects[MODGFX_ACTIVE_EFFECT_COUNT - 2];
        do
        {
            *tailEffects = (ModgfxActiveEffect*)0x0;
            tailEffects = tailEffects + 1;
            i = i + -1;
        }
        while (i != 0);
    }
}

u32
projgfx_spawnPresetEffect(int sourceObj, u32 effectId, ExpgfxAttachedSourceState* sourceState,
                          u32 spawnFlags, u8 modelId, u16* extraArgs)
{
    u32 spawnResult;
    u32 randPick;
    int cfgHead[3];
    u16 cfgSourceVecX;
    u16 cfgSourceVecY;
    u16 cfgSourceVecZ;
    u32 cfgSourcePosX;
    f32 cfgSourcePosY;
    f32 cfgSourcePosZ;
    f32 cfgSourcePosW;
    f32 cfgVelocityX;
    f32 cfgVelocityY;
    f32 cfgVelocityZ;
    f32 cfgStartPosX;
    f32 cfgStartPosY;
    f32 cfgStartPosZ;
    f32 cfgScale;
    u16 cfgTextureSetupFlags;
    u16 cfgTextureId;
    u32 cfgBehaviorFlags;
    u32 cfgRenderFlags;
    u32 cfgOverrideColor0;
    u32 cfgOverrideColor1;
    u32 cfgOverrideColor2;
    u16 cfgColorWord0;
    u16 cfgColorWord1;
    u16 cfgColorWord2;
    u8 cfgEffectIdByte;
    u8 cfgInitialAlpha;
    u8 cfgLinkGroup;
    u8 cfgModelIdByte;
    u32 convHi0;
    u32 randVal0;
    u32 convHi1;
    u32 randVal1;
    u32 convHi2;
    u32 randVal2;
    u32 convHi3;
    u32 randVal3;
    u32 convHi4;
    u32 randVal4;
    u32 convHi5;
    u32 randVal5;
    u32 convHi6;
    u32 randVal6;

    lbl_803DC450 = lbl_803DC450 + lbl_803E0900;
    if (lbl_803E0908 < lbl_803DC450)
    {
        lbl_803DC450 = lbl_803E0904;
    }
    lbl_803DC454 = lbl_803DC454 + lbl_803E090C;
    if (lbl_803E0908 < lbl_803DC454)
    {
        lbl_803DC454 = lbl_803E0910;
    }
    if (sourceObj == 0)
    {
        spawnResult = 0xffffffff;
    }
    else
    {
        if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
        {
            if (sourceState == (ExpgfxAttachedSourceState*)0x0)
            {
                return 0xffffffff;
            }
            cfgSourcePosY = sourceState->sourcePosY.value;
            cfgSourcePosZ = sourceState->sourcePosZ.value;
            cfgSourcePosW = sourceState->sourcePosW.value;
            cfgSourcePosX = sourceState->sourcePosX.bits;
            cfgSourceVecZ = sourceState->sourceVecZ;
            cfgSourceVecY = sourceState->sourceVecY;
            cfgSourceVecX = sourceState->sourceVecX;
            cfgModelIdByte = modelId;
        }
        cfgBehaviorFlags = 0;
        cfgRenderFlags = 0;
        cfgEffectIdByte = effectId;
        cfgStartPosX = lbl_803E0914;
        cfgStartPosY = lbl_803E0914;
        cfgStartPosZ = lbl_803E0914;
        cfgVelocityX = lbl_803E0914;
        cfgVelocityY = lbl_803E0914;
        cfgVelocityZ = lbl_803E0914;
        cfgScale = lbl_803E0914;
        cfgHead[2] = 0;
        cfgHead[1] = 0xffffffff;
        cfgInitialAlpha = 0xff;
        cfgLinkGroup = 0;
        cfgTextureId = 0;
        cfgColorWord0 = 0xffff;
        cfgColorWord1 = 0xffff;
        cfgColorWord2 = 0xffff;
        cfgOverrideColor0 = 0xffff;
        cfgOverrideColor1 = 0xffff;
        cfgOverrideColor2 = 0xffff;
        cfgTextureSetupFlags = 0;
        cfgHead[0] = sourceObj;
        switch (effectId)
        {
        case 0x422:
            if (extraArgs == 0x0)
            {
                return 0;
            }
            cfgScale = lbl_803E0918;
            cfgHead[2] = randomGetRange(10, 0xd);
            cfgInitialAlpha = (u8) * extraArgs;
            cfgBehaviorFlags = 0x80100;
            cfgTextureId = 100;
            cfgLinkGroup = 0x1e;
            break;
        case 0x423:
            randVal0 = randomGetRange(0xfffffff6, 10);
            cfgStartPosX = lbl_803E0910 * (f32)(s32)
            randVal0;
            randVal1 = randomGetRange(0xfffffff6, 10);
            cfgStartPosY = lbl_803E0910 * (f32)(s32)
            randVal1;
            randVal2 = randomGetRange(0xfffffff6, 10);
            cfgStartPosZ = lbl_803E0910 * (f32)(s32)
            randVal2;
            randVal3 = randomGetRange(5, 0xb);
            cfgScale = lbl_803E0900 * (f32)(s32)
            randVal3;
            cfgHead[2] = 0x3c;
            cfgBehaviorFlags = 0x80110;
            cfgLinkGroup = 0x10;
            cfgTextureId = 0xde;
            break;
        case 0x424:
            randVal3 = randomGetRange(0xfffffff6, 10);
            cfgStartPosX = lbl_803E0910 * (f32)(s32)
            randVal3;
            randVal2 = randomGetRange(0xfffffff6, 10);
            cfgStartPosY = lbl_803E0910 * (f32)(s32)
            randVal2;
            randVal1 = randomGetRange(0xfffffff6, 10);
            cfgStartPosZ = lbl_803E0910 * (f32)(s32)
            randVal1;
            randVal0 = randomGetRange(0xfffffffb, 5);
            cfgVelocityX = lbl_803E0904 * (f32)(s32)
            randVal0;
            randVal4 = randomGetRange(3, 10);
            cfgVelocityY = lbl_803E0904 * (f32)(s32)
            randVal4;
            randVal5 = randomGetRange(0xfffffffb, 5);
            cfgVelocityZ = lbl_803E0904 * (f32)(s32)
            randVal5;
            randVal6 = randomGetRange(5, 0xb);
            cfgScale = lbl_803E091C * (f32)(s32)
            randVal6;
            cfgHead[2] = 0x3c;
            cfgBehaviorFlags = 0x1480200;
            cfgLinkGroup = 0x10;
            cfgTextureId = 0xde;
            break;
        case 0x425:
            randVal6 = randomGetRange(8, 10);
            cfgVelocityY = lbl_803E0920 * (f32)(s32)
            randVal6;
            randPick = randomGetRange(0, 0x28);
            if (randPick == 0)
            {
                randVal6 = randomGetRange(0x15, 0x29);
                cfgScale = lbl_803E0900 *
                    (f32)(s32)
                randVal6;
                cfgHead[2] = 0x1cc;
            }
            else
            {
                randVal6 = randomGetRange(8, 0x14);
                cfgScale = lbl_803E0900 *
                    (f32)(s32)
                randVal6;
                cfgHead[2] = randomGetRange(0x5a, 0x78);
            }
            cfgBehaviorFlags = 0x80180200;
            cfgRenderFlags = 0x1000020;
            cfgTextureId = 0xc0b;
            cfgInitialAlpha = 0x7f;
            cfgColorWord2 = 0x3fff;
            cfgColorWord1 = 0x3fff;
            cfgColorWord0 = 0x3fff;
            cfgOverrideColor2 = 0xffff;
            cfgOverrideColor1 = 0xffff;
            cfgOverrideColor0 = 0xffff;
            break;
        case 0x426:
            randVal6 = randomGetRange(0xffffffec, 0x14);
            cfgVelocityX = lbl_803E0920 * (f32)(s32)
            randVal6;
            randVal5 = randomGetRange(8, 0x14);
            cfgVelocityY = lbl_803E0920 * (f32)(s32)
            randVal5;
            randVal4 = randomGetRange(0xffffffec, 0x14);
            cfgVelocityZ = lbl_803E0920 * (f32)(s32)
            randVal4;
            cfgScale = lbl_803E0924;
            cfgHead[2] = 0x32;
            cfgBehaviorFlags = 0x3000200;
            cfgRenderFlags = 0x200020;
            cfgTextureId = 0x33;
            cfgInitialAlpha = 0xff;
            cfgColorWord0 = 0xffff;
            cfgColorWord1 = 0xffff;
            cfgColorWord2 = 0xffff;
            cfgOverrideColor0 = 0xffff;
            cfgOverrideColor1 = randomGetRange(0, 0x8000);
            cfgOverrideColor2 = cfgOverrideColor1;
            break;
        case 0x427:
            randVal6 = randomGetRange(0xffffff9c, 100);
            cfgStartPosX = (f32)(s32)
            randVal6 / lbl_803E0928;
            randVal5 = randomGetRange(0xffffffce, 0x32);
            cfgStartPosY = (f32)(s32)
            randVal5 / lbl_803E092C;
            randVal4 = randomGetRange(0xffffff9c, 100);
            cfgStartPosZ = (f32)(s32)
            randVal4 / lbl_803E0928;
            randVal3 = randomGetRange(1, 4);
            cfgVelocityY = lbl_803E0930 * (f32)(s32)
            randVal3;
            randVal2 = randomGetRange(0, 10);
            cfgScale = lbl_803E0938 * (f32)(s32)
            randVal2
                + lbl_803E0934;
            cfgHead[2] = 0xa0;
            cfgLinkGroup = 0;
            cfgBehaviorFlags = 0x100200;
            cfgTextureId = 0x33;
            break;
        default:
            return 0xffffffff;
        case 0x42b:
            if (extraArgs == 0x0)
            {
                return 0;
            }
            cfgScale = lbl_803E093C;
            cfgHead[2] = randomGetRange(10, 0xd);
            cfgInitialAlpha = (u8) * extraArgs;
            cfgBehaviorFlags = 0x80100;
            cfgTextureId = 0xc7e;
            cfgLinkGroup = 0x1e;
            break;
        case 0x42c:
            randVal6 = randomGetRange(0xfffffff6, 10);
            cfgVelocityX = lbl_803E0940 * (f32)(s32)
            randVal6;
            randVal5 = randomGetRange(10, 0x14);
            cfgVelocityY = lbl_803E0918 * (f32)(s32)
            randVal5;
            randVal4 = randomGetRange(0xfffffff6, 10);
            cfgVelocityZ = lbl_803E0940 * (f32)(s32)
            randVal4;
            cfgScale = lbl_803E0944;
            cfgHead[2] = 0x6e;
            cfgBehaviorFlags = 0x8a100208;
            cfgRenderFlags = 0x20;
            cfgTextureId = 0x5f;
            cfgColorWord0 = 0xffff;
            cfgColorWord1 = 0xffff;
            cfgColorWord2 = 0xffff;
            cfgOverrideColor0 = 0x400;
            cfgOverrideColor1 = 60000;
            cfgOverrideColor2 = 0x1000;
            break;
        case 0x42d:
            randVal6 = randomGetRange(0xffffffec, 0x14);
            cfgVelocityX = lbl_803E0944 * (f32)(s32)
            randVal6;
            randVal5 = randomGetRange(0xffffffec, 0x14);
            cfgVelocityZ = lbl_803E0944 * (f32)(s32)
            randVal5;
            cfgScale = lbl_803E0904;
            cfgHead[2] = 600;
            cfgInitialAlpha = 0x7f;
            cfgBehaviorFlags = 0xa100100;
            cfgRenderFlags = 0x20;
            cfgTextureId = 0x62;
            cfgColorWord0 = 0x400;
            cfgColorWord1 = 60000;
            cfgColorWord2 = 0x1000;
            cfgOverrideColor0 = 0;
            cfgOverrideColor1 = 50000;
            cfgOverrideColor2 = 0;
        }
        cfgBehaviorFlags = cfgBehaviorFlags | spawnFlags;
        if (((cfgBehaviorFlags & 1) != 0) && ((cfgBehaviorFlags & 2) != 0))
        {
            cfgBehaviorFlags = cfgBehaviorFlags ^ 2;
        }
        if ((cfgBehaviorFlags & 1) != 0)
        {
            if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) == 0)
            {
                if (cfgHead[0] != 0)
                {
                    cfgStartPosX = cfgStartPosX + *(f32*)(cfgHead[0] + 0x18);
                    cfgStartPosY = cfgStartPosY + *(f32*)(cfgHead[0] + 0x1c);
                    cfgStartPosZ = cfgStartPosZ + *(f32*)(cfgHead[0] + 0x20);
                }
            }
            else
            {
                cfgStartPosX = cfgStartPosX + cfgSourcePosY;
                cfgStartPosY = cfgStartPosY + cfgSourcePosZ;
                cfgStartPosZ = cfgStartPosZ + cfgSourcePosW;
            }
        }
        spawnResult = (*gExpgfxInterface)->spawnEffect(cfgHead, -1, effectId, 0);
    }
    return spawnResult;
}

void Effect9_func03_nop(void)
{
}

void Effect9_release(void)
{
}

void Effect9_initialise(void)
{
}

ObjectDescriptor11 projgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    projgfx_initialise,
    (ObjectDescriptorCallback)projgfx_release_doUnsupported,
    0,
    projgfx_onMapSetup,
    (ObjectDescriptorCallback)projgfx_func04_ret_m1,
    (ObjectDescriptorCallback)projgfx_func05_nop,
    (ObjectDescriptorCallback)projgfx_func06_nop,
    (ObjectDescriptorCallback)projgfx_func07_nop,
    (ObjectDescriptorCallback)projgfx_getObjectTypeId,
    (ObjectDescriptorCallback)projgfx_setzscale_doUnsupported,
    (ObjectDescriptorCallback)projgfx_rayhit_doUnsupported,
};

char sProjgfxRayhitDoNoLongerSupported[] = "<projgfx rayhit Do>No Longer supported \n";
static u8 sProjgfxStringPad0[] = {0, 0, 0};
char sProjgfxSetzscaleDoNoLongerSupported[] = "<projgfx setzscale  Do>No Longer supported \n";
static u8 sProjgfxStringPad1[] = {0, 0, 0};
char sProjgfxReleaseDoNoLongerSupported[] = "<projgfx release Do>No Longer supported \n";
static u8 sProjgfxStringPad2[] = {0, 0, 0, 0, 0, 0};


extern f32 gEffect9PhaseC;
extern f32 gEffect9PhaseD;
extern int gEffect9SineAngleFast;
extern int gEffect9SineAngleSlow;
extern f32 gEffect9SineSlow;
extern f32 gEffect9SineFast;
extern f32 lbl_803DFE28;
extern f32 lbl_803DFE2C;
extern f32 lbl_803DFE38;
extern f32 gEffect9Pi;
extern f32 gEffect9SineAngleScale;
extern FxNode9 lbl_8039C398;
extern f32 gEffect9PhaseA;
extern f32 gEffect9PhaseB;
extern f32 lbl_803DFE34;
extern f32 lbl_803DFE40;
extern f32 lbl_803DFE44;
extern f32 lbl_803DFE48;
extern f32 lbl_803DFE4C;
extern f32 lbl_803DFE50;
extern f32 lbl_803DFE54;
extern f32 lbl_803DFE58;
extern f32 lbl_803DFE5C;
extern f32 lbl_803DFE60;
extern f32 lbl_803DFE64;
extern f32 lbl_803DFE68;
extern f32 lbl_803DFE6C;
extern f32 lbl_803DFE70;
extern f32 lbl_803DFE74;
extern f32 lbl_803DFE78;
extern f32 lbl_803DFE7C;
extern f32 lbl_803DFE80;
extern f32 lbl_803DFE84;
extern f32 lbl_803DFE88;
extern f32 lbl_803DFE8C;
extern f32 lbl_803DFE90;
extern f32 lbl_803DFE94;
extern f32 lbl_803DFE98;
extern f32 lbl_803DFE9C;
extern f32 lbl_803DFEA0;
extern f32 lbl_803DFEA4;

/*
 * FILL9 installs a zeroed default PartFxSpawnParams (lbl_8039C398) and points
 * spawnParams at it. It is only reached when spawnParams == 0, so the
 * immediately-following `if (spawnParams != 0)` is the non-null path (default
 * just installed) - not a contradiction.
 */
#define FILL9() do {                            \
    lbl_8039C398.posX = 0.0f;             \
    lbl_8039C398.posY = 0.0f;            \
    lbl_8039C398.posZ = 0.0f;            \
    lbl_8039C398.scale = 1.0f;             \
    lbl_8039C398.unk0 = 0;                         \
    lbl_8039C398.unk2 = 0;                         \
    lbl_8039C398.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C398;             \
  } while (0)

#pragma scheduling off
#pragma peephole off
int Effect9_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect9PhaseA = gEffect9PhaseA + lbl_803DFE28;
    if (gEffect9PhaseA > 1.0f) gEffect9PhaseA = lbl_803DFE2C;
    gEffect9PhaseB = gEffect9PhaseB + lbl_803DFE34;
    if (gEffect9PhaseB > 1.0f) gEffect9PhaseB = lbl_803DFE38;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = spawnParams->posX;
        cfg.sourcePosZ = spawnParams->posY;
        cfg.sourcePosW = spawnParams->posZ;
        cfg.sourcePosX = spawnParams->scale;
        cfg.sourceVecZ = spawnParams->rotZ;
        cfg.sourceVecY = spawnParams->rotY;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = 0.0f;
    cfg.startPosY = 0.0f;
    cfg.startPosZ = 0.0f;
    cfg.velocityX = 0.0f;
    cfg.velocityY = 0.0f;
    cfg.velocityZ = 0.0f;
    cfg.scale = 0.0f;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    cfg.textureSetupFlags = 0;
    switch (effectId)
    {
    case 950:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.startPosY = 0.0f;
        cfg.velocityY = lbl_803DFE40 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = lbl_803DFE44 * (f32)(s32)
        randomGetRange(6, 0xa);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xb1df;
        cfg.renderFlags = 0x20;
        break;
    case 949:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFE48 + (f32)(s32)
        randomGetRange(0x1e, 0x64);
        cfg.velocityX = lbl_803DFE4C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFE4C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFE50 * (f32)(s32)
        randomGetRange(0, 0x32);
        cfg.scale = lbl_803DFE54 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 955:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.scale = lbl_803DFE58;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8000201;
        cfg.textureId = 0x62;
        break;
    case 954:
        if (spawnParams == 0)
            FILL9();
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityY = lbl_803DFE5C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFE60;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 972:
        cfg.velocityX = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.velocityZ = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosX = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x1e;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xa5;
        cfg.behaviorFlags = 0x180108;
        cfg.scale = lbl_803DFE70 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.textureId = 0x167;
        break;
    case 971:
        cfg.scale = lbl_803DFE74;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 970:
        cfg.velocityX = lbl_803DFE78 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFE78 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.velocityZ = lbl_803DFE78 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0x64) + lbl_803DFE74;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 967:
        if (spawnParams != 0) cfg.startPosY = spawnParams->posY;
        cfg.scale = spawnParams != 0 ? lbl_803DFE7C * spawnParams->scale : lbl_803DFE80;
        cfg.lifetimeFrames = 0xf;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x80210;
        cfg.textureId = 0x4f9;
        cfg.linkGroup = 0x20;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = 0xff00;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x2000020;
        break;
    case 962:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.startPosY = 0.0f;
        cfg.scale = lbl_803DFE44 * (f32)(s32)
        randomGetRange(6, 0x14);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180108;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xb1df;
        cfg.renderFlags = 0x20;
        break;
    case 960:
    case 961:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.velocityZ = lbl_803DFE84 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DFE84 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DFE88;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x81000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26d;
        if ((int)randomGetRange(0, 3) == 3)
        {
            cfg.scale = lbl_803DFE8C * (f32)(s32)
            randomGetRange(1, 4);
            cfg.behaviorFlags |= 0x100100LL;
            cfg.textureId = 0x2b;
            cfg.initialAlpha = 0x9b;
            effectId = 0x3c1;
        }
        break;
    case 966:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = spawnParams->posX;
            cfg.velocityY = spawnParams->posY;
            cfg.velocityZ = spawnParams->posZ;
        }
        else
        {
            cfg.velocityX = lbl_803DFE28 * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.velocityY = lbl_803DFE74 * (f32)(s32)
            randomGetRange(5, 0x64);
            cfg.velocityZ = lbl_803DFE28 * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = 0.0f;
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 965:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100201;
        cfg.textureId = 0x60;
        break;
    case 964:
        if (spawnParams == 0)
            FILL9();
        cfg.lifetimeFrames = (s32)(lbl_803DFE48 * spawnParams->scale + lbl_803DFE90);
        cfg.scale = lbl_803DFE94 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xe100200;
        cfg.textureId = 0x57;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        break;
    case 963:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = spawnParams->posX;
            cfg.velocityY = spawnParams->posY;
            cfg.velocityZ = spawnParams->posZ;
        }
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFE74;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 969:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFE98 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = spawnParams != 0 ? spawnParams->posX : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosY;
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosX;
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosZ;
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 958:
        cfg.velocityY = lbl_803DFE9C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0x3c) + lbl_803DFE9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100201;
        cfg.textureId = 0x63;
        break;
    case 957:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE74 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFE78 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DFE74 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x96, 0x96);
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : lbl_803DFEA0;
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, -0xa) + cfg.startPosZ;
        cfg.scale = lbl_803DFEA4;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x108000e;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xbe;
        break;
    case 956:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFE28 * (f32)(s32)
        randomGetRange(0, 0x12c);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.scale = lbl_803DFE58 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x180108;
        cfg.textureId = 0x2b;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
#undef FILL9

void Effect9_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect9PhaseC + (step = lbl_803DFE28 * timeDelta);
    gEffect9PhaseC = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseC = lbl_803DFE2C;
    }
    sum = gEffect9PhaseD + step;
    gEffect9PhaseD = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseD = lbl_803DFE38;
    }
    gEffect9SineAngleFast = gEffect9SineAngleFast + framesThisStep * 0x64;
    if (gEffect9SineAngleFast > 0x7fff)
    {
        gEffect9SineAngleFast = 0;
    }
    gEffect9SineFast = mathSinf(gEffect9Pi * (f32)(s16)gEffect9SineAngleFast / gEffect9SineAngleScale);
    gEffect9SineAngleSlow = gEffect9SineAngleSlow + framesThisStep * 0x32;
    if (gEffect9SineAngleSlow > 0x7fff)
    {
        gEffect9SineAngleSlow = 0;
    }
    gEffect9SineSlow = mathSinf(gEffect9Pi * (f32)(s16)gEffect9SineAngleSlow / gEffect9SineAngleScale);
}
