/*
 * partfx (DLL 0x000E) - the particle-effect spawn dispatcher.
 *
 * partfx_spawnObject is the central entry point: it maps an effect id to a
 * fully-populated Expgfx spawn request (cfg) and submits it through
 * gExpgfxInterface->spawnEffect. The big effect-id ranges at the top are
 * delegated to one of 20 lazily-acquired particle resource modules
 * (gPartfxResourceModuleNN, Resource_Acquire id 0x1a..0x2d); each delegation
 * arms a 2000-frame keep-alive in gPartfxResourceTimeouts[NN] and forwards the
 * call to the module's vtable slot 8. partfx_updateFrameState ticks the global
 * scroll/sin phases and decays those 20 timeouts, releasing a module once its
 * timeout expires; partfx_release frees them all. partfx_initialise zeroes the
 * timeout table and cached-module count.
 *
 * NOTE: the modgfx_* / projgfx_* / *ObjDescriptor content below is Ghidra
 * drift duplicated from sibling DLL units (modgfx, projgfx); it is not part of
 * this TU's matched symbol set - only the five partfx_* functions are.
 */
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/resource.h"
#include "main/sfa_shared_decls.h"

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
    int word114;
    int word118;
    int word11C;
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
    u8 byte13B;
    u8 requestedStage;
    u8 byte13D;
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
    return;
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
    return;
}

void modgfx_initExpgfxSpawnConfig(u32 unused1, u32 unused2, u8 colorLowByte,
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
    return;
}

void modgfx_scrollVertexTexcoords(int stateArg, int command)
{
    ModgfxState* state;
    short coord;
    float stepS;
    float stepT;
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
    return;
}

void modgfx_resetBaseVertexState(int stateArg)
{
    ModgfxState* state;
    float zero;
    float one;
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
    return;
}

void modgfx_updateVertexRgb(int state, int command, int mode)
{
    float targetR;
    float targetG;
    float targetB;
    double biasU;
    double biasS;
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
                (float)((double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xc));
            ((ModgfxState*)state)->blendColorG =
                (float)((double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xd));
            ((ModgfxState*)state)->blendColorB =
                (float)((double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xe));
            biasS = DOUBLE_803e00c8;
            ((ModgfxState*)state)->blendColorStepR =
                (targetR - (float)((double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xc))) /
                (float)((double)(int)((ModgfxState*)state)->blendFrameCount);
            convFrames = (double)(int)((ModgfxState*)state)->blendFrameCount;
            ((ModgfxState*)state)->blendColorStepG =
                (targetG - (float)((double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xd))) /
                (float)(convFrames);
            convBlueBase = (double)(u32) * (u8*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10
                                                + 0xe);
            convFrames2 = (double)(int)((ModgfxState*)state)->blendFrameCount;
            ((ModgfxState*)state)->blendColorStepB = (targetB - (float)(convBlueBase)) / (float)(convFrames2);
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
    return;
}

void modgfx_updateEffectPosition(int stateArg, int command, int mode)
{
    ModgfxState* state;
    double biasS;
    u16 rotAngle0;
    u16 unusedRot1;
    u16 unusedRot2;
    float unusedW;
    float unusedX;
    float unusedY;
    float unusedZ;

    state = (ModgfxState*)stateArg;
    biasS = DOUBLE_803e00c8;
    if (mode == 1)
    {
        if (*(s16*)((u8*)state + state->activeChannel * 2 + 0xee) == 0)
        {
            if (((state->flags & 4) != 0) || ((state->flags & 0x80000) != 0))
            {
                unusedX = lbl_803E00B0;
                unusedY = lbl_803E00B0;
                unusedZ = lbl_803E00B0;
                unusedW = lbl_803E00B4;
                rotAngle0 = *(u16*)state->unk04;
                unusedRot1 = rotAngle0;
                unusedRot2 = rotAngle0;
                FUN_80017748(&rotAngle0, (float*)(command + 4));
            }
            *(u32*)&state->posStepX = *(u32*)(command + 4);
            *(u32*)&state->posStepY = *(u32*)(command + 8);
            *(u32*)&state->posStepZ = *(u32*)(command + 0xc);
        }
        else
        {
            state->posStepX =
                *(float*)(command + 4) /
                (float)((double)(int)state->blendFrameCount);
            state->posStepY =
                ((ModgfxVertexGroupCmd*)command)->valueY /
                (float)((double)(int)state->blendFrameCount
                );
            state->posStepZ =
                ((ModgfxVertexGroupCmd*)command)->valueZ /
                (float)((double)(int)state->blendFrameCount
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
    return;
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
    return;
}

void modgfx_updateVertexAlpha(int state, int command, int mode, u32 channel)
{
    float targetAlpha;
    double biasU;
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
        *(float*)(work1 + 0xac) =
            (targetAlpha - (float)((double)(u32) * (u8*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xf)))
            / (float)((double)(int)((ModgfxState*)state)->blendFrameCount);
        convAlphaBase = (double)(u32) * (u8*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->indices *
                                             0x10 + 0xf);
        *(float*)(work1 + 0xb0) = (float)(convAlphaBase);
    }
    work1 = (channel & 0xff) * 8;
    work0 = state + work1;
    *(float*)(work0 + 0xb0) = *(float*)(work0 + 0xac) * lbl_803DDF04 + *(float*)(work0 + 0xb0);
    if (lbl_803E00B0 <= *(float*)(work0 + 0xb0))
    {
        if (lbl_803E00BC < *(float*)(work0 + 0xb0))
        {
            *(float*)(work0 + 0xb0) = lbl_803E00BC;
        }
    }
    else
    {
        *(float*)(work0 + 0xb0) = lbl_803E00B0;
    }
    work0 = 0;
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2 = work2 + 1)
    {
        *(char*)(curVtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf) =
            (char)(int)*(float*)(state + work1 + 0xb0);
        vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf;
        *(u8*)(baseVtxData + vtxOff) = *(u8*)(curVtxData + vtxOff);
        work0 = work0 + 2;
    }
    return;
}

void modgfx_updateVertexScale(int state, int command, int mode, u32 channel)
{
    float targetX;
    float targetY;
    float targetZ;
    double biasS;
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
                    (short)(int)((float)((double)(int)*(short*)(work2 + off)) * targetX);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 2;
                *(short*)(work2 + off) =
                    (short)(int)((float)((double)(int)*(short*)(work2 + off)) * targetY);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 4;
                convA = (double)(int)*(short*)(work2 + off);
                *(short*)(work2 + off) = (short)(int)((float)(convA) * targetZ);
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
        *(float*)(work1 + 0x3c) =
            (targetX - *(float*)(work1 + 0x30)) /
            (float)((double)(int)((ModgfxState*)state)->blendFrameCount);
        convFrames = (double)(int)((ModgfxState*)state)->blendFrameCount;
        *(float*)(work1 + 0x40) = (targetY - *(float*)(work1 + 0x34)) / (float)(convFrames);
        *(float*)(work1 + 0x44) =
            (targetZ - *(float*)(work1 + 0x38)) /
            (float)((double)(int)((ModgfxState*)state)->blendFrameCount);
    }
    work0 = state + (channel & 0xff) * 0x18;
    *(float*)(work0 + 0x30) = *(float*)(work0 + 0x3c) * lbl_803DDF04 + *(float*)(work0 + 0x30);
    *(float*)(work0 + 0x34) = *(float*)(work0 + 0x40) * lbl_803DDF04 + *(float*)(work0 + 0x34);
    *(float*)(work0 + 0x38) = *(float*)(work0 + 0x44) * lbl_803DDF04 + *(float*)(work0 + 0x38);
    targetX = lbl_803E00B4;
    vtxBufA = (int)((ModgfxState*)state)->baseVertexData;
    work1 = *(int*)(state + (u32) * (u8*)(state + 0x130) * 4 + 0x78);
    off = 0;
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2 = work2 + 1)
    {
        if (targetX != *(float*)(work0 + 0x30))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10;
            convB = (double)(int)*(short*)(vtxBufA + vtxOff);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x30) * (float)(convB));
        }
        if (targetX != *(float*)(work0 + 0x34))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 2;
            convB = (double)(int)*(short*)(vtxBufA + vtxOff);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x34) * (float)(convB));
        }
        if (targetX != *(float*)(work0 + 0x38))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 4;
            convB = (double)(int)*(short*)(vtxBufA + vtxOff);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x38) * (float)(convB));
        }
        off = off + 2;
    }
    return;
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
    return;
}

void modgfx_releaseActiveEffectsByType(u64 arg1, u64 arg2, u64 arg3,
                                       u64 arg4, u64 arg5, u64 arg6,
                                       u64 arg7, u64 arg8, short effectType,
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
                arg1 = FUN_80017814(activeEffect->releaseTransformSource);
            }
            if (activeEffect->instanceHandle != 0)
            {
                FUN_80017ac8(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
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
            arg1 = FUN_80017814(activeEffect);
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
}

void modgfx_releaseActiveEffectsByOwner(u64 arg1, u64 arg2, u64 arg3,
                                        u64 arg4, u64 arg5, u64 arg6,
                                        u64 arg7, u64 arg8, int ownerToken)
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
                FUN_80017ac8(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
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
            arg1 = FUN_80017814(activeEffect);
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
}

void modgfx_releaseAllActiveEffects(u64 arg1, u64 arg2, u64 arg3,
                                    u64 arg4, u64 arg5, u64 arg6,
                                    u64 arg7, u64 arg8)
{
    modgfx_releaseActiveEffectsByType(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                      0, 1);
    return;
}

void modgfx_resetActiveEffectRegistry(u64 arg1, u64 arg2, u64 arg3,
                                      u64 arg4, u64 arg5, u64 arg6,
                                      u64 arg7, u64 arg8)
{
    ModgfxActiveEffect** activeEffects;
    int i;

    modgfx_releaseActiveEffectsByType(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
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
    return;
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
    float cfgSourcePosY;
    float cfgSourcePosZ;
    float cfgSourcePosW;
    float cfgVelocityX;
    float cfgVelocityY;
    float cfgVelocityZ;
    float cfgStartPosX;
    float cfgStartPosY;
    float cfgStartPosZ;
    float cfgScale;
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
        cfgEffectIdByte = (u8)effectId;
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
            if (extraArgs == (u16*)0x0)
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
            if (extraArgs == (u16*)0x0)
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
                    cfgStartPosX = cfgStartPosX + *(float*)(cfgHead[0] + 0x18);
                    cfgStartPosY = cfgStartPosY + *(float*)(cfgHead[0] + 0x1c);
                    cfgStartPosZ = cfgStartPosZ + *(float*)(cfgHead[0] + 0x20);
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

void partfx_onMapSetup(void)
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

extern u8 gPartfxCachedResourceCount;
extern s16 gPartfxResourceTimeouts[];
extern f32 timeDelta;
extern u8 framesThisStep;

#pragma scheduling off
#pragma peephole off
void partfx_initialise(void)
{
    s16* p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0)
    {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    gPartfxCachedResourceCount = 0;
}
#pragma reset

extern void*gPartfxResourceModule00;
extern void*gPartfxResourceModule01;
extern void*gPartfxResourceModule02;
extern void*gPartfxResourceModule03;
extern void*gPartfxResourceModule04;
extern void*gPartfxResourceModule05;
extern void*gPartfxResourceModule16;
extern void*gPartfxResourceModule06;
extern void*gPartfxResourceModule07;
extern void*gPartfxResourceModule08;
extern void*gPartfxResourceModule09;
extern void*gPartfxResourceModule10;
extern void*gPartfxResourceModule11;
extern void*gPartfxResourceModule12;
extern void*gPartfxResourceModule13;
extern void*gPartfxResourceModule14;
extern void*gPartfxResourceModule15;
extern void*gPartfxResourceModule17;
extern void*gPartfxResourceModule18;
extern void*gPartfxResourceModule19;
extern f32 gPartfxFrameAnimPhase0;
extern f32 gPartfxFrameAnimPhase1;
extern f32 lbl_803DF4C8;
extern f32 lbl_803DF4CC;
extern f32 lbl_803DF4D0;
extern f32 lbl_803DF4D8;
extern s32 gPartfxOscAngle0;
extern s32 gPartfxOscAngle1;
extern f32 gPartfxOscSine1;
extern f32 gPartfxOscSine0;
extern f32 gPartfxPi;
extern f32 lbl_803DF71C;


/* EN v1.0 0x800AEC50  size: 1992b  tick global effect phases and expire
 * the 20 cached particle resource slots. */
void partfx_updateFrameState(void)
{
    gPartfxFrameAnimPhase0 = gPartfxFrameAnimPhase0 + lbl_803DF4C8 * timeDelta;
    if (gPartfxFrameAnimPhase0 > 1.0f)
    {
        gPartfxFrameAnimPhase0 = lbl_803DF4CC;
    }
    gPartfxFrameAnimPhase1 = gPartfxFrameAnimPhase1 + lbl_803DF4C8 * timeDelta;
    if (gPartfxFrameAnimPhase1 > *(f32*)&lbl_803DF4D0)
    {
        gPartfxFrameAnimPhase1 = lbl_803DF4D8;
    }
    gPartfxOscAngle0 = gPartfxOscAngle0 + framesThisStep * 100;
    if (gPartfxOscAngle0 > 0x7fff)
    {
        gPartfxOscAngle0 = 0;
    }
    gPartfxOscSine0 = mathSinf(gPartfxPi * (f32)(s16)gPartfxOscAngle0 / lbl_803DF71C);
    gPartfxOscAngle1 = gPartfxOscAngle1 + framesThisStep * 0x32;
    if (gPartfxOscAngle1 > 0x7fff)
    {
        gPartfxOscAngle1 = 0;
    }
    gPartfxOscSine1 = mathSinf(gPartfxPi * (f32)(s16)gPartfxOscAngle1 / lbl_803DF71C);
    if (gPartfxResourceTimeouts[0] != 0 && (gPartfxResourceTimeouts[0] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule00 != NULL) Resource_Release(gPartfxResourceModule00);
        gPartfxResourceModule00 = NULL;
        gPartfxResourceTimeouts[0] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[1] != 0 && (gPartfxResourceTimeouts[1] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule01 != NULL) Resource_Release(gPartfxResourceModule01);
        gPartfxResourceModule01 = NULL;
        gPartfxResourceTimeouts[1] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[2] != 0 && (gPartfxResourceTimeouts[2] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule02 != NULL) Resource_Release(gPartfxResourceModule02);
        gPartfxResourceModule02 = NULL;
        gPartfxResourceTimeouts[2] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[3] != 0 && (gPartfxResourceTimeouts[3] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule03 != NULL) Resource_Release(gPartfxResourceModule03);
        gPartfxResourceModule03 = NULL;
        gPartfxResourceTimeouts[3] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[4] != 0 && (gPartfxResourceTimeouts[4] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule04 != NULL) Resource_Release(gPartfxResourceModule04);
        gPartfxResourceModule04 = NULL;
        gPartfxResourceTimeouts[4] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[5] != 0 && (gPartfxResourceTimeouts[5] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule05 != NULL) Resource_Release(gPartfxResourceModule05);
        gPartfxResourceModule05 = NULL;
        gPartfxResourceTimeouts[5] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[16] != 0 && (gPartfxResourceTimeouts[16] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule16 != NULL) Resource_Release(gPartfxResourceModule16);
        gPartfxResourceModule16 = NULL;
        gPartfxResourceTimeouts[16] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[6] != 0 && (gPartfxResourceTimeouts[6] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule06 != NULL) Resource_Release(gPartfxResourceModule06);
        gPartfxResourceModule06 = NULL;
        gPartfxResourceTimeouts[6] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[7] != 0 && (gPartfxResourceTimeouts[7] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule07 != NULL) Resource_Release(gPartfxResourceModule07);
        gPartfxResourceModule07 = NULL;
        gPartfxResourceTimeouts[7] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[8] != 0 && (gPartfxResourceTimeouts[8] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule08 != NULL) Resource_Release(gPartfxResourceModule08);
        gPartfxResourceModule08 = NULL;
        gPartfxResourceTimeouts[8] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[9] != 0 && (gPartfxResourceTimeouts[9] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule09 != NULL) Resource_Release(gPartfxResourceModule09);
        gPartfxResourceModule09 = NULL;
        gPartfxResourceTimeouts[9] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[10] != 0 && (gPartfxResourceTimeouts[10] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule10 != NULL) Resource_Release(gPartfxResourceModule10);
        gPartfxResourceModule10 = NULL;
        gPartfxResourceTimeouts[10] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[11] != 0 && (gPartfxResourceTimeouts[11] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule11 != NULL) Resource_Release(gPartfxResourceModule11);
        gPartfxResourceModule11 = NULL;
        gPartfxResourceTimeouts[11] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[12] != 0 && (gPartfxResourceTimeouts[12] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule12 != NULL) Resource_Release(gPartfxResourceModule12);
        gPartfxResourceModule12 = NULL;
        gPartfxResourceTimeouts[12] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[13] != 0 && (gPartfxResourceTimeouts[13] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule13 != NULL) Resource_Release(gPartfxResourceModule13);
        gPartfxResourceModule13 = NULL;
        gPartfxResourceTimeouts[13] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[14] != 0 && (gPartfxResourceTimeouts[14] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule14 != NULL) Resource_Release(gPartfxResourceModule14);
        gPartfxResourceModule14 = NULL;
        gPartfxResourceTimeouts[14] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[15] != 0 && (gPartfxResourceTimeouts[15] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule15 != NULL) Resource_Release(gPartfxResourceModule15);
        gPartfxResourceModule15 = NULL;
        gPartfxResourceTimeouts[15] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[17] != 0 && (gPartfxResourceTimeouts[17] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule17 != NULL) Resource_Release(gPartfxResourceModule17);
        gPartfxResourceModule17 = NULL;
        gPartfxResourceTimeouts[17] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[18] != 0 && (gPartfxResourceTimeouts[18] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule18 != NULL) Resource_Release(gPartfxResourceModule18);
        gPartfxResourceModule18 = NULL;
        gPartfxResourceTimeouts[18] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[19] != 0 && (gPartfxResourceTimeouts[19] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule19 != NULL) Resource_Release(gPartfxResourceModule19);
        gPartfxResourceModule19 = NULL;
        gPartfxResourceTimeouts[19] = 0;
        gPartfxCachedResourceCount -= 1;
    }
}

/* EN v1.0 0x800AF41C  size: 560b  partfx_release: clear the 20-slot
 * effect-id table and free all 20 cached particle resources. */
void partfx_release(void)
{
    s16* p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0)
    {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    if (gPartfxResourceModule00 != NULL) Resource_Release(gPartfxResourceModule00);
    gPartfxResourceModule00 = NULL;
    if (gPartfxResourceModule01 != NULL) Resource_Release(gPartfxResourceModule01);
    gPartfxResourceModule01 = NULL;
    if (gPartfxResourceModule02 != NULL) Resource_Release(gPartfxResourceModule02);
    gPartfxResourceModule02 = NULL;
    if (gPartfxResourceModule03 != NULL) Resource_Release(gPartfxResourceModule03);
    gPartfxResourceModule03 = NULL;
    if (gPartfxResourceModule04 != NULL) Resource_Release(gPartfxResourceModule04);
    gPartfxResourceModule04 = NULL;
    if (gPartfxResourceModule05 != NULL) Resource_Release(gPartfxResourceModule05);
    gPartfxResourceModule05 = NULL;
    if (gPartfxResourceModule16 != NULL) Resource_Release(gPartfxResourceModule16);
    gPartfxResourceModule16 = NULL;
    if (gPartfxResourceModule06 != NULL) Resource_Release(gPartfxResourceModule06);
    gPartfxResourceModule06 = NULL;
    if (gPartfxResourceModule07 != NULL) Resource_Release(gPartfxResourceModule07);
    gPartfxResourceModule07 = NULL;
    if (gPartfxResourceModule08 != NULL) Resource_Release(gPartfxResourceModule08);
    gPartfxResourceModule08 = NULL;
    if (gPartfxResourceModule09 != NULL) Resource_Release(gPartfxResourceModule09);
    gPartfxResourceModule09 = NULL;
    if (gPartfxResourceModule10 != NULL) Resource_Release(gPartfxResourceModule10);
    gPartfxResourceModule10 = NULL;
    if (gPartfxResourceModule11 != NULL) Resource_Release(gPartfxResourceModule11);
    gPartfxResourceModule11 = NULL;
    if (gPartfxResourceModule12 != NULL) Resource_Release(gPartfxResourceModule12);
    gPartfxResourceModule12 = NULL;
    if (gPartfxResourceModule13 != NULL) Resource_Release(gPartfxResourceModule13);
    gPartfxResourceModule13 = NULL;
    if (gPartfxResourceModule14 != NULL) Resource_Release(gPartfxResourceModule14);
    gPartfxResourceModule14 = NULL;
    if (gPartfxResourceModule15 != NULL) Resource_Release(gPartfxResourceModule15);
    gPartfxResourceModule15 = NULL;
    if (gPartfxResourceModule17 != NULL) Resource_Release(gPartfxResourceModule17);
    gPartfxResourceModule17 = NULL;
    if (gPartfxResourceModule18 != NULL) Resource_Release(gPartfxResourceModule18);
    gPartfxResourceModule18 = NULL;
    if (gPartfxResourceModule19 != NULL) Resource_Release(gPartfxResourceModule19);
    gPartfxResourceModule19 = NULL;
    gPartfxCachedResourceCount = 0;
}

extern f32 gPartfxSpawnAnimPhase0;
extern f32 gPartfxSpawnAnimPhase1;
extern f32 lbl_803DF4D4;
extern f32 lbl_803DF4DC;
extern f32 lbl_803DF4E0;
extern f32 lbl_803DF4E4;
extern f32 lbl_803DF4E8;
extern f32 lbl_803DF4EC;
extern f32 lbl_803DF4F0;
extern f32 lbl_803DF4F4;
extern f32 lbl_803DF4F8;
extern f32 lbl_803DF4FC;
extern f32 lbl_803DF500;
extern f32 lbl_803DF504;
extern f32 lbl_803DF508;
extern f32 lbl_803DF50C;
extern f32 lbl_803DF510;
extern f32 lbl_803DF514;
extern f32 lbl_803DF518;
extern f32 lbl_803DF51C;
extern f32 lbl_803DF520;
extern f32 lbl_803DF524;
extern f32 lbl_803DF528;
extern f32 lbl_803DF52C;
extern f32 lbl_803DF530;
extern f32 lbl_803DF534;
extern f32 lbl_803DF538;
extern f32 lbl_803DF53C;
extern f32 lbl_803DF540;
extern f32 lbl_803DF544;
extern f32 gPartfxAlphaByteScale;
extern f32 lbl_803DF54C;
extern f32 lbl_803DF550;
extern f32 lbl_803DF554;
extern f32 lbl_803DF558;
extern f32 lbl_803DF55C;
extern f32 lbl_803DF560;
extern f32 lbl_803DF564;
extern f32 lbl_803DF568;
extern f32 lbl_803DF56C;
extern f32 lbl_803DF570;
extern f32 lbl_803DF574;
extern f32 lbl_803DF578;
extern f32 lbl_803DF57C;
extern f32 lbl_803DF580;
extern f32 lbl_803DF584;
extern f32 lbl_803DF588;
extern f32 lbl_803DF58C;
extern f32 lbl_803DF590;
extern f32 lbl_803DF594;
extern f32 lbl_803DF598;
extern f32 lbl_803DF59C;
extern f32 lbl_803DF5A0;
extern f32 lbl_803DF5A4;
extern f32 lbl_803DF5A8;
extern f32 lbl_803DF5AC;
extern f32 lbl_803DF5B0;
extern f32 lbl_803DF5B4;
extern f32 lbl_803DF5B8;
extern f32 lbl_803DF5BC;
extern f32 lbl_803DF5C0;
extern f32 lbl_803DF5C4;
extern f32 lbl_803DF5C8;
extern f32 lbl_803DF5CC;
extern f32 lbl_803DF5D0;
extern f32 lbl_803DF5D4;
extern f32 lbl_803DF5D8;
extern f32 lbl_803DF5DC;
extern f32 lbl_803DF5E0;
extern f32 lbl_803DF5E4;
extern f32 lbl_803DF5E8;
extern f32 lbl_803DF5EC;
extern double lbl_803DF5F0;
extern f32 lbl_803DF5F8;
extern f32 lbl_803DF5FC;
extern f32 lbl_803DF600;
extern f32 lbl_803DF604;
extern f32 lbl_803DF608;
extern f32 lbl_803DF60C;
extern f32 lbl_803DF610;
extern f32 lbl_803DF614;
extern f32 lbl_803DF618;
extern f32 lbl_803DF61C;
extern f32 lbl_803DF620;
extern f32 lbl_803DF624;
extern f32 lbl_803DF628;
extern f32 lbl_803DF62C;
extern f32 lbl_803DF630;
extern f32 lbl_803DF634;
extern f32 lbl_803DF638;
extern f32 lbl_803DF63C;
extern f32 lbl_803DF640;
extern f32 lbl_803DF644;
extern f32 lbl_803DF648;
extern f32 lbl_803DF64C;
extern f32 lbl_803DF650;
extern f32 lbl_803DF654;
extern f32 lbl_803DF658;
extern f32 lbl_803DF65C;
extern f32 lbl_803DF660;
extern f32 lbl_803DF664;
extern f32 lbl_803DF668;
extern f32 lbl_803DF66C;
extern f32 lbl_803DF670;
extern f32 lbl_803DF674;
extern f32 lbl_803DF678;
extern f32 lbl_803DF67C;
extern f32 lbl_803DF680;
extern f32 lbl_803DF684;
extern f32 lbl_803DF688;
extern f32 lbl_803DF68C;
extern f32 lbl_803DF690;
extern f32 lbl_803DF694;
extern f32 lbl_803DF698;
extern f32 lbl_803DF69C;
extern f32 lbl_803DF6A0;
extern f32 lbl_803DF6A4;
extern f32 lbl_803DF6A8;
extern f32 lbl_803DF6AC;
extern f32 lbl_803DF6B0;
extern f32 lbl_803DF6B4;
extern f32 lbl_803DF6B8;
extern f32 lbl_803DF6BC;
extern f32 lbl_803DF6C0;
extern f32 lbl_803DF6C4;
extern f32 lbl_803DF6C8;
extern f32 lbl_803DF6CC;
extern f32 lbl_803DF6D0;
extern f32 lbl_803DF6D4;
extern f32 lbl_803DF6D8;
extern f32 lbl_803DF6DC;
extern f32 lbl_803DF6E0;
extern f32 lbl_803DF6E4;
extern f32 lbl_803DF6E8;
extern f32 lbl_803DF6EC;
extern f32 lbl_803DF6F0;
extern f32 lbl_803DF6F4;
extern f32 lbl_803DF6F8;
extern f32 lbl_803DF6FC;
extern f32 lbl_803DF700;
extern f32 lbl_803DF704;
extern f32 lbl_803DF708;
extern s16 gPartfxResourceTimeouts[20];
extern PartFxSpawnParams gPartfxDefaultSpawnParams;

extern void vecRotateZXY(void* obj, f32* vec);
extern char sModgfxAlphaDebugFormat[];
extern void fn_80137948(char* fmt, ...);

int partfx_spawnObject(s16* sourceObj, u32 effectIdArg, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                       u32 modelIdArg, void* extraArgsArg)
{
    int modelId = modelIdArg;
    int effectId = effectIdArg;
    f32* extraArgs = extraArgsArg;
    f32* startPos;
    int intVal;
    s16 i;
    int variant;
    u32 variantU;
    f32 srcPosX;
    f32 srcPosY;
    f32 srcPosZ;
    f32 ftmp0;
    f32 ftmp1;
    f32 ftmp2;
    f32 ftmp3;
    f32 ftmp4;
    struct
    {
        s16 x, y, z;
        f32 m[4];
    } rot;
    PartFxSpawn cfg;

    if (((899 < effectId) && (effectId < 0x3b5)) || ((0x5dc < effectId && (effectId < 0x641))))
    {
        gPartfxResourceTimeouts[0] = 2000;
        if (gPartfxResourceModule00 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule00 = Resource_Acquire(0x1a, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule00 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x257 < effectId) && (effectId < 0x2bc))
    {
        gPartfxResourceTimeouts[1] = 2000;
        if (gPartfxResourceModule01 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule01 = Resource_Acquire(0x1b, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule01 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x1f3 < effectId) && (effectId < 0x258))
    {
        gPartfxResourceTimeouts[2] = 2000;
        if (gPartfxResourceModule02 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule02 = Resource_Acquire(0x1c, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule02 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x18f < effectId) && (effectId < 0x1f4))
    {
        gPartfxResourceTimeouts[3] = 2000;
        if (gPartfxResourceModule03 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule03 = Resource_Acquire(0x1d, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule03 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0xc7 < effectId) && (effectId < 0x12c))
    {
        gPartfxResourceTimeouts[4] = 2000;
        if (gPartfxResourceModule04 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule04 = Resource_Acquire(0x1e, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule04 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x419 < effectId) && (effectId < 0x44c))
    {
        gPartfxResourceTimeouts[5] = 2000;
        if (gPartfxResourceModule05 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule05 = Resource_Acquire(0x1f, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule05 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x739 < effectId) && (effectId < 0x76c))
    {
        gPartfxResourceTimeouts[16] = 2000;
        if (gPartfxResourceModule16 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule16 = Resource_Acquire(0x2a, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule16 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId - 0x84U <= 1) || ((0x89 < effectId && (effectId < 200))))
    {
        gPartfxResourceTimeouts[6] = 2000;
        if (gPartfxResourceModule06 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule06 = Resource_Acquire(0x20, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule06 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x3b5 < effectId) && (effectId < 0x3de))
    {
        gPartfxResourceTimeouts[8] = 2000;
        if (gPartfxResourceModule08 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule08 = Resource_Acquire(0x22, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule08 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x351 < effectId) && (effectId < 0x384))
    {
        gPartfxResourceTimeouts[7] = 2000;
        if (gPartfxResourceModule07 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule07 = Resource_Acquire(0x21, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule07 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x329 < effectId) && (effectId < 0x351))
    {
        gPartfxResourceTimeouts[9] = 2000;
        if (gPartfxResourceModule09 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule09 = Resource_Acquire(0x23, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule09 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x12b < effectId) && (effectId < 0x190))
    {
        gPartfxResourceTimeouts[10] = 2000;
        if (gPartfxResourceModule10 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule10 = Resource_Acquire(0x24, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule10 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x47d < effectId) && (effectId < 0x4b0))
    {
        gPartfxResourceTimeouts[11] = 2000;
        if (gPartfxResourceModule11 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule11 = Resource_Acquire(0x25, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule11 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x4af < effectId) && (effectId < 0x4e2))
    {
        gPartfxResourceTimeouts[12] = 2000;
        if (gPartfxResourceModule12 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule12 = Resource_Acquire(0x27, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule12 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId >= 0x3e8) && (effectId <= 0x419))
    {
        gPartfxResourceTimeouts[13] = 2000;
        if (gPartfxResourceModule13 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule13 = Resource_Acquire(0x28, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule13 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((0x44b < effectId) && (effectId < 0x47e))
    {
        gPartfxResourceTimeouts[14] = 2000;
        if (gPartfxResourceModule14 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule14 = Resource_Acquire(0x26, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule14 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId >= 0x6d7) && (effectId <= 0x707))
    {
        gPartfxResourceTimeouts[15] = 2000;
        if (gPartfxResourceModule15 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule15 = Resource_Acquire(0x29, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule15 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId >= 0x708) && (effectId <= 0x739))
    {
        gPartfxResourceTimeouts[17] = 2000;
        if (gPartfxResourceModule17 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule17 = Resource_Acquire(0x2b, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule17 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId >= 0x76c) && (effectId <= 0x79d))
    {
        gPartfxResourceTimeouts[18] = 2000;
        if (gPartfxResourceModule18 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule18 = Resource_Acquire(0x2c, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule18 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    if ((effectId >= 0x79e) && (effectId <= 0x833))
    {
        gPartfxResourceTimeouts[19] = 2000;
        if (gPartfxResourceModule19 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule19 = Resource_Acquire(0x2d, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule19 + 8))(sourceObj, effectIdArg, spawnParams, spawnFlags,
                                                                   modelIdArg, extraArgsArg);
    }
    gPartfxSpawnAnimPhase0 = gPartfxSpawnAnimPhase0 + lbl_803DF4C8;
    if (gPartfxSpawnAnimPhase0 > 1.0f)
    {
        gPartfxSpawnAnimPhase0 = lbl_803DF4CC;
    }
    gPartfxSpawnAnimPhase1 = gPartfxSpawnAnimPhase1 + lbl_803DF4D4;
    if (gPartfxSpawnAnimPhase1 > 1.0f)
    {
        gPartfxSpawnAnimPhase1 = lbl_803DF4D8;
    }
    if (sourceObj == NULL)
    {
        return -1;
    }
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.sourcePosY = spawnParams->posX;
        cfg.sourcePosZ = spawnParams->posY;
        cfg.sourcePosW = spawnParams->posZ;
        cfg.sourcePosX = spawnParams->scale;
        cfg.sourceVecZ = spawnParams->rotZ;
        cfg.sourceVecY = spawnParams->rotY;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.modelIdByte = modelId;
    }
    variant = '\0';
    cfg.behaviorFlags = 0x0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = effectId;
    startPos = &cfg.startPosX;
    cfg.startPosX = lbl_803DF4DC;
    cfg.startPosY = lbl_803DF4DC;
    cfg.startPosZ = lbl_803DF4DC;
    cfg.velocityX = lbl_803DF4DC;
    cfg.velocityY = lbl_803DF4DC;
    cfg.velocityZ = lbl_803DF4DC;
    cfg.scale = lbl_803DF4DC;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = 0xffffffff;
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
    cfg.attachedSource = sourceObj;
    switch (effectId)
    {
    case 0x5e:

        cfg.scale = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x80180000;
        cfg.textureId = 0x60;
        if (extraArgs != NULL)
        {
            cfg.colorWord0 = ((u16*)extraArgs)[3];
            cfg.colorWord1 = ((u16*)extraArgs)[4];
            cfg.colorWord2 = ((u16*)extraArgs)[5];
            cfg.overrideColor0 = (u32)((u16*)extraArgs)[0];
            cfg.overrideColor1 = (u32)((u16*)extraArgs)[1];
            cfg.overrideColor2 = (u32)((u16*)extraArgs)[2];
        }
        cfg.renderFlags = 0x8400820;
        break;
    case 0x5f:
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x80000;
        cfg.textureId = 0x33;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.renderFlags = 0x8000820;
        break;
    case 0x60:

        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.scale = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.behaviorFlags = 0x80180202;
        cfg.textureId = 0x60;
        if (extraArgs != NULL)
        {
            cfg.colorWord0 = ((u16*)extraArgs)[0];
            cfg.colorWord1 = ((u16*)extraArgs)[1];
            cfg.colorWord2 = ((u16*)extraArgs)[2];
            cfg.lifetimeFrames = (u32)((u16*)extraArgs)[3];
        }
        else
        {
            cfg.colorWord0 = 0x2000;
            cfg.colorWord1 = 0x2000;
            cfg.colorWord2 = 0x2000;
            cfg.lifetimeFrames = 0x78;
        }
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.initialAlpha = 0x7f;
        cfg.renderFlags = 0x4080020;
        break;
    case 0x68c:

        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x1180200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = randomGetRange(0x8000, 0xffff);
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = randomGetRange(0, 0x8000);
        cfg.overrideColor2 = randomGetRange(0, 0xffff);
        cfg.renderFlags = 0x20;
        break;
    case 0x68d:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x1080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = randomGetRange(0, 0xffff);
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.renderFlags = 0x20;
        break;
    case 0x68e:
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x180208;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0x8000, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0xffff);
        cfg.overrideColor1 = randomGetRange(0, 0x8000);
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x68f:

        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x1080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x690:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff9, 7);
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = lbl_803DF4F4 * (f32)(s32)
        randomGetRange(0x14, 0x32);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x80208;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.renderFlags = 0x20;
        break;
    case 0x68b:
        if (spawnParams != NULL)
        {
            cfg.startPosX = spawnParams->posX - ((GameObject*)sourceObj)->anim.worldPosX;
            cfg.startPosZ = spawnParams->posZ - ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            (*startPos) = (f32)(s32)
            randomGetRange(0xfffffff9, 7);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(0xfffffff9, 7);
        }
        cfg.startPosY = lbl_803DF4F8;
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0, 0x32);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.scale = lbl_803DF4E8;
        if (spawnParams != NULL)
        {
            cfg.scale = spawnParams->scale;
        }
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x80080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x1000020;
        break;
    case 0x556:
        cfg.startPosY = lbl_803DF4FC;
        cfg.scale = lbl_803DF500;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
    LAB_800a69a8:
        cfg.startPosY = lbl_803DF4FC;
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
    LAB_800a6a18:
        cfg.startPosY = lbl_803DF4FC;
        cfg.scale = lbl_803DF504;
        cfg.lifetimeFrames = 0x2d;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100210;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        goto LAB_800a6a6c;
    case 0x55d:
        goto LAB_800aeb28;
    case 0x557:
    LAB_800a6a6c:
        cfg.startPosY = lbl_803DF4FC;
        if (extraArgs != NULL)
        {
            cfg.velocityY = lbl_803DF508;
        }
        else
        {
            cfg.velocityY = lbl_803DF50C;
        }
        cfg.scale = lbl_803DF510;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        goto LAB_800a6aec;
    case 0x558:

    LAB_800a6aec:
        cfg.startPosY = lbl_803DF4FC;
        if (extraArgs != NULL)
        {
            cfg.velocityY = lbl_803DF50C;
        }
        else
        {
            cfg.velocityY = lbl_803DF508;
        }
        cfg.scale = lbl_803DF510;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
    LAB_800a6b6c:
        cfg.startPosY = lbl_803DF4FC;
        if (extraArgs != NULL)
        {
            cfg.velocityY = lbl_803DF508;
        }
        else
        {
            cfg.velocityY = lbl_803DF50C;
        }
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        break;
    case 0x55b:
        cfg.startPosY = lbl_803DF4FC;
        if (extraArgs != NULL)
        {
            cfg.velocityY = lbl_803DF50C;
        }
        else
        {
            cfg.velocityY = lbl_803DF508;
        }
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        break;
    case 0x55e:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.startPosY = spawnParams->posY + (f32)(s32)
        randomGetRange(0xfffffffa, 6);
        cfg.velocityX = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803DF514;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400010;
        cfg.renderFlags = 0x400008;
        cfg.textureId = 0xe4;
        break;
    case 0x551:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = lbl_803DF518;
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x91;
        break;
    case 0x552:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = lbl_803DF518;
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0xa100210;
        cfg.textureId = 0x91;
        break;
    case 0x554:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = lbl_803DF518;
        cfg.scale = lbl_803DF51C;
        cfg.lifetimeFrames = 0x37;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0xa100210;
        cfg.textureId = 0x73;
        break;
    case 0x553:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityX = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF4EC * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = lbl_803DF518;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = 0;
        rot.y = 0;
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, startPos);
        cfg.scale = lbl_803DF520;
        cfg.lifetimeFrames = 0x91;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000010;
        cfg.renderFlags = 0x2600000;
        cfg.textureId = 0xe4;
        break;
    case 0x549:

        (*startPos) = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags = 0xc0480110;
        }
        cfg.textureId = 0x85;
        break;
    case 0x54a:
        (*startPos) = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags = 0xc0480110;
        }
        cfg.textureId = 0x84;
        break;
    case 0x54b:
        (*startPos) = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags = 0xc0480110;
        }
        cfg.textureId = 0xc0f;
        break;
    case 0x54c:

        (*startPos) = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags = 0xc0480110;
        }
        cfg.textureId = 0x157;
        break;
    case 0x54d:
        if (extraArgs == NULL)
        {
            variant = '\0';
        }
        else
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = lbl_803DF524 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = lbl_803DF528 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = lbl_803DF52C * (f32)(s32)
            randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x85;
        break;
    case 0x54e:
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = lbl_803DF524 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = lbl_803DF528 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = lbl_803DF52C * (f32)(s32)
            randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x84;
        break;
    case 0x54f:

        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = lbl_803DF524 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = lbl_803DF528 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = lbl_803DF52C * (f32)(s32)
            randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0xc0f;
        break;
    case 0x550:
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = lbl_803DF524 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = lbl_803DF528 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = lbl_803DF52C * (f32)(s32)
            randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x157;
        break;
    case 0x545:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.scale = lbl_803DF530 * spawnParams->scale;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 2;
        cfg.textureId = 0x527;
        cfg.initialAlpha = 0x69;
        break;
    case 0x546:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.scale = lbl_803DF534 * spawnParams->scale;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2000002;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0x73;
        break;
    case 0x547:
        cfg.startPosX = lbl_803DF538;
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffb0, 0x50);
        cfg.velocityY = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.scale = lbl_803DF53C;
        cfg.lifetimeFrames = 300;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x548;
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = lbl_803DF540;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x28;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = (cfg.behaviorFlags | 0x20000);
        break;
    case 0x548:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.scale = lbl_803DF544;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x80201;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0xff;
        break;
    case 0x52b:
    case 0x52c:
    case 0x52d:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            (*startPos) = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            (*startPos) = (*startPos) - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
        }
        if ((int)randomGetRange(0, 0x28) == 0)
        {
            cfg.scale = lbl_803DF4D4;
        }
        else
        {
            cfg.scale = lbl_803DF514;
        }
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.textureId = effectId + -0x3d5;
        break;
    case 0x52f:
    case 0x530:
    case 0x531:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            (*startPos) = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            (*startPos) = (*startPos) - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.velocityZ = lbl_803DF4D8;
        }
        cfg.scale = lbl_803DF514;
        cfg.lifetimeFrames = 100;
        break;
    case 0x53c:

        if (extraArgs != NULL)
        {
            intVal = (int)(gPartfxAlphaByteScale * (lbl_803DF4D0 - *extraArgs));
            cfg.initialAlpha = intVal;
            fn_80137948(sModgfxAlphaDebugFormat, intVal);
        }
        cfg.scale = lbl_803DF54C;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x2000002;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0xe4;
        break;
    case 0x53d:
        cfg.initialAlpha = 0x69;
        cfg.scale = lbl_803DF550;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4fe;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0xb1df;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.startPosZ = lbl_803DF554;
        cfg.initialAlpha = 0x69;
        cfg.scale = lbl_803DF558;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xb1df;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4ff;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.startPosZ = lbl_803DF55C;
        cfg.initialAlpha = 0x69;
        cfg.scale = lbl_803DF560;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4fe;
        break;
    case 0x53e:
        cfg.startPosX = lbl_803DF564;
        cfg.scale = lbl_803DF508;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 2;
        cfg.lifetimeFrames = 1;
        cfg.textureId = 100;
        break;
    case 0x53f:

        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF4CC;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 2;
        cfg.lifetimeFrames = 1;
        cfg.textureId = 0x156;
        break;
    case 0x532:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = lbl_803DF56C * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = sourceObj[2];
        rot.y = sourceObj[1];
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.initialAlpha = 0xcd;
        cfg.behaviorFlags = 0x100110;
        cfg.scale = lbl_803DF570 * (f32)(s32)
        randomGetRange(0x96, 200);
        cfg.lifetimeFrames = 0x28;
        cfg.textureId = 0x89;
        break;
    case 0x533:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(8, 10);
        cfg.velocityZ = lbl_803DF574 * (f32)(s32)
        randomGetRange(10, 0x1e);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = sourceObj[2];
        rot.y = sourceObj[1];
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.scale = lbl_803DF4D4 * (f32)(s32)
        randomGetRange(8, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x78);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x1400020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x3caf;
        cfg.overrideColor1 = 0x3caf;
        cfg.overrideColor2 = 0x3caf;
        break;
    case 0x535:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = lbl_803DF578 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = sourceObj[2];
        rot.y = sourceObj[1];
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF57C * (f32)(s32)
        randomGetRange(0x96, 200);
        cfg.behaviorFlags = 0x2000110;
        cfg.renderFlags = 0x2200000;
        cfg.lifetimeFrames = 0x19;
        cfg.textureId = 0x24;
        break;
    case 0x534:

        cfg.startPosY = lbl_803DF580;
        cfg.velocityX = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xfffffff1, 0xf);
        cfg.velocityY = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xfffffff1, 0xf);
        cfg.velocityZ = lbl_803DF584;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = sourceObj[2];
        rot.y = sourceObj[1];
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF588 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.behaviorFlags = 0x2000110;
        cfg.renderFlags = 0x200000;
        cfg.lifetimeFrames = 0x19;
        cfg.textureId = 0x156;
        break;
    case 0x52a:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF58C;
        cfg.lifetimeFrames = 10;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80440202;
        cfg.textureId = 0x4f9;
        cfg.renderFlags = 0x2000000;
        break;
    case 0x51f:

        cfg.startPosY = lbl_803DF590;
        cfg.scale = lbl_803DF594;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x88140200;
        cfg.textureId = 0x159;
        break;
    case 0x51e:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF598;
        cfg.lifetimeFrames = 10;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80440202;
        cfg.textureId = 0x156;
        break;
    case 0x51c:
        (*startPos) = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = lbl_803DF59C;
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF4E0 * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(100, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        cfg.behaviorFlags = 0x80100100;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = randomGetRange(0, 10) * 0xacf;
        cfg.renderFlags = 0x20;
        cfg.overrideColor1 = cfg.overrideColor0;
        cfg.overrideColor2 = cfg.overrideColor0;
        break;
    case 0x51b:

        cfg.scale = lbl_803DF568 * (f32)(s32)
        randomGetRange(0, 0xf) + lbl_803DF550;
        (*startPos) = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.startPosY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32) + lbl_803DF580;
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityX = (*startPos) / lbl_803DF5A4;
        cfg.velocityY = cfg.startPosY / lbl_803DF5A4;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF5A4;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100110;
        cfg.textureId = 0xe4;
        break;
    case 0x2bc:
    case 0x2bd:
    case 0x2be:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            (*startPos) = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            (*startPos) = (*startPos) - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
        }
        cfg.scale = lbl_803DF5A8;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x100;
        cfg.textureId = (s16)effectId - 0x28c;
        break;
    case 0x4b:

        cfg.scale = lbl_803DF5AC;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xdf;
        break;
    case 0x3c:

        cfg.startPosY = lbl_803DF5B0;
        cfg.scale = lbl_803DF5B4 * (f32)(s32)
        randomGetRange(1, 10) + lbl_803DF550;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x28;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0xc79;
        break;
    case 0x329:
        (*startPos) = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.startPosY = lbl_803DF5B8;
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityX = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(100, 200);
        cfg.velocityY = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(100, 200);
        cfg.velocityZ = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.behaviorFlags = 0x1081010;
        if ((int)randomGetRange(0, 3) == 0)
        {
            cfg.scale = lbl_803DF5BC * (f32)(s32)
            randomGetRange(0x28, 0x50);
            cfg.initialAlpha = 0x8c;
        }
        else
        {
            cfg.scale = lbl_803DF5C0 * (f32)(s32)
            randomGetRange(0x28, 0x50);
            cfg.initialAlpha = 10;
            cfg.behaviorFlags = (cfg.behaviorFlags | 0x100000);
        }
        if ((int)randomGetRange(0, 10) == 0)
        {
            spawnFlags = spawnFlags ^ 4 | 1;
        }
        cfg.lifetimeFrames = 0xdc;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0x8acf;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0x3caf;
        cfg.overrideColor1 = 0x30f7;
        cfg.overrideColor2 = 10000;
        cfg.renderFlags = 0x100020;
        cfg.textureId = 0x60;
        break;
    case 0x3b9:

        cfg.velocityX = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffffec, 0x14);
        cfg.velocityZ = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xffffffec, 0x14);
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0x1e, 100);
        cfg.scale = lbl_803DF4CC;
        cfg.lifetimeFrames = 0x4b0;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x62;
        break;
    case 0x3b8:
        (*startPos) = lbl_803DF5C4 * (f32)(s32)(0x3c - randomGetRange(0, 0x78));
        cfg.startPosY = lbl_803DF580;
        cfg.startPosZ = lbl_803DF5C4 * (f32)(s32)(0x3cU - randomGetRange(0, 0x78));
        cfg.velocityX = lbl_803DF4E0 * (f32)(s32)(0x28U - randomGetRange(0, 0x50));
        cfg.velocityZ = lbl_803DF4E0 * (f32)(s32)(0x28 - randomGetRange(0, 0x50));
        cfg.velocityY = lbl_803DF4E0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xb4;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0x47;
        break;
    case 0x1:
        cfg.startPosY = lbl_803DF5C8;
        cfg.velocityX = lbl_803DF568 * (gPartfxFrameAnimPhase0 * (f32)(s32)
        randomGetRange(0xfffffff1, 0xf)
        )
        ;
        cfg.velocityY = lbl_803DF5B4 * (f32)(s32)
        randomGetRange(5, 0x14);
        cfg.velocityZ = lbl_803DF568 * (gPartfxFrameAnimPhase0 * (f32)(s32)
        randomGetRange(0xfffffff1, 0xf)
        )
        ;
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(0, 10) + lbl_803DF5B4;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0xf;
        cfg.behaviorFlags = 0x588008;
        cfg.renderFlags = 0x10000;
        cfg.textureId = 0x23b;
        cfg.quadVertex3Pad06 = 4;
        break;
    case 0x4:
        cfg.velocityY = lbl_803DF5CC * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(0, 10) + lbl_803DF5D0;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xcd;
        cfg.linkGroup = 6;
        cfg.behaviorFlags = 0xa100200;
        cfg.textureId = 0x47;
        break;
    case 0x3:
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosY = lbl_803DF4D8 * (f32)(s32)
        randomGetRange(0x14, 0x3c);
        cfg.scale = lbl_803DF5D4;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x96;
        cfg.linkGroup = 0x14;
        cfg.behaviorFlags = 0x9100110;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        break;
    case 0x5:

        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = lbl_803DF4E4 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = lbl_803DF5DC * (f32)(s32)
        randomGetRange(100, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
        cfg.linkGroup = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x100218;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        if (cfg.textureId == 0x4c)
        {
            cfg.colorWord0 = 0x6400;
            cfg.colorWord1 = 0x3200;
            cfg.colorWord2 = 0xa000;
            cfg.overrideColor0 = 500;
            cfg.overrideColor1 = 0;
            cfg.overrideColor2 = 1000;
            cfg.renderFlags = 0x4000020;
        }
        break;
    case 0x7:
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = lbl_803DF5D8 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityX = lbl_803DF5E0 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = lbl_803DF5E0 * (f32)(s32)
        randomGetRange(10, 0x28);
        cfg.velocityZ = lbl_803DF5E0 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x32);
        cfg.linkGroup = 0x1e;
        cfg.behaviorFlags = 0x511;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        break;
    case 0x7b:
        cfg.startPosY = lbl_803DF5E4 + (f32)(s32)
        randomGetRange(0, 10);
        cfg.velocityY = lbl_803DF5E8;
        cfg.scale = lbl_803DF508;
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100208;
        cfg.textureId = 0x91;
        break;
    case 0x7f:

        cfg.scale = lbl_803DF5EC;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x400100;
        switch (cfg.sourceVecZ)
        {
        case 0:
            cfg.textureId = 0x15e;
            break;
        case 1:
            cfg.textureId = 0x15f;
            break;
        case 2:
            cfg.textureId = 0x15d;
            break;
        default:
            cfg.textureId = 0x15e;
            break;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x7c:

        cfg.velocityX = lbl_803DF5F0 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = lbl_803DF5F0 * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.scale = lbl_803DF5F8;
        cfg.lifetimeFrames = 300;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x41001c;
        cfg.textureId = 0xc13;
        break;
    case 0x7d:
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x32;
        cfg.behaviorFlags = 0x400100;
        cfg.textureId = 0xc13;
        break;
    case 0x7e:
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x400100;
        cfg.velocityX = lbl_803DF4EC * (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityZ = lbl_803DF4EC * (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityY = lbl_803DF5D0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF5FC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        switch (cfg.sourceVecZ)
        {
        case 0:
            cfg.textureId = 0xdd;
            break;
        case 1:
            cfg.textureId = 0x160;
            break;
        case 2:
            cfg.textureId = 0xdf;
            break;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x3e7:

        cfg.lifetimeFrames = 300;
        cfg.behaviorFlags = 0x80400500;
        cfg.velocityX = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityZ = lbl_803DF550 * (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityY = lbl_803DF568 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF5FC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        if (cfg.sourceVecZ == 1)
        {
            cfg.textureId = 0x160;
        }
        else if (cfg.sourceVecZ < 1)
        {
            if (cfg.sourceVecZ < 0)
            {
            LAB_800a990c:
                cfg.textureId = 0xdf;
            }
            else
            {
                cfg.textureId = 0xdd;
            }
        }
        else
        {
            if (2 < cfg.sourceVecZ) goto LAB_800a990c;
            cfg.textureId = 0xdf;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x80:
        cfg.scale = lbl_803DF5CC;
        cfg.lifetimeFrames = 2;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x32;
        cfg.behaviorFlags = 0x400110;
        cfg.textureId = 0xdf;
        break;
    case 0x81:

        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff1a, 0xe6);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffce, 0xfa);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xffffff1a, 0xe6);
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x165;
        break;
    case 0x82:
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffce, 0xfa);
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x166;
        break;
    case 0x83:

        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffce, 0xfa);
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x167;
        break;
    case 0x71:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffffe, 2);
        cfg.startPosY = lbl_803DF604;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff0, 0x10);
        cfg.velocityY = lbl_803DF608 * (f32)(s32)
        randomGetRange(0xfffffffd, 0xffffffff);
        cfg.scale = lbl_803DF60C * (f32)(s32)
        randomGetRange(1, 3);
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000100;
        cfg.textureId = 0x2c;
        break;
    case 0x6d:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = spawnParams->scale;
        cfg.lifetimeFrames = 1;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x19;
        if (spawnParams->unk4 != 0)
        {
            cfg.initialAlpha = 0x7d;
        }
        cfg.behaviorFlags = 0xc0012;
        cfg.textureId = 0x77;
        break;
    case 0x6a:

        (*startPos) = lbl_803DF4D0 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.startPosY = lbl_803DF4DC;
        cfg.startPosZ = lbl_803DF4D0 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityX = lbl_803DF4DC;
        cfg.velocityY = lbl_803DF5D4 * (f32)(s32)
        randomGetRange(1, 3);
        cfg.velocityZ = lbl_803DF4DC;
        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x5f;
        break;
    case 0x66:
        cfg.linkGroup = 0x20;
        cfg.scale = lbl_803DF610;
        cfg.lifetimeFrames = 0x50;
        cfg.quadVertex3Pad06 = 0x67;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x156;
        break;
    case 0x67:

        cfg.scale = lbl_803DF610;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = randomGetRange(0, 2) + 0x156;
        break;
    case 0x68:
        cfg.velocityX = lbl_803DF5EC * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityY = lbl_803DF5EC * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityZ = lbl_803DF5EC * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF614;
        cfg.lifetimeFrames = 0x69;
        cfg.behaviorFlags = 0x480200;
        cfg.textureId = 0x156;
        break;
    case 0x65:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.scale = lbl_803DF598;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x30;
        break;
    case 0x72:

        cfg.scale = lbl_803DF618 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000802;
        cfg.linkGroup = 0;
        cfg.textureId = 0xde;
        cfg.initialAlpha = randomGetRange(0x96, 0xfa);
        break;
    case 0x73:
        cfg.scale = lbl_803DF61C * (f32)(s32)
        randomGetRange(4, 5) * lbl_803DF530;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        cfg.behaviorFlags = 0x0;
        cfg.renderFlags = 2;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x55:
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x59:

        cfg.velocityX = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.velocityY = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.velocityZ = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(1, 0x28);
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x51:

        cfg.scale = lbl_803DF4C8;
        cfg.lifetimeFrames = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x50:
        cfg.scale = lbl_803DF5CC;
        cfg.lifetimeFrames = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x4d:
        cfg.startPosY = lbl_803DF620;
        cfg.scale = lbl_803DF624;
        cfg.lifetimeFrames = 400;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x4e;
        cfg.behaviorFlags = 0x20100;
        cfg.textureId = 0xdf;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 100 - randomGetRange(0, 200);
        cfg.sourceVecY = 100 - randomGetRange(0, 200);
        cfg.sourceVecX = 100 - randomGetRange(0, 200);
        break;
    case 0x4e:

        cfg.velocityX = lbl_803DF628 * (f32)(s32)(1 - randomGetRange(0, 2));
        cfg.velocityZ = lbl_803DF628 * (f32)(s32)(1U - randomGetRange(0, 2));
        cfg.scale = lbl_803DF62C;
        cfg.lifetimeFrames = 0x4b;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x4a:
        cfg.startPosY = lbl_803DF630;
        cfg.scale = lbl_803DF634;
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x4b;
        cfg.behaviorFlags = 0x70000;
        cfg.textureId = randomGetRange(0, 3) + 0xdd;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4FC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 500 - randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - randomGetRange(0, 1000);
        break;
    case 0x49:
        cfg.startPosY = lbl_803DF604;
        cfg.scale = lbl_803DF530;
        cfg.lifetimeFrames = 0xe;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0x110210;
        cfg.textureId = 0x31;
        break;
    case 0x47:
        (*startPos) = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosY = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosZ = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803DF504;
        cfg.lifetimeFrames = randomGetRange(4, 0xe);
        cfg.behaviorFlags = 0x110100;
        cfg.textureId = 0xc22;
        break;
    case 0x42:

        (*startPos) = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosY = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosZ = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x70800;
        cfg.textureId = randomGetRange(0, 1) + 0xdd;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 500 - randomGetRange(0, 1000);
        cfg.sourceVecY = 500 - randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - randomGetRange(0, 1000);
        break;
    case 0x40:

        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.velocityX = lbl_803DF638 * (f32)(s32)(1U - randomGetRange(0, 2));
        cfg.velocityY = lbl_803DF638 * (f32)(s32)
        randomGetRange(1, 3);
        cfg.velocityZ = lbl_803DF638 * (f32)(s32)(1 - randomGetRange(0, 2));
        cfg.scale = lbl_803DF5CC;
        cfg.lifetimeFrames = 0x96;
        cfg.behaviorFlags = 0x108;
        cfg.textureId = 0x5c;
        break;
    case 0x41:
        ftmp4 = lbl_803DF63C;
        ftmp3 = lbl_803DF640;
        ftmp2 = lbl_803DF638;
        ftmp1 = lbl_803DF5B4;
        for (i = 0; i < 0x1e; i = i + 1)
        {
            cfg.startPosY = ftmp4;
            cfg.velocityX = ftmp3 * (f32)(s32)(2 - randomGetRange(0, 4));
            cfg.velocityY = ftmp2 * (f32)(s32)
            randomGetRange(1, 2);
            cfg.velocityZ = ftmp3 * (f32)(s32)(2U - randomGetRange(0, 4));
            cfg.scale = ftmp1;
            cfg.lifetimeFrames = 0x3c;
            cfg.behaviorFlags = 0x108;
            cfg.textureId = 0x5c;
            if ((cfg.behaviorFlags & 1) != 0)
            {
                if (cfg.attachedSource != NULL)
                {
                    cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.localPosX;
                    cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.localPosY;
                    cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.localPosZ;
                }
                else
                {
                    cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
                    cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
                    cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
                }
            }
            (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        }
        break;
    case 0x55c:
    LAB_800aa8ac:
        cfg.behaviorFlags = 0x20100100;
        cfg.lifetimeFrames = 400;
        if (effectId == 0x3d)
        {
            (*startPos) = lbl_803DF580 - (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.startPosY = lbl_803DF644;
            cfg.startPosZ = lbl_803DF580 - (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.scale = lbl_803DF4EC * (f32)(s32)
            randomGetRange(1, 3);
            cfg.renderFlags = cfg.renderFlags | 0x1000000;
        }
        else if (effectId == 0x3e)
        {
            (*startPos) = lbl_803DF580 - (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.startPosY = lbl_803DF648;
            cfg.startPosZ = lbl_803DF580 - (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.scale = lbl_803DF624 * (f32)(s32)
            randomGetRange(1, 3);
            cfg.renderFlags = cfg.renderFlags | 0x1000000;
        }
        else if (effectId == 0x3f)
        {
            cfg.startPosY = lbl_803DF64C;
            cfg.lifetimeFrames = 100;
            cfg.scale = lbl_803DF624 * (f32)(s32)
            randomGetRange(1, 3);
            cfg.renderFlags = cfg.renderFlags | 0x1000000;
        }
        else if (effectId == 0x43)
        {
            (*startPos) = lbl_803DF650;
            cfg.startPosY = lbl_803DF538;
            cfg.startPosZ = lbl_803DF564 + (f32)(s32)
            randomGetRange(0, 0x78);
            cfg.scale = lbl_803DF4E8 * (f32)(s32)
            randomGetRange(1, 8);
            cfg.behaviorFlags = (cfg.behaviorFlags | 8);
            cfg.renderFlags = cfg.renderFlags | 0x1000000;
        }
        else if (effectId == 0x44)
        {
            (*startPos) = lbl_803DF650;
            cfg.startPosY = lbl_803DF654;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(0, 0x78);
            cfg.velocityY = lbl_803DF658;
            cfg.scale = lbl_803DF4E8 * (f32)(s32)
            randomGetRange(1, 8);
            cfg.renderFlags = cfg.renderFlags | 0x1000000;
        }
        cfg.linkGroup = 0x20;
        cfg.textureId = 0x5f;
        cfg.behaviorFlags = (cfg.behaviorFlags | spawnFlags);
        if ((cfg.behaviorFlags & 1) != 0)
        {
            if (cfg.attachedSource != NULL)
            {
                (*startPos) = (*startPos) + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
            else
            {
                (*startPos) = (*startPos) + cfg.sourcePosY;
                cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
                cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
            }
        }
        if ((effectId == 0x3e) || (effectId == 0x3f))
        {
            cfg.behaviorFlags = (cfg.behaviorFlags | 0x8000000);
        }
        break;
    case 0x3d:
    case 0x3e:
    case 0x3f:
    case 0x43:
    case 0x44:
    case 0x4f:
        goto LAB_800aa8ac;
    case 0x48:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityY = lbl_803DF508 * (f32)(s32)
        randomGetRange(1, 10);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF530;
        rot.z = 2000 - randomGetRange(0, 4000);
        rot.y = 2000 - randomGetRange(0, 4000);
        rot.x = 2000 - randomGetRange(0, 4000);
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.scale = lbl_803DF65C;
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 8;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0xdd;
        break;
    case 0x38:
        srand(0x4233d);
        ftmp1 = lbl_803DF644;
        ftmp2 = lbl_803DF4E8;
        ftmp3 = lbl_803DF600;
        ftmp4 = lbl_803DF660;
        for (i = 0; i < 0x28; i = i + 1)
        {
            cfg.startPosY = ftmp1;
            cfg.velocityX = ftmp2 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
            cfg.velocityZ = ftmp2 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
            cfg.scale = ftmp3;
            cfg.lifetimeFrames = (s32)(ftmp4 * (f32)(s32)randomGetRange(1, 4));
            cfg.behaviorFlags = 0x100011;
            cfg.textureId = 0x30;
            srcPosX = cfg.sourcePosY;
            srcPosY = cfg.sourcePosZ;
            srcPosZ = cfg.sourcePosW;
            if (cfg.attachedSource != NULL)
            {
                srcPosX = ((GameObject*)cfg.attachedSource)->anim.localPosX;
                srcPosY = ((GameObject*)cfg.attachedSource)->anim.localPosY;
                srcPosZ = ((GameObject*)cfg.attachedSource)->anim.localPosZ;
            }
            cfg.startPosZ = cfg.startPosZ + srcPosZ;
            cfg.startPosY = cfg.startPosY + srcPosY;
            (*startPos) = (*startPos) + srcPosX;
            (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        }
        break;
    case 0x35:
        (*startPos) = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = lbl_803DF668;
        cfg.startPosZ = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = lbl_803DF66C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF670 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400001;
        cfg.textureId = 0x47;
        break;
    case 0x3a:

        (*startPos) = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = lbl_803DF580;
        cfg.startPosZ = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = lbl_803DF66C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF670 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xb4;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400200;
        cfg.textureId = 0x47;
        break;
    case 0x3b:
        (*startPos) = lbl_803DF624 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = lbl_803DF604;
        cfg.startPosZ = lbl_803DF624 * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = lbl_803DF66C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF670 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0x47;
        break;
    case 0x53:
        (*startPos) = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosZ = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = lbl_803DF514 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF670 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xd2;
        cfg.behaviorFlags = 0x80000201;
        cfg.textureId = randomGetRange(0, 3) + 0xdd;
        break;
    case 0x2e:

        cfg.scale = lbl_803DF4CC;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x5e;
        break;
    case 0x78:
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 100);
        cfg.scale = lbl_803DF4CC;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x5e;
        break;
    case 0x3e6:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityY = lbl_803DF674 * (f32)(s32)
        randomGetRange(4, 10);
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x15e;
        cfg.quadVertex3Pad06 = 0x85;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0xdf;
        break;
    case 0x77:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityX = lbl_803DF600 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = lbl_803DF66C * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.velocityZ = lbl_803DF600 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400101;
        cfg.textureId = 0xdf;
        break;
    case 0x7a:
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x23);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffc, 4);
        cfg.velocityX = lbl_803DF600 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.velocityZ = lbl_803DF600 * (f32)(s32)
        randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = lbl_803DF600 * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0xc80404;
        cfg.textureId = 0xdf;
        break;
    case 0x76:

        cfg.scale = lbl_803DF678 * (f32)(s32)
        randomGetRange(1, 8);
        cfg.lifetimeFrames = randomGetRange(0, 0x32) + 0x26;
        cfg.initialAlpha = 0xff;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.behaviorFlags = 0x6100110;
        cfg.textureId = 0x159;
        break;
    case 0x2f:
        cfg.scale = lbl_803DF608;
        cfg.lifetimeFrames = 0x32;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x71;
        break;
    case 0x34:

        cfg.scale = lbl_803DF608;
        cfg.lifetimeFrames = 0x1e;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x400210;
        cfg.textureId = 0x71;
        break;
    case 0x30:
        cfg.scale = lbl_803DF4D0;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x7c;
        break;
    case 0x39:
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.startPosZ = lbl_803DF55C;
        }
        else
        {
            cfg.startPosZ = lbl_803DF67C;
        }
        cfg.scale = lbl_803DF680 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = randomGetRange(0, 0x18) + 0x18;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x33;
        break;
    case 0x79:

        if ((int)randomGetRange(0, 1) != 0)
        {
            (*startPos) = lbl_803DF64C;
        }
        else
        {
            (*startPos) = lbl_803DF684;
        }
        cfg.startPosY = (f32)(s32)
        randomGetRange(10, 0x3c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffd, 3);
        cfg.velocityY = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(1, 0x14);
        cfg.scale = lbl_803DF5D0 * (f32)(s32)
        randomGetRange(1, 7);
        cfg.lifetimeFrames = randomGetRange(0, 0xf) + 0xf;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x100100;
        cfg.textureId = 0x156;
        break;
    case 0x75:
        cfg.scale = lbl_803DF638;
        cfg.lifetimeFrames = 0x62;
        cfg.initialAlpha = 0xff;
        cfg.textureSetupFlags = 0xa9;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x159;
        break;
    case 0x32:
        cfg.scale = lbl_803DF5E0;
        cfg.lifetimeFrames = 0x96;
        cfg.behaviorFlags = 0x400012;
        cfg.textureId = 0x7c;
        break;
    case 0x33:
        cfg.startPosY = lbl_803DF644;
        cfg.scale = lbl_803DF62C;
        cfg.lifetimeFrames = 0x55;
        cfg.behaviorFlags = 0x400012;
        cfg.textureId = 0x7c;
        break;
    case 0x69:
        cfg.scale = lbl_803DF688;
        cfg.lifetimeFrames = 0x44;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x60;
        break;
    case 0x2:

        (*startPos) = lbl_803DF638 * (f32)(s32)
        randomGetRange(0xffffffec, 0x14);
        cfg.startPosY = lbl_803DF638 * (f32)(s32)
        randomGetRange(0xffffffec, 0x14);
        cfg.startPosZ = lbl_803DF638 * (f32)(s32)
        randomGetRange(0xffffffec, 0x14);
        cfg.scale = lbl_803DF4C8 * (f32)(s32)
        randomGetRange(0, 0x1e) + lbl_803DF68C;
        cfg.lifetimeFrames = randomGetRange(0, 8) + 8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100100;
        cfg.textureId = 0x33;
        break;
    case 0x2a:
        (*startPos) = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffe2, 0x1e);
        cfg.scale = lbl_803DF4D4 * (f32)(s32)
        randomGetRange(0, 10) + lbl_803DF62C;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x32);
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0xe;
        cfg.behaviorFlags = 0x100110;
        if (extraArgs == NULL)
        {
            cfg.textureId = 0x88;
        }
        else
        {
            cfg.textureId = 0x78;
        }
        break;
    case 0x37:

        cfg.scale = lbl_803DF4E4;
        cfg.lifetimeFrames = 0x14;
        cfg.textureSetupFlags = 0x9a;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x87;
        break;
    case 0x2b:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityX = lbl_803DF608;
        ftmp0 = (f32)(s32)
        randomGetRange(0, 0xfffe);
        ftmp1 = (f32)(s32)
        randomGetRange(0, 0xfffe);
        ftmp2 = (f32)(s32)
        randomGetRange(0, 0xfffe);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = ftmp2;
        rot.y = ftmp1;
        rot.x = ftmp0;
        vecRotateZXY((s16*)&rot, &cfg.velocityX);
        cfg.scale = lbl_803DF690;
        cfg.lifetimeFrames = 0x32;
        cfg.textureSetupFlags = 0;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x30;
        break;
    case 0x2c:
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 10;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80211;
        cfg.textureId = 0x3ff;
        break;
    case 0x28:

        cfg.scale = lbl_803DF4CC;
        cfg.lifetimeFrames = 0x46;
        cfg.behaviorFlags = 0xb100200;
        cfg.textureId = 0x74;
        break;
    case 0x31:

        cfg.scale = lbl_803DF694;
        cfg.lifetimeFrames = 0x46;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0xb100200;
        cfg.textureId = 0x74;
        break;
    case 0x2d:
        cfg.startPosY = lbl_803DF644;
        cfg.velocityX = lbl_803DF4E8 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityZ = lbl_803DF4E8 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = (s32)(lbl_803DF660 * (f32)(s32)randomGetRange(1, 4));
        cfg.behaviorFlags = 0x100000;
        cfg.textureId = 0x30;
        break;
    case 0x25:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX + (f32)(s32)
        randomGetRange(0, 6);
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ + (f32)(s32)
        randomGetRange(0, 6);
        cfg.velocityY = lbl_803DF634 * (f32)(s32)
        randomGetRange(0, 10);
        cfg.scale = lbl_803DF5B4 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100112;
        cfg.textureId = 0x61;
        break;
    case 0x36:
        if (extraArgs == NULL)
        {
            return -1;
        }
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = 0x20;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x1100201;
        cfg.textureId = 0x249;
        break;
    case 0x26:
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffffff, 1);
        if (extraArgs != NULL)
        {
            (*startPos) = (*startPos) + extraArgs[1];
        }
        cfg.startPosY = lbl_803DF4DC;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xffffffff, 1);
        cfg.velocityY = lbl_803DF608;
        cfg.scale = lbl_803DF4E0;
        if (extraArgs == NULL)
        {
            cfg.lifetimeFrames = 0x78;
        }
        else
        {
            cfg.lifetimeFrames = (s32) * extraArgs;
        }
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 99;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = 0;
        rot.y = 0;
        rot.x = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY((s16*)&rot, startPos);
        break;
    case 0xc:
        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10000;
        cfg.textureId = 0x30;
        break;
    case 0xd:

        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10000;
        cfg.textureId = 0x30;
        break;
    case 0xe:
        cfg.startPosY = lbl_803DF604;
        cfg.scale = lbl_803DF4F0;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10002;
        cfg.textureId = 0x30;
        break;
    case 0x0:

        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 6;
        cfg.textureSetupFlags = 0;
        cfg.behaviorFlags = 0x10;
        cfg.textureId = 0x87;
        break;
    case 0xf:

        cfg.startPosX = lbl_803DF698;
        cfg.startPosY = lbl_803DF630;
        cfg.startPosZ = lbl_803DF590;
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = (s32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x110214;
        cfg.textureId = 0x30;
        break;
    case 0x11:
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityY = lbl_803DF608 * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = (s32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x1110214;
        cfg.textureId = 0x33;
        break;
    case 0x19:

        cfg.velocityX = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityY = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.velocityZ = lbl_803DF4E8 * (f32)(s32)
        randomGetRange(0xfffffff6, 10);
        cfg.scale = lbl_803DF4C8;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x211;
        cfg.textureId = 0x30;
        break;
    case 0x1a:
        cfg.velocityX = lbl_803DF4F0 * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.velocityZ = lbl_803DF4F0 * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.scale = lbl_803DF690 * (f32)(s32)
        randomGetRange(0, 4);
        cfg.lifetimeFrames = (s32)(lbl_803DF69C * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x1000211;
        cfg.textureId = 0x30;
        break;
    case 0x1b:

        cfg.velocityY = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.scale = lbl_803DF690 * (f32)(s32)
        randomGetRange(0, 4);
        cfg.lifetimeFrames = (s32)(lbl_803DF6A0 * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.linkGroup = 5;
        cfg.behaviorFlags = 0x1000211;
        cfg.textureId = 0x30;
        break;
    case 0x20:
        cfg.startPosY = lbl_803DF5B8;
        cfg.scale = lbl_803DF62C;
        cfg.lifetimeFrames = 200;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x12;
        cfg.textureId = 0x22d;
        break;
    case 0x21:
        (*startPos) = (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.startPosZ = (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.velocityX = lbl_803DF628;
        cfg.velocityY = lbl_803DF6A4;
        cfg.velocityZ = lbl_803DF628;
        cfg.scale = lbl_803DF62C;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x201;
        cfg.textureId = 0x321;
        break;
    case 0x22:

        cfg.startPosZ = lbl_803DF4FC;
        cfg.scale = lbl_803DF4C8;
        cfg.lifetimeFrames = 0x178e;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x14;
        cfg.textureId = 0x30;
        break;
    case 0x23:
        cfg.startPosY = lbl_803DF580;
        cfg.scale = lbl_803DF6A8;
        cfg.lifetimeFrames = 0x69;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x4b;
        break;
    case 0x24:
        cfg.scale = lbl_803DF6A8;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x400212;
        cfg.textureId = 0x4b;
        break;
    case 0x1c:
        (*startPos) = (f32)(s32)
        randomGetRange(0xffffff38, 200);
        cfg.startPosY = lbl_803DF6AC;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xffffff38, 200);
        cfg.velocityX = lbl_803DF4EC * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.velocityZ = lbl_803DF4EC * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = lbl_803DF68C * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.scale = lbl_803DF6B0;
        cfg.lifetimeFrames = 0x104;
        cfg.behaviorFlags = 0x1000202;
        cfg.quadVertex3Pad06 = 0x1e;
        (*startPos) = lbl_803DF4DC;
        cfg.startPosY = lbl_803DF540;
        cfg.startPosZ = lbl_803DF4DC;
        cfg.velocityZ = lbl_803DF4EC * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 0xa0;
        cfg.behaviorFlags = 0x11000204;
        cfg.textureId = 0x151;
        break;
    case 0x74:

        (*startPos) = (f32)(s32)
        randomGetRange(0xffffffb0, 0x50);
        cfg.startPosY = lbl_803DF4DC;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xffffffb0, 0x50);
        cfg.velocityY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DF5AC;
        cfg.lifetimeFrames = 0x140;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1000204;
        cfg.textureId = 0x151;
        break;
    case 0x1d:

        cfg.startPosY = lbl_803DF6B4;
        cfg.startPosZ = lbl_803DF6B8;
        cfg.velocityX = lbl_803DF68C * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = lbl_803DF68C * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.scale = lbl_803DF6BC;
        cfg.lifetimeFrames = 0x78;
        cfg.behaviorFlags = 0x204;
        cfg.textureId = 0x1f0;
        break;
    case 0x1e:
        cfg.scale = lbl_803DF5B4 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x56;
        cfg.linkGroup = 0;
        break;
    case 0x1f:

        cfg.scale = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.lifetimeFrames = 200;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x54:

        (*startPos) = (f32)(s32)(5 - randomGetRange(0, 10));
        cfg.startPosZ = (f32)(s32)(5U - randomGetRange(0, 10));
        cfg.scale = lbl_803DF5CC * (f32)(s32)
        randomGetRange(2, 0xc);
        cfg.lifetimeFrames = 0x78;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x27:
        cfg.startPosY = lbl_803DF580;
        cfg.scale = lbl_803DF624 * (f32)(s32)
        randomGetRange(1, 2);
        cfg.lifetimeFrames = 200;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x6b;
        break;
    case 0x13:
        cfg.scale = lbl_803DF6C0;
        cfg.lifetimeFrames = 0xd05;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0x11;
        cfg.textureId = 0x30;
        break;
    case 0x14:

        cfg.scale = lbl_803DF530;
        cfg.lifetimeFrames = 0xd;
        cfg.behaviorFlags = 0x110212;
        cfg.textureId = 0x33;
        break;
    case 0x12:

        cfg.startPosY = lbl_803DF630;
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = 0x14d;
        cfg.behaviorFlags = 0x10012;
        cfg.textureId = 0x33;
        break;
    case 0x10:
        cfg.startPosY = (f32)(s32)(0x14 - randomGetRange(0, 0x28));
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = (s32)(lbl_803DF6C4 * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x110204;
        cfg.textureId = 0x30;
        break;
    case 0x6:
        cfg.scale = lbl_803DF624;
        cfg.lifetimeFrames = 0x12;
        cfg.behaviorFlags = 0x300200;
        cfg.textureId = 0x33;
        break;
    case 0x8:

        cfg.startPosY = lbl_803DF644;
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x30;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300002;
        cfg.textureId = 0x2c;
        break;
    case 0x9:
        cfg.startPosY = lbl_803DF644;
        cfg.startPosZ = lbl_803DF5B8;
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300000;
        cfg.textureId = 0x2c;
        break;
    case 0xa:
        cfg.scale = lbl_803DF4EC;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300000;
        cfg.textureId = 0x2c;
        break;
    case 0x6b:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (extraArgs == NULL)
        {
            return -1;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        cfg.scale = lbl_803DF4C8;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = (u8)(int)spawnParams->scale;
        cfg.linkGroup = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc13;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0;
        cfg.sourceVecX = spawnParams->rotX;
        break;
    case 0x6c:
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = 1;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x11;
        cfg.renderFlags = 2;
        cfg.textureId = 0xdd;
        break;
    case 0x56:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        (*startPos) = (f32)(s32)
        randomGetRange(0xfffffffa, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffa, 6);
        cfg.velocityX = spawnParams->scale * (lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffffe, 2)
        )
        ;
        cfg.velocityY = spawnParams->scale * (lbl_803DF4CC * (f32)(s32)
        randomGetRange(0, 4)
        )
        ;
        cfg.velocityZ = spawnParams->scale * (lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffffe, 2)
        )
        ;
        cfg.scale = lbl_803DF634 * spawnParams->scale;
        cfg.lifetimeFrames = 0x18;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.initialAlpha = 0xa5;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        cfg.textureId = 0x60;
        break;
    case 0x57:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 10);
        cfg.velocityX = spawnParams->scale * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.velocityY = spawnParams->scale * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(200, 400)
        )
        ;
        cfg.velocityZ = spawnParams->scale * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.scale = spawnParams->scale * (lbl_803DF524 * (f32)(s32)
        randomGetRange(8, 0xb)
        )
        ;
        cfg.initialAlpha = 0xbe;
        cfg.lifetimeFrames = (s32)(lbl_803DF6C8 * spawnParams->scale);
        cfg.behaviorFlags = 0x1200000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        break;
    case 0x58:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityX = spawnParams->scale * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.velocityY = spawnParams->scale * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(10, 200)
        )
        ;
        cfg.velocityZ = spawnParams->scale * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.scale = spawnParams->scale * (lbl_803DF524 * (f32)(s32)
        randomGetRange(8, 0xb)
        )
        ;
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        break;
    case 0x323:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        (*startPos) = lbl_803DF6CC * (f32)(s32)
        randomGetRange(0xffffffea, 0x15) + (*startPos);
        cfg.startPosY = lbl_803DF6D0 * (f32)(s32)
        randomGetRange(0xffffffe9, 0x16) + cfg.startPosY;
        cfg.startPosZ = lbl_803DF6D4 * (f32)(s32)
        randomGetRange(0xffffffe9, 0x19) + cfg.startPosZ;
        cfg.scale = lbl_803DF6D8 * (f32)(s32)
        randomGetRange(1, 6);
        intVal = randomGetRange(7, 0xf);
        cfg.lifetimeFrames = intVal + 5;
        cfg.textureId = 0xc9a;
        cfg.behaviorFlags = 0x100210;
        cfg.renderFlags = 0x4000800;
        if (extraArgs != NULL)
        {
            variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags |= 0x20;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6DC;
                cfg.lifetimeFrames = intVal + 0xc;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
                cfg.lifetimeFrames = intVal + 0x19;
            }
            else if (variantU == '\x04')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\x05')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\x06')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\a')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\b')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags |= 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
        }
        break;
    case 0x325:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = lbl_803DF6E4;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = randomGetRange(0xffff8001, 0x7fff);
        rot.y = randomGetRange(0xffff8001, 0x7fff);
        rot.x = randomGetRange(0xffff8001, 0x7fff);
        vecRotateZXY((s16*)&rot, startPos);
        cfg.velocityX = -((*startPos) / lbl_803DF4FC);
        cfg.velocityY = -(cfg.startPosY / lbl_803DF4FC);
        cfg.velocityZ = -(cfg.startPosZ / lbl_803DF4FC);
        cfg.scale = lbl_803DF6E8 * (f32)(s32)
        randomGetRange(0x9e, 0x240);
        cfg.lifetimeFrames = randomGetRange(7, 0x12) + 0xc;
        cfg.textureId = 0xc98;
        cfg.behaviorFlags = 0x480110;
        if (extraArgs != NULL)
        {
            variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6DC;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6EC;
            }
        }
        break;
    case 0x326:
        randomGetRange(1, 1);
        cfg.velocityX = lbl_803DF4DC;
        randomGetRange(1, 1);
        cfg.velocityY = lbl_803DF4DC;
        randomGetRange(1, 1);
        cfg.velocityZ = lbl_803DF4DC;
        randomGetRange(1, 1);
        (*startPos) = lbl_803DF4DC;
        randomGetRange(1, 1);
        cfg.startPosY = lbl_803DF4DC;
        randomGetRange(1, 1);
        cfg.startPosZ = lbl_803DF4DC;
        cfg.scale = lbl_803DF6F0 * (f32)(s32)
        randomGetRange(10, 0x1e);
        cfg.lifetimeFrames = randomGetRange(1, 1) + 0x17;
        cfg.textureId = 0xc99;
        cfg.behaviorFlags = 0x180210;
        cfg.initialAlpha = 0x7d;
        if (extraArgs != NULL)
        {
            variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6F4;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6F8;
            }
            else if (variantU == '\x04')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\x05')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\x06')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\a')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
            else if (variantU == '\b')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale = cfg.scale * lbl_803DF6E0;
            }
        }
        break;
    case 0x328:

        cfg.velocityX = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803DF568 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.lifetimeFrames = randomGetRange(4, 0xd);
        cfg.behaviorFlags = 0x180210;
        cfg.renderFlags = 0x4000800;
        cfg.scale = lbl_803DF6FC;
        cfg.textureId = 0xc9d;
        break;
    case 0x3de:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            (*startPos) = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
            cfg.startPosY = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
            cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
        }
        else
        {
            (*startPos) = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.velocityX = lbl_803DF4DC;
        cfg.velocityY = lbl_803DF508;
        cfg.velocityZ = lbl_803DF4DC;
        cfg.scale = lbl_803DF504;
        cfg.lifetimeFrames = 0x96;
        cfg.linkGroup = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080209;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xa000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xc000;
        break;
    case 0x3df:

        (*startPos) = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.startPosY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803DF608 * (f32)(s32)
        randomGetRange(8, 10);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = lbl_803DF4C8 * (f32)(s32)
            randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = lbl_803DF4C8 * (f32)(s32)
            randomGetRange(0x15, 0x29);
            cfg.lifetimeFrames = 0x1cc;
        }
        cfg.behaviorFlags = 0x80380209;
        cfg.renderFlags = 0x5000820;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.overrideColor0 = 0x62c0;
        cfg.overrideColor1 = 0xd310;
        cfg.overrideColor2 = 0x2800;
        cfg.colorWord0 = 0x44c0;
        cfg.colorWord1 = 0xd310;
        cfg.colorWord2 = 0xb00;
        break;
    case 0x320:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityX = lbl_803DF608 * (f32)(s32)
        randomGetRange(0xfffffffe, 2);
        cfg.velocityY = lbl_803DF674 * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF700 * (f32)(s32)
        randomGetRange(1, 3);
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF550;
        cfg.lifetimeFrames = 0x28;
        cfg.renderFlags = 0x5000000;
        cfg.behaviorFlags = 0x180208;
        cfg.textureId = 0xc8f;
        break;
    case 0x321:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0, 4);
        cfg.velocityZ = lbl_803DF704 * (f32)(s32)
        randomGetRange(2, 4);
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 100;
        cfg.behaviorFlags = 0x1180200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc90;
        break;
    case 0x322:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF504;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc90;
        cfg.initialAlpha = 0xa5;
        break;
    case 0x351:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityZ = lbl_803DF708;
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DF618 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.behaviorFlags = 0x8100200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc8f;
        break;
    case 0x51d:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
            gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.sourceVecX = 700;
        cfg.textureId = 0xc09;
        (*startPos) = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.scale = lbl_803DF524 * (f32)(s32)
        randomGetRange(10, 0x14);
        cfg.lifetimeFrames = 0xaa;
        cfg.behaviorFlags = 0xa0104;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        cfg.sourcePosX = lbl_803DF4D0;
        break;
    case 0x55a:
        {
            if (spawnParams == NULL)
            {
                gPartfxDefaultSpawnParams.posX = lbl_803DF4DC;
                gPartfxDefaultSpawnParams.posY = lbl_803DF4DC;
                gPartfxDefaultSpawnParams.posZ = lbl_803DF4DC;
                gPartfxDefaultSpawnParams.scale = lbl_803DF4D0;
                gPartfxDefaultSpawnParams.unk0 = 0;
                gPartfxDefaultSpawnParams.unk2 = 0;
                gPartfxDefaultSpawnParams.unk4 = 0;
                gPartfxDefaultSpawnParams.unk6 = 0;
            }
            cfg.velocityX = lbl_803DF5CC * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803DF568 * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803DF5CC * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803DF528 * (f32)(s32)
            randomGetRange(5, 0x19);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourceVecY = randomGetRange(0, 0xffff);
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourcePosY = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosZ = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosW = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.renderFlags = 0x1000020;
            cfg.behaviorFlags = 0x86000008;
            cfg.overrideColor0 = randomGetRange(0, 0xfff) + 0xf000;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = 0xe000;
            cfg.colorWord1 = 0xe000;
            cfg.overrideColor2 = 0xe000;
            cfg.colorWord2 = 0xe000;
            cfg.textureId = 0x567;
            goto LAB_800aeb30;
        }
    case 0x564:
        cfg.scale = lbl_803DF5A0 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.lifetimeFrames = 0x2d;
        cfg.behaviorFlags = 0x80580210;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0f;
        break;
    case 0x565:

        cfg.scale = lbl_803DF4D0;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x210;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x5b1;
        break;
    case 0x324:
        goto LAB_800aeb30;
    case 0xb:
    case 0x327:
    case 0x52e:
    case 0x555:
    default:
    LAB_800aeb28:
        return -1;
    }
LAB_800aeb30:
    cfg.behaviorFlags = (cfg.behaviorFlags | spawnFlags);
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0))
    {
        cfg.behaviorFlags ^= 2LL;
    }
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
            if (cfg.attachedSource != NULL)
            {
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&cfg, 0xffffffff, effectId, 0);
}
