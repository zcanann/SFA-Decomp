/*
 * effect2 (DLL 0x1B) - one of the "effect" particle DLLs (effect2..effect9
 * share the same modgfx/projgfx engine source; this object exports only its
 * own five Effect2_* entry points).
 *
 * Effect2_func04 is the spawn dispatcher: given an effectId it fills a
 * PartFxSpawn request (velocity / start position / scale / lifetime / texture /
 * behavior+render flags / colors, mostly randomised per spawn) and hands it to
 * gExpgfxInterface->spawnEffect. Effect2_func05 advances this DLL's animated
 * scroll/oscillation globals once per step. Effect2_func03_nop / _release /
 * _initialise are the descriptor stubs.
 *
 * The remaining modgfx_* / projgfx_* bodies are the shared effect-engine source
 * (vertex texcoord scroll, rgb/alpha/scale/rotation blend channels, active-effect
 * registry teardown, expgfx pool alloc); they are matched in their sibling effect
 * DLLs, not in this object's symbol set.
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
    char byte13B;
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
        slotPoolBases++;
        poolIndex++;
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
        poolActiveMasks += 8;
        poolActiveCounts += 8;
        poolSlotTypeIds += 8;
        groupCount--;
    }
    while (groupCount != 0);
    slotPoolBases = gExpgfxSlotPoolBases;
    do
    {
        allocatedPool = FUN_80017830(EXPGFX_POOL_BYTES, 0x14);
        *slotPoolBases = allocatedPool;
        FUN_800033a8(*slotPoolBases, 0, EXPGFX_POOL_BYTES);
        FUN_802420e0(*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases++;
        poolIndex++;
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
    for (i = 0; i < state->vertexCount; i++)
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
        activeVertexData++;
        inactiveVertexData++;
    }
    activeVertexData = modgfx_getActiveVertexBuffer(state);
    for (i = 0; i < state->vertexCount; i++)
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
        activeVertexData++;
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
    for (i = 0; one = lbl_803E00B4, i < state->vertexCount; i++)
    {
        baseVertexData->posX = inactiveVertexData->posX;
        baseVertexData->posY = inactiveVertexData->posY;
        baseVertexData->posZ = inactiveVertexData->posZ;
        baseVertexData->colorR = inactiveVertexData->colorR;
        baseVertexData->colorG = inactiveVertexData->colorG;
        baseVertexData->colorB = inactiveVertexData->colorB;
        baseVertexData->alpha = inactiveVertexData->alpha;
        baseVertexData++;
        inactiveVertexData++;
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
    for (i = 0; i < ((ModgfxVertexGroupCmd*)command)->indexCount; i++)
    {
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xc) =
            (char)(int)((ModgfxState*)state)->blendColorR;
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xd) =
            (char)(int)((ModgfxState*)state)->blendColorG;
        *(char*)(vtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + idxOff) * 0x10 + 0xe) =
            (char)(int)((ModgfxState*)state)->blendColorB;
        idxOff += 2;
    }
    return;
}

void modgfx_updateEffectPosition(int stateArg, int command, int mode)
{
    ModgfxState* state;
    double biasS;
    u16 rotAngle0;
    u16 rotAngle1;
    u16 rotAngle2;
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
                rotAngle1 = rotAngle0;
                rotAngle2 = rotAngle0;
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
            for (work0 = 0; work0 < ((ModgfxVertexGroupCmd*)command)->indexCount; work0++)
            {
                *(char*)(baseVtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 0xf) =
                    (char)(int)targetAlpha;
                work2 = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 0xf;
                *(u8*)(curVtxData + work2) = *(u8*)(baseVtxData + work2);
                work1 += 2;
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
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2++)
    {
        *(char*)(curVtxData + *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf) =
            (char)(int)*(float*)(state + work1 + 0xb0);
        vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work0) * 0x10 + 0xf;
        *(u8*)(baseVtxData + vtxOff) = *(u8*)(curVtxData + vtxOff);
        work0 += 2;
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
            for (work0 = 0; work0 < ((ModgfxVertexGroupCmd*)command)->indexCount; work0++)
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
                work1 += 2;
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
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2++)
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
        off += 2;
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
    for (i = 0; i < state->vertexCount; i++)
    {
        activeVertexData->posX = baseVertexData->posX;
        activeVertexData->posY = baseVertexData->posY;
        activeVertexData->posZ = baseVertexData->posZ;
        activeVertexData->colorR = baseVertexData->colorR;
        activeVertexData->colorG = baseVertexData->colorG;
        activeVertexData->colorB = baseVertexData->colorB;
        activeVertexData->alpha = baseVertexData->alpha;
        activeVertexData++;
        baseVertexData++;
    }
    return;
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
        if ((activeEffect != NULL) &&
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
            activeEffects[i] = NULL;
        }
        i++;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
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
        if ((activeEffect != NULL) && (activeEffect->ownerToken == ownerToken))
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
            activeEffects[i] = NULL;
        }
        i++;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
}

void modgfx_releaseAllActiveEffects(u64 argReg1, u64 argReg2, u64 argReg3,
                                    u64 argReg4, u64 argReg5, u64 argReg6,
                                    u64 argReg7, u64 argReg8)
{
    modgfx_releaseActiveEffectsByType(argReg1, argReg2, argReg3, argReg4, argReg5, argReg6, argReg7, argReg8,
                                      0, 1);
    return;
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
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++)
    {
        activeEffects[i] = NULL;
    }
    i = 2;
    {
        ModgfxActiveEffect** tailEffects;

        tailEffects = &activeEffects[MODGFX_ACTIVE_EFFECT_COUNT - 2];
        do
        {
            *tailEffects = NULL;
            tailEffects++;
            i--;
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
            if (sourceState == NULL)
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
            if (extraArgs == NULL)
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
            if (extraArgs == NULL)
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

void Effect2_func03_nop(void)
{
}

void Effect2_release(void)
{
}

void Effect2_initialise(void)
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

extern f32 gEffect2ScrollPhaseA;
extern f32 gEffect2ScrollPhaseB;
extern int gEffect2SinAngleA;
extern int gEffect2SinAngleB;
extern f32 gEffect2SinValueB;
extern f32 gEffect2SinValueA;
extern f32 lbl_803DF870;
extern f32 lbl_803DF874;
extern f32 lbl_803DF878;
extern f32 lbl_803DF880;
extern f32 lbl_803DF9C8;
extern f32 lbl_803DF9CC;

#pragma scheduling off
#pragma peephole off
void Effect2_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect2ScrollPhaseA + (step = lbl_803DF870 * timeDelta);
    gEffect2ScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseA = lbl_803DF874;
    }
    sum = gEffect2ScrollPhaseB + step;
    gEffect2ScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseB = lbl_803DF880;
    }
    gEffect2SinAngleA = gEffect2SinAngleA + framesThisStep * 0x64;
    if (gEffect2SinAngleA > 0x7fff)
    {
        gEffect2SinAngleA = 0;
    }
    gEffect2SinValueA = mathSinf(lbl_803DF9C8 * (f32)(s16)gEffect2SinAngleA / lbl_803DF9CC);
    gEffect2SinAngleB = gEffect2SinAngleB + framesThisStep * 0x32;
    if (gEffect2SinAngleB > 0x7fff)
    {
        gEffect2SinAngleB = 0;
    }
    gEffect2SinValueB = mathSinf(lbl_803DF9C8 * (f32)(s16)gEffect2SinAngleB / lbl_803DF9CC);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

/* Per-config velocity-range band count (emit[6]/sub[6]/col[6] parallel tables). */
#define EFFECT2_VELOCITY_RANGE_COUNT 6

typedef struct EmitterCfg
{
    f32 vel[7][3];
    f32 g08[3];
    f32 f60;
    int emit[EFFECT2_VELOCITY_RANGE_COUNT];
    int sub[EFFECT2_VELOCITY_RANGE_COUNT];
    u16 col[EFFECT2_VELOCITY_RANGE_COUNT];
    u8 b_a0;
    u8 b_a1;
    u8 pad[2];
} EmitterCfg;

extern EmitterCfg gEffect2VelocityRangeTable;
extern FxNode9 lbl_8039C338;
extern int lbl_803DD2C4;
extern int lbl_803DD348;
extern f32 gEffect2SpawnPhaseA;
extern f32 gEffect2SpawnPhaseB;
extern f32 lbl_803DF87C;
extern f32 lbl_803DF884;
extern f32 lbl_803DF888;
extern f32 lbl_803DF88C;
extern f32 lbl_803DF890;
extern f32 lbl_803DF894;
extern f32 lbl_803DF898;
extern f32 lbl_803DF89C;
extern f32 lbl_803DF8A0;
extern f32 lbl_803DF8A4;
extern f32 lbl_803DF8A8;
extern f32 lbl_803DF8AC;
extern f32 lbl_803DF8B0;
extern f32 lbl_803DF8B4;
extern f32 lbl_803DF8B8;
extern f32 lbl_803DF8BC;
extern f32 lbl_803DF8C0;
extern f32 lbl_803DF8C4;
extern f32 lbl_803DF8C8;
extern f32 lbl_803DF8CC;
extern f32 lbl_803DF8D0;
extern f32 lbl_803DF8D4;
extern f32 lbl_803DF8D8;
extern f32 lbl_803DF8DC;
extern f32 lbl_803DF8E0;
extern f32 lbl_803DF8E4;
extern f32 lbl_803DF8E8;
extern f32 lbl_803DF8EC;
extern f32 lbl_803DF8F0;
extern f32 lbl_803DF8F4;
extern f32 lbl_803DF8F8;
extern f32 lbl_803DF8FC;
extern f32 lbl_803DF900;
extern f32 lbl_803DF904;
extern f32 lbl_803DF908;
extern f32 lbl_803DF90C;
extern f32 lbl_803DF910;
extern f32 lbl_803DF914;
extern f32 lbl_803DF918;
extern f32 lbl_803DF91C;
extern f32 lbl_803DF920;
extern f32 lbl_803DF924;
extern f32 lbl_803DF928;
extern f32 lbl_803DF92C;
extern f32 lbl_803DF930;
extern f32 lbl_803DF934;
extern f32 lbl_803DF938;
extern f32 lbl_803DF93C;
extern f32 lbl_803DF940;
extern f32 lbl_803DF944;
extern f32 lbl_803DF948;
extern f32 lbl_803DF94C;
extern f32 lbl_803DF950;
extern f32 lbl_803DF954;
extern f32 lbl_803DF958;
extern f32 lbl_803DF95C;
extern f32 lbl_803DF960;
extern f32 lbl_803DF964;
extern f32 lbl_803DF968;
extern f32 lbl_803DF96C;
extern f32 lbl_803DF970;
extern f32 lbl_803DF974;
extern f32 lbl_803DF978;
extern f32 lbl_803DF97C;
extern f32 lbl_803DF980;
extern f32 lbl_803DF984;
extern f32 lbl_803DF988;
extern f32 lbl_803DF98C;
extern f32 lbl_803DF990;
extern f32 lbl_803DF994;
extern f32 lbl_803DF998;
extern f32 lbl_803DF99C;
extern f32 lbl_803DF9A0;
extern f32 lbl_803DF9A4;
extern f32 lbl_803DF9A8;
extern f32 lbl_803DF9AC;
extern f32 lbl_803DF9B0;
extern f32 lbl_803DF9B4;
extern f32 lbl_803DF9B8;
extern f32 lbl_803DF9BC;

#define FILL338() do {                          \
    lbl_8039C338.posX = lbl_803DF884;             \
    lbl_8039C338.posY = lbl_803DF884;            \
    lbl_8039C338.posZ = lbl_803DF884;            \
    lbl_8039C338.scale = lbl_803DF878;             \
    lbl_8039C338.unk0 = 0;                         \
    lbl_8039C338.unk2 = 0;                         \
    lbl_8039C338.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C338;             \
  } while (0)

extern s32 gEffect2TextureIdTable[];

int Effect2_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    int i;
    PartFxSpawn cfg;

    gEffect2SpawnPhaseA = gEffect2SpawnPhaseA + lbl_803DF870;
    if (gEffect2SpawnPhaseA > 1.0f) gEffect2SpawnPhaseA = lbl_803DF874;
    gEffect2SpawnPhaseB = gEffect2SpawnPhaseB + lbl_803DF87C;
    if (gEffect2SpawnPhaseB > 1.0f) gEffect2SpawnPhaseB = lbl_803DF880;
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
    cfg.startPosX = lbl_803DF884;
    cfg.startPosY = lbl_803DF884;
    cfg.startPosZ = lbl_803DF884;
    cfg.velocityX = lbl_803DF884;
    cfg.velocityY = lbl_803DF884;
    cfg.velocityZ = lbl_803DF884;
    cfg.scale = lbl_803DF884;
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
    case 0x2b0:
        cfg.velocityX = lbl_803DF888 * (f32)(s32)
        randomGetRange(-0x7c, 0x7c);
        cfg.velocityY = lbl_803DF88C * (f32)(s32)
        randomGetRange(0x392, 0x4d6);
        cfg.velocityZ = lbl_803DF890 * (f32)(s32)
        randomGetRange(-0x7c, 0x7c);
        cfg.startPosX = lbl_803DF894 * (f32)(s32)
        randomGetRange(-0x1d0, 0x1d0);
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF898 * (f32)(s32)
        randomGetRange(-0x1c8, 0x1c8);
        cfg.scale = lbl_803DF89C * (f32)(s32)
        randomGetRange(0x1d, 0x21);
        cfg.lifetimeFrames = 0x13f;
        cfg.textureId = 0x26d;
        cfg.behaviorFlags = 0x400100;
        break;
    case 0x2b1:
        cfg.velocityX = gEffect2VelocityRangeTable.vel[0][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[0][1], gEffect2VelocityRangeTable.vel[0][2]);
        cfg.velocityY = gEffect2VelocityRangeTable.vel[1][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[1][1], gEffect2VelocityRangeTable.vel[1][2]);
        cfg.velocityZ = gEffect2VelocityRangeTable.vel[2][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[2][1], gEffect2VelocityRangeTable.vel[2][2]);
        cfg.startPosX = gEffect2VelocityRangeTable.vel[3][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[3][1], gEffect2VelocityRangeTable.vel[3][2]);
        cfg.startPosY = gEffect2VelocityRangeTable.vel[4][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[4][1], gEffect2VelocityRangeTable.vel[4][2]);
        cfg.startPosZ = gEffect2VelocityRangeTable.vel[5][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[5][1], gEffect2VelocityRangeTable.vel[5][2]);
        cfg.scale = gEffect2VelocityRangeTable.vel[6][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[6][1], gEffect2VelocityRangeTable.vel[6][2]);
        cfg.lifetimeFrames = randomGetRange((s32)gEffect2VelocityRangeTable.g08[1], gEffect2VelocityRangeTable.g08[2]) + (s32)gEffect2VelocityRangeTable.g08[
            0];
        cfg.colorWord0 = gEffect2VelocityRangeTable.col[0];
        cfg.colorWord1 = gEffect2VelocityRangeTable.col[1];
        cfg.colorWord2 = gEffect2VelocityRangeTable.col[2];
        cfg.overrideColor0 = gEffect2VelocityRangeTable.col[3];
        cfg.overrideColor1 = gEffect2VelocityRangeTable.col[4];
        cfg.overrideColor2 = gEffect2VelocityRangeTable.col[5];
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++) if (gEffect2VelocityRangeTable.emit[i] != 0) cfg.behaviorFlags |= 1 << (gEffect2VelocityRangeTable.emit[i] - 1);
        cfg.renderFlags = 0x2000000;
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++) if (gEffect2VelocityRangeTable.sub[i] != 0) cfg.renderFlags |= 1 << (gEffect2VelocityRangeTable.sub[i] - 1);
        cfg.textureId = (s32)gEffect2VelocityRangeTable.f60;
        cfg.initialAlpha = randomGetRange(gEffect2VelocityRangeTable.b_a0, gEffect2VelocityRangeTable.b_a1);
        break;
    case 0x2b2:
        cfg.velocityX = lbl_803DF8A0 * (f32)(s32)
        randomGetRange(-0x128, 0xf9);
        cfg.velocityY = lbl_803DF8A4 * (f32)(s32)
        randomGetRange(0x150, 0x2de);
        cfg.velocityZ = lbl_803DF8A8 * (f32)(s32)
        randomGetRange(-0xfc, 0xf9);
        randomGetRange(0, 0);
        cfg.startPosX = lbl_803DF884;
        randomGetRange(1, 1);
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF8AC * (f32)(s32)
        randomGetRange(0, 0);
        cfg.scale = lbl_803DF8B0 * (f32)(s32)
        randomGetRange(0xa, 0x30);
        cfg.lifetimeFrames = randomGetRange(1, 0x26) + 0xe;
        cfg.textureId = 0x1f;
        cfg.behaviorFlags = 0x1000200;
        break;
    case 0x2af:
        cfg.scale = lbl_803DF8B4;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        if ((int)randomGetRange(0, 1) != 0) cfg.behaviorFlags = 0x8100210;
        else cfg.behaviorFlags = 0x180210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ae:
        cfg.startPosY = lbl_803DF8B8;
        cfg.scale = lbl_803DF8B4;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ad:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.scale = lbl_803DF8C0;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400200;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x2ac:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0x3e8, 0x640);
        cfg.velocityY = lbl_803DF8C4 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.scale = lbl_803DF8C0;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400100;
        cfg.textureId = 0xc0e;
        break;
    case 0x2ab:
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DF8C8 * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF8CC;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2aa:
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DF8D0 * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF8CC;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2a9:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x1f4);
        cfg.scale = lbl_803DF8D4;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x26d;
        break;
    case 0x2a8:
        cfg.velocityX = lbl_803DF8D8 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.velocityY = lbl_803DF8DC * (f32)(s32)
        randomGetRange(5, 0x10);
        cfg.velocityZ = lbl_803DF8E0 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.scale = lbl_803DF8E4;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x201;
        break;
    case 0x2a7:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3c, 0x14);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF8E8 * (f32)(s32)
        randomGetRange(7, 0xa);
        cfg.velocityY = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-0x28, -0x1e);
        cfg.scale = lbl_803DF8F0 * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = randomGetRange(0x186, 0x1c2);
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.overrideColor0 = cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.overrideColor1 = cfg.colorWord1 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.overrideColor2 = cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.renderFlags = 0x1000020;
        cfg.behaviorFlags = 0x86000000;
        cfg.textureId = 0x3a2;
        break;
    case 0x2a6:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3c, 0x14);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF8E8 * (f32)(s32)
        randomGetRange(7, 0xa);
        cfg.velocityY = lbl_803DF8F4 * (f32)(s32)
        randomGetRange(-0x28, -0x1e);
        cfg.scale = lbl_803DF8F8 * (f32)(s32)
        randomGetRange(0x64, 0x78);
        cfg.lifetimeFrames = 0x3b6;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.textureId = 0x5c;
        break;
    case 0x2a5:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0x50, 0x78);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a4:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x5a, 0x5a);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityX = lbl_803DF904 * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityY = lbl_803DF908 * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF90C * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.scale = lbl_803DF87C * (f32)(s32)
        randomGetRange(0x50, 0xc8);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a3:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DF910 * (f32)(s32)
        randomGetRange(0x46, 0x64);
        cfg.scale = lbl_803DF8F4 * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0x2d;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x16c;
        break;
    case 0x2a2:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DF914;
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DF918 * (f32)(s32)
        randomGetRange(0xc, 0x10);
        cfg.velocityZ = lbl_803DF91C * (f32)(s32)
        randomGetRange(0xc, 0x10);
        cfg.scale = lbl_803DF920;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0xc9d;
        break;
    case 0x29d:
        if (spawnParams == 0)
            FILL338();
        cfg.sourceVecX = 0x3e8;
        cfg.sourceVecY = 0x3e8;
        cfg.sourceVecZ = 0x3e8;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 6;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x4a0010;
        if ((int)randomGetRange(0, 1) != 0) cfg.renderFlags = 0x202;
        else cfg.renderFlags = 0x102;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF87C * (f32)(s32)
            randomGetRange(0, 3) + lbl_803DF870;
            cfg.textureId = 0xc0f;
        }
        else
        {
            cfg.scale = lbl_803DF87C * (f32)(s32)
            randomGetRange(0, 3) + lbl_803DF924;
            cfg.textureId = 0xc0f;
        }
        break;
    case 0x29e:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF928;
            cfg.textureId = 0x74;
        }
        else
        {
            cfg.scale = lbl_803DF92C;
            cfg.textureId = 0x74;
        }
        cfg.renderFlags = 2;
        break;
    case 0x29f:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        cfg.renderFlags = 2;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF8C8;
            cfg.textureId = 0xc22;
        }
        else
        {
            cfg.scale = lbl_803DF930;
            cfg.textureId = 0xdc;
        }
        break;
    case 0x2a0:
        if (spawnParams == 0)
            FILL338();
        cfg.lifetimeFrames = 0x1e;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180010;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF934 * (f32)(s32)
            randomGetRange(0x14, 0x32);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = lbl_803DF938 * (f32)(s32)
            randomGetRange(0x14, 0x32);
            cfg.textureId = 0x73;
        }
        break;
    case 0x2a1:
        if (spawnParams == 0)
            FILL338();
        cfg.lifetimeFrames = 0x3c;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x480010;
        cfg.renderFlags = 2;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF93C * (f32)(s32)
            randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = lbl_803DF940 * (f32)(s32)
            randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        break;
    case 0x297:
        cfg.velocityX = lbl_803DF944 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.velocityY = lbl_803DF948 * (f32)(s32)
        randomGetRange(5, 0x10);
        cfg.velocityZ = lbl_803DF94C * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.scale = lbl_803DF950;
        cfg.lifetimeFrames = 0x54;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x25b:
        cfg.scale = lbl_803DF954;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x7b;
        break;
    case 0x25c:
    case 0x269:
    case 0x27d:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF958 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF960 * (f32)(s32)
        randomGetRange(0xe, 0x12);
        cfg.scale = lbl_803DF964;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25c)
        {
            cfg.textureId = 0x7a;
            cfg.quadVertex3Pad06 = 0x25d;
        }
        else if (effectId == 0x272)
        {
            cfg.textureId = 0x202;
            cfg.quadVertex3Pad06 = 0x273;
        }
        else if (effectId == 0x27d)
        {
            cfg.textureId = 0x7a;
            cfg.quadVertex3Pad06 = 0x27e;
        }
        else
        {
            cfg.textureId = 0x1fe;
            cfg.quadVertex3Pad06 = 0x26a;
        }
        break;
    case 0x25d:
    case 0x26a:
    case 0x273:
    case 0x27e:
        cfg.scale = lbl_803DF964;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x7a;
        if (effectId == 0x25d)
        {
            cfg.textureId = 0x7a;
        }
        else if (effectId == 0x273)
        {
            cfg.textureId = 0x202;
        }
        else if (effectId == 0x27e)
        {
            cfg.textureId = 0x7a;
        }
        else
        {
            cfg.textureId = 0x1fe;
        }
        break;
    case 0x25e:
    case 0x26b:
    case 0x27b:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF958 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0xe, 0x12);
        cfg.scale = lbl_803DF968;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x25f;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25e)
        {
            cfg.textureId = 0x79;
            cfg.quadVertex3Pad06 = 0x25d;
        }
        else if (effectId == 0x27b)
        {
            cfg.textureId = 0x1fb;
            cfg.quadVertex3Pad06 = 0x27c;
        }
        else if (effectId == 0x274)
        {
            cfg.textureId = 0x202;
            cfg.quadVertex3Pad06 = 0x275;
        }
        else
        {
            cfg.textureId = 0x1ff;
            cfg.quadVertex3Pad06 = 0x26c;
        }
        break;
    case 0x25f:
    case 0x26c:
    case 0x275:
    case 0x27c:
        cfg.scale = lbl_803DF968;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25f)
        {
            cfg.textureId = 0x79;
        }
        else if (effectId == 0x275)
        {
            cfg.textureId = 0x202;
        }
        else if (effectId == 0x27c)
        {
            cfg.textureId = 0x1fb;
        }
        else
        {
            cfg.textureId = 0x1ff;
        }
        break;
    case 0x260:
    case 0x261:
    case 0x262:
    case 0x278:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x26, 0x26);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x6c, 0x6c);
        cfg.velocityX = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(-6, 6);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        if (effectId == 0x278) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x260];
        break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF904 * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480110;
        if (effectId == 0x276) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x263];
        break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF904 * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480100;
        if (effectId == 0x277) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x266];
        break;
    case 0x26d:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x12, 0x12);
        cfg.velocityZ = lbl_803DF970 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF974;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26e:
        cfg.scale = lbl_803DF974;
        cfg.lifetimeFrames = 0x55;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26f:
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF978;
        cfg.lifetimeFrames = 0x7d;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x125;
        break;
    case 0x270:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 5);
        cfg.scale = lbl_803DF97C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x810020c;
        cfg.textureId = 0x167;
        break;
    case 0x271:
        cfg.startPosY = lbl_803DF884;
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF980;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100204;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x167;
        break;
    case 0x286:
    case 0x287:
    case 0x288:
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 2);
        cfg.velocityX = lbl_803DF96C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF96C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DF984;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        if (effectId == 0x286) cfg.textureId = 0x160;
        else if (effectId == 0x287) cfg.textureId = 0x200;
        else if (effectId == 0x288) cfg.textureId = 0xdd;
        break;
    case 0x27f:
        cfg.scale = lbl_803DF988 * *(f32*)((char*)sourceObj + 8);
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80080208;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0x6400;
        cfg.colorWord1 = 0x3200;
        cfg.colorWord2 = 0xa000;
        cfg.overrideColor0 = 0x1f4;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0x3e8;
        cfg.renderFlags = 0x20;
        break;
    case 0x280:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF98C + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0x14, 0x14);
            cfg.startPosY = lbl_803DF98C;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x14, 0x14);
        }
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF994 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF990;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        cfg.textureId = randomGetRange(0, 2) + 0x208;
        break;
    case 0x281:
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF99C;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0xa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0x5000;
        cfg.colorWord1 = 0x1e00;
        cfg.colorWord2 = 0x7800;
        cfg.overrideColor0 = 0x5000;
        cfg.overrideColor1 = 0x1e00;
        cfg.overrideColor2 = 0x7800;
        cfg.renderFlags = 0x20;
        break;
    case 0x282:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DF970 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(4, 4);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.behaviorFlags = 0x81488200;
        cfg.textureId = 0xc0a;
        break;
    case 0x283:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = lbl_803DF960 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x284:
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF9A4;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0x9b00;
        cfg.overrideColor0 = 0x9600;
        cfg.overrideColor1 = 0x1400;
        cfg.overrideColor2 = 0x1400;
        cfg.renderFlags = 0x20;
        break;
    case 0x285:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.velocityZ = lbl_803DF8D0 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.scale = lbl_803DF870 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A8;
        cfg.lifetimeFrames = randomGetRange(0, 0x32) + 0x32;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0xc0a;
        break;
    case 0x258:
        cfg.velocityX = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF9AC;
        cfg.lifetimeFrames = randomGetRange(0x50, 0x82);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x7b;
        break;
    case 0x289:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.startPosZ = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x3c) + lbl_803DF880;
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x14, 0x8c);
        cfg.behaviorFlags = 0x80400209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x28a:
        cfg.startPosX = lbl_803DF884;
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF9B0;
        cfg.scale = lbl_803DF904;
        cfg.initialAlpha = 0x55;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x40);
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc9d;
        break;
    case 0x28b:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x12c);
        cfg.scale = lbl_803DF978;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x159;
        break;
    case 0x28c:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0xc8);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF9B4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x88108;
        cfg.textureId = 0x159;
        break;
    case 0x28d:
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0xa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x500200;
        cfg.textureId = 0x159;
        break;
    case 0x28e:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0x12c, 0x708);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.velocityX = gEffect2ScrollPhaseA * (lbl_803DF970 * (f32)(s32)
        randomGetRange(-0x28, 0x28)
        )
        ;
        cfg.velocityZ = -gEffect2ScrollPhaseA * (lbl_803DF970 * (f32)(s32)
        randomGetRange(-0x28, 0x28)
        )
        ;
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x118;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x300020;
        cfg.behaviorFlags = 0x2008000;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x63bf;
        cfg.overrideColor1 = 0x9e7;
        cfg.overrideColor2 = 0x3e8;
        cfg.textureId = 0x23b;
        break;
    case 0x28f:
    case 0x290:
    case 0x291:
    case 0x292:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x230;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x86000008;
        cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.colorWord1 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.textureId = effectId + 0x113;
        break;
    case 0x293:
    case 0x294:
    case 0x295:
    case 0x296:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = lbl_803DF9B8;
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityX = lbl_803DF9BC * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF870 * (f32)(s32)
        randomGetRange(0x64, 0xc8);
        cfg.velocityZ = lbl_803DF9BC * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x31000020;
        cfg.behaviorFlags = 0x8e000108;
        cfg.colorWord0 = (u16)(randomGetRange(0, (effectId - 0x292) * 0x2710) + 0x63bf);
        cfg.colorWord1 = (u16)(randomGetRange(0, (effectId - 0x292) * 0x2710) + 0x3caf);
        cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.textureId = effectId + 0x10f;
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
    lbl_803DD348 = lbl_803DD2C4;
    return spawnResult;
}
#undef FILL338

EmitterCfg gEffect2VelocityRangeTable =
{
    {
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.01f, 0.0f, 0.0f },
    },
    { 10.0f, 0.0f, 0.0f },
    517.0f,
    { 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0 },
    { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
    0xFF,
    0xFF,
    { 0x00, 0x00 },
};
