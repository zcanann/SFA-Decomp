#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
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

extern ModgfxActiveEffect* gModgfxActiveEffectRegistry[];

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
FUN_800a2a98(int sourceObj, int effectId, ExpgfxAttachedSourceState* sourceState, u32 spawnFlags,
             u8 modelId)
{
    return 0;
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

u32
FUN_800a3828(int sourceObj, u32 effectId, ExpgfxAttachedSourceState* sourceState, u32 spawnFlags,
             u8 modelId)
{
    return 0;
}

u32
FUN_800a3924(int sourceObj, u32 effectId, ExpgfxAttachedSourceState* sourceState, u32 spawnFlags,
             u8 modelId)
{
    return 0;
}

void Effect1_func03_nop(void)
{
}

void Effect1_release(void)
{
}

void Effect1_initialise(void)
{
}

void Effect2_func03_nop(void);

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

extern f32 timeDelta;
extern u8 framesThisStep;

extern f32 lbl_803DF720;
extern f32 lbl_803DF724;
extern f32 lbl_803DF730;
extern f32 lbl_803DF868;
extern f32 gEffect1SinePhaseScale;
extern f32 gEffect1AnimRampA;
extern f32 gEffect1AnimRampB;
extern int gEffect1SineWaveAPhase;
extern int gEffect1SineWaveBPhase;
extern f32 gEffect1SineWaveB;
extern f32 gEffect1SineWaveA;

#pragma scheduling off
void Effect1_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect1AnimRampA + (step = lbl_803DF720 * timeDelta);
    gEffect1AnimRampA = sum;
    if (sum > 1.0f)
    {
        gEffect1AnimRampA = lbl_803DF724;
    }
    sum = gEffect1AnimRampB + step;
    gEffect1AnimRampB = sum;
    if (sum > 1.0f)
    {
        gEffect1AnimRampB = lbl_803DF730;
    }
    gEffect1SineWaveAPhase = gEffect1SineWaveAPhase + framesThisStep * 0x64;
    if (gEffect1SineWaveAPhase > 0x7fff)
    {
        gEffect1SineWaveAPhase = 0;
    }
    gEffect1SineWaveA = mathSinf(lbl_803DF868 * (f32)(s16)gEffect1SineWaveAPhase / gEffect1SinePhaseScale);
    gEffect1SineWaveBPhase = gEffect1SineWaveBPhase + framesThisStep * 0x32;
    if (gEffect1SineWaveBPhase > 0x7fff)
    {
        gEffect1SineWaveBPhase = 0;
    }
    gEffect1SineWaveB = mathSinf(lbl_803DF868 * (f32)(s16)gEffect1SineWaveBPhase / gEffect1SinePhaseScale);
}

extern f32 lbl_803DF878;
extern f32 lbl_803DFCE0;

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

extern FxNode9 lbl_8039C398;

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

#undef FILL9

extern FxNode9 lbl_8039C380;

#define FILL8() do {                            \
    lbl_8039C380.posX = 0.0f;             \
    lbl_8039C380.posY = 0.0f;            \
    lbl_8039C380.posZ = 0.0f;            \
    lbl_8039C380.scale = 1.0f;             \
    lbl_8039C380.unk0 = 0;                         \
    lbl_8039C380.unk2 = 0;                         \
    lbl_8039C380.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C380;             \
  } while (0)

#undef FILL8

extern FxNode9 lbl_8039C338;
extern f32 lbl_803DF884;

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

extern void vecRotateZXY(void* obj, f32* vec);

#undef FILL338

extern FxNode9 lbl_8039C368;
extern f32 lbl_803DFCEC;

#define FILL368() do {                          \
    lbl_8039C368.posX = lbl_803DFCEC;             \
    lbl_8039C368.posY = lbl_803DFCEC;            \
    lbl_8039C368.posZ = lbl_803DFCEC;            \
    lbl_8039C368.scale = lbl_803DFCE0;             \
    lbl_8039C368.unk0 = 0;                         \
    lbl_8039C368.unk2 = 0;                         \
    lbl_8039C368.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C368;             \
  } while (0)

#undef FILL368

extern FxNode9 lbl_8039C350;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9D4;

#define FILL350() do {                          \
    lbl_8039C350.posX = lbl_803DF9D0;             \
    lbl_8039C350.posY = lbl_803DF9D0;            \
    lbl_8039C350.posZ = lbl_803DF9D0;            \
    lbl_8039C350.scale = lbl_803DF9D4;             \
    lbl_8039C350.unk0 = 0;                         \
    lbl_8039C350.unk2 = 0;                         \
    lbl_8039C350.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C350;             \
  } while (0)

#undef FILL350

extern f32 gEffect1AnimRampC;
extern f32 gEffect1AnimRampD;
// VERIFY lbl_803DF720 may already exist in modgfx.c
// VERIFY lbl_803DF724 may already exist in modgfx.c
// VERIFY lbl_803DF728 may already exist in modgfx.c
extern f32 lbl_803DF72C;
// VERIFY lbl_803DF730 may already exist in modgfx.c
extern f32 lbl_803DF734;
extern f32 lbl_803DF738;
extern f32 lbl_803DF73C;
extern f32 lbl_803DF740;
extern f32 lbl_803DF744;
extern f32 lbl_803DF748;
extern f32 lbl_803DF74C;
extern f32 lbl_803DF750;
extern f32 lbl_803DF754;
extern f32 lbl_803DF758;
extern f32 lbl_803DF75C;
extern f32 lbl_803DF760;
extern f32 lbl_803DF764;
extern f32 lbl_803DF768;
extern f32 lbl_803DF76C;
extern f32 lbl_803DF770;
extern f32 lbl_803DF774;
extern f32 lbl_803DF778;
extern f32 lbl_803DF77C;
extern f32 lbl_803DF780;
extern f32 lbl_803DF784;
extern f32 lbl_803DF788;
extern f32 lbl_803DF78C;
extern f32 lbl_803DF790;
extern f32 lbl_803DF794;
extern f32 lbl_803DF798;
extern f32 lbl_803DF79C;
extern f32 lbl_803DF7A0;
extern f32 lbl_803DF7A4;
extern f32 lbl_803DF7A8;
extern f32 lbl_803DF7AC;
extern f32 lbl_803DF7B0;
extern f32 lbl_803DF7B4;
extern f32 lbl_803DF7B8;
extern f32 lbl_803DF7BC;
extern f32 lbl_803DF7C0;
extern f32 lbl_803DF7C4;
extern f32 lbl_803DF7C8;
extern f32 lbl_803DF7CC;
extern f32 lbl_803DF7D0;
extern f32 lbl_803DF7D4;
extern f32 lbl_803DF7D8;
extern f32 lbl_803DF7DC;
extern f32 lbl_803DF7E0;
extern f32 lbl_803DF7E4;
extern f32 lbl_803DF7E8;
extern f32 lbl_803DF7EC;
extern f32 lbl_803DF7F0;
extern f32 lbl_803DF7F4;
extern f32 lbl_803DF7F8;
extern f32 lbl_803DF7FC;
extern f32 lbl_803DF800;
extern f32 lbl_803DF804;
extern f32 lbl_803DF808;
extern f32 lbl_803DF80C;
extern f32 lbl_803DF810;
extern f32 lbl_803DF814;
extern f32 lbl_803DF818;
extern f32 lbl_803DF81C;
extern f32 lbl_803DF820;
extern f32 lbl_803DF824;
extern f32 lbl_803DF828;
extern f32 lbl_803DF82C;
extern f32 lbl_803DF830;
extern f32 lbl_803DF834;
extern f32 lbl_803DF838;
extern f32 lbl_803DF83C;
extern f32 lbl_803DF840;
extern f32 lbl_803DF844;
extern f32 lbl_803DF848;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF850;
extern f32 lbl_803DF854;
extern f32 lbl_803DF858;
extern FxNode9 lbl_8039C320;
/* MtxBuildArg, vecRotateZXY, randFn_80080100, gExpgfxInterface, randomGetRange
   already declared in modgfx.c. */

/* ===== (2) FILL macro ===== */
#define FILL320() do {                          \
    lbl_8039C320.posX = 0.0f;             \
    lbl_8039C320.posY = 0.0f;            \
    lbl_8039C320.posZ = 0.0f;            \
    lbl_8039C320.scale = 1.0f;             \
    lbl_8039C320.unk0 = 0;                         \
    lbl_8039C320.unk2 = 0;                         \
    lbl_8039C320.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C320;             \
  } while (0)

#pragma peephole off
int Effect1_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    gEffect1AnimRampC = gEffect1AnimRampC + lbl_803DF720;
    if (gEffect1AnimRampC > 1.0f) gEffect1AnimRampC = lbl_803DF724;
    gEffect1AnimRampD = gEffect1AnimRampD + lbl_803DF72C;
    if (gEffect1AnimRampD > 1.0f) gEffect1AnimRampD = lbl_803DF730;
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
    case 0x5fc: /* L_800AF9D8 */
        cfg.scale = lbl_803DF738;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x5c;
        break;
    case 0x5fb: /* L_800AF9F8 */
        cfg.scale = lbl_803DF738;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xe7;
        break;
    case 0x5fa: /* L_800AFA18 */
        cfg.startPosX = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF740 * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF744;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26c;
        break;
    case 0x5f9: /* L_800AFAE0 */
        cfg.startPosX = lbl_803DF748 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF748 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF74C * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF750;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480100;
        cfg.renderFlags = 0x2000000;
        cfg.quadVertex3Pad06 = 0x5e9;
        cfg.textureId = 0x26c;
        break;
    case 0x5e9: /* L_800AFBBC */
        cfg.scale = lbl_803DF750;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x26c;
        break;
    case 0x3a7: /* L_800AFBF0 */
        cfg.scale = lbl_803DF754;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x73;
        break;
    case 0x3a5: /* L_800AFC1C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF760 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x3a6: /* L_800AFD80 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF76C * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF770 * (f32)(s32)
        randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x3a3: /* L_800AFEEC */
        cfg.scale = lbl_803DF73C;
        cfg.lifetimeFrames = 0x4;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x64;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x3a4: /* L_800AFF20 */
        cfg.velocityX = lbl_803DF774 * (f32)(s32)
        randomGetRange(0x19, 0x64);
        cfg.velocityY = lbl_803DF778 * (f32)(s32)
        randomGetRange(0x42, 0x64);
        cfg.velocityZ = lbl_803DF77C * (f32)(s32)
        randomGetRange(0x11, 0x64);
        cfg.startPosX = lbl_803DF780 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DF734;
        cfg.startPosZ = lbl_803DF784 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF788 * (f32)(s32)
        randomGetRange(0x27, 0x50);
        cfg.lifetimeFrames = randomGetRange(0x14, 0x20) + 0xdb;
        cfg.textureId = 0x20c;
        cfg.colorWord0 = 0x10000 - 0x1d0b;
        cfg.colorWord1 = 0x5308;
        cfg.colorWord2 = 0x42d9;
        cfg.overrideColor0 = 0x10000 - 0x7502;
        cfg.overrideColor1 = 0x5866;
        cfg.overrideColor2 = 0x40c3;
        cfg.initialAlpha = randomGetRange(0xd, 0x53);
        cfg.behaviorFlags = 0x480208;
        cfg.renderFlags = 0x8002820;
        break;
    case 0x3a8: /* L_800B00EC */
    case 0x3a2:
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.velocityX = spawnParams->scale * (lbl_803DF78C * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.velocityY = spawnParams->scale * (lbl_803DF790 * (f32)(s32)
        randomGetRange(0x50, 0x8c)
        )
        ;
        cfg.velocityZ = spawnParams->scale * (lbl_803DF794 * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.startPosX = lbl_803DF798 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DF75C;
        cfg.startPosZ = lbl_803DF79C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = spawnParams->scale * (lbl_803DF7A0 * (f32)(s32)
        randomGetRange(0x16, 0x46)
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0xe, 0x30) + 0x29;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x10000 - 0x108b;
        cfg.colorWord1 = 0x10000 - 0x3d92;
        cfg.colorWord2 = 0x4aab;
        cfg.overrideColor0 = 0x10000 - 0x161;
        cfg.overrideColor1 = 0x796c;
        cfg.overrideColor2 = 0x57a0;
        cfg.initialAlpha = randomGetRange(0x29, 0x64);
        cfg.behaviorFlags = 0x80080108;
        if (effectId == 0x3a2)
        {
            cfg.behaviorFlags |= 0x20000000LL;
        }
        cfg.renderFlags = 0x8400820;
        break;
    case 0x3a1: /* L_800B032C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = lbl_803DF7A4 + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityX = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16*)sourceObj)[2];
        es.ry = ((s16*)sourceObj)[1];
        es.rx = *(s16*)sourceObj;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x3a0: /* L_800B04A0 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = lbl_803DF7A4 + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = lbl_803DF7AC * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityX = lbl_803DF760 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(2, 6);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16*)sourceObj)[2];
        es.ry = ((s16*)sourceObj)[1];
        es.rx = *(s16*)sourceObj;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DF764 * (f32)(s32)
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
    case 0x39f: /* L_800B066C */
        cfg.velocityY = lbl_803DF7B4 * (f32)(s32)
        randomGetRange(0xa, 0xe);
        cfg.scale = lbl_803DF7B8;
        cfg.lifetimeFrames = 0x1;
        cfg.initialAlpha = 0x23;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x64;
        break;
    case 0x39a: /* L_800B06CC */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7BC;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x17c;
        break;
    case 0x39b: /* L_800B06FC */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39c: /* L_800B0724 */
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7A8;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39d: /* L_800B0750 */
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x17c;
        break;
    case 0x39e: /* L_800B0788 */
        cfg.velocityZ = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF7C0 * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x1480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x17c;
        break;
    case 0x399: /* L_800B0888 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x64;
        break;
    case 0x397: /* L_800B095C */
        cfg.startPosX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF7CC * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF7D0;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.quadVertex3Pad06 = 0x398;
        cfg.textureId = 0xc0d;
        break;
    case 0x398: /* L_800B0A30 */
        cfg.scale = lbl_803DF7D0;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0d;
        break;
    case 0x5f7: /* L_800B0A64 */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7D4;
        cfg.lifetimeFrames = 0x73;
        cfg.behaviorFlags = 0x8100110;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x77;
        break;
    case 0x5f6: /* L_800B0A98 */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7D8;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x202;
        cfg.textureId = 0x26c;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7DC;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7B0;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF7DC;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2002;
        cfg.textureId = 0x528;
        break;
    case 0x5f5: /* L_800B0BC8 */
        cfg.velocityX = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(-0x384, 0x384);
        cfg.velocityZ = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(-0x384, 0x384);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7E4;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x110;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0xe4;
        break;
    case 0x5f4: /* L_800B0C64 */
        cfg.startPosX = lbl_803DF740 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DF740 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(0x12c, 0x190);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7E0;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5f0: /* L_800B0D2C */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7BC;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x26c;
        break;
    case 0x5f1: /* L_800B0D5C */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f2: /* L_800B0D84 */
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7A8;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f3: /* L_800B0DB0 */
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x528;
        break;
    case 0x5ef: /* L_800B0DE8 */
        cfg.startPosX = lbl_803DF720 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosZ = lbl_803DF720 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityY = lbl_803DF7E8;
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7EC;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x3f2;
        break;
    case 0x5ee: /* L_800B0E9C */
        cfg.velocityZ = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7F4;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x33;
        break;
    case 0x5f8: /* L_800B0F48 */
        cfg.velocityX = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7F4;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x33;
        break;
    case 0x5ed: /* L_800B0FF4 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0x5fe;
        break;
    case 0x5fd: /* L_800B10B4 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8 * (f32)(s32)
        randomGetRange(1, 3);
        cfg.lifetimeFrames = randomGetRange(0, 0x64) + 0x78;
        cfg.behaviorFlags = 0x6100000;
        cfg.renderFlags = 0x10000 - 0x8000;
        cfg.textureId = 0x5ff;
        break;
    case 0x5eb: /* L_800B11B4 */
        cfg.velocityZ = lbl_803DF7F8 * (f32)(s32)
        randomGetRange(0xb4, 0xc8);
        cfg.velocityX = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF740 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7AC;
        cfg.lifetimeFrames = randomGetRange(0x8c, 0xa5);
        cfg.behaviorFlags = 0x81100000;
        cfg.renderFlags = (u32)(0x410000 - 0x7fe0);
        cfg.colorWord0 = 0x7d0;
        cfg.colorWord1 = 0x7d0;
        cfg.colorWord2 = randomGetRange(-0x1388, 0x1388) + 0x2710;
        cfg.overrideColor0 = 0x1f40;
        cfg.overrideColor1 = 0x1f40;
        cfg.overrideColor2 = randomGetRange(-0x1388, 0x1388) + 0x2ee0;
        cfg.textureId = 0x639;
        break;
    case 0x5ea: /* L_800B12D4 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7B0;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x64);
        cfg.behaviorFlags = 0x81100000;
        cfg.renderFlags = (u32)(0x410000 - 0x7fe0);
        cfg.colorWord0 = 0x7d0;
        cfg.colorWord1 = 0x7d0;
        cfg.colorWord2 = randomGetRange(-0x1388, 0x1388) + 0x4e20;
        cfg.overrideColor0 = 0x1f40;
        cfg.overrideColor1 = 0x1f40;
        cfg.overrideColor2 = randomGetRange(-0x1388, 0x1388) + 0x7d00;
        cfg.textureId = 0x639;
        break;
    case 0x5e3: /* L_800B13B0 */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e4: /* L_800B1410 */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e5: /* L_800B1470 */
        cfg.scale = lbl_803DF800;
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0xb9;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5e6: /* L_800B149C */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x12c;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e7: /* L_800B14FC */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e8: /* L_800B155C */
        cfg.scale = lbl_803DF800;
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5dd: /* L_800B1588 */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0xc79;
        break;
    case 0x5de: /* L_800B168C */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x166;
        break;
    case 0x5df: /* L_800B1790 */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5e0: /* L_800B1894 */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc76;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x5e1: /* L_800B1938 */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc74;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x5e2: /* L_800B19DC */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc75;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x396: /* L_800B1A80 */
        cfg.scale = lbl_803DF754;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x159;
        break;
    case 0x394: /* L_800B1AAC */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.scale = lbl_803DF818 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x2f);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0xc79;
        break;
    case 0x395: /* L_800B1BBC */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.scale = lbl_803DF740 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100110;
        cfg.textureId = 0xc79;
        break;
    case 0x393: /* L_800B1CCC */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosX = lbl_803DF730 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityY = lbl_803DF7B4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF81C;
        cfg.lifetimeFrames = randomGetRange(0x212, 0x2a8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        cfg.textureId = 0xc0d;
        break;
    case 0x392: /* L_800B1DC4 */
        cfg.startPosX = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityX = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DF820 * (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80400201;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x390: /* L_800B1F2C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF760 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x391: /* L_800B2090 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF76C * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF770 * (f32)(s32)
        randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x38f: /* L_800B21FC */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x28, 0x8c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.velocityX = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF824 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DF7E4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x300000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x38a: /* L_800B2354 */
        if (spawnParams == 0)
            FILL320();
        cfg.startPosX = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0xa, -0xa);
        cfg.startPosY = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityX = lbl_803DF7DC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF7DC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
        }
        cfg.scale = lbl_803DF828 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x55;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x125;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (randomGetRange(0, 0x2710) + 0x10000) - 0x2711;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = cfg.colorWord0 / 10;
        cfg.overrideColor1 = cfg.colorWord1 / 10;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0xa0;
        break;
    case 0x38b: /* L_800B25A8 */
        cfg.scale = lbl_803DF82C;
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x82000108;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0xc0a;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38c: /* L_800B25DC */
        cfg.startPosY = lbl_803DF830;
        cfg.scale = lbl_803DF834;
        cfg.lifetimeFrames = 0x190;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x38d: /* L_800B2610 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.startPosY = lbl_803DF838;
        cfg.velocityX = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.velocityY = lbl_803DF738 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.velocityZ = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.scale = lbl_803DF83C;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x3010000 - 0x8000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38e: /* L_800B2740 */
        cfg.velocityX = lbl_803DF840 * (f32)(s32)
        randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.velocityZ = lbl_803DF840 * (f32)(s32)
        randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.scale = lbl_803DF83C;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x389: /* L_800B2818 */
        if (spawnParams == 0)
            FILL320();
        cfg.startPosX = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        es.w = lbl_803DF7DC * (f32)(s32)
        randomGetRange(0, 0x258) + lbl_803DF844;
        cfg.velocityY = lbl_803DF720 * (f32)(s32)
        randomGetRange(0, 0xc8) + 1.0f;
        cfg.velocityX = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803DF724;
        cfg.velocityY = cfg.velocityY * es.w;
        cfg.velocityX = cfg.velocityX * es.w;
        cfg.scale = lbl_803DF84C * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF848;
        cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000120;
        cfg.renderFlags = 0x200800;
        cfg.textureId = 0xc0a;
        cfg.quadVertex3Pad06 = 0x385;
        break;
    case 0x388: /* L_800B2A08 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(0, 0x10);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x2e, 0x2e);
        cfg.velocityY = lbl_803DF748 * (f32)(s32)
        randomGetRange(0x10, 0x1e);
        cfg.scale = lbl_803DF7EC;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x1fb;
        break;
    case 0x384: /* L_800B2ACC */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF724 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x387: /* L_800B2C64 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF724 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x81000120;
        cfg.textureId = 0xc0a;
        break;
    case 0x385: /* L_800B2DFC */
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF854;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x386: /* L_800B2EA4 */
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF858;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    default: /* L_800B2F6C */
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
#undef FILL320

void Effect9_func05(void);
