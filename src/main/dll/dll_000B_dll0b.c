/*
 * dll0b (DLL 0x0B) - the engine-wide procedural effects DLL: the shared
 * back end behind the model-graphics (modgfx), explosion-graphics
 * (expgfx) and particle (partfx/projgfx) systems used across the game's
 * effect DLLs.
 *
 * Responsibilities:
 *   - expgfx slot-pool lifecycle (modgfx_allocExpgfxPools /
 *     modgfx_releaseExpgfxPools) and per-spawn config setup.
 *   - modgfx vertex animation: per-frame texcoord scroll, RGB / alpha /
 *     scale / position / rotation channel lerps over a vertex command
 *     stream, double-buffered between an active and base vertex buffer.
 *   - the active-effect registry (modgfx_releaseActiveEffectsBy*): a
 *     0x32-slot table reclaimed by effect type, owner object, or wholesale.
 *   - projgfx_spawnPresetEffect: the preset-effect dispatcher keyed on
 *     effectId 0x422..0x42d, filling an ExpgfxSpawnConfig and handing it
 *     to gExpgfxInterface->spawnEffect.
 *   - the partfx pending-spawn queue (dll_0B_func10..func18) and the
 *     0x32-slot active-particle table (dll_0B_func04 allocate,
 *     dll_0B_func05 update, dll_0B_func09 render, fn_800A1040 free).
 *
 * The three FUN_800a* return-0 stubs Ghidra emitted here were dead
 * (uncalled mirrors duplicated into every effect DLL) and removed.
 */
#include "main/dll/bonespawndata_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/resource.h"

typedef struct ModgfxEffectSlot
{
    u8 pad0[0x4 - 0x0];
    void* sourceObj;
    u8 pad8[0xC - 0x8];
    s16 unkC;
    u8 padE[0x18 - 0xE];
    f32 posOffsetX;
    f32 posOffsetY;
    f32 posOffsetZ;
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x60 - 0x30];
    f32 unk60;
    f32 unk64;
    f32 unk68;
    u8 pad6C[0x9C - 0x6C];
    void* unk9C;
    u8 padA0[0xA4 - 0xA0];
    s32 sourceFlags;
    u8 padA8[0xBC - 0xA8];
    f32 alphaDelta;
    f32 alphaCurrent;
    u8 padC4[0xFC - 0xC4];
    s16 frameIndex;
    s16 frameDuration;
    u8 pad100[0x106 - 0x100];
    s16 unk106;
    s16 unk108;
    s16 unk10A;
    s16 animSlotId;
    u8 pad10E[0x139 - 0x10E];
    s8 emitterCount;
    u8 unk13A;
    u8 pad13B[0x13C - 0x13B];
    u8 pendingFrameIdx;
    u8 pad13D[0x13E - 0x13D];
    u8 unk13E;
    u8 pad13F[0x140 - 0x13F];
} ModgfxEffectSlot;

STATIC_ASSERT(offsetof(ModgfxState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(ModgfxState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(ModgfxState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(ModgfxState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(ModgfxState, posCurX) == 0x60);
STATIC_ASSERT(offsetof(ModgfxState, activeChannel) == 0xFC);
STATIC_ASSERT(offsetof(ModgfxState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(ModgfxState, rotOffsetZ) == 0x106);

#pragma scheduling on
#pragma peephole on
static inline int* Modgfx_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32
#define PARTFX_ACTIVE_EFFECT_COUNT 0x32
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
    return state->vertexBuffers[1 - (uint)state->activeVertexBufferIndex];
}

static ModgfxActiveEffect** modgfx_getActiveEffectRegistry(void)
{
    return gModgfxActiveEffectRegistry;
}

extern void* memcpy(void* dst, const void* src, u32 n);

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
    uint* slotPoolBases;

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
    uint allocatedPool;
    u32* poolActiveMasks;
    s8* poolActiveCounts;
    int poolIndex;
    uint* slotPoolBases;
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
        memset(*slotPoolBases, 0, EXPGFX_POOL_BYTES);
        FUN_802420e0(*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases = slotPoolBases + 1;
        poolIndex = poolIndex + 1;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    memset(-0x7fc63ec8, 0, 0x500);
}

void modgfx_initExpgfxSpawnConfig(undefined4 unused1, undefined4 unused2, u8 colorLowByte,
                                  u32 textureWord, u32 scaleBits)
{
    u32 setupWord;
    u16 setupValue;

    setupWord = FUN_80286840();
    memset((int)&gExpgfxSpawnConfig, 0, EXPGFX_SPAWN_CONFIG_PREFIX_BYTES);
    gExpgfxSpawnConfig.colorByte0.value = (u8)setupValue;
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
    gExpgfxSpawnConfig.quadVertex3Pad06 = (s32)setupWord;
    *(undefined4*)&gExpgfxSpawnConfig.scale = scaleBits;
    gExpgfxSpawnConfig.texture.word = textureWord;
    gExpgfxSpawnConfig.colorByte0.lowByte = colorLowByte;
    FUN_8028688c();
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
    uint wrapCountS;
    uint wrapCountT;

    state = (ModgfxState*)stateArg;
    stepS = lbl_803E00B8 * *(float*)(command + 4) * lbl_803DDF04;
    stepT = lbl_803E00B8 * *(float*)(command + 8) * lbl_803DDF04;
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
        if (wrapCountS == (int)state->vertexCount)
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
        if (wrapCountT == (int)state->vertexCount)
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
    undefined8 convFrames;
    undefined8 convBlueBase;
    undefined8 convFrames2;

    biasU = DOUBLE_803e00c0;
    vtxData = *(int*)(state + (uint) * (byte*)(state + 0x130) * 4 + 0x78);
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
                (float)((double)CONCAT44(0x43300000,
                                         (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xc)) - DOUBLE_803e00c0);
            ((ModgfxState*)state)->blendColorG =
                (float)((double)CONCAT44(0x43300000,
                                         (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xd)) - biasU);
            ((ModgfxState*)state)->blendColorB =
                (float)((double)CONCAT44(0x43300000,
                                         (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10 +
                                             0xe)) - biasU);
            biasS = DOUBLE_803e00c8;
            ((ModgfxState*)state)->blendColorStepR =
                (targetR - (float)((double)CONCAT44(0x43300000,
                                                    (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xc)) - biasU)) /
                (float)((double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000) -
                    DOUBLE_803e00c8);
            convFrames = (double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000);
            ((ModgfxState*)state)->blendColorStepG =
                (targetG - (float)((double)CONCAT44(0x43300000,
                                                    (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xd)) - biasU)) /
                (float)(convFrames - biasS);
            convBlueBase = (double)CONCAT44(0x43300000,
                                            (uint) * (byte*)(vtxData + *((ModgfxVertexGroupCmd*)command)->indices * 0x10
                                                + 0xe)
            );
            convFrames2 = (double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000);
            ((ModgfxState*)state)->blendColorStepB = (targetB - (float)(convBlueBase - biasU)) / (float)(convFrames2 -
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
    double biasS;
    ushort rotAngle0;
    ushort rotAngle1;
    ushort rotAngle2;
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
                rotAngle0 = *(ushort*)state->unk04;
                rotAngle1 = rotAngle0;
                rotAngle2 = rotAngle0;
                FUN_80017748(&rotAngle0, (float*)(command + 4));
            }
            *(undefined4*)&state->posStepX = *(undefined4*)(command + 4);
            *(undefined4*)&state->posStepY = *(undefined4*)(command + 8);
            *(undefined4*)&state->posStepZ = *(undefined4*)(command + 0xc);
        }
        else
        {
            state->posStepX =
                *(float*)(command + 4) /
                (float)((double)CONCAT44(0x43300000, (int)state->blendFrameCount ^ 0x80000000) -
                    DOUBLE_803e00c8);
            state->posStepY =
                *(float*)(command + 8) /
                (float)((double)CONCAT44(0x43300000, (int)state->blendFrameCount ^ 0x80000000) - biasS
                );
            state->posStepZ =
                *(float*)(command + 0xc) /
                (float)((double)CONCAT44(0x43300000, (int)state->blendFrameCount ^ 0x80000000) - biasS
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
        targetRotZ = (short)(int)*(float*)(command + 4);
        targetRotY = (short)(int)*(float*)(command + 8);
        targetRotX = (short)(int)*(float*)(command + 0xc);
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
                (short)(((int)targetRotZ - (int)state->rotOffsetZ) / (int)state->blendFrameCount
                );
            state->rotStepY =
                (short)(((int)targetRotY - (int)state->rotOffsetY) / (int)state->blendFrameCount
                );
            state->rotStepX =
                (short)(((int)targetRotX - (int)state->rotOffsetX) / (int)state->blendFrameCount
                );
        }
    }
    state->rotOffsetZ = state->rotOffsetZ + state->rotStepZ;
    state->rotOffsetY = state->rotOffsetY + state->rotStepY;
    state->rotOffsetX = state->rotOffsetX + state->rotStepX;
}

void modgfx_updateVertexAlpha(int state, int command, int mode, uint channel)
{
    float targetAlpha;
    double biasU;
    int work0;
    int vtxOff;
    int curVtxData;
    int baseVtxData;
    int work1;
    int work2;
    undefined8 convAlphaBase;

    biasU = DOUBLE_803e00c0;
    curVtxData = *(int*)(state + (uint) * (byte*)(state + 0x130) * 4 + 0x78);
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
                *(undefined*)(curVtxData + work2) = *(undefined*)(baseVtxData + work2);
                work1 = work1 + 2;
            }
            return;
        }
        work1 = state + (channel & 0xff) * 8;
        *(float*)(work1 + 0xac) =
            (targetAlpha - (float)((double)CONCAT44(0x43300000,
                                                    (uint) * (byte*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->
                                                        indices *
                                                        0x10 + 0xf)) - DOUBLE_803e00c0))
            / (float)((double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000) -
                DOUBLE_803e00c8);
        convAlphaBase = (double)CONCAT44(0x43300000,
                                         (uint) * (byte*)(baseVtxData + *((ModgfxVertexGroupCmd*)command)->indices *
                                             0x10 + 0xf));
        *(float*)(work1 + 0xb0) = (float)(convAlphaBase - biasU);
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
        *(undefined*)(baseVtxData + vtxOff) = *(undefined*)(curVtxData + vtxOff);
        work0 = work0 + 2;
    }
}

void modgfx_updateVertexScale(int state, int command, int mode, uint channel)
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
    undefined8 convFrames;
    undefined8 convA;
    undefined8 convB;

    biasS = DOUBLE_803e00c8;
    if (mode == 1)
    {
        targetX = ((ModgfxVertexGroupCmd*)command)->valueX;
        targetY = ((ModgfxVertexGroupCmd*)command)->valueY;
        targetZ = ((ModgfxVertexGroupCmd*)command)->valueZ;
        if ((int)((ModgfxState*)state)->blendFrameCount == 0)
        {
            work2 = (int)((ModgfxState*)state)->baseVertexData;
            vtxBufA = *(int*)(state + (uint) * (byte*)(state + 0x130) * 4 + 0x78);
            work1 = 0;
            for (work0 = 0; work0 < ((ModgfxVertexGroupCmd*)command)->indexCount; work0 = work0 + 1)
            {
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10;
                *(short*)(work2 + off) =
                    (short)(int)((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short*)(work2 + off) ^ 0x80000000) -
                        biasS) * targetX);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 2;
                *(short*)(work2 + off) =
                    (short)(int)((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short*)(work2 + off) ^ 0x80000000) -
                        biasS) * targetY);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 4;
                convA = (double)CONCAT44(0x43300000, (int)*(short*)(work2 + off) ^ 0x80000000);
                *(short*)(work2 + off) = (short)(int)((float)(convA - biasS) * targetZ);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10;
                *(undefined2*)(vtxBufA + off) = *(undefined2*)(work2 + off);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 2;
                *(undefined2*)(vtxBufA + off) = *(undefined2*)(work2 + off);
                off = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + work1) * 0x10 + 4;
                *(undefined2*)(vtxBufA + off) = *(undefined2*)(work2 + off);
                work1 = work1 + 2;
            }
            return;
        }
        work1 = state + (channel & 0xff) * 0x18;
        *(float*)(work1 + 0x3c) =
            (targetX - *(float*)(work1 + 0x30)) /
            (float)((double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000) -
                DOUBLE_803e00c8);
        convFrames = (double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000);
        *(float*)(work1 + 0x40) = (targetY - *(float*)(work1 + 0x34)) / (float)(convFrames - biasS);
        *(float*)(work1 + 0x44) =
            (targetZ - *(float*)(work1 + 0x38)) /
            (float)((double)CONCAT44(0x43300000, (int)((ModgfxState*)state)->blendFrameCount ^ 0x80000000) - biasS);
    }
    work0 = state + (channel & 0xff) * 0x18;
    *(float*)(work0 + 0x30) = *(float*)(work0 + 0x3c) * lbl_803DDF04 + *(float*)(work0 + 0x30);
    *(float*)(work0 + 0x34) = *(float*)(work0 + 0x40) * lbl_803DDF04 + *(float*)(work0 + 0x34);
    *(float*)(work0 + 0x38) = *(float*)(work0 + 0x44) * lbl_803DDF04 + *(float*)(work0 + 0x38);
    targetX = lbl_803E00B4;
    vtxBufA = (int)((ModgfxState*)state)->baseVertexData;
    work1 = *(int*)(state + (uint) * (byte*)(state + 0x130) * 4 + 0x78);
    off = 0;
    for (work2 = 0; work2 < ((ModgfxVertexGroupCmd*)command)->indexCount; work2 = work2 + 1)
    {
        if (targetX != *(float*)(work0 + 0x30))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10;
            convB = (double)CONCAT44(0x43300000, (int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x30) * (float)(convB - DOUBLE_803e00c8));
        }
        if (targetX != *(float*)(work0 + 0x34))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 2;
            convB = (double)CONCAT44(0x43300000, (int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x34) * (float)(convB - DOUBLE_803e00c8));
        }
        if (targetX != *(float*)(work0 + 0x38))
        {
            vtxOff = *(short*)((int)((ModgfxVertexGroupCmd*)command)->indices + off) * 0x10 + 4;
            convB = (double)CONCAT44(0x43300000, (int)*(short*)(vtxBufA + vtxOff) ^ 0x80000000);
            *(short*)(work1 + vtxOff) =
                (short)(int)(*(float*)(work0 + 0x38) * (float)(convB - DOUBLE_803e00c8));
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

void modgfx_releaseActiveEffectsByType(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                       undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                       undefined8 param_7, undefined8 param_8, short effectType,
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
                param_1 = FUN_80017814(activeEffect->releaseTransformSource);
            }
            if (activeEffect->instanceHandle != 0)
            {
                FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
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
            param_1 = FUN_80017814(activeEffect);
            activeEffects[i] = NULL;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
}

void modgfx_releaseActiveEffectsByOwner(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                        undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                        undefined8 param_7, undefined8 param_8, int ownerToken)
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
                FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
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
            param_1 = FUN_80017814(activeEffect);
            activeEffects[i] = NULL;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
}

void modgfx_releaseAllActiveEffects(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                    undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                    undefined8 param_7, undefined8 param_8)
{
    modgfx_releaseActiveEffectsByType(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                      0, 1);
}

void modgfx_resetActiveEffectRegistry(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                      undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                      undefined8 param_7, undefined8 param_8)
{
    ModgfxActiveEffect** activeEffects;
    int i;

    modgfx_releaseActiveEffectsByType(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                      0, 1);
    activeEffects = modgfx_getActiveEffectRegistry();
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i = i + 1)
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
            tailEffects = tailEffects + 1;
            i = i + -1;
        }
        while (i != 0);
    }
}

undefined4
projgfx_spawnPresetEffect(int sourceObj, undefined4 effectId, ExpgfxAttachedSourceState* sourceState,
                          uint spawnFlags, undefined modelId, undefined2* extraArgs)
{
    undefined4 spawnResult;
    uint randPick;
    int cfgHead[3];
    undefined2 cfgSourceVecX;
    undefined2 cfgSourceVecY;
    undefined2 cfgSourceVecZ;
    undefined4 cfgSourcePosX;
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
    undefined2 cfgTextureSetupFlags;
    undefined2 cfgTextureId;
    uint cfgBehaviorFlags;
    undefined4 cfgRenderFlags;
    undefined4 cfgOverrideColor0;
    uint cfgOverrideColor1;
    uint cfgOverrideColor2;
    undefined2 cfgColorWord0;
    undefined2 cfgColorWord1;
    undefined2 cfgColorWord2;
    undefined cfgEffectIdByte;
    undefined cfgInitialAlpha;
    undefined cfgLinkGroup;
    undefined cfgModelIdByte;
    undefined4 convHi0;
    uint randVal0;
    undefined4 convHi1;
    uint randVal1;
    undefined4 convHi2;
    uint randVal2;
    undefined4 convHi3;
    uint randVal3;
    undefined4 convHi4;
    uint randVal4;
    undefined4 convHi5;
    uint randVal5;
    undefined4 convHi6;
    uint randVal6;

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
        cfgEffectIdByte = (undefined)effectId;
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
            cfgInitialAlpha = (undefined) * extraArgs;
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
            cfgInitialAlpha = (undefined) * extraArgs;
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

extern u8 lbl_8039BE98[];
extern ModgfxPendingSpawn gModgfxPendingSpawnQueue[];
extern s16 gModgfxLastSpawnHandle;
extern s16 gModgfxSequenceParamIndex;
extern ModgfxPendingSpawn* gModgfxPendingSpawnWriteCursor;
extern ModgfxPendingSpawn* gModgfxPendingSpawnStartCursor;
#define gModgfxSpawnContext (*(ModgfxSpawnContext *)lbl_8039BE98)
s16 dll_0B_func18(void) { return gModgfxLastSpawnHandle; }

#pragma scheduling off
#pragma peephole off
void dll_0B_func17(u32 flags)
{
    gModgfxSpawnContext.flags |= flags;
}

void dll_0B_func15(void* params) { memcpy(gModgfxSpawnContext.sequenceParams, params, 0xe); }

void dll_0B_func14(s16 value)
{
    u8* state = lbl_8039BE98;
    state = state + gModgfxSequenceParamIndex * 2;
    *(s16*)(state + 0x46) = value;
}

void dll_0B_func13(s16 x)
{
    gModgfxSequenceParamIndex = x;
}

void dll_0B_func12(void)
{
    gModgfxSequenceParamIndex++;
}

void dll_0B_func11(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10)
{
    u32 sequenceIndex = (u8)gModgfxSequenceParamIndex;
    gModgfxPendingSpawnWriteCursor->sequenceIndex = sequenceIndex;
    gModgfxPendingSpawnWriteCursor->param14 = param14;
    gModgfxPendingSpawnWriteCursor->param10 = param10;
    gModgfxPendingSpawnWriteCursor->modelOrResource = modelOrResource;
    gModgfxPendingSpawnWriteCursor->posX = posX;
    gModgfxPendingSpawnWriteCursor->posY = posY;
    gModgfxPendingSpawnWriteCursor->posZ = posZ;
    gModgfxPendingSpawnWriteCursor++;
}

void dll_0B_func10(void)
{
    ModgfxPendingSpawn* cursor = gModgfxPendingSpawnQueue;
    gModgfxPendingSpawnStartCursor = cursor;
    gModgfxPendingSpawnWriteCursor = cursor;
    gModgfxSequenceParamIndex = 0;
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

extern u8 lbl_803DD282;
extern void fn_800A1040(s16 a, int b);

#pragma scheduling on
#pragma peephole on
void dll_0B_func0B(void)
{
    lbl_803DD282 = lbl_803DD282 + 1;
}

#pragma scheduling off
void dll_0B_func06(void)
{
    fn_800A1040(0, 1);
}

void dll_0B_release(void)
{
    fn_800A1040(0, 1);
}

extern f32 lbl_803DF430;
extern f32 lbl_803DF434;
extern void mm_free(void* p);
extern void textureFree(void* resource);
extern void*gPartfxActiveEffects[];
extern void Obj_FreeObject(void* obj);
#pragma peephole off
void dll_0B_initialise(void)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        arr[i] = NULL;
    }
}

#pragma peephole off
void dll_0B_func0F(int p1, u8 p2, u8 p3, int p4, int p5)
{
    f32 fz;
    f32 fz2;
    memset(&gModgfxSpawnContext, 0, sizeof(gModgfxSpawnContext));
    gModgfxSpawnContext.modeByte = p2;
    gModgfxSpawnContext.attachedSource = (void*)p1;
    gModgfxSpawnContext.sourceModeCopy = p2;
    fz = lbl_803DF430;
    gModgfxSpawnContext.posX = fz;
    gModgfxSpawnContext.posY = fz;
    gModgfxSpawnContext.posZ = fz;
    gModgfxSpawnContext.vecX = fz;
    gModgfxSpawnContext.vecY = fz;
    gModgfxSpawnContext.vecZ = fz;
    fz2 = lbl_803DF434;
    gModgfxSpawnContext.scale = fz2;
    gModgfxSpawnContext.word40 = p4;
    gModgfxSpawnContext.word3C = p5;
    gModgfxSpawnContext.byte59 = p3;
    gModgfxSpawnContext.byte5A = 0;
    gModgfxSpawnContext.byte5B = 0;
}

#pragma peephole reset

void dll_0B_func0A(s16* p)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && *p == arr[i]->sequenceId)
        {
            arr[i]->releaseRequested = 1;
        }
    }
    *p = -1;
}

void dll_0B_func0C(void* p1, char p2)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == p1)
        {
            arr[i]->byte13B = p2;
        }
    }
}

void dll_0B_func0D(void* p1)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == p1)
        {
            arr[i]->releaseRequested = 1;
        }
    }
}

void dll_0B_func07(void* p1)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] == NULL) continue;
        if (arr[i]->sourceObject != p1) continue;
        if (arr[i]->instanceObject != NULL)
        {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL)
        {
            textureFree(arr[i]->textureResource);
        }
        if (arr[i]->textureIsBorrowed == 0)
        {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}

#pragma dont_inline on
void fn_800A1040(s16 p1, int p2)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] == NULL) continue;
        if (p1 != arr[i]->sequenceId && p2 == 0) continue;
        if (arr[i]->auxAllocation != NULL)
        {
            mm_free(arr[i]->auxAllocation);
        }
        if (arr[i]->instanceObject != NULL)
        {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL)
        {
            textureFree(arr[i]->textureResource);
        }
        if (arr[i]->textureIsBorrowed == 0)
        {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}
#pragma dont_inline reset

extern void Sfx_PlayFromObject(void* obj, int id);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 timeDelta;
extern u8 framesThisStep;

extern void GXSetCullMode(int mode);
extern void setTextColor(void* ctx, int r, int g, int b, int a);
extern void _textSetColor(void* ctx, int r, int g, int b, int a);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void gxTexColorFn_80079254(void);
extern void textRenderSetupFn_80079804(void);
extern void gxBlendFn_80078b4c(void);
extern void drawFn_8005cf8c(void* a, void* b, int count);

/* EN v1.0 0x800A433C  size: 1764b  per-bone particle vertex update + draw. */

extern void* textureLoadAsset(int id);
extern void* mmAlloc(int size, int align, int flag);

extern f32 lbl_803DF438;

void fn_800A02DC(ModgfxState* state, f32* in)
{
    extern f32 lbl_803DD284;
    s32 dx, dy;
    ModgfxVertexData* cur;
    ModgfxVertexData* prev;
    u8 ovx, ovy;
    int i;
    int j;
    ModgfxVertexData* slot;

    dx = (s32)(lbl_803DF438 * (in[1] * lbl_803DD284));
    dy = (s32)(lbl_803DF438 * (in[2] * lbl_803DD284));

    cur = state->vertexBuffers[state->activeVertexBufferIndex];
    prev = state->vertexBuffers[1 - (u32)state->activeVertexBufferIndex];

    ovx = 0;
    ovy = 0;
    for (i = 0; i < (s32)state->vertexCount; i++)
    {
        cur->texCoordS = prev->texCoordS;
        cur->texCoordT = prev->texCoordT;
        cur->texCoordS = (s16)(cur->texCoordS + dx);
        if ((s32)cur->texCoordS > 0x100) ovx++;
        if ((s32)cur->texCoordS < -0x100) ovx++;
        cur->texCoordT = (s16)(cur->texCoordT + dy);
        if ((s32)cur->texCoordT > 0x100) ovy++;
        if ((s32)cur->texCoordT < -0x100) ovy++;
        cur++;
        prev++;
    }

    slot = state->vertexBuffers[state->activeVertexBufferIndex];
    for (j = 0; j < (s32)state->vertexCount; j++)
    {
        if ((s32)ovx == (s32)state->vertexCount)
        {
            if ((s32)slot->texCoordS > 0x100)
            {
                slot->texCoordS -= 0x100;
            }
            else
            {
                slot->texCoordS += 0x100;
            }
        }
        if ((s32)ovy == (s32)state->vertexCount)
        {
            if ((s32)slot->texCoordT > 0x100)
            {
                slot->texCoordT -= 0x100;
            }
            else
            {
                slot->texCoordT += 0x100;
            }
        }
        slot++;
    }
}

#pragma peephole on
void fn_800A0FD0(ModgfxState* state)
{
    int i;
    ModgfxVertexData* src;
    ModgfxVertexData* dst = state->vertexBuffers[state->activeVertexBufferIndex];
    src = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++)
    {
        dst->posX = src->posX;
        dst->posY = src->posY;
        dst->posZ = src->posZ;
        dst->colorR = src->colorR;
        dst->colorG = src->colorG;
        dst->colorB = src->colorB;
        dst->alpha = src->alpha;
        dst++;
        src++;
    }
}

void fn_800A0478(ModgfxState* state)
{
    int i;
    ModgfxVertexData* dst;
    ModgfxVertexData* src;
    f32 f1;
    f32 f0;
    src = state->vertexBuffers[1 - (u32)state->activeVertexBufferIndex];
    dst = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++)
    {
        dst->posX = src->posX;
        dst->posY = src->posY;
        dst->posZ = src->posZ;
        dst->colorR = src->colorR;
        dst->colorG = src->colorG;
        dst->colorB = src->colorB;
        dst->alpha = src->alpha;
        dst++;
        src++;
    }
    f1 = *(f32*)&lbl_803DF434;
    *(f32*)((char*)state + 0x30) = f1;
    *(f32*)((char*)state + 0x34) = f1;
    *(f32*)((char*)state + 0x38) = f1;
    f0 = lbl_803DF430;
    *(f32*)((char*)state + 0x3C) = f0;
    *(f32*)((char*)state + 0x40) = f0;
    *(f32*)((char*)state + 0x44) = f0;
    *(f32*)((char*)state + 0x48) = f1;
    *(f32*)((char*)state + 0x4C) = f1;
    *(f32*)((char*)state + 0x50) = f1;
    *(f32*)((char*)state + 0x54) = f0;
    *(f32*)((char*)state + 0x58) = f0;
    *(f32*)((char*)state + 0x5C) = f0;
}

#pragma peephole off
void fn_800A081C(int p1, int p2, int mode)
{
    extern void vecRotateZXY(void*, f32*);
    extern f32 lbl_803DD284;
    extern f32 lbl_803DF430;
    extern f32 lbl_803DF434;

    if (mode == 1)
    {
        if (((s16*)((char*)p1 + 238))[((ModgfxState*)p1)->activeChannel] == 0)
        {
            int flags = ((ModgfxState*)p1)->flags;
            if ((flags & 0x4) != 0 || (flags & 0x80000) != 0)
            {
                s16 buf[12];
                f32* fbuf = (f32*)&buf[4];
                s16 v;
                f32 fill = lbl_803DF430;
                fbuf[1] = fill;
                fbuf[2] = fill;
                fbuf[3] = fill;
                fbuf[0] = lbl_803DF434;
                v = *((ModgfxState*)p1)->unk04;
                buf[0] = v;
                buf[1] = v;
                buf[2] = v;
                vecRotateZXY(buf, (f32*)(p2 + 0x4));
            }
            ((ModgfxState*)p1)->posStepX = ((ModgfxVertexGroupCmd*)p2)->valueX;
            ((ModgfxState*)p1)->posStepY = ((ModgfxVertexGroupCmd*)p2)->valueY;
            ((ModgfxState*)p1)->posStepZ = ((ModgfxVertexGroupCmd*)p2)->valueZ;
        }
        else
        {
            ((ModgfxState*)p1)->posStepX = ((ModgfxVertexGroupCmd*)p2)->valueX / (f32)(s32)((ModgfxState*)p1)->
                blendFrameCount;
            ((ModgfxState*)p1)->posStepY = ((ModgfxVertexGroupCmd*)p2)->valueY / (f32)(s32)((ModgfxState*)p1)->
                blendFrameCount;
            ((ModgfxState*)p1)->posStepZ = ((ModgfxVertexGroupCmd*)p2)->valueZ / (f32)(s32)((ModgfxState*)p1)->
                blendFrameCount;
        }
        ((ModgfxState*)p1)->posCurX = ((ModgfxState*)p1)->posCurX + ((ModgfxState*)p1)->posStepX;
        ((ModgfxState*)p1)->posCurY = ((ModgfxState*)p1)->posCurY + ((ModgfxState*)p1)->posStepY;
        ((ModgfxState*)p1)->posCurZ = ((ModgfxState*)p1)->posCurZ + ((ModgfxState*)p1)->posStepZ;
    }
    else
    {
        ((ModgfxState*)p1)->posCurX = ((ModgfxState*)p1)->posStepX * lbl_803DD284 + ((ModgfxState*)p1)->posCurX;
        ((ModgfxState*)p1)->posCurY = ((ModgfxState*)p1)->posStepY * lbl_803DD284 + ((ModgfxState*)p1)->posCurY;
        ((ModgfxState*)p1)->posCurZ = ((ModgfxState*)p1)->posStepZ * lbl_803DD284 + ((ModgfxState*)p1)->posCurZ;
    }
}

/* EN v1.0 0x800A09C4  size: 240b  modgfx_stepS16VectorLerp: integer-vector lerp setup.
 * On mode 1, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
void modgfx_stepS16VectorLerp(int* obj, f32* params, int mode)
{
    if (mode == 1)
    {
        int tx = (int)params[1];
        int ty = (int)params[2];
        int tz = (int)params[3];
        if (((ModgfxState*)obj)->blendFrameCount != 0)
        {
            ((ModgfxState*)obj)->rotStepZ = (s16)(
                ((s16)tx - ((ModgfxState*)obj)->rotOffsetZ) / ((ModgfxState*)obj)->blendFrameCount);
            ((ModgfxState*)obj)->rotStepY = (s16)(
                ((s16)ty - ((ModgfxState*)obj)->rotOffsetY) / ((ModgfxState*)obj)->blendFrameCount);
            ((ModgfxState*)obj)->rotStepX = (s16)(
                ((s16)tz - ((ModgfxState*)obj)->rotOffsetX) / ((ModgfxState*)obj)->blendFrameCount);
        }
        else
        {
            ((ModgfxState*)obj)->rotOffsetZ = tx;
            ((ModgfxState*)obj)->rotStepZ = 0;
            ((ModgfxState*)obj)->rotOffsetY = ty;
            ((ModgfxState*)obj)->rotStepY = 0;
            ((ModgfxState*)obj)->rotOffsetX = tz;
            ((ModgfxState*)obj)->rotStepX = 0;
        }
    }
    ((ModgfxState*)obj)->rotOffsetZ += ((ModgfxState*)obj)->rotStepZ;
    ((ModgfxState*)obj)->rotOffsetY += ((ModgfxState*)obj)->rotStepY;
    ((ModgfxState*)obj)->rotOffsetX += ((ModgfxState*)obj)->rotStepX;
}

/* EN v1.0 0x800A113C  size: 276b  dll_0B_func0E: flag every active effect
 * whose owner object has the 0x800 state bit by setting its byte _13e. */
void dll_0B_func0E(void)
{
    PartfxEffectState* effect;
    GameObject* sourceObject;
    int i;
    PartfxEffectState** effects = (PartfxEffectState**)gPartfxActiveEffects;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        effect = effects[i];
        if (effect != NULL)
        {
            sourceObject = effect->sourceObject;
            if (sourceObject != NULL && (sourceObject->objectFlags & 0x800) != 0)
            {
                effect->frameUpdated = 1;
            }
        }
    }
}

extern f32 lbl_803DD284;

void dll_0B_onMapSetup(void)
{
    int i;

    fn_800A1040(0, 1);
    for (i = 0; i < 0x32; i++)
    {
        gPartfxActiveEffects[i] = NULL;
    }
}

extern void* Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32 x);

void dll_0B_func08(void* param)
{
    int** arr = (int**)gPartfxActiveEffects;
    int i;

    for (i = 0; i < 0x32; i++)
    {
        if (arr[i] != NULL && *(void**)((char*)arr[i] + 0x4) == param)
        {
            if (*(int*)((char*)arr[i] + 0xa4) & 0x10000)
            {
                fn_800A1040(*(s16*)((char*)arr[i] + 0x10c), 0);
            }
            else
            {
                *(f32*)((char*)arr[i] + 0x18) = *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x18);
                *(f32*)((char*)arr[i] + 0x1c) = *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x1c);
                *(f32*)((char*)arr[i] + 0x20) = *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x20);
                *(f32*)((char*)arr[i] + 0x14) = *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x8);
                *(s16*)((char*)arr[i] + 0x10) = *(s16*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x4);
                *(s16*)((char*)arr[i] + 0xe) = *(s16*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x2);
                *(s16*)((char*)arr[i] + 0xc) = *(s16*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x0);
                if (*(int*)((char*)arr[i] + 0xa4) & 0x2)
                {
                    *(f32*)((char*)arr[i] + 0x6c) += *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x24);
                    *(f32*)((char*)arr[i] + 0x70) += *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x28);
                    *(f32*)((char*)arr[i] + 0x74) += *(f32*)((char*)*(void**)((char*)arr[i] + 0x4) + 0x2c);
                }
                if (!(*(int*)((char*)arr[i] + 0xa4) & 0x200000))
                {
                    *(u32*)((char*)arr[i] + 0xa4) |= 0x200000;
                }
                *(int*)((char*)arr[i] + 0x4) = 0;
            }
        }
    }
}


void dll_0B_func16(void* a, void* b, void* c, void* d, void* e, int f, void* g)
{
    gModgfxSpawnContext.pendingSpawns = gModgfxPendingSpawnQueue;
    gModgfxSpawnContext.pendingSpawnCount = gModgfxPendingSpawnWriteCursor - gModgfxPendingSpawnStartCursor;
    if (g == NULL && f == 0)
    {
        gModgfxSpawnContext.flags |= 0x2000000LL;
    }
    else
    {
        gModgfxSpawnContext.flags |= 0x4000000LL;
    }
    if (gModgfxSpawnContext.flags & 1)
    {
        if (gModgfxSpawnContext.attachedSource != NULL)
        {
            gModgfxSpawnContext.posX += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosX;
            gModgfxSpawnContext.posY += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosY;
            gModgfxSpawnContext.posZ += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosZ;
        }
        else
        {
            gModgfxSpawnContext.posX += ((ExpgfxSourceObject*)a)->localPosX;
            gModgfxSpawnContext.posY += ((ExpgfxSourceObject*)a)->localPosY;
            gModgfxSpawnContext.posZ += ((ExpgfxSourceObject*)a)->localPosZ;
        }
    }
    {
        extern s16 dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g);
        gModgfxLastSpawnHandle = dll_0B_func04(&gModgfxSpawnContext, 0, (int)c, b, (int)e, d, f, g);
    }
}

extern f32 lbl_803DF460;
extern s16 lbl_803DD280;

int dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g)
{
    u8* st = (u8*)base;
    int slot;
    int found;
    int i;
    int n;
    int divThresh;
    int total;
    int base0;
    f32 fz430;
    f32 fz434;
    void** scan;

    total = 0;
    found = 0;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT && found == 0; i++)
    {
        if (((void**)gPartfxActiveEffects)[i] == NULL) found = 1;
    }
    if (found)
    {
        slot = i - 1;
    }
    else
    {
        slot = -1;
    }
    if (slot == -1)
    {
        return 0;
    }

    n = *(s8*)(st + 0x5d);
    for (i = 0; i < n; i++)
    {
        u8* item = *(u8**)st + i * 0x18;
        if ((*(u32*)item & 0xf7fff180) == 0 && *(s16*)(item + 0x14) != 0)
        {
            total += *(s16*)(item + 0x14);
        }
    }

    base0 = 0;
    if ((*(u32*)(st + 0x54) & 0x800) == 0)
    {
        base0 = ((e * 3) << 4) + (int)(long)((c * 3) << 4);
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot] = (PartfxEffectState*)mmAlloc(base0 + n * 0x18 + total * 2 + 0x240, 0x15, 0);
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot] == NULL)
    {
        fn_800A1040(0, 0);
        return -1;
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData = (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot] + sizeof(PartfxEffectState);
    {
        u8* bufp = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData;
        if ((*(u32*)(st + 0x54) & 0x800) == 0)
        {
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[0] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[1] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[2] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[0] = bufp;
            bufp += c * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[1] = bufp;
            bufp += c * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[2] = bufp;
            bufp += c * 16;
        }
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->baseVertexBuffer = bufp;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->baseColorBuffer = bufp + 0x80;
    }

    if (*(int*)(st + 0x40) != 0)
    {
        divThresh = e / *(int*)(st + 0x40);
    }
    else
    {
        divThresh = e;
    }
    if ((*(u32*)(st + 0x54) & 0x800) == 0)
    {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4)
        {
            u8* dstc = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[k];
            int bias = 0;
            int j;
            s16* sd = (s16*)d;
            for (j = 0; j < e; j++)
            {
                if ((*(u32*)(st + 0x54) & 0x8000000) && j == divThresh)
                {
                    bias = *(int*)(st + 0x3c);
                }
                dstc[1] = sd[0] - bias;
                dstc[2] = sd[1] - bias;
                dstc[3] = sd[2] - bias;
                sd += 3;
                dstc += 0x10;
            }
        }
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = NULL;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 0;
    if (g != NULL)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = g;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 1;
    }
    else if (f != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = textureLoadAsset(f);
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 0;
    }

    if ((*(u32*)(st + 0x54) & 0x800) == 0)
    {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4)
        {
            u8* dstv = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[k];
            int j;
            s16* sb = (s16*)b;
            for (j = 0; j < c; j++)
            {
                *(s16*)(dstv + 0) = sb[0];
                *(s16*)(dstv + 2) = sb[1];
                *(s16*)(dstv + 4) = sb[2];
                if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource != NULL)
                {
                    *(s16*)(dstv + 8) = lbl_803DF460 * ((f32)sb[3] / (f32) * (u16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource +
                        0xa));
                    *(s16*)(dstv + 0xa) = lbl_803DF460 * ((f32)sb[4] / (f32) * (u16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource +
                        0xc));
                }
                dstv[0xc] = 0xff;
                dstv[0xd] = 0xff;
                dstv[0xe] = 0xff;
                dstv[0xf] = 0xff;
                dstv += 0x10;
                sb += 5;
            }
        }
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCount = st[0x5d];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word114 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word118 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word11C = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxAllocation = NULL;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->releaseRequested = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte13D = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageTimer = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->nextStage = -1;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->requestedStage = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[0] = *(s16*)(st + 0x46);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[1] = *(s16*)(st + 0x48);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[2] = *(s16*)(st + 0x4a);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[3] = *(s16*)(st + 0x4c);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[4] = *(s16*)(st + 0x4e);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[5] = *(s16*)(st + 0x50);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[6] = *(s16*)(st + 0x52);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands = (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData + base0 + 0x100;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer = NULL;
    if (total != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer = (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCount * 0x18;
    }

    {
        u8* dst = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer;
        int m;
        int off;
        for (m = 0, off = 0; m < ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCount; m++, off += 0x18)
        {
            ((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands)[off + 0x16] = (*(u8**)st)[off + 0x16];
            *(s16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x14) = *(s16*)(*(u8**)st + off + 0x14);
            *(int*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x10) = 0;
            *(int*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off) = *(int*)(*(u8**)st + off);
            if ((*(int*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off) & 0xf7fff180) == 0 &&
                *(s16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x14) != 0)
            {
                int k;
                *(int*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x10) = 0;
                *(u8**)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x10) = dst;
                dst += *(s16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x14) * 2;
                for (k = 0; k < *(s16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x14); k++)
                {
                    *(s16*)(*(u8**)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0x10) + k * 2) =
                        *(s16*)(*(u8**)(*(u8**)st + off + 0x10) + k * 2);
                }
            }
            *(f32*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 4) = *(f32*)(*(u8**)st + off + 4);
            *(f32*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 8) = *(f32*)(*(u8**)st + off + 8);
            *(f32*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off + 0xc) = *(f32*)(*(u8**)st + off + 0xc);
        }
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->currentStage = -1;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageFrameCountdown = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorVertexCount;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->flags = *(int*)(st + 0x54);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosX = *(f32*)(st + 0x2c);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosY = *(f32*)(st + 0x30);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosZ = *(f32*)(st + 0x34);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->renderScale = *(f32*)(st + 0x38);
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->flags & 1)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosX = *(f32*)(st + 0x2c);
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosY = *(f32*)(st + 0x30);
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosZ = *(f32*)(st + 0x34);
    }
    fz430 = lbl_803DF430;
    fz434 = lbl_803DF434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepX = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepY = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepZ = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[0] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[1] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[2] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[1] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[2] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[0] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[2] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[0] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[1] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[2] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[0] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[1] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetZ = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetY = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetX = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec120 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec122 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec124 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[0].step = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[0].cur = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[1].step = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[1].cur = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorR = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorG = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorB = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepR = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepG = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepB = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityX = *(f32*)(st + 0x20);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityY = *(f32*)(st + 0x24);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityZ = *(f32*)(st + 0x28);
    lbl_803DD280 = lbl_803DD280 + 1;
    if (lbl_803DD280 > 0x4e20)
    {
        lbl_803DD280 = 0;
    }
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sequenceId = lbl_803DD280;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte126 = lbl_803DD282;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexCount = (s16)c;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorVertexCount = (s16)e;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourceObject = *(void**)(st + 4);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->instanceObject = NULL;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourceYawIndex = st[0x5c];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawGroupCount = *(int*)(st + 0x40);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawGroupStride = *(int*)(st + 0x3c);
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->initialStateByte = st[0x59];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->soundHandle = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->activeVertexBufferIndex = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte13B = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->frameUpdated = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer = st[0x5b];
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep = 0x3c / ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer;
    }
    else
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep = 0;
    }
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameFadeStep = 0xff / ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep;
    }
    else
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameFadeStep = 0;
    }
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrame = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->initialDelayFrames = *(s16*)(st + 0x44);
    return ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sequenceId;
}

extern s16 renderModeSetOrGet(int mode);
extern void* Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(void* mtx, int id);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void selectTexture(void* tex, int slot);
extern int getAngle(f32 dx, f32 dz);
extern void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex);
extern void setMatrixFromObjectPos(f32 * mtx, s16 * src);
extern void mtx44Transpose(f32 * src, f32 * dst);
extern void gxTevAddTextureFrameBlendStages(void);
extern void fn_80078DFC(void);
extern void fn_80078ED0(void);
extern void textBlendSetupFn_80078a7c(void);
extern void fn_800542F4(void);
extern f32 lbl_803DF450;
extern f32 lbl_803DF454;
extern f32 lbl_803DF458;
extern f32 lbl_803DF45C;

typedef struct
{
    s16 ang[3];
    s16 pad;
    f32 scale;
    f32 pos[3];
} EffXform;

int dll_0B_func09(void* a0, int a1, int a2, u8 a3, void* a4)
{
    u8 ar;
    u8 ag;
    u8 ab;
    f32 rot[3];
    f32 pos[3];
    EffXform xf;
    f32 mtxA[12];
    f32 mtxB[16];
    int** p;
    int slot;
    void* view;
    void* buf1;
    void* buf2;
    u8 aligned;
    void* tex;
    int texCount;
    int n131;
    int n131p1;
    f32 dirX;
    f32 dirZ;
    f32 dscale;

    n131 = 0;
    n131p1 = 0;
    if (a4 != NULL)
    {
        getAmbientColor(*(u8*)((char*)a4 + 0xf2), &ar, &ag, &ab);
    }
    else
    {
        getAmbientColor(0, &ar, &ag, &ab);
    }
    GXSetCullMode(0);
    if (renderModeSetOrGet(-1) == 1)
    {
        return 1;
    }
    view = Camera_GetCurrentViewSlot();
    p = (int**)gPartfxActiveEffects;
    for (slot = 0; slot < 50; slot++, p++)
    {
        if (*p == NULL) continue;
        if (*(s16*)((char*)*p + 0x10c) == -1) continue;
        if (a3)
        {
            if ((*(int*)((char*)*p + 0xa4) & 0x2000) == 0) continue;
        }
        if (a3)
        {
            if (*(void**)((char*)*p + 4) != a4) continue;
        }
        if (!a3)
        {
            if (*(int*)((char*)*p + 0xa4) & 0x2000) continue;
        }
        if (*(int*)((char*)*p + 0xa4) & 0x800)
        {
            *(u8*)((char*)*p + 0x13e) = 0;
        }
        aligned = 0;
        buf1 = *(void**)((char*)*p + (int)*(u8*)((char*)*p + 0x130) * 4 + 0x78);
        buf2 = *(void**)((char*)*p + (int)*(u8*)((char*)*p + 0x130) * 4 + 0x84);
        xf.pos[0] = lbl_803DF430;
        xf.pos[1] = lbl_803DF430;
        xf.pos[2] = lbl_803DF430;
        xf.scale = lbl_803DF434;
        xf.ang[2] = 0;
        xf.ang[1] = 0;
        pos[0] = *(f32*)((char*)*p + 0x60);
        pos[1] = *(f32*)((char*)*p + 0x64);
        pos[2] = *(f32*)((char*)*p + 0x68);
        if (*(int*)((char*)*p + 0xa4) & 0x4)
        {
            if (lbl_803DF430 == pos[2] + (pos[0] + pos[1]))
            {
                aligned = 1;
            }
            if (!aligned)
            {
                if (*(void**)((char*)*p + 4) != NULL)
                {
                    xf.ang[0] = *(s16*)(*(char**)((char*)*p + 4));
                    xf.ang[1] = *(s16*)(*(char**)((char*)*p + 4) + 2);
                    xf.ang[2] = *(s16*)(*(char**)((char*)*p + 4) + 4);
                    vecRotateZXY(&xf.ang[0], &pos[0]);
                }
            }
        }
        rot[0] = lbl_803DF430;
        rot[1] = lbl_803DF430;
        rot[2] = lbl_803DF430;
        if ((*(int*)((char*)*p + 0xa4) & 1) == 0)
        {
            if (*(void**)((char*)*p + 4) != NULL)
            {
                rot[0] = *(f32*)(*(char**)((char*)*p + 4) + 0x18);
                rot[1] = *(f32*)(*(char**)((char*)*p + 4) + 0x1c);
                rot[2] = *(f32*)(*(char**)((char*)*p + 4) + 0x20);
            }
            else
            {
                rot[0] = *(f32*)((char*)*p + 0x18);
                rot[1] = *(f32*)((char*)*p + 0x1c);
                rot[2] = *(f32*)((char*)*p + 0x20);
                Obj_RotateLocalOffsetByYaw((f32*)((char*)*p + 0x18), &rot[0], *(s8*)((char*)*p + 0x135));
            }
        }
        if (rot[0] > lbl_803DF450 || rot[0] < lbl_803DF454)
        {
            rot[0] = -playerMapOffsetX;
        }
        if (rot[1] > lbl_803DF450 || rot[1] < lbl_803DF454)
        {
            rot[1] = lbl_803DF430;
        }
        if (rot[2] > lbl_803DF450 || rot[2] < lbl_803DF454)
        {
            rot[2] = -playerMapOffsetZ;
        }
        xf.pos[0] = rot[0] + pos[0];
        xf.pos[1] = rot[1] + pos[1];
        xf.pos[2] = rot[2] + pos[2];
        if (*(int*)((char*)*p + 0xa4) & 0x400000)
        {
            dscale = lbl_803DF458 * *(f32*)((char*)*p + 0xd4);
            xf.scale = dscale + dscale / (f32)randomGetRange(1, 10);
        }
        else
        {
            xf.scale = lbl_803DF45C * *(f32*)((char*)*p + 0xd4);
        }
        if (*(int*)((char*)*p + 0xa4) & 0x80000)
        {
            xf.ang[2] = *(s16*)(*(char**)((char*)*p + 4) + 4);
            xf.ang[1] = *(s16*)(*(char**)((char*)*p + 4) + 2);
            xf.ang[0] = *(s16*)(*(char**)((char*)*p + 4));
        }
        else if (aligned && *(void**)((char*)*p + 4) != NULL)
        {
            xf.ang[2] = *(s16*)((char*)*p + 0x106) + *(s16*)(*(char**)((char*)*p + 4) + 4);
            xf.ang[1] = *(s16*)((char*)*p + 0x108) + *(s16*)(*(char**)((char*)*p + 4) + 2);
            xf.ang[0] = *(s16*)((char*)*p + 0x10a) + *(s16*)(*(char**)((char*)*p + 4));
        }
        else if (aligned)
        {
            xf.ang[2] = *(s16*)((char*)*p + 0x106) + *(s16*)((char*)*p + 0x10);
            xf.ang[1] = *(s16*)((char*)*p + 0x108) + *(s16*)((char*)*p + 0xe);
            xf.ang[0] = *(s16*)((char*)*p + 0x10a) + *(s16*)((char*)*p + 0xc);
        }
        else
        {
            xf.ang[2] = *(s16*)((char*)*p + 0x106);
            xf.ang[1] = *(s16*)((char*)*p + 0x108);
            xf.ang[0] = *(s16*)((char*)*p + 0x10a);
        }
        if (*(int*)((char*)*p + 0xa4) & 0x1000)
        {
            if (*(void**)((char*)*p + 4) != NULL)
            {
                dirX = *(f32*)((char*)view + 0x44) - *(f32*)(*(char**)((char*)*p + 4) + 0x18);
                dirZ = *(f32*)&((GameObject*)view)->anim.placementData - *(f32*)(*(char**)((char*)*p + 4) + 0x20);
                dscale = sqrtf(dirX * dirX + dirZ * dirZ);
                if (dscale != lbl_803DF430)
                {
                    dirX = dirX / dscale;
                    dirZ = dirZ / dscale;
                }
                xf.ang[0] = xf.ang[0] + (int)(f32)(u16)
                getAngle(dirX, dirZ);
            }
        }
        xf.pos[0] = xf.pos[0] - playerMapOffsetX;
        xf.pos[2] = xf.pos[2] - playerMapOffsetZ;
        setMatrixFromObjectPos(mtxB, &xf.ang[0]);
        mtx44Transpose(mtxB, mtxA);
        PSMTXConcat((f32*)Camera_GetViewMatrix(), mtxA, mtxA);
        GXLoadPosMtxImm(mtxA, 0);
        tex = *(void**)((char*)*p + 0x98);
        if (tex != NULL)
        {
            texCount = (u8)(*(u16*)((char*)tex + 0x10) >> 8);
        }
        if (tex != NULL && *(u8*)((char*)*p + 0x132) != 0)
        {
            *(u8*)((char*)*p + 0x133) = *(u8*)((char*)*p + 0x133) - 1;
            if (*(u8*)((char*)*p + 0x133) == 0)
            {
                *(u8*)((char*)*p + 0x133) = 0x3c / *(u8*)((char*)*p + 0x132);
                *(u8*)((char*)*p + 0x131) = *(u8*)((char*)*p + 0x131) + 1;
                if ((u8) * (u8*)((char*)*p + 0x131) >= (u32)texCount)
                {
                    *(u8*)((char*)*p + 0x131) = 0;
                }
            }
        }
        if (*(int*)((char*)*p + 0xa4) & 0x8)
        {
            setTextColor(a0, ar, ag, ab, 0xff);
        }
        else if (*(void**)((char*)*p + 4) != NULL && (*(int*)((char*)*p + 0xa4) & 0x4000))
        {
            setTextColor(a0, 0xff, 0xff, 0xff, *(u8*)(*(char**)((char*)*p + 4) + 0x37));
        }
        else
        {
            setTextColor(a0, 0xff, 0xff, 0xff, 0xff);
        }
        tex = *(void**)((char*)*p + 0x98);
        if (tex != NULL)
        {
            n131 = *(u8*)((char*)*p + 0x131);
            n131p1 = (u8)(n131 + 1);
            if (n131p1 > texCount - 1)
            {
                n131p1 = 0;
            }
        }
        if (*(int*)((char*)*p + 0xa4) & 0x1000000)
        {
            if (*(u8*)((char*)*p + 0x13e) != 0 || (*(int*)((char*)*p + 0xa4) & 0x400))
            {
                int j;
                for (j = 0; j < (u8)n131p1; j++)
                {
                    tex = *(void**)tex;
                }
                _textSetColor(a0, 0xff, 0xff, 0xff,
                              (u8)(0xff - *(u8*)((char*)*p + 0x133) * *(u8*)((char*)*p + 0x134)));
                textureSetupFn_800799c0();
                gxTevAddTextureFrameBlendStages();
                fn_80078DFC();
                textRenderSetupFn_80079804();
                selectTexture(tex, 1);
            }
        }
        else if (*(int*)((char*)*p + 0xa4) & 0x2000000)
        {
            textureSetupFn_800799c0();
            fn_80078ED0();
            textRenderSetupFn_80079804();
        }
        else if (*(int*)((char*)*p + 0xa4) & 0x4000000)
        {
            textureSetupFn_800799c0();
            geomDrawFn_800796f0();
            gxTexColorFn_80079254();
            textRenderSetupFn_80079804();
        }
        if (*(int*)((char*)*p + 0xa4) & 0x05000000)
        {
            if (*(u8*)((char*)*p + 0x13e) != 0 || (*(int*)((char*)*p + 0xa4) & 0x400))
            {
                int j;
                tex = *(void**)((char*)*p + 0x98);
                for (j = 0; j < (u8)n131; j++)
                {
                    tex = *(void**)tex;
                }
                selectTexture(tex, 0);
            }
        }
        if (*(int*)((char*)*p + 0xa4) & 0x100)
        {
            gxBlendFn_80078b4c();
        }
        else if ((*(int*)((char*)*p + 0xa4) & 0x10) && (*(int*)((char*)*p + 0xa4) & 0x80))
        {
            textBlendSetupFn_80078a7c();
        }
        else if (*(int*)((char*)*p + 0xa4) & 0x80)
        {
            gxBlendFn_80078b4c();
        }
        else if (*(int*)((char*)*p + 0xa4) & 0x10)
        {
            textBlendSetupFn_80078a7c();
        }
        else
        {
            gxBlendFn_80078b4c();
        }
        if (*(int*)((char*)*p + 0xa4) & 0x40)
        {
            GXSetCullMode(1);
        }
        else
        {
            GXSetCullMode(0);
        }
        if (*(u8*)((char*)*p + 0x13e) != 0 || (*(int*)((char*)*p + 0xa4) & 0x400))
        {
            int di;
            for (di = 0; di < (u8) * (u8*)((char*)*p + 0x136); di++)
            {
                if (*(int*)((char*)*p + 0xa4) & 0x8000000)
                {
                    drawFn_8005cf8c(buf1, buf2, *(s16*)((char*)*p + 0xec) / (u8) * (u8*)((char*)*p + 0x136));
                }
                else
                {
                    drawFn_8005cf8c(buf1, buf2, *(s16*)((char*)*p + 0xec));
                }
                buf1 = (char*)buf1 + ((u8) * (u8*)((char*)*p + 0x137) << 4);
                if (*(int*)((char*)*p + 0xa4) & 0x8000000)
                {
                    buf2 = (char*)buf2 + ((*(s16*)((char*)*p + 0xec) / (u8) * (u8*)((char*)*p + 0x136)) << 4);
                }
            }
            fn_800542F4();
            *(u8*)((char*)*p + 0x130) = 1 - *(u8*)((char*)*p + 0x130);
        }
    }
    return 0;
}

void fn_800A0AB4(void* state, void* p, int mode, u8 idx)
{
    extern f32 lbl_803DD284;
    extern f32 lbl_803DF430;
    extern f32 lbl_803DF43C;
    int k = idx * 2;
    char* slots = (char*)state + 0x78;
    u8* bufB = *(u8**)(slots + *(u8*)((char*)state + 0x130) * 4);
    u8* bufA = *(u8**)((char*)state + 0x80);
    int j;

    if (mode == 1)
    {
        f32 target = *(f32*)((char*)p + 0x4);
        s16 frames = *(s16*)((char*)state + 0xfe);
        if (frames != 0)
        {
            ((f32*)((char*)state + 0xac))[k] =
                (target - (f32)(u32)
            bufA[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xf]
            )
            /
            (f32)frames;
            ((f32*)((char*)state + 0xac))[k + 1] =
                (f32)(u32)
            bufA[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xf];
            goto animate;
        }
        for (j = 0; j < *(s16*)((char*)p + 0x14); j++)
        {
            bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = (int)target;
            bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] =
                bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf];
        }
        return;
    }
animate:
    ((f32*)((char*)state + 0xac))[k + 1] =
        ((f32*)((char*)state + 0xac))[k + 1] +
        ((f32*)((char*)state + 0xac))[k] * lbl_803DD284;
    if (((f32*)((char*)state + 0xac))[k + 1] < lbl_803DF430)
    {
        ((f32*)((char*)state + 0xac))[k + 1] = lbl_803DF430;
    }
    else if (((f32*)((char*)state + 0xac))[k + 1] > lbl_803DF43C)
    {
        ((f32*)((char*)state + 0xac))[k + 1] = lbl_803DF43C;
    }
    {
        int ofs = k * 4 + 0xb0;
        for (j = 0; j < *(s16*)((char*)p + 0x14); j++)
        {
            bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = (int)*(f32*)((char*)state + ofs);
            bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] =
                bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf];
        }
    }
}

void fn_800A0524(void* state, void* p, int mode)
{
    extern f32 lbl_803DF430;
    extern f32 lbl_803DF43C;
    u8* buf = ((u8**)((char*)state + 0x78))[*(u8*)((char*)state + 0x130)];
    int j;

    if (mode == 1)
    {
        f32 tr = *(f32*)((char*)p + 0x4);
        f32 tg = *(f32*)((char*)p + 0x8);
        f32 tb = *(f32*)((char*)p + 0xc);
        if (*(s16*)((char*)state + 0xfe) != 0)
        {
            *(f32*)((char*)state + 0xbc) = (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xc];
            *(f32*)((char*)state + 0xc0) = (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xd];
            *(f32*)((char*)state + 0xc4) = (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xe];
            *(f32*)((char*)state + 0xc8) =
                (tr - (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xc]
            )
            /
            (f32) * (s16*)((char*)state + 0xfe);
            *(f32*)((char*)state + 0xcc) =
                (tg - (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xd]
            )
            /
            (f32) * (s16*)((char*)state + 0xfe);
            *(f32*)((char*)state + 0xd0) =
                (tb - (f32)(u32)
            buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xe]
            )
            /
            (f32) * (s16*)((char*)state + 0xfe);
        }
        else
        {
            *(f32*)((char*)state + 0xbc) = tr;
            *(f32*)((char*)state + 0xc0) = tg;
            *(f32*)((char*)state + 0xc4) = tb;
            *(f32*)((char*)state + 0xd0) =
            *(f32*)((char*)state + 0xcc) =
            *(f32*)((char*)state + 0xc8) = lbl_803DF430;
        }
    }
    *(f32*)((char*)state + 0xbc) += *(f32*)((char*)state + 0xc8);
    *(f32*)((char*)state + 0xc0) += *(f32*)((char*)state + 0xcc);
    *(f32*)((char*)state + 0xc4) += *(f32*)((char*)state + 0xd0);
    if (*(f32*)((char*)state + 0xbc) < lbl_803DF430)
    {
        *(f32*)((char*)state + 0xbc) = lbl_803DF430;
    }
    else if (*(f32*)((char*)state + 0xbc) > lbl_803DF43C)
    {
        *(f32*)((char*)state + 0xbc) = lbl_803DF43C;
    }
    if (*(f32*)((char*)state + 0xc0) < lbl_803DF430)
    {
        *(f32*)((char*)state + 0xc0) = lbl_803DF430;
    }
    else if (*(f32*)((char*)state + 0xc0) > lbl_803DF43C)
    {
        *(f32*)((char*)state + 0xc0) = lbl_803DF43C;
    }
    if (*(f32*)((char*)state + 0xc4) < lbl_803DF430)
    {
        *(f32*)((char*)state + 0xc4) = lbl_803DF430;
    }
    else if (*(f32*)((char*)state + 0xc4) > lbl_803DF43C)
    {
        *(f32*)((char*)state + 0xc4) = lbl_803DF43C;
    }
    for (j = 0; j < *(s16*)((char*)p + 0x14); j++)
    {
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xc] = (int)*(f32*)((char*)state + 0xbc);
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xd] = (int)*(f32*)((char*)state + 0xc0);
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xe] = (int)*(f32*)((char*)state + 0xc4);
    }
}

void fn_800A0C78(void* state, void* p, int mode, u8 idx)
{
    extern f32 lbl_803DD284;
    extern f32 lbl_803DF434;
    int idx2 = idx * 2;
#define base ((char*)state + idx2 * 0xc)
    int j;

    if (mode == 1)
    {
        f32 tx = ((ModgfxVertexGroupCmd*)p)->valueX;
        f32 ty = ((ModgfxVertexGroupCmd*)p)->valueY;
        f32 tz = ((ModgfxVertexGroupCmd*)p)->valueZ;
        if (((ModgfxState*)state)->blendFrameCount != 0)
        {
            *(f32*)(base + 0x3c) = (tx - *(f32*)(base + 0x30)) / (f32)((ModgfxState*)state)->blendFrameCount;
            *(f32*)(base + 0x40) = (ty - *(f32*)(base + 0x34)) / (f32)((ModgfxState*)state)->blendFrameCount;
            *(f32*)(base + 0x44) = (tz - *(f32*)(base + 0x38)) / (f32)((ModgfxState*)state)->blendFrameCount;
        }
        else
        {
            u8* buf2 = *(u8**)((char*)((u32*)state + *(u8*)((char*)state + 0x130)) + 0x78);
            u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
            for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
            {
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) =
                    tx * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) =
                    ty * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) =
                    tz * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
            }
            return;
        }
    }
    *(f32*)(base + 0x30) = *(f32*)(base + 0x30) + *(f32*)(base + 0x3c) * lbl_803DD284;
    *(f32*)(base + 0x34) = *(f32*)(base + 0x34) + *(f32*)(base + 0x40) * lbl_803DD284;
    *(f32*)(base + 0x38) = *(f32*)(base + 0x38) + *(f32*)(base + 0x44) * lbl_803DD284;
    {
        u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
        u8* buf2 = *(u8**)((char*)((u32*)state + *(u8*)((char*)state + 0x130)) + 0x78);
        for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
        {
            if (lbl_803DF434 != *(f32*)(base + 0x30))
            {
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) =
                    *(f32*)(base + 0x30) *
                    (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
            }
            if (lbl_803DF434 != *(f32*)(base + 0x34))
            {
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) =
                    *(f32*)(base + 0x34) *
                    (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
            }
            if (lbl_803DF434 != *(f32*)(base + 0x38))
            {
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) =
                    *(f32*)(base + 0x38) *
                    (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
            }
        }
    }
#undef base
}

extern int Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern void ObjList_GetObjects(int* idx, int* count);
extern void Sfx_StopObjectChannel(void* obj, int ch);
extern f32 lbl_803DF43C;

typedef void (*ExpFn2)(void*, int);
typedef void (*ExpFn3)(void*, void*, int);
typedef void (*ExpFn4)(void*, void*, int, int);
typedef void (*ExpResFn6)(void*, int, void*, int, int, void*);

#define E9 ((char *)*(int **)((char *)eff + 0x9c))

void dll_0B_func05(void)
{
    int slot;
    int** pp;
    int* eff;
    int reprocess;
    int active;
    int emIdx;
    int emOff;
    int feFlag;
    int cntC;
    int cntA;
    int k;
    void* res;
    s16 ang[3];
    f32 q[4];
    BoneSpawnData tmpl;
    int objIdx;
    int objCount;

    emIdx = 0;
    gExpgfxUpdatingActivePools = 2;
    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    lbl_803DD284 = timeDelta;
    pp = (int**)gPartfxActiveEffects;
    for (slot = 0; slot < 50; slot++, pp++)
    {
        reprocess = 1;
        while (reprocess)
        {
            reprocess = 0;
            eff = *pp;
            if (eff == NULL) break;
            if (((ModgfxEffectSlot*)eff)->animSlotId == -1) break;
            active = 0;
            ((ModgfxEffectSlot*)eff)->unk13E = 0;
            if (((ModgfxEffectSlot*)eff)->frameDuration < 0 || ((ModgfxEffectSlot*)eff)->frameIndex == -1)
            {
                ((ModgfxEffectSlot*)eff)->frameIndex += 1;
                if (((ModgfxEffectSlot*)eff)->frameIndex > 6)
                {
                    fn_800A1040(((ModgfxEffectSlot*)eff)->animSlotId, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot*)eff)->frameDuration = *(s16*)((char*)eff + ((ModgfxEffectSlot*)eff)->frameIndex * 2
                    + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            else if (((ModgfxEffectSlot*)eff)->pendingFrameIdx != 0)
            {
                ((ModgfxEffectSlot*)eff)->frameIndex = ((ModgfxEffectSlot*)eff)->pendingFrameIdx;
                ((ModgfxEffectSlot*)eff)->pendingFrameIdx = 0;
                if (((ModgfxEffectSlot*)eff)->frameIndex > 6)
                {
                    fn_800A1040(((ModgfxEffectSlot*)eff)->animSlotId, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot*)eff)->frameDuration = *(s16*)((char*)eff + ((ModgfxEffectSlot*)eff)->frameIndex * 2
                    + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            cntC = 0;
            cntA = 0;
            ((ExpFn3)fn_800A0FD0)(eff, E9 + emIdx * 0x18, active);
            feFlag = 0;
            emIdx = 0;
            emOff = 0;
            for (; emIdx < ((ModgfxEffectSlot*)eff)->emitterCount; emIdx++, emOff += 0x18)
            {
                int flags;
                if (*(s16*)((char*)eff + 0xfc) != *(u8*)(E9 + emOff + 0x16)) continue;
                flags = *(int*)(E9 + emOff);
                if ((flags & 0x1000) && *(f32*)(E9 + emOff + 0x4) > lbl_803DF430 && ((ModgfxEffectSlot*)eff)->frameIndex
                    > 0)
                {
                    ((ModgfxEffectSlot*)eff)->frameIndex = *(s16*)(E9 + emIdx * 0x18 + 0x14);
                    *(f32*)(E9 + emIdx * 0x18 + 0x4) = *(f32*)(E9 + emIdx * 0x18 + 0x4) - lbl_803DF434;
                    ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                    break;
                }
                if (flags & 0x2000)
                {
                    if (((ModgfxEffectSlot*)eff)->unk13A != 0)
                    {
                        ((ModgfxEffectSlot*)eff)->unk13A = 0;
                        *(int*)(E9 + emIdx * 0x18) = 0;
                        *(int*)(E9 + emIdx * 0x18) = 0x20;
                        ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (*(s16*)((char*)eff + 0xfc) > 0)
                    {
                        feFlag = 1;
                        ((ModgfxEffectSlot*)eff)->frameIndex = *(s16*)(E9 + emIdx * 0x18 + 0x14);
                        ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000)
                {
                    tmpl.x = ((ModgfxEffectSlot*)eff)->unk60;
                    tmpl.y = ((ModgfxEffectSlot*)eff)->unk64;
                    tmpl.z = ((ModgfxEffectSlot*)eff)->unk68;
                    q[1] = lbl_803DF430;
                    q[2] = lbl_803DF430;
                    q[3] = lbl_803DF430;
                    q[0] = lbl_803DF434;
                    if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                    {
                        ang[0] = *(s16*)((char*)eff + 0xc);
                    }
                    else
                    {
                        ang[0] = *(s16*)(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj);
                    }
                    ang[1] = 0;
                    ang[2] = 0;
                    vecRotateZXY(&ang[0], &tmpl.x);
                    if (*(int*)eff == 0)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            int* o;
                            if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                            {
                                tmpl.x += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x18);
                                tmpl.y += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x1c);
                                tmpl.z += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x20);
                            }
                            else
                            {
                                tmpl.x += ((ModgfxEffectSlot*)eff)->posOffsetX;
                                tmpl.y += ((ModgfxEffectSlot*)eff)->posOffsetY;
                                tmpl.z += ((ModgfxEffectSlot*)eff)->posOffsetZ;
                            }
                            o = Obj_AllocObjectSetup(0x20, 0x66);
                            ((GameObject*)o)->anim.rootMotionScale = tmpl.x;
                            ((GameObject*)o)->anim.localPosX = tmpl.y;
                            *(f32*)&((ObjDef*)o)->jointData = tmpl.z;
                            *(int*)eff = (int)Obj_SetupObject(o, 5, -1, -1, 0);
                            *(int*)(*(int*)eff + 0xf8) = 1;
                        }
                    }
                    else if (*(int*)eff != 0)
                    {
                        if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                        {
                            tmpl.x += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x18);
                            tmpl.y += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x1c);
                            tmpl.z += *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x20);
                        }
                        else
                        {
                            tmpl.x += ((ModgfxEffectSlot*)eff)->posOffsetX;
                            tmpl.y += ((ModgfxEffectSlot*)eff)->posOffsetY;
                            tmpl.z += ((ModgfxEffectSlot*)eff)->posOffsetZ;
                        }
                        *(f32*)(*(int*)eff + 0x18) = tmpl.x;
                        *(f32*)(*(int*)eff + 0x1c) = tmpl.y;
                        *(f32*)(*(int*)eff + 0x20) = tmpl.z;
                    }
                    if (*(int*)eff != 0)
                    {
                        int* o = *(int**)eff;
                        int* list = *(int**)((char*)*(int**)&((GameObject*)o)->anim.hitReactState + 0x50);
                        if (list != NULL)
                        {
                            if (*(s16*)((char*)list + 0x44) == (int)*(f32*)(E9 + emOff + 0x4))
                            {
                                Obj_FreeObject(o);
                                *(int*)eff = 0;
                                *(int*)(E9 + emIdx * 0x18) ^= 0x10000000;
                                if (*(f32*)(E9 + emIdx * 0x18 + 0xc) >= lbl_803DF430 && *(int**)&((ModgfxEffectSlot*)
                                    eff)->sourceObj != NULL)
                                {
                                    (*gPartfxInterface)->spawnObject(
                                        *(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                        (int)*(f32*)(E9 + emIdx * 0x18 + 0xc),
                                        &tmpl, 0x200001, -1, NULL);
                                }
                                ((ModgfxEffectSlot*)eff)->pendingFrameIdx = (int)*(f32*)(E9 + emIdx * 0x18 + 0x8);
                                break;
                            }
                        }
                    }
                }
                ObjList_GetObjects(&objIdx, &objCount);
                if (*(int*)(E9 + emOff) & 0x2)
                {
                    fn_800A0C78(eff, E9 + emOff, active, (u8)cntC);
                    cntC++;
                }
                if (*(int*)(E9 + emOff) & 0x4)
                {
                    fn_800A0AB4(eff, E9 + emOff, active, (u8)cntA);
                    cntA++;
                }
                if (*(int*)(E9 + emOff) & 0x8)
                {
                    ((ExpFn4)fn_800A0524)(eff, E9 + emOff, active, 0);
                }
                if (*(int*)(E9 + emOff) & 0x100)
                {
                    ((ModgfxEffectSlot*)eff)->unk106 = ((ModgfxEffectSlot*)eff)->unk106 + (int)(*(f32*)(E9 + emOff +
                        0x4) * lbl_803DD284);
                    ((ModgfxEffectSlot*)eff)->unk108 = ((ModgfxEffectSlot*)eff)->unk108 + (int)(*(f32*)(E9 + emOff +
                        0x8) * lbl_803DD284);
                    ((ModgfxEffectSlot*)eff)->unk10A = ((ModgfxEffectSlot*)eff)->unk10A + (int)(*(f32*)(E9 + emOff +
                        0xc) * lbl_803DD284);
                }
                if (*(int*)(E9 + emOff) & 0x80)
                {
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (*(int*)(E9 + emOff) & 0x8000000)
                {
                    *(f32*)(E9 + emOff + 0xc) = (f32)randomGetRange(0, 0xffff);
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (*(int*)(E9 + emOff) & 0x4000)
                {
                    ((ExpFn4)fn_800A02DC)(eff, E9 + emOff, active, 0);
                }
                if ((*(int*)(E9 + emOff) & 0x10000) && active != 0)
                {
                    if (*(s16*)(E9 + emOff + 0x14) == -1)
                    {
                        Sfx_StopObjectChannel(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0x40);
                    }
                    else
                    {
                        Sfx_PlayFromObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                           (u16) * (s16*)(E9 + emOff + 0x14));
                    }
                }
                if (*(int*)(E9 + emOff) & 0x100000)
                {
                    GameObject* obj = *(GameObject**)&((ModgfxEffectSlot*)eff)->sourceObj;
                    if (active == 1)
                    {
                        if (((ModgfxEffectSlot*)eff)->frameDuration != 0)
                        {
                            ((ModgfxEffectSlot*)eff)->alphaDelta =
                                (*(f32*)(E9 + emOff + 0x4) - (f32)(u32)
                            obj->anim.alpha
                            )
                            /
                            (f32)((ModgfxEffectSlot*)eff)->frameDuration;
                            ((ModgfxEffectSlot*)eff)->alphaCurrent = (f32)(u32)
                            obj->anim.alpha;
                        }
                        else
                        {
                            ((ModgfxEffectSlot*)eff)->alphaDelta =
                                *(f32*)(E9 + emOff + 0x4) - (f32)(u32)
                            obj->anim.alpha;
                            ((ModgfxEffectSlot*)eff)->alphaCurrent = lbl_803DF430;
                        }
                    }
                    ((ModgfxEffectSlot*)eff)->alphaCurrent = ((ModgfxEffectSlot*)eff)->alphaCurrent + ((ModgfxEffectSlot
                        *)eff)->alphaDelta;
                    if (((ModgfxEffectSlot*)eff)->alphaCurrent > lbl_803DF43C)
                    {
                        ((ModgfxEffectSlot*)eff)->alphaCurrent = lbl_803DF43C;
                    }
                    else if (((ModgfxEffectSlot*)eff)->alphaCurrent < lbl_803DF430)
                    {
                        ((ModgfxEffectSlot*)eff)->alphaCurrent = lbl_803DF430;
                    }
                    obj->anim.alpha = (int)((ModgfxEffectSlot*)eff)->alphaCurrent;
                }
                if (*(int*)(E9 + emOff) & 0x400000)
                {
                    ((ExpFn4)fn_800A081C)(eff, E9 + emOff, active, 0);
                }
                if (*(int*)(E9 + emOff) & 0x80000000)
                {
                    ((ModgfxEffectSlot*)eff)->unk24 = *(f32*)(E9 + emOff + 0x4) * lbl_803DD284 + ((ModgfxEffectSlot*)
                        eff)->unk24;
                    ((ModgfxEffectSlot*)eff)->unk28 = *(f32*)(E9 + emOff + 0x8) * lbl_803DD284 + ((ModgfxEffectSlot*)
                        eff)->unk28;
                    ((ModgfxEffectSlot*)eff)->unk2C = *(f32*)(E9 + emOff + 0xc) * lbl_803DD284 + ((ModgfxEffectSlot*)
                        eff)->unk2C;
                }
                if (*(int*)(E9 + emOff) & 0x800000)
                {
                    if ((*(int*)(E9 + emOff) & 0x1000000) && lbl_803DF430 == *(f32*)(E9 + emOff + 0x8))
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + emOff + 0x4); k++)
                        {
                            if (randomGetRange(0, (int)*(f32*)(E9 + emOff + 0xc)) == 0)
                            {
                                if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                                {
                                    (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                     *(s16*)(E9 + emOff + 0x14), NULL, 0x10001, -1,
                                                                     NULL);
                                }
                                else
                                {
                                    (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                     *(s16*)(E9 + emOff + 0x14), NULL, 0x10001, -1,
                                                                     NULL);
                                }
                            }
                        }
                    }
                    else if (lbl_803DF430 == *(f32*)(E9 + emOff + 0x8))
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + emOff + 0x4); k++)
                        {
                            if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                            {
                                (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                 *(s16*)(E9 + emOff + 0x14), (char*)eff + 0xc, 0x10002,
                                                                 -1, NULL);
                            }
                            else
                            {
                                (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                 *(s16*)(E9 + emOff + 0x14), NULL, 0x10002, -1, NULL);
                            }
                        }
                    }
                    else if (lbl_803DF434 == *(f32*)(E9 + emOff + 0x8))
                    {
                        if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                        {
                            tmpl.x = ((ModgfxEffectSlot*)eff)->unk60;
                            tmpl.y = ((ModgfxEffectSlot*)eff)->unk64;
                            tmpl.z = ((ModgfxEffectSlot*)eff)->unk68;
                            if (*(int**)&((ModgfxEffectSlot*)eff)->sourceObj != NULL)
                            {
                                (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                 *(s16*)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        }
                        else
                        {
                            tmpl.x = *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x18) + ((
                                ModgfxEffectSlot*)eff)->unk60;
                            tmpl.y = *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x1c) + ((
                                ModgfxEffectSlot*)eff)->unk64;
                            tmpl.z = *(f32*)((char*)*(int**)&((ModgfxEffectSlot*)eff)->sourceObj + 0x20) + ((
                                ModgfxEffectSlot*)eff)->unk68;
                            if (*(int**)&((ModgfxEffectSlot*)eff)->sourceObj != NULL)
                            {
                                (*gPartfxInterface)->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                                 *(s16*)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        }
                    }
                }
                if (*(int*)(E9 + emOff) & 0x4000000)
                {
                    res = Resource_Acquire((u16)(*(s16*)(E9 + emOff + 0x14) + 0x58), 1);
                    if (*(int*)(E9 + emOff) & 0x1000000)
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + emOff + 0x4); k++)
                        {
                            if (randomGetRange(0, 5) == 0)
                            {
                                if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                                {
                                    (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, (char*)eff + 0xc, 1, -1, NULL);
                                }
                                else
                                {
                                    (*(ExpResFn6*)(*(int*)res + 4))(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0,
                                                                    NULL, 1, -1, NULL);
                                }
                            }
                        }
                    }
                    else
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + emOff + 0x4); k++)
                        {
                            if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                            {
                                (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, (char*)eff + 0xc, 1, -1, NULL);
                            }
                            else
                            {
                                (*(ExpResFn6*)(*(int*)res + 4))(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0, NULL,
                                                                1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0)
            {
                ((ModgfxEffectSlot*)eff)->frameDuration = ((ModgfxEffectSlot*)eff)->frameDuration - framesThisStep;
            }
        }
    slot_done:
        gExpgfxUpdatingActivePools = 0;
    }
}
