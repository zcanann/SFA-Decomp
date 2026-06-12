#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
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


typedef struct ModgfxVertexData
{
    s16 posX;
    s16 posY;
    s16 posZ;
    s16 unused06;
    s16 texCoordS;
    s16 texCoordT;
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 alpha;
} ModgfxVertexData;

/* per-channel vertex-scale blend record (state+0x30, stride 0x18, 2 channels) */
typedef struct ModgfxScaleChannel
{
    f32 cur[3];
    f32 step[3];
} ModgfxScaleChannel;

/* per-channel vertex-alpha blend record (state+0xAC, stride 8, 2 channels) */
typedef struct ModgfxAlphaChannel
{
    f32 step;
    f32 cur;
} ModgfxAlphaChannel;

typedef struct ModgfxState
{
    u8 pad00[4];
    s16* unk04; /* current vertex-index list */
    u8 pad08[0x24 - 0x08];
    f32 posStepX; /* 0x24: per-step vertex-position delta */
    f32 posStepY;
    f32 posStepZ;
    ModgfxScaleChannel scaleChannels[2];
    f32 posCurX; /* 0x60: accumulated vertex-position offset */
    f32 posCurY;
    f32 posCurZ;
    u8 pad6C[0x78 - 0x6C];
    ModgfxVertexData* vertexBuffers[2];
    ModgfxVertexData* baseVertexData;
    u8 pad84[0xA4 - 0x84];
    u32 flags;
    u8 padA8[4];
    ModgfxAlphaChannel alphaChannels[2];
    f32 blendColorR; /* 0xBC: current blended vertex color */
    f32 blendColorG;
    f32 blendColorB;
    f32 blendColorStepR; /* 0xC8 */
    f32 blendColorStepG;
    f32 blendColorStepB;
    u8 padD4[0xEA - 0xD4];
    s16 vertexCount;
    u8 padEC[2];
    s16 channelFrames[7]; /* 0xEE: per-channel remaining blend frames */
    s16 activeChannel; /* 0xFC */
    s16 blendFrameCount;
    s16 rotStepZ;
    s16 rotStepY;
    s16 rotStepX;
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 effectId;
    u8 pad10E[0x130 - 0x10E];
    u8 activeVertexBufferIndex;
} ModgfxState;

STATIC_ASSERT(offsetof(ModgfxState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(ModgfxState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(ModgfxState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(ModgfxState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(ModgfxState, posCurX) == 0x60);
STATIC_ASSERT(offsetof(ModgfxState, activeChannel) == 0xFC);
STATIC_ASSERT(offsetof(ModgfxState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(ModgfxState, rotOffsetZ) == 0x106);

/* vertex-group command payload handed to the updateVertex* handlers */
typedef struct ModgfxVertexGroupCmd
{
    u8 unk00[4];
    f32 valueX; /* rgb r / scale x / alpha */
    f32 valueY;
    f32 valueZ;
    s16* indices; /* vertex indices, stride 2 */
    s16 indexCount;
} ModgfxVertexGroupCmd;

static inline int* Modgfx_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32
#define PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE 0x200000
#define PARTFX_ACTIVE_EFFECT_COUNT 0x32
#define PARTFX_STAGE_COUNT 7

typedef struct ModgfxActiveEffect
{
    int instanceHandle;
    int ownerToken;
    u8 pad08[0x98 - 0x08];
    int sharedResourceHandle;
    int releaseTransformSource;
    u8 padA4[0x10C - 0xA4];
    s16 effectType;
    u8 pad10E[0x12C - 0x10E];
    int state;
    u8 pad130[0x13F - 0x130];
    u8 keepSharedResource;
} ModgfxActiveEffect;

typedef struct ModgfxPendingSpawn
{
    int modelOrResource;
    float posX;
    float posY;
    float posZ;
    int param10;
    s16 param14;
    u8 sequenceIndex;
    u8 pad17;
} ModgfxPendingSpawn;

typedef struct ModgfxSpawnContext
{
    ModgfxPendingSpawn* pendingSpawns;
    void* attachedSource;
    u8 pad08[0x20 - 0x08];
    f32 vecX;
    f32 vecY;
    f32 vecZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 scale;
    int word3C;
    int word40;
    s16 sourceModeCopy;
    s16 sequenceParams[7];
    u32 flags;
    u8 modeByte;
    u8 byte59;
    u8 byte5A;
    u8 byte5B;
    u8 pad5C;
    s8 pendingSpawnCount;
    u8 pad5E[0x60 - 0x5E];
} ModgfxSpawnContext;

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

extern undefined4 FUN_800033a8();
extern void* memcpy(void* dst, const void* src, u32 n);
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern uint FUN_80017830();
extern void* mmAlloc(int size, int heap, int flags);
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80053754();
extern undefined4 FUN_802420e0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern ExpgfxSpawnConfig gExpgfxSpawnConfig;
extern EffectInterface** gPartfxInterface;
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

/*
 * --INFO--
 *
 * Function: modgfx_releaseExpgfxPools
 * EN v1.0 Address: 0x800A00A8
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x800A0108
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_allocExpgfxPools
 * EN v1.0 Address: 0x800A0138
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x800A015C
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
        FUN_800033a8(*slotPoolBases, 0, EXPGFX_POOL_BYTES);
        FUN_802420e0(*slotPoolBases, EXPGFX_POOL_BYTES);
        slotPoolBases = slotPoolBases + 1;
        poolIndex = poolIndex + 1;
    }
    while (poolIndex < EXPGFX_POOL_COUNT);
    FUN_800033a8(-0x7fc63ec8, 0, 0x500);
    return;
}


/*
 * --INFO--
 *
 * Function: modgfx_initExpgfxSpawnConfig
 * EN v1.0 Address: 0x800A0280
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800A04C0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void modgfx_initExpgfxSpawnConfig(undefined4 param_1, undefined4 param_2, undefined colorLowByte,
                                  undefined4 textureWord, undefined4 scaleBits)
{
    undefined4 setupWord;
    ushort setupValue;

    setupWord = FUN_80286840();
    FUN_800033a8((int)&gExpgfxSpawnConfig, 0, EXPGFX_SPAWN_CONFIG_PREFIX_BYTES);
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_scrollVertexTexcoords
 * EN v1.0 Address: 0x800A0330
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x800A0568
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_resetBaseVertexState
 * EN v1.0 Address: 0x800A04B4
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x800A0704
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: modgfx_updateVertexRgb
 * EN v1.0 Address: 0x800A0560
 * EN v1.0 Size: 924b
 * EN v1.1 Address: 0x800A07B0
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_updateEffectPosition
 * EN v1.0 Address: 0x800A08FC
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x800A0AA8
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_updateEffectRotation
 * EN v1.0 Address: 0x800A0A88
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x800A0C50
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_updateVertexAlpha
 * EN v1.0 Address: 0x800A0B6C
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800A0D40
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_updateVertexScale
 * EN v1.0 Address: 0x800A0D84
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x800A0F04
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_restoreActiveVertexState
 * EN v1.0 Address: 0x800A115C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x800A125C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: modgfx_releaseActiveEffectsByType
 * EN v1.0 Address: 0x800A11CC
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x800A12CC
 * EN v1.1 Size: 1156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
        if ((activeEffect != (ModgfxActiveEffect*)0x0) &&
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
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
}


/*
 * --INFO--
 *
 * Function: modgfx_releaseActiveEffectsByOwner
 * EN v1.0 Address: 0x800A1340
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x800A2294
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
        if ((activeEffect != (ModgfxActiveEffect*)0x0) && (activeEffect->ownerToken == ownerToken))
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
            activeEffects[i] = (ModgfxActiveEffect*)0x0;
        }
        i = i + 1;
    }
    while (i < MODGFX_ACTIVE_EFFECT_COUNT);
    return;
}

/*
 * --INFO--
 *
 * Function: modgfx_releaseAllActiveEffects
 * EN v1.0 Address: 0x800A1480
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800A2364
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void modgfx_releaseAllActiveEffects(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                    undefined8 param_4, undefined8 param_5, undefined8 param_6,
                                    undefined8 param_7, undefined8 param_8)
{
    modgfx_releaseActiveEffectsByType(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                      0, 1);
    return;
}


/*
 * --INFO--
 *
 * Function: modgfx_resetActiveEffectRegistry
 * EN v1.0 Address: 0x800A15D8
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x800A3A68
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_800a2a98
 * EN v1.0 Address: 0x800A2A98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800B3428
 * EN v1.1 Size: 15400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800a2a98(int param_1, int param_2, ExpgfxAttachedSourceState* param_3, uint param_4,
             undefined param_5)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: projgfx_spawnPresetEffect
 * EN v1.0 Address: 0x800A332C
 * EN v1.0 Size: 784b
 * EN v1.1 Address: 0x800BD6C8
 * EN v1.1 Size: 2756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
            if (extraArgs == (undefined2*)0x0)
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
            if (extraArgs == (undefined2*)0x0)
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


/*
 * --INFO--
 *
 * Function: FUN_800a3828
 * EN v1.0 Address: 0x800A3828
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800BFC04
 * EN v1.1 Size: 5920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800a3828(int param_1, undefined4 param_2, ExpgfxAttachedSourceState* param_3, uint param_4,
             undefined param_5)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_800a3924
 * EN v1.0 Address: 0x800A3924
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C1458
 * EN v1.1 Size: 5660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800a3924(int param_1, undefined4 param_2, ExpgfxAttachedSourceState* param_3, uint param_4,
             undefined param_5)
{
    return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void projgfx_func07_nop(void);

void projgfx_func06_nop(void);

void projgfx_func05_nop(void);

void projgfx_onMapSetup(void);

void projgfx_initialise(void);

void playerShadow_func03_nop(void);

void playerShadow_release_nop(void);

void playerShadow_initialise_nop(void);

void boneParticleEffect_func08_nop(void)
{
}

void boneParticleEffect_func06_nop(void)
{
}

void boneParticleEffect_func04_nop(void)
{
}

void boneParticleEffect_func03_nop(void)
{
}

void partfx_onMapSetup(void);

void Effect1_func03_nop(void);

void Effect1_release(void);

void Effect1_initialise(void);

void Effect2_func03_nop(void);

void Effect2_release(void);

void Effect2_initialise(void);

void Effect3_func05_nop(void);

void Effect3_func03_nop(void);

void Effect3_release(void);

void Effect3_initialise(void);

void Effect4_func03_nop(void);

void Effect4_release(void);

void Effect4_initialise(void);

void Effect5_func03_nop(void);

void Effect5_release(void);

void Effect5_initialise(void);

void Effect6_func03_nop(void);

void Effect6_release(void);

void Effect6_initialise(void);

void Effect7_func03_nop(void);

void Effect7_release(void);

void Effect7_initialise(void);

void Effect8_func03_nop(void);

void Effect8_release(void);

void Effect8_initialise(void);

void Effect9_func03_nop(void);

void Effect9_release(void);

void Effect9_initialise(void);

/* 8b "li r3, N; blr" returners. */
int projgfx_getObjectTypeId(void);

/* sda21 accessors. */
extern u8 lbl_8039BE98[];
extern ModgfxPendingSpawn gModgfxPendingSpawnQueue[];
extern s16 gModgfxLastSpawnHandle;
extern s16 gModgfxSequenceParamIndex;
extern ModgfxPendingSpawn* gModgfxPendingSpawnWriteCursor;
extern ModgfxPendingSpawn* gModgfxPendingSpawnStartCursor;
#define gModgfxSpawnContext (*(ModgfxSpawnContext *)lbl_8039BE98)
#pragma scheduling off
#pragma peephole off
s16 dll_0B_func18(void);

void dll_0B_func17(u32 flags);

void dll_0B_func15(void* params);

void dll_0B_func14(s16 value);

void dll_0B_func13(s16 x);

void dll_0B_func12(void);

void dll_0B_func11(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10);

void dll_0B_func10(void);
#pragma peephole reset
#pragma scheduling reset

/* OSReport(literal) wrapper. */
extern void OSReport(const char* fmt, ...);
#pragma scheduling off
void projgfx_release_doUnsupported(void);
#pragma scheduling reset

/* OSReport-stub returns. */

#define PROJGFX_UNSUPPORTED_FALSE_RETURN 0

#pragma scheduling off
int projgfx_rayhit_doUnsupported(void);

int projgfx_setzscale_doUnsupported(void);
#pragma scheduling reset

/* Pattern wrappers. */
int projgfx_func04_ret_m1(void);

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

/* Small stub recoveries (drifted unit, add-as-new). */
extern u8 lbl_803DD282;
extern u8 gPlayerShadowMode;
extern u8 gPartfxCachedResourceCount;
extern void fn_800A1040(s16 a, int b);
extern s16 gPartfxResourceTimeouts[];
extern u32 lbl_802C2160[];
extern f32 lbl_803DF46C;
extern f32 lbl_803DF488;
extern f32 lbl_803DF48C;
extern f32 lbl_803DF490;
extern f32 lbl_803DF494;
extern f32 lbl_803DF498;
extern f32 lbl_803DF49C;
extern f32 lbl_803DF4A0;
extern f32 lbl_803DF4A4;
extern void hitDetect_calcSweptSphereBounds(void* out, void* top, void* bottom, void* params, int count);
extern void hitDetectFn_800691c0(void* obj, void* hitData, int flags, int arg3);
extern void fn_80069968(int* outA, int* outB);
extern void fn_80069958(int** out);
void fn_800A3AF0(void* table, int count, void* ctx, f32 a, f32 b);

void dll_0B_func0B(void);

#pragma scheduling off
void dll_0B_func06(void);

void dll_0B_release(void);
#pragma scheduling reset

#pragma peephole off
void playerShadow_setMode(u8 v);
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void playerShadow_renderObject(void* obj);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF430;
extern f32 lbl_803DF434;
#define BONE_PARTICLE_EFFECT_BUFFER_COUNT 7
#define BONE_PARTICLE_EFFECT_BUFFER_BYTES 0x140
#define BONE_PARTICLE_EFFECT_SLOT_COUNT 20
extern void*gBoneParticleEffectBuffers[];
extern void* lbl_803DD2A4;
extern void* lbl_803DD2A8;
extern void mm_free(void* p);
extern void textureFree(void* resource);
extern void*gPartfxActiveEffects[];
extern void Obj_FreeObject(void* obj);
#pragma peephole off
#pragma scheduling off
void dll_0B_initialise(void);

void dll_0B_func0F(int p1, int p2, int p3, int p4, int p5);

void dll_0B_func0A(s16* p);

void dll_0B_func0C(void* p1, char p2);

void dll_0B_func0D(void* p1);

void dll_0B_func07(void* p1);

#pragma dont_inline on
void fn_800A1040(s16 p1, int p2);
#pragma dont_inline reset

void boneParticleEffect_release(void)
{
    int i;
    void** p;
    void* zero;
    i = 0;
    p = gBoneParticleEffectBuffers;
    zero = NULL;
    do
    {
        if (*p != NULL) mm_free(*p);
        *p = zero;
        p++;
        i++;
    }
    while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    if (lbl_803DD2A4 != NULL) textureFree(lbl_803DD2A4);
    if (lbl_803DD2A8 != NULL) textureFree(lbl_803DD2A8);
}

extern void Sfx_PlayFromObject(void* obj, int id);
extern f32 lbl_8030FE38[];
extern s16 lbl_803DD2BC;
extern s16 lbl_803DD2B4;
extern s32 lbl_803DD2B0;
extern s32 lbl_803DD2B8;
extern f32 lbl_803DD2AC;
extern f32 lbl_803DB798;
extern s32 lbl_803DD2A0;
extern f32 lbl_803DF4A8;
extern f32 lbl_803DF4AC;
extern f32 lbl_803DF4B0;
extern f32 lbl_803DF4B4;
extern f32 lbl_803DF4B8;
extern f32 lbl_803DF4C0;
extern f32 lbl_803DF4C4;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 timeDelta;
extern u8 framesThisStep;
typedef u8 BoneFxJRow[16];

typedef struct BoneFxVtx
{
    u16 e0;
    u16 de;
    u16 dc;
    u16 pad;
    f32 w;
    f32 vx;
    f32 vy;
    f32 vz;
} BoneFxVtx;

extern void Matrix_TransformPoint(void* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Camera_LoadModelViewMatrix(void* a, int b, void* c, f32 e, f32 f, int d);
extern void GXSetCullMode(int mode);
extern void setTextColor(void* ctx, int r, int g, int b, int a);
extern void _textSetColor(void* ctx, int r, int g, int b, int a);
extern void textureFn_800541ac(void* ctx, void* tex, int a, int b, int c, int d, int e);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void gxTexColorFn_80079254(void);
extern void textRenderSetupFn_80079804(void);
extern void gxBlendFn_80078b4c(void);
extern void drawFn_8005cf8c(void* a, void* b, int count);

/* EN v1.0 0x800A433C  size: 1764b  per-bone particle vertex update + draw. */
void boneParticleEffect_update(void* ctx, int p2, u8* o)
{
    BoneFxVtx s;
    u8* base;
    int* m;
    int slot;
    void** grp;
    void** grp2;
    int row;
    s16 j;
    s16 k;
    u32 id;
    u32 cls;
    u8* mtx;
    u8* idp;
    f32* pa;
    f32* pb;
    f32* pc;
    u8* jb;
    s32 idx;
    f32 dx;
    f32 dy;
    f32 dz;

    base = (u8*)(int)lbl_8030FE38;
    if (GameBit_Get(0x468) != 0)
    {
        GameBit_Set(0x468, 0);
        lbl_803DD2BC = 0xf;
        Sfx_PlayFromObject(o, 0x281);
    }
    m = Modgfx_GetActiveModel((void*)o);
    if (lbl_803DD2B4 > 6)
    {
        lbl_803DD2B4 = 0;
    }
    if (lbl_803DD2B0 > *(u8*)(*m + 0xf3) - 1)
    {
        lbl_803DD2B0 = 0;
    }
    lbl_803DD2B8 = lbl_803DD2B8 + framesThisStep;
    if (lbl_803DD2B8 > 0x1f)
    {
        lbl_803DD2B8 = lbl_803DD2B8 - 0x1f;
    }
    lbl_803DD2AC = lbl_803DB798 * timeDelta + lbl_803DD2AC;
    if (lbl_803DD2AC > lbl_803DF4AC)
    {
        lbl_803DB798 = lbl_803DB798 * lbl_803DF4B0;
        lbl_803DD2AC = lbl_803DF4AC;
        Sfx_PlayFromObject(o, 0x282);
    }
    else if (lbl_803DD2AC < lbl_803DF4B4)
    {
        lbl_803DB798 = lbl_803DB798 * lbl_803DF4B0;
        lbl_803DD2AC = lbl_803DF4B4;
        Sfx_PlayFromObject(o, 0x282);
    }
    slot = 0;
    grp2 = gBoneParticleEffectBuffers;
    grp = gBoneParticleEffectBuffers;
    do
    {
        if (slot != 5)
        {
            lbl_803DD2B4 = slot;
            row = 0;
            j = 0;
            idp = base + 0x5b4;
            while (j < 5)
            {
                s.vx = 0.0f;
                s.vy = 0.0f;
                s.vz = 0.0f;
                s.w = 1.0f;
                s.dc = 0;
                s.de = 0;
                s.e0 = 0;
                id = *(u8*)(base + lbl_803DD2B4 * 5 + j + 0x5b4);
                jb = (u8*)((int*)m)[(*(u16*)((u8*)m + 0x18) & 1) + 3];
                mtx = (u8*)((BoneFxJRow*)jb + (id << 4));
                dx = *(f32*)(mtx + 0x30) + playerMapOffsetX;
                dy = *(f32*)(mtx + 0x34);
                dz = *(f32*)(mtx + 0x38) + playerMapOffsetZ;
                dx = dx - *(f32*)(o + 0xc);
                dy = dy - *(f32*)(o + 0x10);
                dz = dz - *(f32*)(o + 0x14);
                dx = dx * 20.02f;
                if (id == 0x1d || id == 0x1d)
                {
                    dy = 20.02f * (lbl_803DF4C0 + dy);
                }
                else
                {
                    dy = dy * 20.02f;
                }
                dz = dz * 20.02f;
                Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                k = 0;
                pa = (f32*)(base + 0x90);
                pb = (f32*)(int)lbl_8030FE38;
                pc = (f32*)(base + 0x120);
                while (k < 4)
                {
                    u8* t;
                    u8* t4;
                    id = *(u8*)(idp + lbl_803DD2B4 * 5);
                    t = base + id;
                    cls = *(u8*)(t + 0x590);
                    if (cls == 0)
                    {
                        s.vx = pa[0] * *(f32*)((base + 0x5d8) + id * 4);
                        s.vy = pa[1] * *(f32*)((base + 0x5d8) + id * 4);
                        s.vz = pa[2] * *(f32*)(t4 + 0x664);
                    }
                    else if (cls == 1)
                    {
                        s.vx = pb[0] * *(f32*)((base + 0x5d8) + id * 4);
                        s.vy = pb[1] * *(f32*)((base + 0x5d8) + id * 4);
                        s.vz = pb[2] * *(f32*)(t4 + 0x664);
                    }
                    else if (cls == 2)
                    {
                        t4 = base + id * 4;
                        s.vx = pc[0] * *(f32*)(t4 + 0x5d8);
                        s.vy = pc[1] * *(f32*)(t4 + 0x5d8);
                        s.vz = pc[2] * *(f32*)(t4 + 0x664);
                    }
                    Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                    s.vx = s.vx + playerMapOffsetX;
                    s.vz = s.vz + playerMapOffsetZ;
                    idx = (k + row) * 0x10;
                    *(s16*)((u8*)*grp + idx) = (s32)(dx + (s.vx - *(f32*)(o + 0xc)));
                    *(s16*)((u8*)*grp + idx + 2) = (s32)(dy + (s.vy - *(f32*)(o + 0x10)));
                    *(s16*)((u8*)*grp + idx + 4) = (s32)(dz + (s.vz - *(f32*)(o + 0x14)));
                    *(u8*)((u8*)*grp + idx + 0xf) = 0x9b;
                    t = base + idx;
                    *(s16*)((u8*)*grp + idx + 0xa) = (s16)(*(s16*)(t + 0x1ba) - (lbl_803DD2B8 << 2));
                    pa += 3;
                    pb += 3;
                    pc += 3;
                    k += 1;
                }
                row += 4;
                idp += 1;
                j += 1;
            }
        }
        grp += 1;
        slot += 1;
    }
    while (slot < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    s.vx = *(f32*)(o + 0xc);
    s.vy = *(f32*)(o + 0x10);
    s.vz = *(f32*)(o + 0x14);
    s.w = lbl_803DF4C4;
    setTextColor(ctx, 0xff, 0xff, 0xff, 0xff);
    if (lbl_803DD2BC != 0)
    {
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        if ((int)randomGetRange(0, 1) != 0)
        {
            textureFn_800541ac(ctx, lbl_803DD2A4, 0, 0, 0, 0, 0);
        }
        else
        {
            textureFn_800541ac(ctx, lbl_803DD2A8, 0, 0, 0, 0, 0);
        }
        lbl_803DD2BC -= framesThisStep;
        if (lbl_803DD2BC < 0)
        {
            lbl_803DD2BC = 0;
        }
    }
    else
    {
        textureFn_800541ac(ctx, lbl_803DD2A4, 0, 0, 0, 0, 0);
    }
    Camera_LoadModelViewMatrix(ctx, p2, &s, lbl_803DF4B8, lbl_803DF4A8, 0);
    GXSetCullMode(0);
    _textSetColor(ctx, 0xff, 0xff, 0xff, 0xff);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    gxTexColorFn_80079254();
    textRenderSetupFn_80079804();
    gxBlendFn_80078b4c();
    {
        int i;
        i = 0;
        do
        {
            drawFn_8005cf8c(*grp2, base + 0x2f0, 0x20);
            grp2 += 1;
            i += 1;
        }
        while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    }
    lbl_803DD2A0 = 1 - lbl_803DD2A0;
}

typedef struct
{
    s16 a, b, c;
    u16 pad;
    s16 d, e;
    u8 f, g, h, alpha;
} ParticleSlot;

extern ParticleSlot gBoneParticleInitData[];
extern void* textureLoadAsset(int id);
extern void* mmAlloc(int size, int align, int flag);

void boneParticleEffect_initialise(void)
{
    int i;
    int j;

    lbl_803DD2A4 = textureLoadAsset(0x16b);
    lbl_803DD2A8 = textureLoadAsset(0x201);
    gBoneParticleEffectBuffers[0] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[1] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[2] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[3] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[4] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[5] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[6] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    for (i = 0; i < BONE_PARTICLE_EFFECT_BUFFER_COUNT; i++)
    {
        for (j = 0; j < BONE_PARTICLE_EFFECT_SLOT_COUNT; j++)
        {
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].a = gBoneParticleInitData[j].a;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].b = gBoneParticleInitData[j].b;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].c = gBoneParticleInitData[j].c;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].d = gBoneParticleInitData[j].d;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].e = gBoneParticleInitData[j].e;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].f = gBoneParticleInitData[j].f;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].g = gBoneParticleInitData[j].g;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].h = gBoneParticleInitData[j].h;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].alpha = 0xff;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803DF438;

#pragma peephole off
#pragma scheduling off
void fn_800A02DC(ModgfxState* state, f32* in);
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void fn_800A0FD0(ModgfxState* state);

void fn_800A0478(ModgfxState* state);
#pragma scheduling reset


#pragma peephole off
#pragma scheduling off
void partfx_initialise(void);
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void fn_800A081C(int p1, int p2, int mode);
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800A09C4  size: 240b  modgfx_stepS16VectorLerp: integer-vector lerp setup.
 * On mode 1, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
#pragma scheduling off
#pragma peephole off
void modgfx_stepS16VectorLerp(int* obj, f32* params, int mode);
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800A113C  size: 276b  dll_0B_func0E: flag every active effect
 * whose owner object has the 0x800 state bit by setting its byte _13e. */
#pragma scheduling off
#pragma peephole off
void dll_0B_func0E(void);
#pragma peephole reset
#pragma scheduling reset

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

extern f32 lbl_803DB7A8;
extern f32 lbl_803DB7AC;
extern f32 lbl_803DF4C8;
extern f32 lbl_803DF4CC;
extern f32 lbl_803DF4D0;
extern f32 lbl_803DF4D8;
extern s32 lbl_803DD318;
extern s32 lbl_803DD31C;
extern f32 lbl_803DD320;
extern f32 lbl_803DD324;
extern f32 lbl_803DF718;
extern f32 lbl_803DF71C;
extern f32 mathSinf(f32);

/* EN v1.0 0x800AEC50  size: 1992b  tick global effect phases and expire
 * the 20 cached particle resource slots. */
#pragma scheduling off
#pragma peephole off
void partfx_updateFrameState(void);
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800AF41C  size: 560b  partfx_release: clear the 20-slot
 * effect-id table and free all 20 cached particle resources. */
#pragma scheduling off
#pragma peephole off
void partfx_release(void);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF720;
extern f32 lbl_803DF724;
extern f32 lbl_803DF730;
extern f32 lbl_803DF868;
extern f32 lbl_803DF86C;
extern f32 lbl_803DB7B8;
extern f32 lbl_803DB7BC;
extern int lbl_803DD328;
extern int lbl_803DD32C;
extern f32 lbl_803DD330;
extern f32 lbl_803DD334;
extern f32 lbl_803DD284;

#pragma scheduling off
void Effect1_func05(void);
#pragma scheduling reset

extern f32 lbl_803DB7C8;
extern f32 lbl_803DB7CC;
extern f32 lbl_803DB7D8;
extern f32 lbl_803DB7DC;
extern f32 lbl_803DB7E8;
extern f32 lbl_803DB7EC;
extern f32 lbl_803DB7F8;
extern f32 lbl_803DB7FC;
extern f32 lbl_803DB808;
extern f32 lbl_803DB80C;
extern f32 lbl_803DB818;
extern f32 lbl_803DB81C;
extern f32 lbl_803DB828;
extern f32 lbl_803DB82C;
extern int lbl_803DD338;
extern int lbl_803DD33C;
extern f32 lbl_803DD340;
extern f32 lbl_803DD344;
extern int lbl_803DD350;
extern int lbl_803DD354;
extern f32 lbl_803DD358;
extern f32 lbl_803DD35C;
extern int lbl_803DD360;
extern int lbl_803DD364;
extern f32 lbl_803DD368;
extern f32 lbl_803DD36C;
extern int lbl_803DD370;
extern int lbl_803DD374;
extern f32 lbl_803DD378;
extern f32 lbl_803DD37C;
extern int lbl_803DD380;
extern int lbl_803DD384;
extern f32 lbl_803DD388;
extern f32 lbl_803DD38C;
extern int lbl_803DD390;
extern int lbl_803DD394;
extern f32 lbl_803DD398;
extern f32 lbl_803DD39C;
extern int lbl_803DD3A0;
extern int lbl_803DD3A4;
extern f32 lbl_803DD3A8;
extern f32 lbl_803DD3AC;
extern f32 lbl_803DF870;
extern f32 lbl_803DF874;
extern f32 lbl_803DF878;
extern f32 lbl_803DF880;
extern f32 lbl_803DF9C8;
extern f32 lbl_803DF9CC;
extern f32 lbl_803DFA88;
extern f32 lbl_803DFA8C;
extern f32 lbl_803DFA90;
extern f32 lbl_803DFA98;
extern f32 lbl_803DFBD8;
extern f32 lbl_803DFBDC;
extern f32 lbl_803DFBE0;
extern f32 lbl_803DFBE4;
extern f32 lbl_803DFBE8;
extern f32 lbl_803DFBF0;
extern f32 lbl_803DFC78;
extern f32 lbl_803DFC7C;
extern f32 lbl_803DFC80;
extern f32 lbl_803DFC84;
extern f32 lbl_803DFC90;
extern f32 lbl_803DFCD0;
extern f32 lbl_803DFCD4;
extern f32 lbl_803DFCD8;
extern f32 lbl_803DFCDC;
extern f32 lbl_803DFCE0;
extern f32 lbl_803DFCE8;
extern f32 lbl_803DFD90;
extern f32 lbl_803DFD94;
extern f32 lbl_803DFD98;
extern f32 lbl_803DFD9C;
extern f32 lbl_803DFDA8;
extern f32 lbl_803DFE20;
extern f32 lbl_803DFE24;
extern f32 lbl_803DFE28;
extern f32 lbl_803DFE2C;
extern f32 lbl_803DFE38;
extern f32 lbl_803DFEB0;
extern f32 lbl_803DFEB4;

#pragma scheduling off
#pragma peephole off
void Effect2_func05(void);

void Effect4_func05(void);

void Effect5_func05(void);

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */
typedef struct PartFxSpawn
{
    void* attachedSource;
    int quadVertex3Pad06;
    int lifetimeFrames;
    s16 sourceVecX;
    s16 sourceVecY;
    s16 sourceVecZ;
    u8 pad12[2];
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 sourcePosW;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 scale;
    s16 textureSetupFlags;
    s16 textureId;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 overrideColor0;
    u32 overrideColor1;
    u32 overrideColor2;
    u16 colorWord0;
    u16 colorWord1;
    u16 colorWord2;
    u8 effectIdByte;
    u8 pad5f[1];
    u8 initialAlpha;
    u8 linkGroup;
    u8 modelIdByte;
} PartFxSpawn;

extern f32 lbl_803DB7F0;
extern f32 lbl_803DB7F4;
extern f32 lbl_803DFC8C;
extern f32 lbl_803DFC94;
extern f32 lbl_803DFC98;
extern f32 lbl_803DFC9C;
extern f32 lbl_803DFCA0;
extern f32 lbl_803DFCA4;
extern f32 lbl_803DFCA8;
extern f32 lbl_803DFCAC;
extern f32 lbl_803DFCB0;
extern f32 lbl_803DFCB4;
extern f32 lbl_803DFCB8;
extern f32 lbl_803DFCBC;
extern f32 lbl_803DFCC0;
extern f32 lbl_803DFCC4;

int Effect6_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

void Effect6_func05(void);

void Effect7_func05(void);

void Effect8_func05(void);

typedef struct FxNode9
{
    s16 x, y, z;
    s16 pad6;
    f32 f8;
    f32 fc;
    f32 f10;
    f32 f14;
} FxNode9;

extern FxNode9 lbl_8039C398;
extern f32 lbl_803DB820;
extern f32 lbl_803DB824;
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

#define FILL9() do {                            \
    lbl_8039C398.fc = 0.0f;             \
    lbl_8039C398.f10 = 0.0f;            \
    lbl_8039C398.f14 = 0.0f;            \
    lbl_8039C398.f8 = 1.0f;             \
    lbl_8039C398.x = 0;                         \
    lbl_8039C398.y = 0;                         \
    lbl_8039C398.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C398;             \
  } while (0)

int Effect9_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);
#undef FILL9

extern FxNode9 lbl_8039C380;
extern void randFn_80080100();
extern f32 lbl_803DB810;
extern f32 lbl_803DB814;
extern f32 lbl_803DFDA4;
extern f32 lbl_803DFDB0;
extern f32 lbl_803DFDB4;
extern f32 lbl_803DFDB8;
extern f32 lbl_803DFDBC;
extern f32 lbl_803DFDC0;
extern f32 lbl_803DFDC4;
extern f32 lbl_803DFDC8;
extern f32 lbl_803DFDCC;
extern f32 lbl_803DFDD0;
extern f32 lbl_803DFDD4;
extern f32 lbl_803DFDD8;
extern f32 lbl_803DFDDC;
extern f32 lbl_803DFDE0;
extern f32 lbl_803DFDE4;
extern f32 lbl_803DFDE8;
extern f32 lbl_803DFDEC;
extern f32 lbl_803DFDF0;
extern f32 lbl_803DFDF4;
extern f32 lbl_803DFDF8;
extern f32 lbl_803DFDFC;
extern f32 lbl_803DFE00;
extern f32 lbl_803DFE04;
extern f32 lbl_803DFE08;
extern f32 lbl_803DFE0C;
extern f32 lbl_803DFE10;

#define FILL8() do {                            \
    lbl_8039C380.fc = 0.0f;             \
    lbl_8039C380.f10 = 0.0f;            \
    lbl_8039C380.f14 = 0.0f;            \
    lbl_8039C380.f8 = 1.0f;             \
    lbl_8039C380.x = 0;                         \
    lbl_8039C380.y = 0;                         \
    lbl_8039C380.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C380;             \
  } while (0)

int Effect8_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);
#undef FILL8

typedef struct EmitterCfg
{
    f32 vel[7][3];
    f32 g08[3];
    f32 f60;
    int emit[6];
    int sub[6];
    u16 col[6];
    u8 b_a0;
    u8 b_a1;
    u8 pad[2];
} EmitterCfg;

extern EmitterCfg lbl_80310560;
extern FxNode9 lbl_8039C338;
extern int lbl_803DD2C4;
extern int lbl_803DD348;
extern f32 lbl_803DB7C0;
extern f32 lbl_803DB7C4;
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
    lbl_8039C338.fc = lbl_803DF884;             \
    lbl_8039C338.f10 = lbl_803DF884;            \
    lbl_8039C338.f14 = lbl_803DF884;            \
    lbl_8039C338.f8 = lbl_803DF878;             \
    lbl_8039C338.x = 0;                         \
    lbl_8039C338.y = 0;                         \
    lbl_8039C338.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C338;             \
  } while (0)

extern s32 lbl_80310660[];

/* ---- partfx_spawnObject (FUN_800a4df4, v1.0) ---- */
extern f32 lbl_803DB7A0;
extern f32 lbl_803DB7A4;
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
extern f32 lbl_803DF548;
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
extern f32 lbl_803DF5F0;
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
extern s16 lbl_8039C308[12];
extern void srand(int seed);
extern void vecRotateZXY(void* obj, f32* vec);
extern char sModgfxAlphaDebugFormat[];
extern void fn_80137948(char* fmt, ...);

int partfx_spawnObject(s16* sourceObj, u32 effectIdArg, s16* spawnParams, u32 spawnFlags, u32 modelIdArg, void* extraArgsArg);


int Effect2_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);
#undef FILL338

extern void* Obj_GetPlayerObject();
extern FxNode9 lbl_8039C368;
extern f32 lbl_803DB800;
extern f32 lbl_803DB804;
extern f32 lbl_803DFCEC;
extern f32 lbl_803DFCF0;
extern f32 lbl_803DFCF4;
extern f32 lbl_803DFCF8;
extern f32 lbl_803DFCFC;
extern f32 lbl_803DFD00;
extern f32 lbl_803DFD04;
extern f32 lbl_803DFD08;
extern f32 lbl_803DFD0C;
extern f32 lbl_803DFD10;
extern f32 lbl_803DFD14;
extern f32 lbl_803DFD18;
extern f32 lbl_803DFD1C;
extern f32 lbl_803DFD20;
extern f32 lbl_803DFD24;
extern f32 lbl_803DFD28;
extern f32 lbl_803DFD2C;
extern f32 lbl_803DFD30;
extern f32 lbl_803DFD34;
extern f32 lbl_803DFD38;
extern f32 lbl_803DFD3C;
extern f32 lbl_803DFD40;
extern f32 lbl_803DFD44;
extern f32 lbl_803DFD48;
extern f32 lbl_803DFD4C;
extern f32 lbl_803DFD50;
extern f32 lbl_803DFD54;
extern f32 lbl_803DFD58;
extern f32 lbl_803DFD5C;
extern f32 lbl_803DFD60;
extern f32 lbl_803DFD64;
extern f32 lbl_803DFD68;
extern f32 lbl_803DFD6C;
extern f32 lbl_803DFD70;
extern f32 lbl_803DFD74;
extern f32 lbl_803DFD78;
extern f32 lbl_803DFD7C;
extern f32 lbl_803DFD80;
extern f32 lbl_803DFD84;

#define FILL368() do {                          \
    lbl_8039C368.fc = lbl_803DFCEC;             \
    lbl_8039C368.f10 = lbl_803DFCEC;            \
    lbl_8039C368.f14 = lbl_803DFCEC;            \
    lbl_8039C368.f8 = lbl_803DFCE0;             \
    lbl_8039C368.x = 0;                         \
    lbl_8039C368.y = 0;                         \
    lbl_8039C368.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C368;             \
  } while (0)

int Effect7_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);
#undef FILL368

typedef struct MtxBuildArg
{
    s16 rx;
    s16 ry;
    s16 rz;
    u8 pad6[2];
    f32 w;
    f32 a;
    f32 b;
    f32 c;
} MtxBuildArg;

extern f32 lbl_803DB7E0;
extern f32 lbl_803DB7E4;
extern f32 lbl_803DFBEC;
extern f32 lbl_803DFBF4;
extern f32 lbl_803DFBF8;
extern f32 lbl_803DFBFC;
extern f32 lbl_803DFC00;
extern f32 lbl_803DFC04;
extern f32 lbl_803DFC08;
extern f32 lbl_803DFC0C;
extern f32 lbl_803DFC10;
extern f32 lbl_803DFC14;
extern f32 lbl_803DFC18;
extern f32 lbl_803DFC1C;
extern f32 lbl_803DFC20;
extern f32 lbl_803DFC24;
extern f32 lbl_803DFC28;
extern f32 lbl_803DFC2C;
extern f32 lbl_803DFC30;
extern f32 lbl_803DFC34;
extern f32 lbl_803DFC38;
extern f32 lbl_803DFC3C;
extern f32 lbl_803DFC40;
extern f32 lbl_803DFC44;
extern f32 lbl_803DFC48;
extern f32 lbl_803DFC4C;
extern f32 lbl_803DFC50;
extern f32 lbl_803DFC54;
extern f32 lbl_803DFC58;
extern f32 lbl_803DFC5C;
extern f32 lbl_803DFC60;
extern f32 lbl_803DFC64;
extern f32 lbl_803DFC68;

int Effect5_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

extern f32 mathCosf(f32);
extern FxNode9 lbl_8039C350;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9D4;
extern f32 lbl_803DF9D8;
extern f32 lbl_803DF9DC;
extern f32 lbl_803DF9E0;
extern f32 lbl_803DF9E4;
extern f32 lbl_803DF9E8;
extern f32 lbl_803DF9EC;
extern f32 lbl_803DF9F0;
extern f32 lbl_803DF9F4;
extern f32 lbl_803DF9F8;
extern f32 lbl_803DF9FC;
extern f32 lbl_803DFA00;
extern f32 lbl_803DFA04;
extern f32 lbl_803DFA08;
extern f32 lbl_803DFA0C;
extern f32 lbl_803DFA10;
extern f32 lbl_803DFA14;
extern f32 lbl_803DFA18;
extern f32 lbl_803DFA1C;
extern f32 lbl_803DFA20;
extern f32 lbl_803DFA24;
extern f32 lbl_803DFA28;
extern f32 lbl_803DFA2C;
extern f32 lbl_803DFA30;
extern f32 lbl_803DFA34;
extern f32 lbl_803DFA38;
extern f32 lbl_803DFA3C;
extern f32 lbl_803DFA40;
extern f32 lbl_803DFA44;
extern f32 lbl_803DFA48;
extern f32 lbl_803DFA4C;
extern f32 lbl_803DFA50;
extern f32 lbl_803DFA54;
extern f32 lbl_803DFA58;
extern f32 lbl_803DFA5C;
extern f32 lbl_803DFA60;
extern f32 lbl_803DFA64;
extern f32 lbl_803DFA68;
extern f32 lbl_803DFA6C;
extern f32 lbl_803DFA70;
extern f32 lbl_803DFA74;
extern f32 lbl_803DFA78;

#define FILL350() do {                          \
    lbl_8039C350.fc = lbl_803DF9D0;             \
    lbl_8039C350.f10 = lbl_803DF9D0;            \
    lbl_8039C350.f14 = lbl_803DF9D0;            \
    lbl_8039C350.f8 = lbl_803DF9D4;             \
    lbl_8039C350.x = 0;                         \
    lbl_8039C350.y = 0;                         \
    lbl_8039C350.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C350;             \
  } while (0)

int Effect3_func04(void* sourceObj, int effectId, void* spawnParamsRaw, u32 spawnFlags, u8 modelId, void* param_6v);
#undef FILL350

extern f32 lbl_803DB7D0;
extern f32 lbl_803DB7D4;
extern f32 lbl_803DFA94;
extern f32 lbl_803DFA9C;
extern f32 lbl_803DFAA0;
extern f32 lbl_803DFAA4;
extern f32 lbl_803DFAA8;
extern f32 lbl_803DFAAC;
extern f32 lbl_803DFAB0;
extern f32 lbl_803DFAB4;
extern f32 lbl_803DFAB8;
extern f32 lbl_803DFABC;
extern f32 lbl_803DFAC0;
extern f32 lbl_803DFAC4;
extern f32 lbl_803DFAC8;
extern f32 lbl_803DFACC;
extern f32 lbl_803DFAD0;
extern f32 lbl_803DFAD4;
extern f32 lbl_803DFAD8;
extern f32 lbl_803DFADC;
extern f32 lbl_803DFAE0;
extern f32 lbl_803DFAE4;
extern f32 lbl_803DFAE8;
extern f32 lbl_803DFAEC;
extern f32 lbl_803DFAF0;
extern f32 lbl_803DFAF4;
extern f32 lbl_803DFAF8;
extern f32 lbl_803DFAFC;
extern f32 lbl_803DFB00;
extern f32 lbl_803DFB04;
extern f32 lbl_803DFB08;
extern f32 lbl_803DFB0C;
extern f32 lbl_803DFB10;
extern f32 lbl_803DFB14;
extern f32 lbl_803DFB18;
extern f32 lbl_803DFB1C;
extern f32 lbl_803DFB20;
extern f32 lbl_803DFB24;
extern f32 lbl_803DFB28;
extern f32 lbl_803DFB2C;
extern f32 lbl_803DFB30;
extern f32 lbl_803DFB34;
extern f32 lbl_803DFB38;
extern f32 lbl_803DFB3C;
extern f32 lbl_803DFB40;
extern f32 lbl_803DFB44;
extern f32 lbl_803DFB48;
extern f32 lbl_803DFB4C;
extern f32 lbl_803DFB50;
extern f32 lbl_803DFB54;
extern f32 lbl_803DFB58;
extern f32 lbl_803DFB5C;
extern f32 lbl_803DFB60;
extern f32 lbl_803DFB64;
extern f32 lbl_803DFB68;
extern f32 lbl_803DFB6C;
extern f32 lbl_803DFB70;
extern f32 lbl_803DFB74;
extern f32 lbl_803DFB78;
extern f32 lbl_803DFB7C;
extern f32 lbl_803DFB80;
extern f32 lbl_803DFB84;
extern f32 lbl_803DFB88;
extern f32 lbl_803DFB8C;
extern f32 lbl_803DFB90;
extern f32 lbl_803DFB94;
extern f32 lbl_803DFB98;
extern f32 lbl_803DFB9C;
extern f32 lbl_803DFBA0;
extern f32 lbl_803DFBA4;
extern f32 lbl_803DFBA8;
extern f32 lbl_803DFBAC;
extern f32 lbl_803DFBB0;
extern f32 lbl_803DFBB4;
extern f32 lbl_803DFBB8;
extern f32 lbl_803DFBBC;
extern f32 lbl_803DFBC0;
extern f32 lbl_803DFBC4;
extern f32 lbl_803DFBC8;

int Effect4_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

/* ===== (1) extern declarations needed by Effect1_func04 ===== */
/* lbl_803DF720/724/728/730 already declared in modgfx.c; the rest are new. */
extern f32 lbl_803DB7B0;
extern f32 lbl_803DB7B4;
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
/* lbl_803DF860 = int->f64 magic bias (.sdata2), auto-emitted; do NOT declare. */
/* MtxBuildArg, vecRotateZXY, randFn_80080100, gExpgfxInterface, randomGetRange
   already declared in modgfx.c. */

/* ===== (2) FILL macro ===== */
#define FILL320() do {                          \
    lbl_8039C320.fc = 0.0f;             \
    lbl_8039C320.f10 = 0.0f;            \
    lbl_8039C320.f14 = 0.0f;            \
    lbl_8039C320.f8 = 1.0f;             \
    lbl_8039C320.x = 0;                         \
    lbl_8039C320.y = 0;                         \
    lbl_8039C320.z = 0;                         \
    spawnParams = (s16 *)&lbl_8039C320;             \
  } while (0)

/* ===== (3) function ===== */
int Effect1_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);
#undef FILL320

void Effect9_func05(void);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dll_0B_onMapSetup(void);
#pragma peephole reset
#pragma scheduling reset

extern void* Obj_GetActiveModel(void);
extern void* ObjModel_GetJointMatrix(void* model, int joint);
extern void PSMTXMultVec(void* m, void* src, void* dst);

typedef struct BoneSpawnData
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    s16 unk6;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} BoneSpawnData;

#pragma scheduling off
void boneParticleEffect_spawnAtBones(void* obj, int effectId, void* extraArg, u8 prob, short* src)
{
    void* model;
    int i;
    BoneSpawnData data;

    model = Obj_GetActiveModel();
    for (i = 0; i < *(u8*)(*(int*)model + 0xf3); i++)
    {
        if ((int)randomGetRange(1, 0x64) <= prob)
        {
            void* mtx;
            data.x = lbl_803DF4A8;
            data.y = lbl_803DF4A8;
            data.z = lbl_803DF4A8;
            data.scale = lbl_803DF4B8;
            data.unk4 = 0;
            data.unk2 = 0;
            data.unk0 = 0;
            mtx = ObjModel_GetJointMatrix(model, i);
            PSMTXMultVec(mtx, &data.x, &data.x);
            data.x = data.x - ((GameObject*)obj)->anim.worldPosX;
            data.y = data.y - ((GameObject*)obj)->anim.worldPosY;
            data.z = data.z - ((GameObject*)obj)->anim.worldPosZ;
            data.x = data.x + playerMapOffsetX;
            data.z = data.z + playerMapOffsetZ;
            if (src != NULL)
            {
                data.scale = *(f32*)((char*)src + 0x8);
                data.unk0 = src[0];
                data.unk4 = src[2];
                data.unk2 = src[1];
                data.unk6 = src[3];
            }
            else
            {
                data.scale = lbl_803DF4B8;
                data.unk0 = 0;
                data.unk4 = 0;
                data.unk2 = 0;
                data.unk6 = 0;
            }
            (*gPartfxInterface)->spawnObject(obj, effectId, &data, 2, -1, extraArg);
        }
    }
}
#pragma scheduling reset

extern void* Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32 x);
extern f32 lbl_8030FDE8[];
extern s16 lbl_803DD29A;
extern s16 lbl_803DD29C;
extern f32 lbl_803DF468;
extern f32 lbl_803DF470;
extern f32 lbl_803DF474;
extern f32 lbl_803DF478;

#pragma scheduling off
#pragma peephole off
void fn_800A3AF0(void* table, int count, void* ctx, f32 a, f32 b);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dll_0B_func08(void* param);
#pragma peephole reset
#pragma scheduling reset

extern int dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g);

#pragma scheduling off
#pragma peephole off
void dll_0B_func16(void* a, void* b, void* c, void* d, void* e, int f, void* g);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF460;
extern s16 lbl_803DD280;

#pragma scheduling off
#pragma peephole off
int dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g);
#pragma peephole reset
#pragma scheduling reset

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

#pragma scheduling off
#pragma peephole off
int dll_0B_func09(void* a0, int a1, int a2, u8 a3, void* a4);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0AB4(void* state, void* p, int mode, u8 idx);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0524(void* state, void* p, int mode);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0C78(void* state, void* p, int mode, u8 idx);
#pragma peephole reset
#pragma scheduling reset

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

#pragma scheduling off
#pragma peephole off
void dll_0B_func05(void);
#pragma peephole reset
#pragma scheduling reset
