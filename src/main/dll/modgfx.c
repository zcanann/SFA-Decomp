#include "main/audio/sfx_ids.h"
#include "main/expgfx.h"
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
#define MODGFX_EFFECT_RENDER_BUFFER_COUNT 7
#define MODGFX_EFFECT_RENDER_BUFFER_BYTES 0x140
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
#define gModgfxEffectRenderBuffers DAT_8039cf20

extern ModgfxActiveEffect*gModgfxActiveEffectRegistry[];
extern int gModgfxEffectRenderBuffers[];

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
extern void fn_8005D108();
extern void trackDolphin_buildSweptBounds(uint* boundsOut, float* startPoints, float* endPoints,
                                          float* radii, int pointCount);
extern void trackDolphin_getCurrentTrackPoint(uint * *param_1);
extern void trackDolphin_getCurrentIntersectionList(int* entryCountOut, undefined4* entryListOut);
extern undefined4 FUN_802420e0();
extern void DCFlushRange(void* addr, u32 nBytes);
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern ExpgfxSpawnConfig gExpgfxSpawnConfig;
extern ExpgfxAttachedSourceState gProjgfxDefaultAttachedSource;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e00c0;
extern f64 DOUBLE_803e00c8;
extern f64 DOUBLE_803e0100;
extern f64 DOUBLE_803e0270;
extern f64 DOUBLE_803e0390;
extern f64 DOUBLE_803e04e0;
extern f64 DOUBLE_803e0640;
extern f64 DOUBLE_803e0700;
extern f64 DOUBLE_803e0850;
extern f64 DOUBLE_803e08f0;
extern f64 DOUBLE_803e0948;
extern f64 DOUBLE_803e0a08;
extern f64 DOUBLE_803e0a98;
extern f64 DOUBLE_803e0b28;
extern f32 lbl_803DC074;
extern f32 lbl_803DC3F8;
extern f32 lbl_803DC400;
extern f32 lbl_803DC404;
extern f32 lbl_803DC408;
extern f32 lbl_803DC40C;
extern f32 lbl_803DC410;
extern f32 lbl_803DC414;
extern f32 lbl_803DC418;
extern f32 lbl_803DC41C;
extern f32 lbl_803DC420;
extern f32 lbl_803DC424;
extern f32 lbl_803DC428;
extern f32 lbl_803DC42C;
extern f32 lbl_803DC430;
extern f32 lbl_803DC434;
extern f32 lbl_803DC438;
extern f32 lbl_803DC43C;
extern f32 lbl_803DC440;
extern f32 lbl_803DC444;
extern f32 lbl_803DC448;
extern f32 lbl_803DC44C;
extern f32 lbl_803DC450;
extern f32 lbl_803DC454;
extern f32 lbl_803DC458;
extern f32 lbl_803DC45C;
extern f32 lbl_803DC460;
extern f32 lbl_803DC464;
extern f32 lbl_803DC468;
extern f32 lbl_803DC46C;
extern f32 lbl_803DC470;
extern f32 lbl_803DC474;
extern f32 lbl_803DC478;
extern f32 lbl_803DC47C;
extern f32 lbl_803DC480;
extern f32 lbl_803DC484;
extern f32 lbl_803DC488;
extern f32 lbl_803DC48C;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDF04;
extern f32 lbl_803DDF2C;
extern f32 lbl_803DDFA0;
extern f32 lbl_803DDFA4;
extern f32 lbl_803DDFB0;
extern f32 lbl_803DDFB4;
extern f32 lbl_803DDFC0;
extern f32 lbl_803DDFC4;
extern f32 lbl_803DDFD8;
extern f32 lbl_803DDFDC;
extern f32 lbl_803DDFE8;
extern f32 lbl_803DDFEC;
extern f32 lbl_803DDFF8;
extern f32 lbl_803DDFFC;
extern f32 lbl_803DE008;
extern f32 lbl_803DE00C;
extern f32 lbl_803DE018;
extern f32 lbl_803DE01C;
extern f32 lbl_803DE028;
extern f32 lbl_803DE02C;
extern f32 lbl_803E00B0;
extern f32 lbl_803E00B4;
extern f32 lbl_803E00B8;
extern f32 lbl_803E00BC;
extern f32 lbl_803E00D0;
extern f32 lbl_803E00D4;
extern f32 lbl_803E00D8;
extern f32 lbl_803E00DC;
extern f32 lbl_803E00E0;
extern f32 lbl_803E00E8;
extern f32 lbl_803E00EC;
extern f32 lbl_803E00F0;
extern f32 lbl_803E00F4;
extern f32 lbl_803E00F8;
extern f32 lbl_803E0108;
extern f32 lbl_803E010C;
extern f32 lbl_803E0110;
extern f32 lbl_803E0114;
extern f32 lbl_803E0118;
extern f32 lbl_803E011C;
extern f32 lbl_803E0120;
extern f32 lbl_803E0124;
extern f32 lbl_803E0128;
extern f32 lbl_803E012C;
extern f32 lbl_803E0130;
extern f32 lbl_803E0134;
extern f32 lbl_803E0138;
extern f32 lbl_803E013C;
extern f32 lbl_803E0140;
extern f32 lbl_803E0144;
extern f32 lbl_803E0148;
extern f32 lbl_803E014C;
extern f32 lbl_803E0150;
extern f32 lbl_803E0154;
extern f32 lbl_803E0158;
extern f32 lbl_803E015C;
extern f32 lbl_803E0160;
extern f32 lbl_803E0164;
extern f32 lbl_803E0168;
extern f32 lbl_803E016C;
extern f32 lbl_803E0170;
extern f32 lbl_803E0174;
extern f32 lbl_803E0178;
extern f32 lbl_803E017C;
extern f32 lbl_803E0180;
extern f32 lbl_803E0184;
extern f32 lbl_803E0188;
extern f32 lbl_803E018C;
extern f32 lbl_803E0190;
extern f32 lbl_803E0194;
extern f32 lbl_803E0198;
extern f32 lbl_803E019C;
extern f32 lbl_803E01A0;
extern f32 lbl_803E01A4;
extern f32 lbl_803E01A8;
extern f32 lbl_803E01AC;
extern f32 lbl_803E01B0;
extern f32 lbl_803E01B4;
extern f32 lbl_803E01B8;
extern f32 lbl_803E01BC;
extern f32 lbl_803E01C0;
extern f32 lbl_803E01C4;
extern f32 lbl_803E01C8;
extern f32 lbl_803E01CC;
extern f32 lbl_803E01D0;
extern f32 lbl_803E01D4;
extern f32 lbl_803E01D8;
extern f32 lbl_803E01DC;
extern f32 lbl_803E01E0;
extern f32 lbl_803E01E4;
extern f32 lbl_803E01E8;
extern f32 lbl_803E01EC;
extern f32 lbl_803E01F0;
extern f32 lbl_803E01F4;
extern f32 lbl_803E01F8;
extern f32 lbl_803E01FC;
extern f32 lbl_803E0200;
extern f32 lbl_803E0204;
extern f32 lbl_803E0208;
extern f32 lbl_803E020C;
extern f32 lbl_803E0210;
extern f32 lbl_803E0214;
extern f32 lbl_803E0218;
extern f32 lbl_803E021C;
extern f32 lbl_803E0220;
extern f32 lbl_803E0224;
extern f32 lbl_803E0228;
extern f32 lbl_803E022C;
extern f32 lbl_803E0230;
extern f32 lbl_803E0234;
extern f32 lbl_803E0238;
extern f32 lbl_803E023C;
extern f32 lbl_803E0240;
extern f32 lbl_803E0244;
extern f32 lbl_803E0248;
extern f32 lbl_803E024C;
extern f32 lbl_803E0250;
extern f32 lbl_803E0254;
extern f32 lbl_803E0258;
extern f32 lbl_803E025C;
extern f32 lbl_803E0260;
extern f32 lbl_803E0264;
extern f32 lbl_803E0268;
extern f32 lbl_803E026C;
extern f32 lbl_803E0278;
extern f32 lbl_803E027C;
extern f32 lbl_803E0280;
extern f32 lbl_803E0284;
extern f32 lbl_803E0288;
extern f32 lbl_803E028C;
extern f32 lbl_803E0290;
extern f32 lbl_803E0294;
extern f32 lbl_803E0298;
extern f32 lbl_803E029C;
extern f32 lbl_803E02A0;
extern f32 lbl_803E02A4;
extern f32 lbl_803E02A8;
extern f32 lbl_803E02AC;
extern f32 lbl_803E02B0;
extern f32 lbl_803E02B4;
extern f32 lbl_803E02B8;
extern f32 lbl_803E02BC;
extern f32 lbl_803E02C0;
extern f32 lbl_803E02C4;
extern f32 lbl_803E02C8;
extern f32 lbl_803E02CC;
extern f32 lbl_803E02D0;
extern f32 lbl_803E02D4;
extern f32 lbl_803E02D8;
extern f32 lbl_803E02DC;
extern f32 lbl_803E02E0;
extern f32 lbl_803E02E4;
extern f32 lbl_803E02E8;
extern f32 lbl_803E02EC;
extern f32 lbl_803E02F0;
extern f32 lbl_803E02F4;
extern f32 lbl_803E02F8;
extern f32 lbl_803E02FC;
extern f32 lbl_803E0300;
extern f32 lbl_803E0304;
extern f32 lbl_803E0308;
extern f32 lbl_803E030C;
extern f32 lbl_803E0310;
extern f32 lbl_803E0314;
extern f32 lbl_803E0318;
extern f32 lbl_803E031C;
extern f32 lbl_803E0320;
extern f32 lbl_803E0324;
extern f32 lbl_803E0328;
extern f32 lbl_803E032C;
extern f32 lbl_803E0330;
extern f32 lbl_803E0334;
extern f32 lbl_803E0338;
extern f32 lbl_803E033C;
extern f32 lbl_803E0340;
extern f32 lbl_803E0344;
extern f32 lbl_803E0348;
extern f32 lbl_803E034C;
extern f32 lbl_803E0350;
extern f32 lbl_803E0354;
extern f32 lbl_803E0358;
extern f32 lbl_803E035C;
extern f32 lbl_803E0360;
extern f32 lbl_803E0364;
extern f32 lbl_803E0368;
extern f32 lbl_803E036C;
extern f32 lbl_803E0370;
extern f32 lbl_803E0374;
extern f32 lbl_803E0378;
extern f32 lbl_803E037C;
extern f32 lbl_803E0380;
extern f32 lbl_803E0384;
extern f32 lbl_803E0388;
extern f32 lbl_803E03A0;
extern f32 lbl_803E03A4;
extern f32 lbl_803E03A8;
extern f32 lbl_803E03AC;
extern f32 lbl_803E03B0;
extern f32 lbl_803E03B4;
extern f32 lbl_803E03B8;
extern f32 lbl_803E03BC;
extern f32 lbl_803E03C0;
extern f32 lbl_803E03C4;
extern f32 lbl_803E03C8;
extern f32 lbl_803E03CC;
extern f32 lbl_803E03D0;
extern f32 lbl_803E03D4;
extern f32 lbl_803E03D8;
extern f32 lbl_803E03DC;
extern f32 lbl_803E03E0;
extern f32 lbl_803E03E4;
extern f32 lbl_803E03E8;
extern f32 lbl_803E03EC;
extern f32 lbl_803E03F0;
extern f32 lbl_803E03F4;
extern f32 lbl_803E03F8;
extern f32 lbl_803E03FC;
extern f32 lbl_803E0400;
extern f32 lbl_803E0404;
extern f32 lbl_803E0408;
extern f32 lbl_803E040C;
extern f32 lbl_803E0410;
extern f32 lbl_803E0414;
extern f32 lbl_803E0418;
extern f32 lbl_803E041C;
extern f32 lbl_803E0420;
extern f32 lbl_803E0424;
extern f32 lbl_803E0428;
extern f32 lbl_803E042C;
extern f32 lbl_803E0430;
extern f32 lbl_803E0434;
extern f32 lbl_803E0438;
extern f32 lbl_803E043C;
extern f32 lbl_803E0440;
extern f32 lbl_803E0444;
extern f32 lbl_803E0448;
extern f32 lbl_803E044C;
extern f32 lbl_803E0450;
extern f32 lbl_803E0454;
extern f32 lbl_803E0458;
extern f32 lbl_803E045C;
extern f32 lbl_803E0460;
extern f32 lbl_803E0464;
extern f32 lbl_803E0468;
extern f32 lbl_803E046C;
extern f32 lbl_803E0470;
extern f32 lbl_803E0474;
extern f32 lbl_803E0478;
extern f32 lbl_803E047C;
extern f32 lbl_803E0480;
extern f32 lbl_803E0484;
extern f32 lbl_803E0488;
extern f32 lbl_803E048C;
extern f32 lbl_803E0490;
extern f32 lbl_803E0494;
extern f32 lbl_803E0498;
extern f32 lbl_803E049C;
extern f32 lbl_803E04A0;
extern f32 lbl_803E04A4;
extern f32 lbl_803E04A8;
extern f32 lbl_803E04AC;
extern f32 lbl_803E04B0;
extern f32 lbl_803E04B4;
extern f32 lbl_803E04B8;
extern f32 lbl_803E04BC;
extern f32 lbl_803E04C0;
extern f32 lbl_803E04C4;
extern f32 lbl_803E04C8;
extern f32 lbl_803E04CC;
extern f32 lbl_803E04D0;
extern f32 lbl_803E04D4;
extern f32 lbl_803E04D8;
extern f32 lbl_803E04F0;
extern f32 lbl_803E04F4;
extern f32 lbl_803E04F8;
extern f32 lbl_803E04FC;
extern f32 lbl_803E0500;
extern f32 lbl_803E0504;
extern f32 lbl_803E0508;
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;
extern f32 lbl_803E051C;
extern f32 lbl_803E0520;
extern f32 lbl_803E0524;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;
extern f32 lbl_803E053C;
extern f32 lbl_803E0540;
extern f32 lbl_803E0544;
extern f32 lbl_803E0548;
extern f32 lbl_803E054C;
extern f32 lbl_803E0550;
extern f32 lbl_803E0554;
extern f32 lbl_803E0558;
extern f32 lbl_803E055C;
extern f32 lbl_803E0560;
extern f32 lbl_803E0564;
extern f32 lbl_803E0568;
extern f32 lbl_803E056C;
extern f32 lbl_803E0570;
extern f32 lbl_803E0574;
extern f32 lbl_803E0578;
extern f32 lbl_803E057C;
extern f32 lbl_803E0580;
extern f32 lbl_803E0584;
extern f32 lbl_803E0588;
extern f32 lbl_803E058C;
extern f32 lbl_803E0590;
extern f32 lbl_803E0594;
extern f32 lbl_803E0598;
extern f32 lbl_803E059C;
extern f32 lbl_803E05A0;
extern f32 lbl_803E05A4;
extern f32 lbl_803E05A8;
extern f32 lbl_803E05AC;
extern f32 lbl_803E05B0;
extern f32 lbl_803E05B4;
extern f32 lbl_803E05B8;
extern f32 lbl_803E05BC;
extern f32 lbl_803E05C0;
extern f32 lbl_803E05C4;
extern f32 lbl_803E05C8;
extern f32 lbl_803E05CC;
extern f32 lbl_803E05D0;
extern f32 lbl_803E05D4;
extern f32 lbl_803E05D8;
extern f32 lbl_803E05DC;
extern f32 lbl_803E05E0;
extern f32 lbl_803E05E4;
extern f32 lbl_803E05E8;
extern f32 lbl_803E05EC;
extern f32 lbl_803E05F0;
extern f32 lbl_803E05F4;
extern f32 lbl_803E05F8;
extern f32 lbl_803E05FC;
extern f32 lbl_803E0600;
extern f32 lbl_803E0604;
extern f32 lbl_803E0608;
extern f32 lbl_803E060C;
extern f32 lbl_803E0610;
extern f32 lbl_803E0614;
extern f32 lbl_803E0618;
extern f32 lbl_803E061C;
extern f32 lbl_803E0620;
extern f32 lbl_803E0624;
extern f32 lbl_803E0628;
extern f32 lbl_803E062C;
extern f32 gFloatNegOne;
extern f32 gFloatOne;
extern f32 gFloatZero;
extern f32 lbl_803E063C;
extern f32 lbl_803E0650;
extern f32 lbl_803E0654;
extern f32 gFloatHalf;
extern f32 lbl_803E065C;
extern f32 lbl_803E0660;
extern f32 lbl_803E0664;
extern f32 lbl_803E0668;
extern f32 lbl_803E066C;
extern f32 lbl_803E0670;
extern f32 lbl_803E0674;
extern f32 lbl_803E0678;
extern f32 lbl_803E067C;
extern f32 lbl_803E0680;
extern f32 lbl_803E0684;
extern f32 lbl_803E0688;
extern f32 lbl_803E068C;
extern f32 lbl_803E0690;
extern f32 lbl_803E0694;
extern f32 lbl_803E0698;
extern f32 lbl_803E069C;
extern f32 lbl_803E06A0;
extern f32 lbl_803E06A4;
extern f32 lbl_803E06A8;
extern f32 lbl_803E06AC;
extern f32 lbl_803E06B0;
extern f32 lbl_803E06B4;
extern f32 lbl_803E06B8;
extern f32 lbl_803E06BC;
extern f32 lbl_803E06C0;
extern f32 lbl_803E06C4;
extern f32 lbl_803E06C8;
extern f32 lbl_803E06CC;
extern f32 lbl_803E06D0;
extern f32 lbl_803E06D4;
extern f32 lbl_803E06E0;
extern f32 lbl_803E06E4;
extern f32 lbl_803E06E8;
extern f32 lbl_803E06EC;
extern f32 lbl_803E06F0;
extern f32 lbl_803E06F4;
extern f32 lbl_803E06F8;
extern f32 lbl_803E0708;
extern f32 lbl_803E070C;
extern f32 lbl_803E0710;
extern f32 lbl_803E0714;
extern f32 lbl_803E0718;
extern f32 lbl_803E071C;
extern f32 lbl_803E0720;
extern f32 lbl_803E0724;
extern f32 lbl_803E0728;
extern f32 lbl_803E072C;
extern f32 lbl_803E0730;
extern f32 lbl_803E0734;
extern f32 lbl_803E0738;
extern f32 lbl_803E073C;
extern f32 lbl_803E0740;
extern f32 lbl_803E0744;
extern f32 lbl_803E0748;
extern f32 lbl_803E074C;
extern f32 lbl_803E0750;
extern f32 lbl_803E0754;
extern f32 lbl_803E0758;
extern f32 lbl_803E075C;
extern f32 lbl_803E0760;
extern f32 lbl_803E0764;
extern f32 lbl_803E0768;
extern f32 lbl_803E076C;
extern f32 lbl_803E0770;
extern f32 lbl_803E0774;
extern f32 lbl_803E0778;
extern f32 lbl_803E077C;
extern f32 lbl_803E0780;
extern f32 lbl_803E0784;
extern f32 lbl_803E0788;
extern f32 lbl_803E078C;
extern f32 lbl_803E0790;
extern f32 lbl_803E0794;
extern f32 lbl_803E0798;
extern f32 lbl_803E079C;
extern f32 lbl_803E07A0;
extern f32 lbl_803E07A4;
extern f32 lbl_803E07A8;
extern f32 lbl_803E07AC;
extern f32 lbl_803E07B0;
extern f32 lbl_803E07B4;
extern f32 lbl_803E07B8;
extern f32 lbl_803E07BC;
extern f32 lbl_803E07C0;
extern f32 lbl_803E07C4;
extern f32 lbl_803E07C8;
extern f32 lbl_803E07CC;
extern f32 lbl_803E07D0;
extern f32 lbl_803E07D4;
extern f32 lbl_803E07D8;
extern f32 lbl_803E07DC;
extern f32 lbl_803E07E0;
extern f32 lbl_803E07E4;
extern f32 lbl_803E07E8;
extern f32 lbl_803E07EC;
extern f32 lbl_803E07F0;
extern f32 lbl_803E07F4;
extern f32 lbl_803E07F8;
extern f32 lbl_803E07FC;
extern f32 lbl_803E0800;
extern f32 lbl_803E0804;
extern f32 lbl_803E0808;
extern f32 lbl_803E080C;
extern f32 lbl_803E0810;
extern f32 lbl_803E0814;
extern f32 lbl_803E0818;
extern f32 lbl_803E081C;
extern f32 lbl_803E0820;
extern f32 lbl_803E0824;
extern f32 lbl_803E0828;
extern f32 lbl_803E082C;
extern f32 lbl_803E0830;
extern f32 lbl_803E0834;
extern f32 lbl_803E0838;
extern f32 lbl_803E083C;
extern f32 lbl_803E0840;
extern f32 lbl_803E0844;
extern f32 lbl_803E0848;
extern f32 lbl_803E0860;
extern f32 lbl_803E0864;
extern f32 lbl_803E0868;
extern f32 lbl_803E086C;
extern f32 lbl_803E0870;
extern f32 lbl_803E0874;
extern f32 lbl_803E0878;
extern f32 lbl_803E087C;
extern f32 lbl_803E0880;
extern f32 lbl_803E0884;
extern f32 lbl_803E0888;
extern f32 lbl_803E088C;
extern f32 lbl_803E0890;
extern f32 lbl_803E0894;
extern f32 lbl_803E0898;
extern f32 lbl_803E089C;
extern f32 lbl_803E08A0;
extern f32 lbl_803E08A4;
extern f32 lbl_803E08A8;
extern f32 lbl_803E08AC;
extern f32 lbl_803E08B0;
extern f32 lbl_803E08B4;
extern f32 lbl_803E08B8;
extern f32 lbl_803E08BC;
extern f32 lbl_803E08C0;
extern f32 lbl_803E08C4;
extern f32 lbl_803E08C8;
extern f32 lbl_803E08CC;
extern f32 lbl_803E08D0;
extern f32 lbl_803E08D4;
extern f32 lbl_803E08D8;
extern f32 lbl_803E08DC;
extern f32 lbl_803E08E0;
extern f32 lbl_803E08E4;
extern f32 lbl_803E08E8;
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
extern f32 lbl_803E0958;
extern f32 lbl_803E095C;
extern f32 lbl_803E0960;
extern f32 lbl_803E0964;
extern f32 lbl_803E0968;
extern f32 lbl_803E096C;
extern f32 lbl_803E0970;
extern f32 lbl_803E0974;
extern f32 lbl_803E0978;
extern f32 lbl_803E097C;
extern f32 lbl_803E0980;
extern f32 lbl_803E0984;
extern f32 lbl_803E0988;
extern f32 lbl_803E098C;
extern f32 lbl_803E0990;
extern f32 lbl_803E0994;
extern f32 lbl_803E0998;
extern f32 lbl_803E099C;
extern f32 lbl_803E09A0;
extern f32 lbl_803E09A4;
extern f32 lbl_803E09A8;
extern f32 lbl_803E09AC;
extern f32 lbl_803E09B0;
extern f32 lbl_803E09B4;
extern f32 lbl_803E09B8;
extern f32 lbl_803E09BC;
extern f32 lbl_803E09C0;
extern f32 lbl_803E09C4;
extern f32 lbl_803E09C8;
extern f32 lbl_803E09CC;
extern f32 lbl_803E09D0;
extern f32 lbl_803E09D4;
extern f32 lbl_803E09D8;
extern f32 lbl_803E09DC;
extern f32 lbl_803E09E0;
extern f32 lbl_803E09E4;
extern f32 lbl_803E09E8;
extern f32 lbl_803E09EC;
extern f32 lbl_803E09F0;
extern f32 lbl_803E09F4;
extern f32 lbl_803E09F8;
extern f32 lbl_803E09FC;
extern f32 lbl_803E0A00;
extern f32 lbl_803E0A04;
extern f32 lbl_803E0A18;
extern f32 lbl_803E0A1C;
extern f32 lbl_803E0A20;
extern f32 lbl_803E0A24;
extern f32 lbl_803E0A28;
extern f32 lbl_803E0A2C;
extern f32 lbl_803E0A30;
extern f32 lbl_803E0A34;
extern f32 lbl_803E0A38;
extern f32 lbl_803E0A3C;
extern f32 lbl_803E0A40;
extern f32 lbl_803E0A44;
extern f32 lbl_803E0A48;
extern f32 lbl_803E0A4C;
extern f32 lbl_803E0A50;
extern f32 lbl_803E0A54;
extern f32 lbl_803E0A58;
extern f32 lbl_803E0A5C;
extern f32 lbl_803E0A60;
extern f32 lbl_803E0A64;
extern f32 lbl_803E0A68;
extern f32 lbl_803E0A6C;
extern f32 lbl_803E0A74;
extern f32 lbl_803E0A78;
extern f32 lbl_803E0A7C;
extern f32 lbl_803E0A80;
extern f32 lbl_803E0A84;
extern f32 lbl_803E0A88;
extern f32 lbl_803E0A8C;
extern f32 lbl_803E0A90;
extern f32 lbl_803E0AA8;
extern f32 lbl_803E0AAC;
extern f32 lbl_803E0AB0;
extern f32 lbl_803E0AB4;
extern f32 lbl_803E0AB8;
extern f32 lbl_803E0ABC;
extern f32 lbl_803E0AC0;
extern f32 lbl_803E0AC4;
extern f32 lbl_803E0AC8;
extern f32 lbl_803E0ACC;
extern f32 lbl_803E0AD0;
extern f32 lbl_803E0AD4;
extern f32 lbl_803E0AD8;
extern f32 lbl_803E0ADC;
extern f32 lbl_803E0AE0;
extern f32 lbl_803E0AE4;
extern f32 lbl_803E0AE8;
extern f32 lbl_803E0AEC;
extern f32 lbl_803E0AF0;
extern f32 lbl_803E0AF4;
extern f32 lbl_803E0AF8;
extern f32 lbl_803E0AFC;
extern f32 lbl_803E0B00;
extern f32 lbl_803E0B04;
extern f32 lbl_803E0B08;
extern f32 lbl_803E0B0C;
extern f32 lbl_803E0B10;
extern f32 lbl_803E0B14;
extern f32 lbl_803E0B18;
extern f32 lbl_803E0B1C;
extern f32 lbl_803E0B20;
extern f32 lbl_803E0B24;
extern void* PTR_FUN_80310888;
extern void* PTR_FUN_80310894;
extern void* PTR_LAB_803108a0;

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
void projgfx_func07_nop(void)
{
}

void projgfx_func06_nop(void)
{
}

void projgfx_func05_nop(void)
{
}

void projgfx_onMapSetup(void)
{
}

void projgfx_initialise(void)
{
}

void playerShadow_func03_nop(void)
{
}

void playerShadow_release_nop(void)
{
}

void playerShadow_initialise_nop(void)
{
}

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

void partfx_onMapSetup(void)
{
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

void Effect2_func03_nop(void)
{
}

void Effect2_release(void)
{
}

void Effect2_initialise(void)
{
}

void Effect3_func05_nop(void)
{
}

void Effect3_func03_nop(void)
{
}

void Effect3_release(void)
{
}

void Effect3_initialise(void)
{
}

void Effect4_func03_nop(void)
{
}

void Effect4_release(void)
{
}

void Effect4_initialise(void)
{
}

void Effect5_func03_nop(void)
{
}

void Effect5_release(void)
{
}

void Effect5_initialise(void)
{
}

void Effect6_func03_nop(void)
{
}

void Effect6_release(void)
{
}

void Effect6_initialise(void)
{
}

void Effect7_func03_nop(void)
{
}

void Effect7_release(void)
{
}

void Effect7_initialise(void)
{
}

void Effect8_func03_nop(void)
{
}

void Effect8_release(void)
{
}

void Effect8_initialise(void)
{
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

/* 8b "li r3, N; blr" returners. */
int projgfx_getObjectTypeId(void) { return 0x0; }

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
s16 dll_0B_func18(void) { return gModgfxLastSpawnHandle; }

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
#pragma peephole reset
#pragma scheduling reset

/* OSReport(literal) wrapper. */
extern void OSReport(const char* fmt, ...);
#pragma scheduling off
void projgfx_release_doUnsupported(void) { OSReport(sProjgfxReleaseDoNoLongerSupported); }
#pragma scheduling reset

/* OSReport-stub returns. */

#define PROJGFX_UNSUPPORTED_FALSE_RETURN 0

#pragma scheduling off
int projgfx_rayhit_doUnsupported(void)
{
    OSReport(sProjgfxRayhitDoNoLongerSupported);
    return PROJGFX_UNSUPPORTED_FALSE_RETURN;
}

int projgfx_setzscale_doUnsupported(void)
{
    OSReport(sProjgfxSetzscaleDoNoLongerSupported);
    return PROJGFX_UNSUPPORTED_FALSE_RETURN;
}
#pragma scheduling reset

/* Pattern wrappers. */
int projgfx_func04_ret_m1(void) { return -0x1; }

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
extern f64 lbl_803DF480;
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
#pragma scheduling reset

#pragma peephole off
void playerShadow_setMode(u8 v)
{
    if (v == 0 || v >= 0xa)
    {
        gPlayerShadowMode = v;
    }
}
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void playerShadow_renderObject(void* obj)
{
    u32* defaults;
    u32 params[4];
    int* tileInfo;
    int hitTable;
    int hitCount;
    int hitTableValue;
    u32 mode;
    f32 hitData[6];
    f32 verts[8][3];
    f32 radius;
    f32 height;
    f32 minX;
    f32 maxX;
    f32 topY;
    f32 bottomY;
    f32 minZ;
    f32 maxZ;

    defaults = lbl_802C2160;
    params[0] = defaults[0];
    params[1] = defaults[1];
    params[2] = defaults[2];
    params[3] = defaults[3];
    hitTable = 0;

    if (gPlayerShadowMode == 0)
    {
        return;
    }

    mode = gPlayerShadowMode - 0xb;
    if (mode <= 6)
    {
        switch (mode)
        {
        case 0:
            radius = lbl_803DF488;
            height = radius;
            break;
        case 1:
            radius = lbl_803DF48C;
            height = lbl_803DF490;
            break;
        case 2:
            radius = lbl_803DF494;
            height = lbl_803DF488;
            break;
        case 3:
            radius = lbl_803DF494;
            height = lbl_803DF488;
            break;
        case 4:
            radius = lbl_803DF498;
            height = lbl_803DF490;
            break;
        case 5:
            radius = lbl_803DF49C;
            height = lbl_803DF4A0;
            break;
        case 6:
            radius = lbl_803DF4A4;
            height = radius;
            break;
        }
    }
    else
    {
        radius = lbl_803DF46C;
        height = radius;
    }

    minX = ((GameObject*)obj)->anim.localPosX - radius;
    maxX = ((GameObject*)obj)->anim.localPosX + radius;
    topY = ((GameObject*)obj)->anim.localPosY + height;
    bottomY = ((GameObject*)obj)->anim.localPosY - height;
    minZ = ((GameObject*)obj)->anim.localPosZ - radius;
    maxZ = ((GameObject*)obj)->anim.localPosZ + radius;

    verts[0][0] = minX;
    verts[0][1] = topY;
    verts[0][2] = minZ;
    verts[1][0] = minX;
    verts[1][1] = topY;
    verts[1][2] = maxZ;
    verts[2][0] = maxX;
    verts[2][1] = topY;
    verts[2][2] = maxZ;
    verts[3][0] = maxX;
    verts[3][1] = topY;
    verts[3][2] = minZ;
    verts[4][0] = minX;
    verts[4][1] = bottomY;
    verts[4][2] = minZ;
    verts[5][0] = minX;
    verts[5][1] = bottomY;
    verts[5][2] = maxZ;
    verts[6][0] = maxX;
    verts[6][1] = bottomY;
    verts[6][2] = maxZ;
    verts[7][0] = maxX;
    verts[7][1] = bottomY;
    verts[7][2] = minZ;

    hitDetect_calcSweptSphereBounds(hitData, &verts[0], &verts[4], params, 4);
    hitDetectFn_800691c0(obj, hitData, 0x84, 0);
    fn_80069968(&hitCount, &hitTable);
    hitTableValue = hitTable;
    fn_80069958(&tileInfo);
    fn_800A3AF0((void*)hitTableValue, hitCount, obj,
                ((GameObject*)obj)->anim.localPosX - (f32)tileInfo[0],
                ((GameObject*)obj)->anim.localPosZ - (f32)tileInfo[2]);
}
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
void dll_0B_initialise(void)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        arr[i] = NULL;
    }
}

void dll_0B_func0F(int p1, int p2, int p3, int p4, int p5)
{
    ModgfxSpawnContext* context = &gModgfxSpawnContext;
    f32 fz;
    f32 fz2;
    memset(context, 0, sizeof(*context));
    context->modeByte = p2;
    context->attachedSource = (void*)p1;
    context->sourceModeCopy = (u8)p2;
    fz = lbl_803DF430;
    context->posX = fz;
    context->posY = fz;
    context->posZ = fz;
    context->vecX = fz;
    context->vecY = fz;
    context->vecZ = fz;
    fz2 = lbl_803DF434;
    context->scale = fz2;
    context->word40 = p4;
    context->word3C = p5;
    context->byte59 = p3;
    context->byte5A = 0;
    context->byte5B = 0;
}

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
        if ((s16)p1 != arr[i]->sequenceId && p2 == 0) continue;
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
extern f32 lbl_803DF4BC;
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
        if ((s32)cur->texCoordS > 0x100) ovx = (u8)(ovx + 1);
        if ((s32)cur->texCoordS < -0x100) ovx = (u8)(ovx + 1);
        cur->texCoordT = (s16)(cur->texCoordT + dy);
        if ((s32)cur->texCoordT > 0x100) ovy = (u8)(ovy + 1);
        if ((s32)cur->texCoordT < -0x100) ovy = (u8)(ovy + 1);
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
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
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
#pragma scheduling reset


#pragma peephole off
#pragma scheduling off
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
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void fn_800A081C(int p1, int p2, int mode)
{
    extern void vecRotateZXY(void*, f32*);
    extern f32 lbl_803DD284;
    extern f32 lbl_803DF430;
    extern f32 lbl_803DF434;

    if (mode == 1)
    {
        if (((ModgfxState*)p1)->channelFrames[((ModgfxState*)p1)->activeChannel] == 0)
        {
            int flags = ((ModgfxState*)p1)->flags;
            if ((flags & 0x4) != 0 || (flags & 0x80000) != 0)
            {
                s16 buf[6];
                f32* fbuf = (f32*)&buf[2];
                s16 v = *((ModgfxState*)p1)->unk04;
                f32 fill = lbl_803DF430;
                fbuf[3] = fill;
                fbuf[2] = fill;
                fbuf[1] = fill;
                fbuf[0] = lbl_803DF434;
                buf[2] = v;
                buf[1] = v;
                buf[0] = v;
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
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800A09C4  size: 240b  modgfx_stepS16VectorLerp: integer-vector lerp setup.
 * On mode 1, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
#pragma scheduling off
#pragma peephole off
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
    ((ModgfxState*)obj)->rotOffsetZ = ((ModgfxState*)obj)->rotOffsetZ + ((ModgfxState*)obj)->rotStepZ;
    ((ModgfxState*)obj)->rotOffsetY = ((ModgfxState*)obj)->rotOffsetY + ((ModgfxState*)obj)->rotStepY;
    ((ModgfxState*)obj)->rotOffsetX = ((ModgfxState*)obj)->rotOffsetX + ((ModgfxState*)obj)->rotStepX;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800A113C  size: 276b  dll_0B_func0E: flag every active effect
 * whose owner object has the 0x800 state bit by setting its byte _13e. */
#pragma scheduling off
#pragma peephole off
void dll_0B_func0E(void)
{
    int i;
    PartfxEffectState** effects = (PartfxEffectState**)gPartfxActiveEffects;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        PartfxEffectState* effect = effects[i];
        GameObject* sourceObject;
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
void partfx_updateFrameState(void)
{
    lbl_803DB7A8 = lbl_803DB7A8 + lbl_803DF4C8 * timeDelta;
    if (lbl_803DB7A8 > 1.0f)
    {
        lbl_803DB7A8 = lbl_803DF4CC;
    }
    lbl_803DB7AC = lbl_803DB7AC + lbl_803DF4C8 * timeDelta;
    if (lbl_803DB7AC > *(f32*)&lbl_803DF4D0)
    {
        lbl_803DB7AC = lbl_803DF4D8;
    }
    lbl_803DD318 = lbl_803DD318 + framesThisStep * 100;
    if (lbl_803DD318 > 0x7fff)
    {
        lbl_803DD318 = 0;
    }
    lbl_803DD324 = mathSinf(lbl_803DF718 * (f32)(s16)lbl_803DD318 / lbl_803DF71C);
    lbl_803DD31C = lbl_803DD31C + framesThisStep * 0x32;
    if (lbl_803DD31C > 0x7fff)
    {
        lbl_803DD31C = 0;
    }
    lbl_803DD320 = mathSinf(lbl_803DF718 * (f32)(s16)lbl_803DD31C / lbl_803DF71C);
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
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800AF41C  size: 560b  partfx_release: clear the 20-slot
 * effect-id table and free all 20 cached particle resources. */
#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF720;
extern f32 lbl_803DF724;
extern f32 lbl_803DF728;
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
void Effect1_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7B8 + (step = lbl_803DF720 * timeDelta);
    lbl_803DB7B8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7B8 = lbl_803DF724;
    }
    sum = lbl_803DB7BC + step;
    lbl_803DB7BC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7BC = lbl_803DF730;
    }
    lbl_803DD328 = lbl_803DD328 + framesThisStep * 0x64;
    if (lbl_803DD328 > 0x7fff)
    {
        lbl_803DD328 = 0;
    }
    lbl_803DD334 = mathSinf(lbl_803DF868 * (f32)(s16)lbl_803DD328 / lbl_803DF86C);
    lbl_803DD32C = lbl_803DD32C + framesThisStep * 0x32;
    if (lbl_803DD32C > 0x7fff)
    {
        lbl_803DD32C = 0;
    }
    lbl_803DD330 = mathSinf(lbl_803DF868 * (f32)(s16)lbl_803DD32C / lbl_803DF86C);
}
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
extern f32 lbl_803DFC88;
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
extern f32 lbl_803DFDA0;
extern f32 lbl_803DFDA8;
extern f32 lbl_803DFE20;
extern f32 lbl_803DFE24;
extern f32 lbl_803DFE28;
extern f32 lbl_803DFE2C;
extern f32 lbl_803DFE30;
extern f32 lbl_803DFE38;
extern f32 lbl_803DFEB0;
extern f32 lbl_803DFEB4;

#pragma scheduling off
#pragma peephole off
void Effect2_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7C8 + (step = lbl_803DF870 * timeDelta);
    lbl_803DB7C8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7C8 = lbl_803DF874;
    }
    sum = lbl_803DB7CC + step;
    lbl_803DB7CC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7CC = lbl_803DF880;
    }
    lbl_803DD338 = lbl_803DD338 + framesThisStep * 0x64;
    if (lbl_803DD338 > 0x7fff)
    {
        lbl_803DD338 = 0;
    }
    lbl_803DD344 = mathSinf(lbl_803DF9C8 * (f32)(s16)lbl_803DD338 / lbl_803DF9CC);
    lbl_803DD33C = lbl_803DD33C + framesThisStep * 0x32;
    if (lbl_803DD33C > 0x7fff)
    {
        lbl_803DD33C = 0;
    }
    lbl_803DD340 = mathSinf(lbl_803DF9C8 * (f32)(s16)lbl_803DD33C / lbl_803DF9CC);
}

void Effect4_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7D8 + (step = lbl_803DFA88 * timeDelta);
    lbl_803DB7D8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7D8 = lbl_803DFA8C;
    }
    sum = lbl_803DB7DC + step;
    lbl_803DB7DC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7DC = lbl_803DFA98;
    }
    lbl_803DD350 = lbl_803DD350 + framesThisStep * 0x64;
    if (lbl_803DD350 > 0x7fff)
    {
        lbl_803DD350 = 0;
    }
    lbl_803DD35C = mathSinf(lbl_803DFBD8 * (f32)(s16)lbl_803DD350 / lbl_803DFBDC);
    lbl_803DD354 = lbl_803DD354 + framesThisStep * 0x32;
    if (lbl_803DD354 > 0x7fff)
    {
        lbl_803DD354 = 0;
    }
    lbl_803DD358 = mathSinf(lbl_803DFBD8 * (f32)(s16)lbl_803DD354 / lbl_803DFBDC);
}

void Effect5_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7E8 + (step = lbl_803DFBE0 * timeDelta);
    lbl_803DB7E8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7E8 = lbl_803DFBE4;
    }
    sum = lbl_803DB7EC + step;
    lbl_803DB7EC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7EC = lbl_803DFBF0;
    }
    lbl_803DD360 = lbl_803DD360 + framesThisStep * 0x64;
    if (lbl_803DD360 > 0x7fff)
    {
        lbl_803DD360 = 0;
    }
    lbl_803DD36C = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD360 / lbl_803DFC7C);
    lbl_803DD364 = lbl_803DD364 + framesThisStep * 0x32;
    if (lbl_803DD364 > 0x7fff)
    {
        lbl_803DD364 = 0;
    }
    lbl_803DD368 = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD364 / lbl_803DFC7C);
}

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

int Effect6_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB7F0 = lbl_803DB7F0 + lbl_803DFC80;
    if (lbl_803DB7F0 > 1.0f) lbl_803DB7F0 = lbl_803DFC84;
    lbl_803DB7F4 = lbl_803DB7F4 + lbl_803DFC8C;
    if (lbl_803DB7F4 > 1.0f) lbl_803DB7F4 = lbl_803DFC90;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803DFC94;
    cfg.startPosY = lbl_803DFC94;
    cfg.startPosZ = lbl_803DFC94;
    cfg.velocityX = lbl_803DFC94;
    cfg.velocityY = lbl_803DFC94;
    cfg.velocityZ = lbl_803DFC94;
    cfg.scale = lbl_803DFC94;
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
    case 0x422:
        if (extraArgs == 0) return 0;
        cfg.scale = lbl_803DFC98;
        cfg.lifetimeFrames = randomGetRange(0xa, 0xd);
        cfg.initialAlpha = (u8) * (u16*)extraArgs;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x64;
        cfg.linkGroup = 0x1e;
        break;
    case 0x423:
        cfg.startPosX = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFC80 * (f32)(s32)
        randomGetRange(5, 0xb);
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80110;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x424:
        cfg.startPosX = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFC90 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityX = lbl_803DFC84 * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityY = lbl_803DFC84 * (f32)(s32)
        randomGetRange(3, 0xa);
        cfg.velocityZ = lbl_803DFC84 * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.scale = lbl_803DFC9C * (f32)(s32)
        randomGetRange(5, 0xb);
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x1480200;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x425:
        cfg.velocityY = lbl_803DFCA0 * (f32)(s32)
        randomGetRange(8, 0xa);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = lbl_803DFC80 * (f32)(s32)
            randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = lbl_803DFC80 * (f32)(s32)
            randomGetRange(0x15, 0x29);
            cfg.lifetimeFrames = 0x1cc;
        }
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord2 = 0x3fff;
        cfg.colorWord1 = 0x3fff;
        cfg.colorWord0 = 0x3fff;
        cfg.overrideColor2 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        break;
    case 0x426:
        cfg.velocityX = lbl_803DFCA0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFCA0 * (f32)(s32)
        randomGetRange(8, 0x14);
        cfg.velocityZ = lbl_803DFCA0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFCA4;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x3000200;
        cfg.renderFlags = 0x200020;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = cfg.overrideColor2 = randomGetRange(0, 0x8000);
        break;
    case 0x427:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFCA8;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803DFCAC;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFCA8;
        cfg.velocityY = lbl_803DFCB0 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFCB8 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFCB4;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x33;
        break;
    case 0x42b:
        if (extraArgs == 0) return 0;
        cfg.scale = lbl_803DFCBC;
        cfg.lifetimeFrames = randomGetRange(0xa, 0xd);
        cfg.initialAlpha = (u8) * (u16*)extraArgs;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xc7e;
        cfg.linkGroup = 0x1e;
        break;
    case 0x42c:
        cfg.velocityX = lbl_803DFCC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFC98 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFCC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFCC4;
        cfg.lifetimeFrames = 0x6e;
        cfg.behaviorFlags = 0x8A100208;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x400;
        cfg.overrideColor1 = 0xEA60;
        cfg.overrideColor2 = 0x1000;
        break;
    case 0x42d:
        cfg.velocityX = lbl_803DFCC4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFCC4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFC84;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0xA100100;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0x400;
        cfg.colorWord1 = 0xEA60;
        cfg.colorWord2 = 0x1000;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xC350;
        cfg.overrideColor2 = 0;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

void Effect6_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7F8 + (step = lbl_803DFC80 * timeDelta);
    lbl_803DB7F8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7F8 = lbl_803DFC84;
    }
    sum = lbl_803DB7FC + step;
    lbl_803DB7FC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7FC = lbl_803DFC90;
    }
    lbl_803DD370 = lbl_803DD370 + framesThisStep * 0x64;
    if (lbl_803DD370 > 0x7fff)
    {
        lbl_803DD370 = 0;
    }
    lbl_803DD37C = mathSinf(lbl_803DFCD0 * (f32)(s16)lbl_803DD370 / lbl_803DFCD4);
    lbl_803DD374 = lbl_803DD374 + framesThisStep * 0x32;
    if (lbl_803DD374 > 0x7fff)
    {
        lbl_803DD374 = 0;
    }
    lbl_803DD378 = mathSinf(lbl_803DFCD0 * (f32)(s16)lbl_803DD374 / lbl_803DFCD4);
}

void Effect7_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB808 + (step = lbl_803DFCD8 * timeDelta);
    lbl_803DB808 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB808 = lbl_803DFCDC;
    }
    sum = lbl_803DB80C + step;
    lbl_803DB80C = sum;
    if (sum > 1.0f)
    {
        lbl_803DB80C = lbl_803DFCE8;
    }
    lbl_803DD380 = lbl_803DD380 + framesThisStep * 0x64;
    if (lbl_803DD380 > 0x7fff)
    {
        lbl_803DD380 = 0;
    }
    lbl_803DD38C = mathSinf(lbl_803DFD90 * (f32)(s16)lbl_803DD380 / lbl_803DFD94);
    lbl_803DD384 = lbl_803DD384 + framesThisStep * 0x32;
    if (lbl_803DD384 > 0x7fff)
    {
        lbl_803DD384 = 0;
    }
    lbl_803DD388 = mathSinf(lbl_803DFD90 * (f32)(s16)lbl_803DD384 / lbl_803DFD94);
}

void Effect8_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB818 + (step = lbl_803DFD98 * timeDelta);
    lbl_803DB818 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB818 = lbl_803DFD9C;
    }
    sum = lbl_803DB81C + step;
    lbl_803DB81C = sum;
    if (sum > 1.0f)
    {
        lbl_803DB81C = lbl_803DFDA8;
    }
    lbl_803DD390 = lbl_803DD390 + framesThisStep * 0x64;
    if (lbl_803DD390 > 0x7fff)
    {
        lbl_803DD390 = 0;
    }
    lbl_803DD39C = mathSinf(lbl_803DFE20 * (f32)(s16)lbl_803DD390 / lbl_803DFE24);
    lbl_803DD394 = lbl_803DD394 + framesThisStep * 0x32;
    if (lbl_803DD394 > 0x7fff)
    {
        lbl_803DD394 = 0;
    }
    lbl_803DD398 = mathSinf(lbl_803DFE20 * (f32)(s16)lbl_803DD394 / lbl_803DFE24);
}

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
extern f32 lbl_803DFE3C;
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

int Effect9_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB820 = lbl_803DB820 + lbl_803DFE28;
    if (lbl_803DB820 > 1.0f) lbl_803DB820 = lbl_803DFE2C;
    lbl_803DB824 = lbl_803DB824 + lbl_803DFE34;
    if (lbl_803DB824 > 1.0f) lbl_803DB824 = lbl_803DFE38;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
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
    switch (effectId - 949)
    {
    case 1:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
    case 0:
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
    case 6:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803DFE58;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8000201;
        cfg.textureId = 0x62;
        break;
    case 5:
        if (spawnParams == 0)
            FILL9();
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityY = lbl_803DFE5C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFE60;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 23:
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
    case 22:
        cfg.scale = lbl_803DFE74;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 21:
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
    case 18:
        if (spawnParams != 0) cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.scale = spawnParams != 0 ? lbl_803DFE7C * ((PartFxSpawnParams*)spawnParams)->unk8 : lbl_803DFE80;
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
    case 13:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
    case 11:
    case 12:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
    case 17:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
    case 16:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100201;
        cfg.textureId = 0x60;
        break;
    case 15:
        if (spawnParams == 0)
            FILL9();
        cfg.lifetimeFrames = (s32)(lbl_803DFE48 * ((PartFxSpawnParams*)spawnParams)->unk8 + lbl_803DFE90);
        cfg.scale = lbl_803DFE94 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xe100200;
        cfg.textureId = 0x57;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourceVecX = *spawnParams;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        break;
    case 14:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
    case 20:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFE98 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unkC : 0.0f;
        cfg.startPosY = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk10 : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk14 : 0.0f;
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
    case 9:
        cfg.velocityY = lbl_803DFE9C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0x3c) + lbl_803DFE9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100201;
        cfg.textureId = 0x63;
        break;
    case 8:
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
        cfg.startPosZ = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk14 : 0.0f;
        cfg.startPosY = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk10 : lbl_803DFEA0;
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, -0xa) + cfg.startPosZ;
        cfg.scale = lbl_803DFEA4;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x108000e;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xbe;
        break;
    case 7:
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
#undef FILL9

extern FxNode9 lbl_8039C380;
extern void randFn_80080100();
extern f32 lbl_803DB810;
extern f32 lbl_803DB814;
extern f32 lbl_803DFDA4;
extern f32 lbl_803DFDAC;
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

int Effect8_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB810 = lbl_803DB810 + lbl_803DFD98;
    if (lbl_803DB810 > 1.0f) lbl_803DB810 = lbl_803DFD9C;
    lbl_803DB814 = lbl_803DB814 + lbl_803DFDA4;
    if (lbl_803DB814 > 1.0f) lbl_803DB814 = lbl_803DFDA8;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
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
    case 0x361:
        cfg.velocityX = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x362:
        cfg.velocityX = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x35f:
        cfg.startPosX = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0xa, 0x78);
        cfg.velocityY = lbl_803DFDB8 * (f32)(s32)
        randomGetRange(2, 0x64);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180201;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0x9b00;
        cfg.overrideColor0 = 0x9600;
        cfg.overrideColor1 = 0x1400;
        cfg.overrideColor2 = 0x1400;
        cfg.renderFlags = 0x20;
        break;
    case 0x360:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = lbl_803DFDBC + (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.textureId = 0x208;
        break;
    case 0x357:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.colorWord0 = (u16)((u8)((PartFxSpawnParams*)spawnParams)->unk4 << 8);
        cfg.colorWord1 = (u16)((u8)((PartFxSpawnParams*)spawnParams)->unk2 << 8);
        cfg.colorWord2 = (u16)((u8)((PartFxSpawnParams*)spawnParams)->unk0 << 8);
        cfg.overrideColor0 = 0xfe00;
        cfg.overrideColor1 = 0xfe00;
        cfg.overrideColor2 = 0xfe00;
        cfg.scale = lbl_803DFDCC;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x78;
        cfg.behaviorFlags = 0x8000201;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x71;
        break;
    case 0x359:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = lbl_803DFDBC + (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x352:
        cfg.scale = lbl_803DFDD0;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0xa100208;
        cfg.textureId = 0x91;
        break;
    case 0x353:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-2, 2);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityX = lbl_803DFDD4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDD4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.scale = lbl_803DFDD8 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x17c) + 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80400109;
        cfg.textureId = 0x47;
        break;
    case 0x354:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-4, 4);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-4, 4);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x1000001;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x355:
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x356:
        cfg.scale = lbl_803DFDC4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.velocityY = lbl_803DFDDC * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.behaviorFlags = 0x80201;
        cfg.textureId = 0x62;
        break;
    case 0x35a:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DFDB0 * (lbl_803DFDE0 * (f32)(s32)((PartFxSpawnParams*)spawnParams)->unk4);
        cfg.lifetimeFrames = 0x3c;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = ((PartFxSpawnParams*)spawnParams)->unk4 << 8;
        cfg.overrideColor1 = ((PartFxSpawnParams*)spawnParams)->unk4 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x60;
        cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.behaviorFlags = 0x201;
        cfg.textureId = 0x76;
        break;
    case 0x35b:
        if (spawnParams == 0)
            FILL8();
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0xc22;
        break;
    case 0x35c:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)((PartFxSpawnParams*)spawnParams)->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = (u16)(((PartFxSpawnParams*)spawnParams)->unk0 << 8);
        cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = ((PartFxSpawnParams*)spawnParams)->unk0 << 8;
        cfg.overrideColor1 = ((PartFxSpawnParams*)spawnParams)->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35d:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)((PartFxSpawnParams*)spawnParams)->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = ((PartFxSpawnParams*)spawnParams)->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35e:
        if (spawnParams == 0)
            FILL8();
        cfg.scale = lbl_803DFDEC;
        cfg.startPosY = lbl_803DFDF0;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk4 : 0xff;
        cfg.linkGroup = 0;
        cfg.startPosX = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unkC : 0.0f;
        cfg.startPosY = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk10 : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? ((PartFxSpawnParams*)spawnParams)->unk14 : 0.0f;
        cfg.behaviorFlags = 0xa100200;
        cfg.textureId = 0x7d;
        break;
    case 0x367:
        cfg.startPosX = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = lbl_803DFDF4;
        cfg.startPosZ = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityX = lbl_803DFDF8 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(0x64, 0xc8);
        cfg.velocityZ = lbl_803DFDF8 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFDFC * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xe6;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x10000000;
        cfg.behaviorFlags = 0x8f000000;
        cfg.textureId = 0x56e;
        break;
    case 0x369:
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x366:
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x3e8);
        cfg.startPosZ = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosY = lbl_803DFE00;
        cfg.scale = lbl_803DFDB0;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0x50;
        break;
    case 0x365:
        cfg.velocityY = lbl_803DFE04 * (f32)(s32)
        randomGetRange(0x6e, 0xc8);
        cfg.startPosZ = lbl_803DFE08 * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = lbl_803DFE08 * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.scale = lbl_803DFE0C * (f32)(s32)
        randomGetRange(1, 0x14) + lbl_803DFD98;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0, 0x258);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0, 0x258);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0, 0x258);
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x15e;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x86000008;
        cfg.textureId = 0x3a2;
        break;
    case 0x364:
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(5, 0x64);
        cfg.scale = lbl_803DFE10;
        cfg.lifetimeFrames = 0x50;
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x2710) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0xa0;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
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
extern void getCurSeqNo();
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

int partfx_spawnObject(s16* sourceObj, u32 effectIdArg, s16* spawnParams, u32 spawnFlags,
                       u32 modelIdArg, void* extraArgsArg)
{
    int modelId = (int)modelIdArg;
    int effectId = (int)effectIdArg;
    f32* extraArgs = (f32*)extraArgsArg;
    int intVal;
    s16 i;
    u8 variant;
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
        return (*(int (**)())(*(int*)gPartfxResourceModule00 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x257 < effectId) && (effectId < 0x2bc))
    {
        gPartfxResourceTimeouts[1] = 2000;
        if (gPartfxResourceModule01 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule01 = Resource_Acquire(0x1b, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule01 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x1f3 < effectId) && (effectId < 0x258))
    {
        gPartfxResourceTimeouts[2] = 2000;
        if (gPartfxResourceModule02 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule02 = Resource_Acquire(0x1c, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule02 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x18f < effectId) && (effectId < 0x1f4))
    {
        gPartfxResourceTimeouts[3] = 2000;
        if (gPartfxResourceModule03 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule03 = Resource_Acquire(0x1d, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule03 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0xc7 < effectId) && (effectId < 0x12c))
    {
        gPartfxResourceTimeouts[4] = 2000;
        if (gPartfxResourceModule04 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule04 = Resource_Acquire(0x1e, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule04 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x419 < effectId) && (effectId < 0x44c))
    {
        gPartfxResourceTimeouts[5] = 2000;
        if (gPartfxResourceModule05 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule05 = Resource_Acquire(0x1f, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule05 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x739 < effectId) && (effectId < 0x76c))
    {
        gPartfxResourceTimeouts[16] = 2000;
        if (gPartfxResourceModule16 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule16 = Resource_Acquire(0x2a, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule16 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId - 0x84U < 2) || ((0x89 < effectId && (effectId < 200))))
    {
        gPartfxResourceTimeouts[6] = 2000;
        if (gPartfxResourceModule06 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule06 = Resource_Acquire(0x20, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule06 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x3b5 < effectId) && (effectId < 0x3de))
    {
        gPartfxResourceTimeouts[8] = 2000;
        if (gPartfxResourceModule08 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule08 = Resource_Acquire(0x22, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule08 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x351 < effectId) && (effectId < 0x384))
    {
        gPartfxResourceTimeouts[7] = 2000;
        if (gPartfxResourceModule07 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule07 = Resource_Acquire(0x21, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule07 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x329 < effectId) && (effectId < 0x351))
    {
        gPartfxResourceTimeouts[9] = 2000;
        if (gPartfxResourceModule09 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule09 = Resource_Acquire(0x23, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule09 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x12b < effectId) && (effectId < 0x190))
    {
        gPartfxResourceTimeouts[10] = 2000;
        if (gPartfxResourceModule10 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule10 = Resource_Acquire(0x24, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule10 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x47d < effectId) && (effectId < 0x4b0))
    {
        gPartfxResourceTimeouts[11] = 2000;
        if (gPartfxResourceModule11 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule11 = Resource_Acquire(0x25, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule11 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x4af < effectId) && (effectId < 0x4e2))
    {
        gPartfxResourceTimeouts[12] = 2000;
        if (gPartfxResourceModule12 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule12 = Resource_Acquire(0x27, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule12 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId >= 0x3e8) && (effectId <= 0x419))
    {
        gPartfxResourceTimeouts[13] = 2000;
        if (gPartfxResourceModule13 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule13 = Resource_Acquire(0x28, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule13 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((0x44b < effectId) && (effectId < 0x47e))
    {
        gPartfxResourceTimeouts[14] = 2000;
        if (gPartfxResourceModule14 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule14 = Resource_Acquire(0x26, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule14 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId >= 0x6d7) && (effectId <= 0x707))
    {
        gPartfxResourceTimeouts[15] = 2000;
        if (gPartfxResourceModule15 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule15 = Resource_Acquire(0x29, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule15 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId >= 0x708) && (effectId <= 0x739))
    {
        gPartfxResourceTimeouts[17] = 2000;
        if (gPartfxResourceModule17 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule17 = Resource_Acquire(0x2b, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule17 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId >= 0x76c) && (effectId <= 0x79d))
    {
        gPartfxResourceTimeouts[18] = 2000;
        if (gPartfxResourceModule18 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule18 = Resource_Acquire(0x2c, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule18 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if ((effectId >= 0x79e) && (effectId <= 0x833))
    {
        gPartfxResourceTimeouts[19] = 2000;
        if (gPartfxResourceModule19 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule19 = Resource_Acquire(0x2d, 2);
        }
        return (*(int (**)())(*(int*)gPartfxResourceModule19 + 8))(sourceObj, effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    lbl_803DB7A0 = lbl_803DB7A0 + lbl_803DF4C8;
    if (lbl_803DB7A0 > 1.0f)
    {
        lbl_803DB7A0 = lbl_803DF4CC;
    }
    lbl_803DB7A4 = lbl_803DB7A4 + lbl_803DF4D4;
    if (lbl_803DB7A4 > 1.0f)
    {
        lbl_803DB7A4 = lbl_803DF4D8;
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
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    variant = '\0';
    cfg.behaviorFlags = 0x0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
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
            cfg.colorWord0 = *(ushort*)((int)extraArgs + 6);
            cfg.colorWord1 = *(ushort*)(extraArgs + 2);
            cfg.colorWord2 = *(ushort*)((int)extraArgs + 10);
            cfg.overrideColor0 = (u32) * (ushort*)extraArgs;
            cfg.overrideColor1 = (u32) * (ushort*)((int)extraArgs + 2);
            cfg.overrideColor2 = (u32) * (ushort*)(extraArgs + 1);
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
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.renderFlags = 0x8000820;
        break;
    case 0x60:

        cfg.startPosX = (f32)(s32)
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
            cfg.colorWord0 = *(ushort*)extraArgs;
            cfg.colorWord1 = *(ushort*)((int)extraArgs + 2);
            cfg.colorWord2 = *(ushort*)(extraArgs + 1);
            cfg.lifetimeFrames = (u32) * (ushort*)((int)extraArgs + 6);
        }
        else
        {
            cfg.colorWord0 = 0x2000;
            cfg.colorWord1 = 0x2000;
            cfg.colorWord2 = 0x2000;
            cfg.lifetimeFrames = 0x78;
        }
        cfg.overrideColor0 = (u32)cfg.colorWord0;
        cfg.overrideColor1 = (u32)cfg.colorWord1;
        cfg.overrideColor2 = (u32)cfg.colorWord2;
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
        cfg.startPosX = (f32)(s32)
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

        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = (f32)(s32)
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC - *(f32*)(sourceObj + 0xc);
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14 - *(f32*)(sourceObj + 0x10);
        }
        else
        {
            cfg.startPosX = (f32)(s32)
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
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 + (f32)(s32)
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
        rot.x = *(s16*)sourceObj;
        vecRotateZXY((s16*)&rot, &cfg.startPosX);
        cfg.scale = lbl_803DF520;
        cfg.lifetimeFrames = 0x91;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000010;
        cfg.renderFlags = 0x2600000;
        cfg.textureId = 0xe4;
        break;
    case 0x549:

        cfg.startPosX = lbl_803DF508 * (f32)(s32)
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
        cfg.startPosX = lbl_803DF508 * (f32)(s32)
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
        cfg.startPosX = lbl_803DF508 * (f32)(s32)
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

        cfg.startPosX = lbl_803DF508 * (f32)(s32)
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.scale = lbl_803DF530 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 2;
        cfg.textureId = 0x527;
        cfg.initialAlpha = 0x69;
        break;
    case 0x546:

        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.scale = lbl_803DF534 * ((PartFxSpawnParams*)spawnParams)->unk8;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
        }
        if (randomGetRange(0, 0x28) == 0)
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
        cfg.textureId = (s16)effectId + -0x3d5;
        break;
    case 0x52f:
    case 0x530:
    case 0x531:
        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.velocityZ = lbl_803DF4D8;
        }
        cfg.scale = lbl_803DF514;
        cfg.lifetimeFrames = 100;
        break;
    case 0x53c:

        if (extraArgs != NULL)
        {
            intVal = (int)(lbl_803DF548 * (lbl_803DF4D0 - *extraArgs));
            cfg.initialAlpha = (u8)intVal;
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
        cfg.overrideColor0 = 0xb1df;
        cfg.overrideColor1 = 0xb1df;
        cfg.overrideColor2 = 0xffff;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.startPosZ = lbl_803DF554;
        cfg.initialAlpha = 0x69;
        cfg.scale = lbl_803DF558;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xb1df;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xb1df;
        cfg.overrideColor2 = 0xffff;
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
        cfg.overrideColor0 = 0xb1df;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        rot.x = *(s16*)sourceObj;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        rot.x = *(s16*)sourceObj;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        rot.x = *(s16*)sourceObj;
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
        rot.x = *(s16*)sourceObj;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DF598;
        cfg.lifetimeFrames = 10;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80440202;
        cfg.textureId = 0x156;
        break;
    case 0x51c:
        cfg.startPosX = lbl_803DF4CC * (f32)(s32)
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
        cfg.startPosX = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.startPosY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32) + lbl_803DF580;
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffffce, 0x32);
        cfg.velocityX = cfg.startPosX / lbl_803DF5A4;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
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
        cfg.startPosX = lbl_803DF4CC * (f32)(s32)
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
        if (randomGetRange(0, 3) == 0)
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
        if (randomGetRange(0, 10) == 0)
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
        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = lbl_803DF5C4 * (f32)(s32)(0x3c - randomGetRange(0, 0x78));
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
        cfg.velocityX = lbl_803DF568 * (lbl_803DB7A8 * (f32)(s32)
        randomGetRange(0xfffffff1, 0xf)
        )
        ;
        cfg.velocityY = lbl_803DF5B4 * (f32)(s32)
        randomGetRange(5, 0x14);
        cfg.velocityZ = lbl_803DF568 * (lbl_803DB7A8 * (f32)(s32)
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
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4;
        break;
    case 0x5:

        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = lbl_803DF5D8 * (f32)(s32)
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
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4;
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
        cfg.startPosX = lbl_803DF5D8 * (f32)(s32)
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
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4;
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

        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffce, 0xfa);
        cfg.startPosX = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x166;
        break;
    case 0x83:

        cfg.startPosX = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xffffffce, 0xfa);
        cfg.startPosX = (f32)(s32)
        randomGetRange(0xffffff60, 0xa0);
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x167;
        break;
    case 0x71:
        cfg.startPosX = (f32)(s32)
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 1;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x19;
        if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
        {
            cfg.initialAlpha = 0x7d;
        }
        cfg.behaviorFlags = 0xc0012;
        cfg.textureId = 0x77;
        break;
    case 0x6a:

        cfg.startPosX = lbl_803DF4D0 * (f32)(s32)
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
        cfg.textureId = randomGetRange(0, 2);
        cfg.textureId = cfg.textureId + 0x156;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.sourceVecZ = randomGetRange(0, 200);
        cfg.sourceVecZ = 100 - cfg.sourceVecZ;
        cfg.sourceVecY = randomGetRange(0, 200);
        cfg.sourceVecY = 100 - cfg.sourceVecY;
        cfg.sourceVecX = randomGetRange(0, 200);
        cfg.sourceVecX = 100 - cfg.sourceVecX;
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
        cfg.textureId = randomGetRange(0, 3);
        cfg.textureId = cfg.textureId + 0xdd;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4FC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = randomGetRange(0, 1000);
        cfg.sourceVecY = 500 - cfg.sourceVecY;
        cfg.sourceVecX = randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - cfg.sourceVecX;
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
        cfg.startPosX = lbl_803DF4F8 - (f32)(s32)
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

        cfg.startPosX = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosY = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosZ = lbl_803DF4F8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803DF568;
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x70800;
        cfg.textureId = randomGetRange(0, 1);
        cfg.textureId = cfg.textureId + 0xdd;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = randomGetRange(0, 1000);
        cfg.sourceVecZ = 500 - cfg.sourceVecZ;
        cfg.sourceVecY = randomGetRange(0, 1000);
        cfg.sourceVecY = 500 - cfg.sourceVecY;
        cfg.sourceVecX = randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - cfg.sourceVecX;
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
            cfg.startPosY = (f32)ftmp4;
            cfg.velocityX = ftmp3 * (f32)(s32)(2 - randomGetRange(0, 4));
            cfg.velocityY = ftmp2 * (f32)(s32)
            randomGetRange(1, 2);
            cfg.velocityZ = ftmp3 * (f32)(s32)(2U - randomGetRange(0, 4));
            cfg.scale = (f32)ftmp1;
            cfg.lifetimeFrames = 0x3c;
            cfg.behaviorFlags = 0x108;
            cfg.textureId = 0x5c;
            if ((cfg.behaviorFlags & 1) != 0)
            {
                if (cfg.attachedSource != NULL)
                {
                    cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0xc);
                    cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x10);
                    cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x14);
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
            cfg.startPosX = lbl_803DF580 - (f32)(s32)
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
            cfg.startPosX = lbl_803DF580 - (f32)(s32)
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
            cfg.startPosX = lbl_803DF650;
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
            cfg.startPosX = lbl_803DF650;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
            else
            {
                cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
        }
        cfg.velocityY = lbl_803DF508 * (f32)(s32)
        randomGetRange(1, 10);
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF530;
        rot.z = randomGetRange(0, 4000);
        rot.z = 2000 - rot.z;
        rot.y = randomGetRange(0, 4000);
        rot.y = 2000 - rot.y;
        rot.x = randomGetRange(0, 4000);
        rot.x = 2000 - rot.x;
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
            cfg.startPosY = (f32)ftmp1;
            cfg.velocityX = ftmp2 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
            cfg.velocityZ = ftmp2 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
            cfg.scale = (f32)ftmp3;
            cfg.lifetimeFrames = (u32)(ftmp4 * (f32)(s32)randomGetRange(1, 4));
            cfg.behaviorFlags = 0x100011;
            cfg.textureId = 0x30;
            srcPosX = cfg.sourcePosY;
            srcPosY = cfg.sourcePosZ;
            srcPosZ = cfg.sourcePosW;
            if (cfg.attachedSource != NULL)
            {
                srcPosX = *(f32*)((char*)cfg.attachedSource + 0xc);
                srcPosY = *(f32*)((char*)cfg.attachedSource + 0x10);
                srcPosZ = *(f32*)((char*)cfg.attachedSource + 0x14);
            }
            cfg.startPosZ = cfg.startPosZ + srcPosZ;
            cfg.startPosY = cfg.startPosY + srcPosY;
            cfg.startPosX = cfg.startPosX + srcPosX;
            (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        }
        break;
    case 0x35:
        cfg.startPosX = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
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

        cfg.startPosX = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
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
        cfg.startPosX = lbl_803DF624 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
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
        cfg.startPosX = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosZ = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = lbl_803DF514 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF670 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xd2;
        cfg.behaviorFlags = 0x80000201;
        cfg.textureId = randomGetRange(0, 3);
        cfg.textureId = cfg.textureId + 0xdd;
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
        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = (f32)(s32)
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
        if (randomGetRange(0, 1) != 0)
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

        if (randomGetRange(0, 1) != 0)
        {
            cfg.startPosX = lbl_803DF64C;
        }
        else
        {
            cfg.startPosX = lbl_803DF684;
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

        cfg.startPosX = lbl_803DF638 * (f32)(s32)
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
        cfg.startPosX = lbl_803DF4CC * (f32)(s32)
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
        cfg.lifetimeFrames = (u32)(lbl_803DF660 * (f32)(s32)randomGetRange(1, 4));
        cfg.behaviorFlags = 0x100000;
        cfg.textureId = 0x30;
        break;
    case 0x25:

        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC + (f32)(s32)
        randomGetRange(0, 6);
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14 + (f32)(s32)
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
        cfg.startPosX = (f32)(s32)
        randomGetRange(0xffffffff, 1);
        if (extraArgs != NULL)
        {
            cfg.startPosX = cfg.startPosX + extraArgs[1];
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
            cfg.lifetimeFrames = (u32) * extraArgs;
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
        rot.x = *(s16*)sourceObj;
        vecRotateZXY((s16*)&rot, &cfg.startPosX);
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
        cfg.lifetimeFrames = (u32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x110214;
        cfg.textureId = 0x30;
        break;
    case 0x11:
        cfg.velocityX = lbl_803DF4E4 * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityY = lbl_803DF608 * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.velocityZ = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = lbl_803DF4E0;
        cfg.lifetimeFrames = (u32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0, 3) + 1U));
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
        cfg.lifetimeFrames = (u32)(lbl_803DF69C * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x1000211;
        cfg.textureId = 0x30;
        break;
    case 0x1b:

        cfg.velocityY = lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.scale = lbl_803DF690 * (f32)(s32)
        randomGetRange(0, 4);
        cfg.lifetimeFrames = (u32)(lbl_803DF6A0 * (f32)(s32)(randomGetRange(0, 3) + 1U));
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
        cfg.startPosX = (f32)(s32)(10 - randomGetRange(0, 0x14));
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
        cfg.startPosX = (f32)(s32)
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
        cfg.startPosX = lbl_803DF4DC;
        cfg.startPosY = lbl_803DF540;
        cfg.startPosZ = lbl_803DF4DC;
        cfg.velocityZ = lbl_803DF4EC * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.scale = lbl_803DF600;
        cfg.lifetimeFrames = 0xa0;
        cfg.behaviorFlags = 0x11000204;
        cfg.textureId = 0x151;
        break;
    case 0x74:

        cfg.startPosX = (f32)(s32)
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

        cfg.startPosX = (f32)(s32)(5 - randomGetRange(0, 10));
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
        cfg.lifetimeFrames = (u32)(lbl_803DF6C4 * (f32)(s32)(randomGetRange(0, 3) + 1U));
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (extraArgs == NULL)
        {
            return -1;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        cfg.scale = lbl_803DF4C8;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = (u8)(int)((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.linkGroup = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc13;
        cfg.sourcePosY = lbl_803DF4DC;
        cfg.sourcePosZ = lbl_803DF4DC;
        cfg.sourcePosW = lbl_803DF4DC;
        cfg.sourcePosX = lbl_803DF4D0;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0;
        cfg.sourceVecX = *spawnParams;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.startPosX = (f32)(s32)
        randomGetRange(0xfffffffa, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffffa, 6);
        cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffffe, 2)
        )
        ;
        cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF4CC * (f32)(s32)
        randomGetRange(0, 4)
        )
        ;
        cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF508 * (f32)(s32)
        randomGetRange(0xfffffffe, 2)
        )
        ;
        cfg.scale = lbl_803DF634 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x18;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.initialAlpha = 0xa5;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32) * (byte*)extraArgs << 8;
            cfg.colorWord0 = (ushort)cfg.overrideColor0;
            cfg.overrideColor1 = (u32) * (byte*)((int)extraArgs + 1) << 8;
            cfg.colorWord1 = (ushort)cfg.overrideColor1;
            cfg.overrideColor2 = (u32) * (byte*)((int)extraArgs + 2) << 8;
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        cfg.textureId = 0x60;
        break;
    case 0x57:

        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 10);
        cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(200, 400)
        )
        ;
        cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF5B4 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF524 * (f32)(s32)
        randomGetRange(8, 0xb)
        )
        ;
        cfg.initialAlpha = 0xbe;
        cfg.lifetimeFrames = (u32)(lbl_803DF6C8 * ((PartFxSpawnParams*)spawnParams)->unk8);
        cfg.behaviorFlags = 0x1200000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32) * (byte*)extraArgs << 8;
            cfg.colorWord0 = (ushort)cfg.overrideColor0;
            cfg.overrideColor1 = (u32) * (byte*)((int)extraArgs + 1) << 8;
            cfg.colorWord1 = (ushort)cfg.overrideColor1;
            cfg.overrideColor2 = (u32) * (byte*)((int)extraArgs + 2) << 8;
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        break;
    case 0x58:
        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(10, 200)
        )
        ;
        cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF4F0 * (f32)(s32)
        randomGetRange(0xffffff9c, 100)
        )
        ;
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF524 * (f32)(s32)
        randomGetRange(8, 0xb)
        )
        ;
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32) * (byte*)extraArgs << 8;
            cfg.colorWord0 = (ushort)cfg.overrideColor0;
            cfg.overrideColor1 = (u32) * (byte*)((int)extraArgs + 1) << 8;
            cfg.colorWord1 = (ushort)cfg.overrideColor1;
            cfg.overrideColor2 = (u32) * (byte*)((int)extraArgs + 2) << 8;
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
            cfg.renderFlags = 0x1000020;
        }
        break;
    case 0x323:
        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
        }
        cfg.startPosX = lbl_803DF6CC * (f32)(s32)
        randomGetRange(0xffffffea, 0x15) + cfg.startPosX;
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
            variant = *(u8*)extraArgs;
            if (variant == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags |= 0x20;
            }
            else if (variant == '\x02')
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
            else if (variant == '\x03')
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
            else if (variant == '\x04')
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
            else if (variant == '\x05')
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
            else if (variant == '\x06')
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
            else if (variant == '\a')
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
            else if (variant == '\b')
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
        }
        cfg.startPosZ = lbl_803DF6E4;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = randomGetRange(0xffff8001, 0x7fff);
        rot.y = randomGetRange(0xffff8001, 0x7fff);
        rot.x = randomGetRange(0xffff8001, 0x7fff);
        vecRotateZXY((s16*)&rot, &cfg.startPosX);
        cfg.velocityX = -(cfg.startPosX / lbl_803DF4FC);
        cfg.velocityY = -(cfg.startPosY / lbl_803DF4FC);
        cfg.velocityZ = -(cfg.startPosZ / lbl_803DF4FC);
        cfg.scale = lbl_803DF6E8 * (f32)(s32)
        randomGetRange(0x9e, 0x240);
        cfg.lifetimeFrames = randomGetRange(7, 0x12) + 0xc;
        cfg.textureId = 0xc98;
        cfg.behaviorFlags = 0x480110;
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
            if (variant == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variant == '\x02')
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
            else if (variant == '\x03')
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
        cfg.startPosX = lbl_803DF4DC;
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
            variant = *(u8*)extraArgs;
            if (variant == '\x01')
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
            else if (variant == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variant == '\x03')
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
            else if (variant == '\x04')
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
            else if (variant == '\x05')
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
            else if (variant == '\x06')
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
            else if (variant == '\a')
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
            else if (variant == '\b')
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        if (spawnParams == NULL)
        {
            cfg.startPosX = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
            cfg.startPosY = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
            cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
            randomGetRange(0xfffffff6, 10);
        }
        else
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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

        cfg.startPosX = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.startPosY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.startPosZ = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803DF608 * (f32)(s32)
        randomGetRange(8, 10);
        if (randomGetRange(0, 0x28) != 0)
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.velocityX = lbl_803DF608 * (f32)(s32)
        randomGetRange(0xfffffffe, 2);
        cfg.velocityY = lbl_803DF674 * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF700 * (f32)(s32)
        randomGetRange(1, 3);
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DF550;
        cfg.lifetimeFrames = 0x28;
        cfg.renderFlags = 0x5000000;
        cfg.behaviorFlags = 0x180208;
        cfg.textureId = 0xc8f;
        break;
    case 0x321:
        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.velocityY = lbl_803DF4CC * (f32)(s32)
        randomGetRange(0, 4);
        cfg.velocityZ = lbl_803DF704 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803DF4E8;
        cfg.lifetimeFrames = 100;
        cfg.behaviorFlags = 0x1180200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc90;
        break;
    case 0x322:

        if (spawnParams == NULL)
        {
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.velocityZ = lbl_803DF708;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
            ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
            ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
            spawnParams = lbl_8039C308;
        }
        cfg.sourceVecX = 700;
        cfg.textureId = 0xc09;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
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
                ((PartFxSpawnParams*)lbl_8039C308)->unkC = lbl_803DF4DC;
                ((PartFxSpawnParams*)lbl_8039C308)->unk10 = lbl_803DF4DC;
                ((PartFxSpawnParams*)lbl_8039C308)->unk14 = lbl_803DF4DC;
                ((PartFxSpawnParams*)lbl_8039C308)->unk8 = lbl_803DF4D0;
                ((PartFxSpawnParams*)lbl_8039C308)->unk0 = 0;
                ((PartFxSpawnParams*)lbl_8039C308)->unk2 = 0;
                ((PartFxSpawnParams*)lbl_8039C308)->unk4 = 0;
                ((PartFxSpawnParams*)lbl_8039C308)->unk6 = 0;
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
            cfg.colorWord0 = (ushort)cfg.overrideColor0;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&cfg, 0xffffffff, effectId, 0);
}


int Effect2_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    int i;
    PartFxSpawn cfg;

    lbl_803DB7C0 = lbl_803DB7C0 + lbl_803DF870;
    if (lbl_803DB7C0 > 1.0f) lbl_803DB7C0 = lbl_803DF874;
    lbl_803DB7C4 = lbl_803DB7C4 + lbl_803DF87C;
    if (lbl_803DB7C4 > 1.0f) lbl_803DB7C4 = lbl_803DF880;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
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
        cfg.velocityX = lbl_80310560.vel[0][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[0][1], (s32)lbl_80310560.vel[0][2]);
        cfg.velocityY = lbl_80310560.vel[1][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[1][1], (s32)lbl_80310560.vel[1][2]);
        cfg.velocityZ = lbl_80310560.vel[2][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[2][1], (s32)lbl_80310560.vel[2][2]);
        cfg.startPosX = lbl_80310560.vel[3][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[3][1], (s32)lbl_80310560.vel[3][2]);
        cfg.startPosY = lbl_80310560.vel[4][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[4][1], (s32)lbl_80310560.vel[4][2]);
        cfg.startPosZ = lbl_80310560.vel[5][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[5][1], (s32)lbl_80310560.vel[5][2]);
        cfg.scale = lbl_80310560.vel[6][0] * (f32)(s32)
        randomGetRange((s32)lbl_80310560.vel[6][1], (s32)lbl_80310560.vel[6][2]);
        cfg.lifetimeFrames = randomGetRange((s32)lbl_80310560.g08[1], (s32)lbl_80310560.g08[2]) + (s32)lbl_80310560.g08[
            0];
        cfg.colorWord0 = lbl_80310560.col[0];
        cfg.colorWord1 = lbl_80310560.col[1];
        cfg.colorWord2 = lbl_80310560.col[2];
        cfg.overrideColor0 = lbl_80310560.col[3];
        cfg.overrideColor1 = lbl_80310560.col[4];
        cfg.overrideColor2 = lbl_80310560.col[5];
        for (i = 0; i < 6; i++) if (lbl_80310560.emit[i] != 0) cfg.behaviorFlags |= 1 << (lbl_80310560.emit[i] - 1);
        cfg.renderFlags = 0x2000000;
        for (i = 0; i < 6; i++) if (lbl_80310560.sub[i] != 0) cfg.renderFlags |= 1 << (lbl_80310560.sub[i] - 1);
        cfg.textureId = (s32)lbl_80310560.f60;
        cfg.initialAlpha = randomGetRange(lbl_80310560.b_a0, lbl_80310560.b_a1);
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.lifetimeFrames = 6;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x4a0010;
        if ((int)randomGetRange(0, 1) != 0) cfg.renderFlags = 0x202;
        else cfg.renderFlags = 0x102;
        if (0.0f == ((PartFxSpawnParams*)spawnParams)->unk8)
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        if (0.0f == ((PartFxSpawnParams*)spawnParams)->unk8)
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        cfg.renderFlags = 2;
        if (0.0f == ((PartFxSpawnParams*)spawnParams)->unk8)
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
        if (0.0f == ((PartFxSpawnParams*)spawnParams)->unk8)
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
        if (0.0f == ((PartFxSpawnParams*)spawnParams)->unk8)
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
        if (effectId == 0x278) cfg.textureId = (s16)lbl_80310660[3];
        else cfg.textureId = (s16)lbl_80310660[effectId - 0x260];
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
        if (effectId == 0x276) cfg.textureId = (s16)lbl_80310660[3];
        else cfg.textureId = (s16)lbl_80310660[effectId - 0x263];
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
        if (effectId == 0x277) cfg.textureId = (s16)lbl_80310660[3];
        else cfg.textureId = (s16)lbl_80310660[effectId - 0x266];
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803DF98C + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.velocityX = lbl_803DB7C8 * (lbl_803DF970 * (f32)(s32)
        randomGetRange(-0x28, 0x28)
        )
        ;
        cfg.velocityZ = -lbl_803DB7C8 * (lbl_803DF970 * (f32)(s32)
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    lbl_803DD348 = lbl_803DD2C4;
    return spawnResult;
}
#undef FILL338

extern void* Obj_GetPlayerObject();
extern FxNode9 lbl_8039C368;
extern f32 lbl_803DB800;
extern f32 lbl_803DB804;
extern f32 lbl_803DFCE4;
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

int Effect7_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    void* player;
    PartFxSpawn cfg;

    player = Obj_GetPlayerObject();
    lbl_803DB800 += 0.001f;
    if (lbl_803DB800 > 1.0f) lbl_803DB800 = 0.1f;
    lbl_803DB804 += 0.0003f;
    if (lbl_803DB804 > 1.0f) lbl_803DB804 = 0.3f;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803DFCEC;
    cfg.startPosY = lbl_803DFCEC;
    cfg.startPosZ = lbl_803DFCEC;
    cfg.velocityX = lbl_803DFCEC;
    cfg.velocityY = lbl_803DFCEC;
    cfg.velocityZ = lbl_803DFCEC;
    cfg.scale = lbl_803DFCEC;
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
    case 0xae:
        cfg.velocityX = lbl_803DFCF0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DFCF4 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityY = lbl_803DFCF0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DFCF8 * (f32)(s32)
        randomGetRange(0x1e, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x88;
        break;
    case 0xaf:
        cfg.velocityX = lbl_803DFCFC * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DFCF4 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityY = lbl_803DFCFC * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DFD00 * (f32)(s32)
        randomGetRange(0x3c, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 8;
        cfg.textureId = 0xe4;
        break;
    case 0xad:
        cfg.velocityX = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DFD08 * (f32)(s32)
        randomGetRange(6, 0x16);
        cfg.velocityZ = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DFCEC;
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFD0C;
        cfg.lifetimeFrames = 0x91;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
        cfg.colorWord2 = 0x3caf;
        cfg.overrideColor0 = 0xf52f;
        cfg.overrideColor1 = 0xf52f;
        cfg.overrideColor2 = 0xf52f;
        cfg.behaviorFlags = 0x3000020;
        cfg.renderFlags = 0x2600020;
        cfg.textureId = 0xe4;
        break;
    case 0xac:
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DFCEC;
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityX = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DFD10 * (f32)(s32)
        randomGetRange(9, 0xc);
        cfg.velocityZ = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DFD14 * (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x5f;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x3caf;
        cfg.colorWord1 = 0x3caf;
        cfg.colorWord2 = 0x3caf;
        cfg.overrideColor0 = 0xa70f;
        cfg.overrideColor1 = 0xa70f;
        cfg.overrideColor2 = 0xa70f;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80180100;
        cfg.renderFlags = 0x20;
        break;
    case 0x84:
        cfg.velocityX = lbl_803DFD18 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD04 * (f32)(s32)
        randomGetRange(4, 0xa);
        cfg.velocityZ = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD20 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1400211;
        cfg.textureId = 0xdf;
        break;
    case 0x85:
        if (extraArgs == 0) return 0;
        cfg.startPosX = ((GameObject*)player)->anim.worldPosX;
        cfg.startPosY = ((GameObject*)player)->anim.worldPosY;
        cfg.startPosZ = ((GameObject*)player)->anim.worldPosZ;
        cfg.scale = lbl_803DFD24;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4 + 0x170;
        break;
    case 0x8a:
        cfg.startPosX = lbl_803DFD28;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFD2C;
        cfg.scale = lbl_803DFD30 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x10e;
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xf;
        cfg.behaviorFlags = 0x2000011;
        cfg.textureId = 0x5f;
        break;
    case 0x8b:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.velocityX = lbl_803DFD34 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD34 * (f32)(s32)
        randomGetRange(4, 0xa);
        cfg.velocityZ = lbl_803DFD34 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD38 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x378;
        cfg.behaviorFlags = 0x80000119;
        cfg.textureId = 0x125;
        break;
    case 0x8e:
        cfg.velocityX = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD3C;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100110;
        cfg.textureId = 0x30;
        break;
    case 0x8f:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.velocityX = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        if ((int)randomGetRange(0, 0xc) == 0)
        {
            cfg.scale = lbl_803DFD40 * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0x5f;
        }
        else
        {
            cfg.scale = lbl_803DFD44 * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0xff;
        }
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x400108;
        cfg.textureId = 0x33;
        break;
    case 0x9a:
        cfg.startPosX = lbl_803DFD48;
        cfg.startPosY = lbl_803DFD4C + (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.scale = lbl_803DFD04 * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x78);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x125;
        cfg.linkGroup = 5;
        break;
    case 0x9b:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.startPosY = lbl_803DFD4C - (f32)(s32)
        randomGetRange(0, 0x42);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x60, 0x60);
        cfg.velocityY = lbl_803DFD50 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.scale = lbl_803DFD54 * (f32)(s32)
        randomGetRange(0xa, 0x28);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x125;
        break;
    case 0x9c:
        cfg.velocityX = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD58;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xdd;
        break;
    case 0x9f:
        cfg.velocityX = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD54;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.behaviorFlags = 0x81480000;
        cfg.renderFlags = 0x410800;
        cfg.textureId = 0x167;
        break;
    case 0xa0:
        if (spawnParams == 0)
            FILL368();
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0xa, 0);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = cfg.startPosY + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = cfg.startPosZ + ((PartFxSpawnParams*)spawnParams)->unk14;
            if (lbl_803DFCE0 == ((PartFxSpawnParams*)spawnParams)->unk8)
            {
                cfg.initialAlpha = 0xff;
            }
            else
            {
                cfg.initialAlpha = (u8)(s32)(lbl_803DFD60 * ((PartFxSpawnParams*)spawnParams)->unk8);
            }
        }
        cfg.scale = lbl_803DFD64 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x2d;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x125;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0xa1:
        cfg.velocityY = lbl_803DFD68 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFD6C * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.startPosZ = lbl_803DFD70 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFD70 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD74 * (f32)(s32)
        randomGetRange(0x32, 0xc8);
        cfg.lifetimeFrames = 0x96;
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.renderFlags = 0x4020020;
        cfg.initialAlpha = randomGetRange(0x7f, 0xff);
        cfg.colorWord0 = cfg.overrideColor0 = 0xa70f;
        cfg.colorWord1 = cfg.overrideColor1 = 0xa70f;
        cfg.colorWord2 = cfg.overrideColor2 = 0xc350;
        break;
    case 0xa3:
        if (spawnParams == 0) break;
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityZ = lbl_803DFD78 * (f32)(s32)
        randomGetRange(0x64, 0x78);
        cfg.scale = lbl_803DFD7C * (f32)(s32)
        randomGetRange(0x3c, 0x50);
        {
            int t = randomGetRange(0, 5);
            t += ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.lifetimeFrames = t + 7;
        }
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0xc0080004;
        cfg.renderFlags = 0x4420800;
        break;
    case 0xa7:
        cfg.velocityX = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD20 * (f32)(s32)
        randomGetRange(0x23, 0x32);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x28) + 0xa;
        cfg.textureId = 0xc13;
        cfg.behaviorFlags = 0x81080010;
        cfg.renderFlags = 0x482800;
        break;
    case 0xa8:
        cfg.scale = lbl_803DFCDC;
        cfg.lifetimeFrames = 0xe;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x5fd;
        cfg.initialAlpha = 0x64;
        break;
    case 0xa9:
        if (spawnParams != 0)
        {
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DFD20 * (f32)(s32)
            randomGetRange(0x4b, 0x64)
            )
            ;
        }
        else
        {
            cfg.scale = lbl_803DFD20 * (f32)(s32)
            randomGetRange(0x4b, 0x64);
        }
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x96;
        break;
    case 0xaa:
        cfg.scale = lbl_803DFD84 * (f32)(s32)
        randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0xf, 0x19);
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x4000000;
        cfg.initialAlpha = 0x96;
        break;
    case 0xab:
        cfg.scale = lbl_803DFD84 * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x2d);
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0x80180210;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x8c:
    case 0x8d:
    case 0x9d:
    case 0x9e:
    case 0xa5:
    case 0xa6:
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
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

int Effect5_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7E0 = lbl_803DB7E0 + lbl_803DFBE0;
    if (lbl_803DB7E0 > 1.0f) lbl_803DB7E0 = lbl_803DFBE4;
    lbl_803DB7E4 = lbl_803DB7E4 + lbl_803DFBEC;
    if (lbl_803DB7E4 > 1.0f) lbl_803DB7E4 = lbl_803DFBF0;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803DFBF4;
    cfg.startPosY = lbl_803DFBF4;
    cfg.startPosZ = lbl_803DFBF4;
    cfg.velocityX = lbl_803DFBF4;
    cfg.velocityY = lbl_803DFBF4;
    cfg.velocityZ = lbl_803DFBF4;
    cfg.scale = lbl_803DFBF4;
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
    case 0xc8:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.scale = lbl_803DFBF8 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100111;
        cfg.textureId = 0xc10;
        break;
    case 0xca:
        if (spawnParams == 0) return 0;
        cfg.velocityX = lbl_803DFBFC * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFBFC * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFC00 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = *spawnParams;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFC04 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x180108;
        cfg.renderFlags = 0x5000000;
        if (((PartFxSpawnParams*)spawnParams)->unk4 == 0)
        {
            cfg.textureId = 0x2b;
        }
        else if (((PartFxSpawnParams*)spawnParams)->unk4 == 1)
        {
            cfg.textureId = 0x1a1;
        }
        else if (((PartFxSpawnParams*)spawnParams)->unk4 == 2)
        {
            cfg.textureId = 0xc10;
            cfg.renderFlags = cfg.renderFlags | 0x800;
        }
        else
        {
            cfg.textureId = 0x2b;
        }
        break;
    case 0xcb:
        if (spawnParams == 0) return 0;
        cfg.velocityX = lbl_803DFC08 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFC0C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFC08 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = *spawnParams;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFC10 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x1080100;
        cfg.renderFlags = 0x5000000;
        if (((PartFxSpawnParams*)spawnParams)->unk4 == 0)
        {
            cfg.textureId = 0x2b;
        }
        else if (((PartFxSpawnParams*)spawnParams)->unk4 == 1)
        {
            cfg.textureId = 0x1a1;
        }
        else if (((PartFxSpawnParams*)spawnParams)->unk4 == 2)
        {
            cfg.textureId = 0xc10;
            cfg.renderFlags = cfg.renderFlags | 0x800;
        }
        else
        {
            cfg.textureId = 0x2b;
        }
        break;
    case 0xcc:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.startPosY = lbl_803DFC14 * (f32)(s32)
        randomGetRange(1, 2);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DFC18 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFC18 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFC1C * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80108;
        cfg.textureId = 0x5c;
        break;
    case 0xcd:
        cfg.startPosX = (f32)(s32)
        randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = lbl_803DFC20 + cfg.startPosX / lbl_803DFC20;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = lbl_803DFC24 * cfg.startPosX;
        cfg.scale = lbl_803DFC28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xce:
        cfg.startPosX = lbl_803DFC2C + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC30 + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = lbl_803DFC34 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFC38 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xcf:
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = lbl_803DFC20 + cfg.startPosX / lbl_803DFC20;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = -cfg.startPosX;
        cfg.scale = lbl_803DFC28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xd0:
        cfg.startPosX = lbl_803DFC40 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC30 + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = lbl_803DFC44 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFC38 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd1:
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x46, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0xf) + 0x14;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x180210;
        cfg.textureId = 0x159;
        break;
    case 0xd2:
        cfg.scale = lbl_803DFBFC;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x159;
        break;
    case 0xd3:
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        cfg.startPosY = lbl_803DFC48 + (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = lbl_803DFBE4 * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.scale = lbl_803DFC4C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xa0;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x180108;
        cfg.textureId = 0x5c;
        break;
    case 0xd4:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0xa, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x1c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFC50 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFC54 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC58 + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd5:
        cfg.scale = lbl_803DFC5C;
        cfg.quadVertex3Pad06 = 0xd6;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000;
        cfg.textureId = 0x159;
        break;
    case 0xd6:
        cfg.scale = lbl_803DFC5C;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x159;
        break;
    case 0xd7:
        cfg.startPosX = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x32, 0xa);
        cfg.startPosZ = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.velocityY = lbl_803DFC64 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = lbl_803DFC68 * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x8c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180100;
        cfg.textureId = 0x5f;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

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

int Effect3_func04(void* sourceObj, int effectId, void* spawnParamsRaw, u32 spawnFlags,
                   u8 modelId, void* param_6v)
{
    int spawnResult;
    PartFxSpawn cfg;
    s16* extraArgs = (s16*)param_6v;
    s16* spawnParams = (s16*)spawnParamsRaw;

    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803DF9D0;
    cfg.startPosY = lbl_803DF9D0;
    cfg.startPosZ = lbl_803DF9D0;
    cfg.velocityX = lbl_803DF9D0;
    cfg.velocityY = lbl_803DF9D0;
    cfg.velocityZ = lbl_803DF9D0;
    cfg.scale = lbl_803DF9D0;
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
    case 0x1f4:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = cfg.startPosY + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = cfg.startPosZ + ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803DF9DC * (f32)(s32)
        randomGetRange(0xd, 0x14);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f5:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = cfg.startPosY + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = cfg.startPosZ + ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803DF9E0 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f6:
        cfg.scale = lbl_803DF9E4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x40;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0x16d;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f7:
        if (spawnParams == 0)
            FILL350();
        if (spawnParams != 0) cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.scale = lbl_803DF9E8;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0xc13;
        cfg.linkGroup = 0x20;
        break;
    case 0x1f8:
        if (spawnParams == 0)
            FILL350();
        if (spawnParams != 0)
        {
            cfg.scale = lbl_803DF9E8 * ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        else
        {
            cfg.scale = lbl_803DF9E8;
        }
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        cfg.initialAlpha = 0x64;
        cfg.behaviorFlags |= 0x80100LL;
        cfg.textureId = 0xc79;
        cfg.linkGroup = 0;
        cfg.colorWord0 = 0xe600;
        cfg.colorWord1 = 0x8800;
        cfg.colorWord2 = 0xa100;
        cfg.overrideColor0 = 0xe600;
        cfg.overrideColor1 = 0x8800;
        cfg.overrideColor2 = 0xa100;
        cfg.renderFlags = 0x20;
        break;
    case 0x1fb:
        cfg.scale = lbl_803DF9EC;
        cfg.lifetimeFrames = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100114;
        cfg.textureId = 0x17c;
        break;
    case 0x1fc:
        cfg.scale = lbl_803DF9E8;
        cfg.lifetimeFrames = 0x44;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x4c;
        break;
    case 0x1fd:
        cfg.startPosX = lbl_803DF9D0;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-3, 3);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-3, 3);
        cfg.velocityX = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF9F4;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0x140101;
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.textureId = 0x33;
        }
        else
        {
            cfg.textureId = 0xc7e;
        }
        break;
    case 0x1fe:
        if (spawnParams == 0)
            FILL350();
        if (extraArgs == 0) return -1;
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = *(f32*)extraArgs;
            cfg.velocityY = lbl_803DF9E8 * (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.velocityZ = *(f32*)(extraArgs + 2);
        }
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9F8;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x81088000;
        cfg.behaviorFlags = 0x1000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1ff:
        cfg.startPosY = lbl_803DFA00;
        cfg.scale = lbl_803DF9E0;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
        break;
    case 0x200:
        Sfx_PlayFromObject(sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803DFA04 * (f32)cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x201:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803DFA0C;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.velocityY = lbl_803DF9E8 * (f32)(s32)
        randomGetRange(1, 5);
        cfg.scale = lbl_803DFA10;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 0x202:
        cfg.velocityY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0x96, 0xc8) / lbl_803DFA14;
        cfg.scale = lbl_803DFA1C * ((f32)(s32)
        randomGetRange(0x32, 0x64) / lbl_803DFA14
        )
        +lbl_803DFA18;
        cfg.lifetimeFrames = (s32)(((PartFxSpawnParams*)spawnParams)->unk8 / cfg.velocityY);
        if (cfg.lifetimeFrames < 0xa) cfg.lifetimeFrames = 0xa;
        if (cfg.lifetimeFrames > 0x78) cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x201;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = 0xc9f;
        cfg.initialAlpha = 0x60;
        break;
    case 0x203:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 1:
            cfg.startPosX = -((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 2:
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        case 3:
            cfg.startPosZ = -((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        }
        cfg.scale = lbl_803DFA24;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x184;
        cfg.initialAlpha = 0xc4;
        break;
    case 0x204:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 1:
            cfg.startPosX = -((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 2:
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        case 3:
            cfg.startPosZ = -((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        }
        cfg.velocityY = lbl_803DFA28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DFA2C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400110;
        cfg.textureId = 0x47;
        break;
    case 0x205:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 1:
            cfg.startPosX = -((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 2:
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        case 3:
            cfg.startPosZ = -((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        }
        cfg.velocityY = lbl_803DFA28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x9b;
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x180210;
        cfg.colorWord0 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.colorWord1 = cfg.colorWord0 / (int)randomGetRange(1, 3);
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0x2710);
        cfg.overrideColor1 = (int)cfg.overrideColor0 / (int)randomGetRange(1, 3);
        cfg.overrideColor2 = 0;
        cfg.textureId = 0x60;
        break;
    case 0x206:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 - lbl_803DFA30;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 1:
            cfg.startPosX = -((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unk14,
                           (s16)(s32) * (f32*)(spawnParams + 10));
            break;
        case 2:
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        case 3:
            cfg.startPosZ = -((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - ((PartFxSpawnParams*)spawnParams)->unkC, (s16)(s32) * (f32*)(spawnParams + 6));
            break;
        }
        cfg.velocityY = lbl_803DFA34 * (f32)(s32)
        randomGetRange(0x50, 0x64);
        cfg.scale = lbl_803DFA1C * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.textureId = 0x60;
        break;
    case 0x208:
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosY = lbl_803DFA38;
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.velocityY = lbl_803DFA3C * (f32)(s32)
        randomGetRange(0x190, 0x258);
        cfg.velocityX = lbl_803DFA04 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFA04 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFA44 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA40;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0xe7;
        break;
    case 0x209:
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.velocityY = lbl_803DFA48 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DFA4C * (lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA50
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0x73, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x20a:
        {
            f32 a;
            f32 b;
            if (spawnParams == 0)
                FILL350();
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 5);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-5, 5);
            a = lbl_803DF9E0 * (f32)(s32)
            randomGetRange(0, 0x258) + lbl_803DFA54;
            cfg.velocityY = lbl_803DFA10 * (f32)(s32)
            randomGetRange(0, 0xc8) + lbl_803DF9D4;
            cfg.velocityX = mathSinf(lbl_803DFA58 * (f32) * (s16*)sourceObj / lbl_803DFA5C);
            cfg.velocityZ = mathCosf(lbl_803DFA58 * (f32) * (s16*)sourceObj / lbl_803DFA5C);
            b = a * (lbl_803DFA60 * (f32)(s32)
            randomGetRange(0, 0x14)
            )
            +lbl_803DF9D8;
            cfg.velocityX = cfg.velocityX * b;
            cfg.velocityZ = cfg.velocityZ * b;
            cfg.velocityY = cfg.velocityY * a;
            cfg.scale = lbl_803DFA68 * (f32)(s32)
            randomGetRange(0, 0xa) + lbl_803DFA64;
            cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x3000120;
            cfg.renderFlags = 0x200000;
            cfg.textureId = 0xc0a;
            cfg.quadVertex3Pad06 = 0x20b;
        }
        break;
    case 0x20b:
        cfg.velocityY = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DFA6C;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = (u16)cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x20c:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.velocityX = lbl_803DFA24 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFA24 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA70;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x20b;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x20d:
        cfg.velocityX = lbl_803DFA74 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFA78 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFA74 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0, 0x190);
        cfg.scale = lbl_803DFA04 * (f32)(s32)
        randomGetRange(0xf, 0x19);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x4a0104;
        cfg.renderFlags = 0x40008;
        cfg.sourcePosY = lbl_803DF9D0;
        cfg.sourcePosZ = lbl_803DF9D0;
        cfg.sourcePosW = lbl_803DF9D0;
        cfg.sourceVecX = 0x46;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        cfg.sourcePosX = lbl_803DF9D4;
        cfg.textureId = 0xe0;
        break;
    case 0x20e:
        cfg.startPosY = lbl_803DFA38;
        cfg.scale = lbl_803DF9F0;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11800004;
        cfg.initialAlpha = 0xa0;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
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
extern void ObjSeq_func20();
extern void ObjSeq_func23();

int Effect4_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    int randPick;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7D0 = lbl_803DB7D0 + lbl_803DFA88;
    if (lbl_803DB7D0 > 1.0f) lbl_803DB7D0 = lbl_803DFA8C;
    lbl_803DB7D4 = lbl_803DB7D4 + lbl_803DFA94;
    if (lbl_803DB7D4 > 1.0f) lbl_803DB7D4 = lbl_803DFA98;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803DFA9C;
    cfg.startPosY = lbl_803DFA9C;
    cfg.startPosZ = lbl_803DFA9C;
    cfg.velocityX = lbl_803DFA9C;
    cfg.velocityY = lbl_803DFA9C;
    cfg.velocityZ = lbl_803DFA9C;
    cfg.scale = lbl_803DFA9C;
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
    case 0x1c8:
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.velocityX = lbl_803DFAA0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = cfg.velocityX * (lbl_803DFAA0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e)
        )
        ;
        cfg.scale = lbl_803DFAA4 * (f32)(s32)
        randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80118;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0x566;
        break;
    case 0x1c9:
        cfg.startPosZ = lbl_803DFAA8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFAAC * (f32)(s32)
        randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x4f9;
        break;
    case 0x1ca:
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.scale = lbl_803DFAB4 * (f32)(s32)
        randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x400110;
        if ((int)randomGetRange(0, 2) == 0)
        {
            cfg.renderFlags = cfg.renderFlags | 0x100;
        }
        else
        {
            cfg.renderFlags = cfg.renderFlags | 0x400;
        }
        cfg.textureId = 0x4f9;
        break;
    case 0x1c7:
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x46, 0x46);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0x82, 0xaa);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x46, 0x46);
        cfg.scale = lbl_803DFAB0;
        cfg.lifetimeFrames = 0x190;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.behaviorFlags = 0x80480108;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x33;
        break;
    case 0x1c5:
        cfg.startPosX = lbl_803DFAB8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFABC;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x33;
        break;
    case 0x1c4:
        cfg.startPosX = lbl_803DFAC0;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x26c;
        break;
    case 0x1c6:
        cfg.startPosX = lbl_803DFAC8 + (f32)(s32)
        randomGetRange(0, 0x5a);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFACC * (f32)(s32)
        randomGetRange(1, 0x14);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1c3:
        cfg.velocityY = lbl_803DFA8C;
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100110;
        cfg.textureId = 0x23b;
        break;
    case 0x190:
        cfg.scale = lbl_803DFAD0 * (f32)(s32)
        randomGetRange(1, 5);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x14);
        cfg.renderFlags = 0x2;
        cfg.linkGroup = 0;
        cfg.textureId = 0xdf;
        break;
    case 0x191:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x8, 0x8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x8, 0x8);
        cfg.velocityY = lbl_803DFAD4 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFA88;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xde;
        break;
    case 0x192:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xd0, 0xd0);
        cfg.velocityY = lbl_803DFAD8 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFADC;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0x1dd;
        break;
    case 0x193:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = lbl_803DFAD4 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFADC;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0xde;
        break;
    case 0x194:
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x5, 0x5);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x5, 0x5);
        cfg.scale = lbl_803DFAE0;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0xde;
        break;
    case 0x195:
        cfg.scale = lbl_803DFAE4;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480214;
        cfg.textureId = 0xde;
        break;
    case 0x196:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = lbl_803DFAE8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803DFAEC * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.velocityZ = lbl_803DFAE8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.scale = lbl_803DFAF0;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x8acf;
        cfg.overrideColor0 = 0xafc8;
        cfg.overrideColor1 = 0x3a98;
        cfg.overrideColor2 = 0x5dc;
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x24;
        cfg.textureId = 0x1dd;
        break;
    case 0x197:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = lbl_803DFAF4 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803DFAF8 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.velocityZ = lbl_803DFAF4 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.scale = lbl_803DFAB0;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.colorWord0 = 0xf82f;
        cfg.colorWord1 = 0xf447;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xa7f8;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.behaviorFlags = 0x80080610;
        cfg.renderFlags = 0x24;
        cfg.textureId = 0x1de;
        break;
    case 0x198:
        cfg.startPosY = lbl_803DFAFC * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.scale = lbl_803DFB00;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x91;
        break;
    case 0x199:
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB04;
        cfg.lifetimeFrames = 0;
        cfg.initialAlpha = (u8)(randomGetRange(0, 0x37) + 0xc8);
        cfg.linkGroup = 0;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x156;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x157;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0xc0e;
        }
        cfg.behaviorFlags = 0x80011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19a:
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.lifetimeFrames = 0xc;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19b:
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.lifetimeFrames = 0;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x80011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19c:
        cfg.scale = lbl_803DFB10;
        cfg.lifetimeFrames = 0x2;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x156;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x157;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0xc0e;
        }
        cfg.behaviorFlags = 0x480001;
        break;
    case 0x19d:
        cfg.scale = lbl_803DFB14;
        cfg.lifetimeFrames = 0xf;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180201;
        break;
    case 0x19f:
        cfg.startPosX = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFB18 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x37, 0x4b);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x4402800;
        break;
    case 0x1a0:
        cfg.scale = lbl_803DFB1C * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x1bc:
        cfg.startPosX = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFB18 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x8c, 0xa5);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0x167;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4400000;
        break;
    case 0x1bd:
        cfg.scale = lbl_803DFB1C * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0x64;
        cfg.behaviorFlags = 0x4080100;
        break;
    case 0x1a1:
        cfg.startPosX = lbl_803DFB20 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB20 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityX = lbl_803DFAEC * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB24 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DFB28;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x1a2;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a2:
        cfg.scale = lbl_803DFB28;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a3:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(0, 0x1e) + lbl_803DFB20;
        cfg.scale = lbl_803DFB2C * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80500209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x1a4:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803DFB30 + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803DFB34;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB38 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB40 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFB3C;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x208;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x209;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0x20a;
        }
        break;
    case 0x1a5:
        if (spawnParams != 0)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk8 <= lbl_803DFAB0)
            {
                ((PartFxSpawnParams*)spawnParams)->unk8 = *(f32*)&lbl_803DFAB0;
            }
            cfg.velocityY = -((PartFxSpawnParams*)spawnParams)->unk8;
        }
        else
        {
            cfg.velocityY = lbl_803DFB44 * (f32)(s32)
            randomGetRange(0, 0x14);
        }
        cfg.velocityX = lbl_803DFB48 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB48 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB4C * (f32)(s32)
        randomGetRange(2, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x46);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480108;
        cfg.textureId = 0xc13;
        break;
    case 0x1a6:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803DFB34;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB38 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB40 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFB3C;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x208;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x209;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0x20a;
        }
        cfg.colorWord0 = 0x3200;
        cfg.colorWord1 = 0x3200;
        cfg.colorWord2 = 0x7800;
        cfg.overrideColor0 = 0x3200;
        cfg.overrideColor1 = 0x3200;
        cfg.overrideColor2 = 0x7800;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b6:
        if (spawnParams != 0)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        else
        {
            cfg.velocityY = lbl_803DFAD8 * (f32)(s32)
            randomGetRange(-3, 3);
        }
        cfg.scale = lbl_803DFB00;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x88100200;
        cfg.textureId = 0xc79;
        break;
    case 0x1a7:
        cfg.scale = lbl_803DFB50;
        cfg.lifetimeFrames = randomGetRange(0, 0xfa) + 0x96;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x1a8;
        cfg.behaviorFlags = 0x80490008;
        cfg.textureId = 0x167;
        break;
    case 0x1a8:
        cfg.scale = lbl_803DFB54;
        cfg.lifetimeFrames = 0xa;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480100;
        cfg.textureId = 0x167;
        break;
    case 0x1a9:
        if ((int)randomGetRange(0, 0x50) == 0)
        {
            cfg.lifetimeFrames = 0xf0;
            cfg.velocityX = lbl_803DFB58;
        }
        else
        {
            cfg.lifetimeFrames = 0x78;
            cfg.velocityX = lbl_803DFB5C;
        }
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFABC;
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xdf;
        break;
    case 0x1b3:
        if (spawnParams == 0) return -1;
        cfg.velocityX = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.velocityY = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.velocityZ = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.startPosY = lbl_803DFB64;
        vecRotateZXY(spawnParams, &cfg.velocityX);
        cfg.scale = lbl_803DFB68 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0x10;
        cfg.quadVertex3Pad06 = 0x1b4;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x159;
        break;
    case 0x1b4:
        cfg.scale = lbl_803DFB6C * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80201;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x159;
        break;
    case 0x1aa:
        if (spawnParams == 0) return -1;
        cfg.velocityX = lbl_803DFA88 * (f32)(s32)
        randomGetRange(0, 0x640) + lbl_803DFB70;
        vecRotateZXY(spawnParams, &cfg.velocityX);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.scale = lbl_803DFABC;
            cfg.initialAlpha = 0xff;
        }
        else
        {
            cfg.scale = lbl_803DFAF8;
            cfg.initialAlpha = 0x9b;
        }
        cfg.lifetimeFrames = 0xf0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xdf;
        break;
    case 0x1af:
        if (spawnParams == 0) return -1;
        cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unkC * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unkC * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0x190, 0x1f4);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080404;
        cfg.textureId = 0x5c;
        cfg.colorWord0 = 0xfffe;
        cfg.colorWord1 = 0x8ace;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0x4e20;
        cfg.overrideColor1 = 0x9c40;
        cfg.overrideColor2 = 0xfffe;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b0:
        if (spawnParams == 0) return -1;
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB7C;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = (s16)randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)randomGetRange(0, 0xffff);
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x167;
        break;
    case 0x1b1:
        if (spawnParams == 0) return -1;
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unkC * (lbl_803DFB80 * (f32)(s32)
        randomGetRange(1, 5)
        )
        ;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = (s16)randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)randomGetRange(0, 0xffff);
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x30;
        break;
    case 0x1b2:
        cfg.velocityX = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x81480204;
        cfg.textureId = 0x30;
        break;
    case 0x1ae:
        cfg.velocityX = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480104;
        cfg.renderFlags = 8;
        cfg.textureId = 0x30;
        break;
    case 0x1ab:
        cfg.startPosX = lbl_803DFB88;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.velocityX = cfg.startPosX / lbl_803DFB30;
        cfg.velocityY = cfg.startPosY / lbl_803DFB30;
        cfg.velocityZ = cfg.startPosZ / lbl_803DFB30;
        cfg.scale = lbl_803DFB8C * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480504;
        cfg.textureId = 0x30;
        break;
    case 0x1ac:
        cfg.startPosX = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB94 * (f32)(s32)
        randomGetRange(0x1f4, 0x3e8);
        cfg.initialAlpha = randomGetRange(0x9b, 0xff);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x1e;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80180104;
        cfg.textureId = 0x60;
        cfg.overrideColor0 = 0x6400;
        cfg.overrideColor1 = (randomGetRange(0, 0x55) + 0xaa) << 8;
        cfg.overrideColor2 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.renderFlags = 0x20;
        break;
    case 0x1ad:
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB6C * (f32)(s32)
        randomGetRange(0xc8, 0x5dc);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x1e;
        cfg.initialAlpha = (u8)(randomGetRange(0xb4, 0xc8) + 0x37);
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80580104;
        cfg.textureId = 0xc22;
        cfg.overrideColor0 = 0xc800;
        cfg.overrideColor1 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.overrideColor2 = (randomGetRange(0, 0x19) + 0xe6) << 8;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b9:
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosX = lbl_803DFB9C * (f32)(s32)
        randomGetRange(0, 0x3e8) + lbl_803DFB98;
        cfg.startPosY = lbl_803DFBA0 * cfg.startPosX;
        cfg.velocityX = lbl_803DFBA8 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFBA4;
        cfg.velocityY = lbl_803DFBA0 * cfg.velocityX;
        cfg.scale = lbl_803DFBAC * (f32)(s32)
        randomGetRange(1, 6);
        cfg.lifetimeFrames = 0xbe;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6000100;
        cfg.textureId = 0x20;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0x5fb4;
        cfg.sourceVecX = -0x3fff;
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        break;
    case 0x1bf:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(0, 0x3e8);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFB38 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.velocityZ = lbl_803DFB38 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFBB4;
        cfg.lifetimeFrames = 0x15e;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x300020;
        cfg.behaviorFlags = 0x3008000;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x63bf;
        cfg.overrideColor1 = 0x9e7;
        cfg.overrideColor2 = 0x3e8;
        cfg.textureId = 0x23b;
        break;
    case 0x1c0:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.scale = lbl_803DFBB4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1c1:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DFBB8 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.scale = lbl_803DFB48 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x9b;
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x80100;
        cfg.colorWord0 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.colorWord1 = cfg.colorWord0 / (int)randomGetRange(1, 3);
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0x2710);
        cfg.overrideColor1 = (int)cfg.overrideColor0 / (int)randomGetRange(1, 3);
        cfg.overrideColor2 = 0;
        cfg.textureId = 0x60;
        break;
    case 0x1c2:
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityZ = cfg.velocityZ * lbl_803DFBBC;
        }
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityY = cfg.velocityY * lbl_803DFBBC;
        }
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x14;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1ba:
        cfg.startPosY = lbl_803DFBC0;
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DFBA0 * cfg.startPosX;
        cfg.scale = lbl_803DFBC4 * (f32)(s32)
        randomGetRange(1, 6);
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x20;
        break;
    case 0x1b8:
        cfg.startPosX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.scale = lbl_803DFBC8 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x56;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

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
int Effect1_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7B0 = lbl_803DB7B0 + lbl_803DF720;
    if (lbl_803DB7B0 > 1.0f) lbl_803DB7B0 = lbl_803DF724;
    lbl_803DB7B4 = lbl_803DB7B4 + lbl_803DF72C;
    if (lbl_803DB7B4 > 1.0f) lbl_803DB7B4 = lbl_803DF730;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
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
        cfg.behaviorFlags = 0x8048100;
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
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
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
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
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
        cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF78C * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF790 * (f32)(s32)
        randomGetRange(0x50, 0x8c)
        )
        ;
        cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF794 * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.startPosX = lbl_803DF798 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DF75C;
        cfg.startPosZ = lbl_803DF79C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803DF7A0 * (f32)(s32)
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
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = lbl_803DF7A4 + ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = lbl_803DF7A4 + ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.velocityX = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DF764 * (f32)(s32)
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803DF7C4 + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.sourceVecX = *spawnParams;
            cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.renderFlags = 0x200000;
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
        cfg.behaviorFlags = 0x8000210;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803DF7C4 + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.sourceVecX = *spawnParams;
            cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803DF7C4 + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.sourceVecX = *spawnParams;
            cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
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
        cfg.behaviorFlags = 0x8110000;
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
        cfg.behaviorFlags = 0x8110000;
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
        cfg.behaviorFlags = 0x8050100;
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
        cfg.behaviorFlags = 0x8050100;
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
        cfg.behaviorFlags = 0x8050100;
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
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk14;
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
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.behaviorFlags = 0x8048208;
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
        cfg.behaviorFlags = 0x8040201;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x390: /* L_800B1F2C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
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
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
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
            cfg.startPosX = cfg.startPosX + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = cfg.startPosY + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = cfg.startPosZ + ((PartFxSpawnParams*)spawnParams)->unk14;
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
        cfg.overrideColor0 = (u16)cfg.colorWord0 / 10;
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
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
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
        es.a = lbl_803DF7DC * (f32)(s32)
        randomGetRange(0, 0x258) + lbl_803DF844;
        cfg.velocityY = lbl_803DF720 * (f32)(s32)
        randomGetRange(0, 0xc8) + 1.0f;
        cfg.velocityX = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803DF724;
        cfg.velocityY = cfg.velocityY * es.a;
        cfg.velocityX = cfg.velocityX * es.a;
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
        cfg.behaviorFlags = 0x8100120;
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
        cfg.overrideColor0 = (u16)cfg.colorWord0;
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
        cfg.behaviorFlags = 0x8048200;
        cfg.textureId = 0xc0d;
        break;
    default: /* L_800B2F6C */
        return -1;
    }
    /* ===== common dispatch tail (L_800B2F74) ===== */
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
#undef FILL320

void Effect9_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB828 + (step = lbl_803DFE28 * timeDelta);
    lbl_803DB828 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB828 = lbl_803DFE2C;
    }
    sum = lbl_803DB82C + step;
    lbl_803DB82C = sum;
    if (sum > 1.0f)
    {
        lbl_803DB82C = lbl_803DFE38;
    }
    lbl_803DD3A0 = lbl_803DD3A0 + framesThisStep * 0x64;
    if (lbl_803DD3A0 > 0x7fff)
    {
        lbl_803DD3A0 = 0;
    }
    lbl_803DD3AC = mathSinf(lbl_803DFEB0 * (f32)(s16)lbl_803DD3A0 / lbl_803DFEB4);
    lbl_803DD3A4 = lbl_803DD3A4 + framesThisStep * 0x32;
    if (lbl_803DD3A4 > 0x7fff)
    {
        lbl_803DD3A4 = 0;
    }
    lbl_803DD3A8 = mathSinf(lbl_803DFEB0 * (f32)(s16)lbl_803DD3A4 / lbl_803DFEB4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dll_0B_onMapSetup(void)
{
    int i;

    fn_800A1040(0, 1);
    for (i = 0; i < 0x32; i++)
    {
        gPartfxActiveEffects[i] = NULL;
    }
}
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
void fn_800A3AF0(void* table, int count, void* ctx, f32 a, f32 b)
{
    BoneSpawnData data;
    void* cam;
    int found;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 len;
    f32 sc;
    f32 p0x;
    f32 p0y;
    f32 p0z;
    f32 p1x;
    f32 p1y;
    f32 p1z;
    f32 p2x;
    f32 p2y;
    f32 p2z;
    f32 r1;
    f32 r2;
    f32 s;
    f32 w0;
    f32 w1;
    f32 w2;

    found = 0;
    cam = Camera_GetCurrentViewSlot();
    lbl_803DD29A = *(s16*)cam;
    lbl_803DD29C = ((GameObject*)cam)->anim.rotY;
    dx = ((GameObject*)cam)->anim.localPosX - ((GameObject*)ctx)->anim.localPosX;
    dy = ((GameObject*)cam)->anim.localPosY - ((GameObject*)ctx)->anim.localPosY;
    dz = ((GameObject*)cam)->anim.localPosZ - ((GameObject*)ctx)->anim.localPosZ;
    for (i = 0; i < count; i++)
    {
        int t = *(s8*)((char*)table + i * 0x4c + 0x48);
        if (t == 0x12 || (u8)(t - 0x10) <= 1 || (u8)(t - 0x14) <= 1 || t == 0x17)
        {
            lbl_8030FDE8[0] = dx;
            lbl_8030FDE8[1] = dy;
            lbl_8030FDE8[2] = dz;
            len = sqrtf(dy * dy + dx * dx + dz * dz);
            sc = lbl_803DF468 * len;
            if (lbl_803DF46C != len)
            {
                dx = dx / len;
                dy = dy / len;
                dz = dz / len;
            }
            dx = dx * sc;
            dy = dy * sc;
            dz = dz * sc;
            data.x = lbl_803DF46C;
            data.y = lbl_803DF46C;
            data.z = lbl_803DF46C;
            data.scale = lbl_803DF470;
            data.unk4 = 0;
            data.unk2 = 0;
            data.unk0 = 0;
            found = 1;
            i = count;
        }
    }
    if (found)
    {
        int j;
        char* e = (char*)table;
        for (j = 0; j < count; j++)
        {
            int t = *(s8*)(e + 0x48);
            if (t == 0x12 || (u8)(t - 0x10) <= 1 || (u8)(t - 0x14) <= 1 || t == 0x17)
            {
                int rt;
                p0x = ((GameObject*)ctx)->anim.localPosX + ((f32) * (s16*)(e + 0x10) - a);
                p0y = (f32) * (s16*)(e + 0x16);
                p0z = ((GameObject*)ctx)->anim.localPosZ + ((f32) * (s16*)(e + 0x1c) - b);
                p1x = ((GameObject*)ctx)->anim.localPosX + ((f32) * (s16*)(e + 0x12) - a);
                p1y = (f32) * (s16*)(e + 0x18);
                p1z = ((GameObject*)ctx)->anim.localPosZ + ((f32) * (s16*)(e + 0x1e) - b);
                p2x = ((GameObject*)ctx)->anim.localPosX + ((f32) * (s16*)(e + 0x14) - a);
                p2y = (f32) * (s16*)(e + 0x1a);
                p2z = ((GameObject*)ctx)->anim.localPosZ + ((f32) * (s16*)(e + 0x20) - b);
                r1 = (f32)randomGetRange(1, 1000) / lbl_803DF474;
                r2 = (f32)randomGetRange(1, 1000) / lbl_803DF474;
                s = sqrtf(r2);
                w0 = lbl_803DF470 - s;
                w1 = (lbl_803DF470 - r1) * s;
                w2 = r1 * s;
                data.x = w0 * p0x + w1 * p1x + w2 * p2x;
                data.y = w0 * p0y + w1 * p1y + w2 * p2y;
                data.z = w0 * p0z + w1 * p1z + w2 * p2z;
                data.y = data.y + lbl_803DF478;
                rt = *(s8*)(e + 0x48);
                if (rt == 0x12 || rt == 0x10)
                {
                    if (randomGetRange(0, 0x1e) == 1)
                    {
                        (*gPartfxInterface)->spawnObject(ctx, 0x72, &data, 0x200001, -1, NULL);
                    }
                }
                else if (rt == 0x11)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x14)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x15)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x17)
                {
                    (*gPartfxInterface)->spawnObject(ctx, 0x190, &data, 0x111, -1, NULL);
                    (*gPartfxInterface)->spawnObject(ctx, 0x190, &data, 0x111, -1, NULL);
                    (*gPartfxInterface)->spawnObject(ctx, 0x190, &data, 0x111, -1, NULL);
                }
            }
            e += 0x4c;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

extern int dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g);

#pragma scheduling off
#pragma peephole off
void dll_0B_func16(void* a, void* b, void* c, void* d, void* e, int f, void* g)
{
    ModgfxSpawnContext* context = &gModgfxSpawnContext;

    context->pendingSpawns = gModgfxPendingSpawnQueue;
    context->pendingSpawnCount = gModgfxPendingSpawnWriteCursor - gModgfxPendingSpawnStartCursor;
    if (g == NULL && f == 0)
    {
        context->flags |= 0x2000000;
    }
    else
    {
        context->flags |= 0x4000000;
    }
    if (context->flags & 1)
    {
        if (context->attachedSource != NULL)
        {
            context->posX += ((ExpgfxSourceObject*)context->attachedSource)->worldPosX;
            context->posY += ((ExpgfxSourceObject*)context->attachedSource)->worldPosY;
            context->posZ += ((ExpgfxSourceObject*)context->attachedSource)->worldPosZ;
        }
        else
        {
            context->posX += ((ExpgfxSourceObject*)a)->localPosX;
            context->posY += ((ExpgfxSourceObject*)a)->localPosY;
            context->posZ += ((ExpgfxSourceObject*)a)->localPosZ;
        }
    }
    gModgfxLastSpawnHandle = dll_0B_func04(context, 0, (int)c, b, (int)e, d, f, g);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF460;
extern s16 lbl_803DD280;

#pragma scheduling off
#pragma peephole off
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
    PartfxEffectState** effects;
    PartfxEffectState* effect;

    effects = (PartfxEffectState**)gPartfxActiveEffects;
    total = 0;
    found = 0;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT && found == 0; i++)
    {
        if (effects[i] == NULL) found = 1;
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

    effects[slot] = (PartfxEffectState*)mmAlloc(base0 + n * 0x18 + total * 2 + 0x240, 0x15, 0);
    effect = effects[slot];
    if (effect == NULL)
    {
        fn_800A1040(0, 0);
        return -1;
    }

    effect->inlineData = (u8*)effect + sizeof(PartfxEffectState);
    {
        u8* bufp = effect->inlineData;
        if ((*(u32*)(st + 0x54) & 0x800) == 0)
        {
            effect->colorBuffers[0] = bufp;
            bufp += e * 16;
            effect->colorBuffers[1] = bufp;
            bufp += e * 16;
            effect->colorBuffers[2] = bufp;
            bufp += e * 16;
            effect->vertexBuffers[0] = bufp;
            bufp += c * 16;
            effect->vertexBuffers[1] = bufp;
            bufp += c * 16;
            effect->vertexBuffers[2] = bufp;
            bufp += c * 16;
        }
        effect->baseVertexBuffer = bufp;
        effect->baseColorBuffer = bufp + 0x80;
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
            u8* dstc = effect->colorBuffers[k];
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

    effect->textureResource = NULL;
    effect->textureIsBorrowed = 0;
    if (g != NULL)
    {
        effect->textureResource = g;
        effect->textureIsBorrowed = 1;
    }
    else if (f != 0)
    {
        effect->textureResource = textureLoadAsset(f);
        effect->textureIsBorrowed = 0;
    }

    if ((*(u32*)(st + 0x54) & 0x800) == 0)
    {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4)
        {
            u8* dstv = effect->vertexBuffers[k];
            int j;
            s16* sb = (s16*)b;
            for (j = 0; j < c; j++)
            {
                *(s16*)(dstv + 0) = sb[0];
                *(s16*)(dstv + 2) = sb[1];
                *(s16*)(dstv + 4) = sb[2];
                if (effect->textureResource != NULL)
                {
                    *(s16*)(dstv + 8) = lbl_803DF460 * ((f32)sb[3] / (f32) * (u16*)((u8*)effect->textureResource +
                        0xa));
                    *(s16*)(dstv + 0xa) = lbl_803DF460 * ((f32)sb[4] / (f32) * (u16*)((u8*)effect->textureResource +
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

    effect->emitterCount = st[0x5d];
    effect->word114 = 0;
    effect->word118 = 0;
    effect->word11C = 0;
    effect->auxAllocation = NULL;
    effect->releaseRequested = 0;
    effect->byte13D = 0;
    effect->stageTimer = 0;
    effect->nextStage = -1;
    effect->requestedStage = 0;
    effect->stageDurations[0] = *(s16*)(st + 0x46);
    effect->stageDurations[1] = *(s16*)(st + 0x48);
    effect->stageDurations[2] = *(s16*)(st + 0x4a);
    effect->stageDurations[3] = *(s16*)(st + 0x4c);
    effect->stageDurations[4] = *(s16*)(st + 0x4e);
    effect->stageDurations[5] = *(s16*)(st + 0x50);
    effect->stageDurations[6] = *(s16*)(st + 0x52);
    effect->emitterCommands = (u8*)effect->inlineData + base0 + 0x100;
    effect->auxSequenceBuffer = NULL;
    if (total != 0)
    {
        effect->auxSequenceBuffer = (u8*)effect->emitterCommands + effect->emitterCount * 0x18;
    }

    {
        u8* dst = effect->auxSequenceBuffer;
        int m;
        int off;
        for (m = 0, off = 0; m < effect->emitterCount; m++, off += 0x18)
        {
            ((u8*)effect->emitterCommands)[off + 0x16] = (*(u8**)st)[off + 0x16];
            *(s16*)((u8*)effect->emitterCommands + off + 0x14) = *(s16*)(*(u8**)st + off + 0x14);
            *(int*)((u8*)effect->emitterCommands + off + 0x10) = 0;
            *(int*)((u8*)effect->emitterCommands + off) = *(int*)(*(u8**)st + off);
            if ((*(int*)((u8*)effect->emitterCommands + off) & 0xf7fff180) == 0 &&
                *(s16*)((u8*)effect->emitterCommands + off + 0x14) != 0)
            {
                int k;
                *(int*)((u8*)effect->emitterCommands + off + 0x10) = 0;
                *(u8**)((u8*)effect->emitterCommands + off + 0x10) = dst;
                dst += *(s16*)((u8*)effect->emitterCommands + off + 0x14) * 2;
                for (k = 0; k < *(s16*)((u8*)effect->emitterCommands + off + 0x14); k++)
                {
                    *(s16*)(*(u8**)((u8*)effect->emitterCommands + off + 0x10) + k * 2) =
                        *(s16*)(*(u8**)(*(u8**)st + off + 0x10) + k * 2);
                }
            }
            *(f32*)((u8*)effect->emitterCommands + off + 4) = *(f32*)(*(u8**)st + off + 4);
            *(f32*)((u8*)effect->emitterCommands + off + 8) = *(f32*)(*(u8**)st + off + 8);
            *(f32*)((u8*)effect->emitterCommands + off + 0xc) = *(f32*)(*(u8**)st + off + 0xc);
        }
    }

    effect->currentStage = -1;
    effect->stageFrameCountdown = effect->colorVertexCount;
    effect->flags = *(int*)(st + 0x54);
    effect->drawPosX = *(f32*)(st + 0x2c);
    effect->drawPosY = *(f32*)(st + 0x30);
    effect->drawPosZ = *(f32*)(st + 0x34);
    effect->renderScale = *(f32*)(st + 0x38);
    if (effect->flags & 1)
    {
        effect->sourcePosX = *(f32*)(st + 0x2c);
        effect->sourcePosY = *(f32*)(st + 0x30);
        effect->sourcePosZ = *(f32*)(st + 0x34);
    }
    fz430 = lbl_803DF430;
    fz434 = lbl_803DF434;
    effect->posStepX = fz430;
    effect->posStepY = fz430;
    effect->posStepZ = fz430;
    effect->scaleChannels[0].cur[0] = fz434;
    effect->scaleChannels[0].cur[1] = fz434;
    effect->scaleChannels[0].cur[2] = fz434;
    effect->scaleChannels[0].step[1] = fz430;
    effect->scaleChannels[0].step[2] = fz430;
    effect->scaleChannels[0].step[0] = fz430;
    effect->scaleChannels[1].cur[2] = fz434;
    effect->scaleChannels[1].cur[0] = fz434;
    effect->scaleChannels[1].cur[1] = fz434;
    effect->scaleChannels[1].step[2] = fz430;
    effect->scaleChannels[1].step[0] = fz430;
    effect->scaleChannels[1].step[1] = fz430;
    effect->rotOffsetZ = 0;
    effect->rotOffsetY = 0;
    effect->rotOffsetX = 0;
    effect->vec120 = 0;
    effect->vec122 = 0;
    effect->vec124 = 0;
    effect->alphaChannels[0].step = fz430;
    effect->alphaChannels[0].cur = fz430;
    effect->alphaChannels[1].step = fz430;
    effect->alphaChannels[1].cur = fz430;
    effect->blendColorR = fz430;
    effect->blendColorG = fz430;
    effect->blendColorB = fz430;
    effect->blendColorStepR = fz430;
    effect->blendColorStepG = fz430;
    effect->blendColorStepB = fz430;
    effect->velocityX = *(f32*)(st + 0x20);
    effect->velocityY = *(f32*)(st + 0x24);
    effect->velocityZ = *(f32*)(st + 0x28);
    lbl_803DD280 = lbl_803DD280 + 1;
    if (lbl_803DD280 > 0x4e20)
    {
        lbl_803DD280 = 0;
    }
    effect->sequenceId = lbl_803DD280;
    effect->byte126 = lbl_803DD282;
    effect->vertexCount = (s16)c;
    effect->colorVertexCount = (s16)e;
    effect->sourceObject = *(void**)(st + 4);
    effect->instanceObject = NULL;
    effect->sourceYawIndex = st[0x5c];
    effect->drawGroupCount = *(int*)(st + 0x40);
    effect->drawGroupStride = *(int*)(st + 0x3c);
    effect->initialStateByte = st[0x59];
    effect->soundHandle = 0;
    effect->activeVertexBufferIndex = 0;
    effect->byte13B = 0;
    effect->frameUpdated = 0;
    effect->textureFrameTimer = st[0x5b];
    if (effect->textureFrameTimer != 0)
    {
        effect->textureFrameStep = 0x3c / effect->textureFrameTimer;
    }
    else
    {
        effect->textureFrameStep = 0;
    }
    if (effect->textureFrameStep != 0)
    {
        effect->textureFrameFadeStep = 0xff / effect->textureFrameStep;
    }
    else
    {
        effect->textureFrameFadeStep = 0;
    }
    effect->textureFrame = 0;
    effect->initialDelayFrames = *(s16*)(st + 0x44);
    return effect->sequenceId;
}
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0524(void* state, void* p, int mode)
{
    extern f32 lbl_803DF430;
    extern f32 lbl_803DF43C;
    u8* buf = *(u8**)((char*)state + *(u8*)((char*)state + 0x130) * 4 + 0x78);
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
            *(f32*)((char*)state + 0xc8) = lbl_803DF430;
            *(f32*)((char*)state + 0xcc) = lbl_803DF430;
            *(f32*)((char*)state + 0xd0) = lbl_803DF430;
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0C78(void* state, void* p, int mode, u8 idx)
{
    extern f32 lbl_803DD284;
    extern f32 lbl_803DF434;
    char* base = (char*)state + idx * 2 * 0xc;
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
            u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
            u8* buf2 = *(u8**)((char*)state + *(u8*)((char*)state + 0x130) * 4 + 0x78);
            for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
            {
                s16 v = ((ModgfxVertexGroupCmd*)p)->indices[j];
                *(s16*)(buf + v * 16 + 0) = (int)((f32) * (s16*)(buf + v * 16 + 0) * tx);
                *(s16*)(buf + v * 16 + 2) = (int)((f32) * (s16*)(buf + v * 16 + 2) * ty);
                *(s16*)(buf + v * 16 + 4) = (int)((f32) * (s16*)(buf + v * 16 + 4) * tz);
                *(s16*)(buf2 + v * 16 + 0) = *(s16*)(buf + v * 16 + 0);
                *(s16*)(buf2 + v * 16 + 2) = *(s16*)(buf + v * 16 + 2);
                *(s16*)(buf2 + v * 16 + 4) = *(s16*)(buf + v * 16 + 4);
            }
            return;
        }
    }
    *(f32*)(base + 0x30) = *(f32*)(base + 0x30) + *(f32*)(base + 0x3c) * lbl_803DD284;
    *(f32*)(base + 0x34) = *(f32*)(base + 0x34) + *(f32*)(base + 0x40) * lbl_803DD284;
    *(f32*)(base + 0x38) = *(f32*)(base + 0x38) + *(f32*)(base + 0x44) * lbl_803DD284;
    {
        u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
        u8* buf2 = *(u8**)((char*)state + *(u8*)((char*)state + 0x130) * 4 + 0x78);
        for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
        {
            s16 v = ((ModgfxVertexGroupCmd*)p)->indices[j];
            if (lbl_803DF434 != *(f32*)(base + 0x30))
            {
                *(s16*)(buf2 + v * 16 + 0) = (int)(*(f32*)(base + 0x30) * (f32) * (s16*)(buf + v * 16 + 0));
            }
            if (lbl_803DF434 != *(f32*)(base + 0x34))
            {
                *(s16*)(buf2 + v * 16 + 2) = (int)(*(f32*)(base + 0x34) * (f32) * (s16*)(buf + v * 16 + 2));
            }
            if (lbl_803DF434 != *(f32*)(base + 0x38))
            {
                *(s16*)(buf2 + v * 16 + 4) = (int)(*(f32*)(base + 0x38) * (f32) * (s16*)(buf + v * 16 + 4));
            }
        }
    }
}
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
#pragma peephole reset
#pragma scheduling reset
