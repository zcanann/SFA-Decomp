#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/objanim_internal.h"
#include "main/resource.h"

typedef struct ModgfxEffectSlot {
    u8 pad0[0x4 - 0x0];
    void *unk4;
    u8 pad8[0xC - 0x8];
    s16 unkC;
    u8 padE[0x18 - 0xE];
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x60 - 0x30];
    f32 unk60;
    f32 unk64;
    f32 unk68;
    u8 pad6C[0x9C - 0x6C];
    void *unk9C;
    u8 padA0[0xA4 - 0xA0];
    s32 unkA4;
    u8 padA8[0xBC - 0xA8];
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0xFC - 0xC4];
    s16 counterFC;
    s16 unkFE;
    u8 pad100[0x106 - 0x100];
    s16 unk106;
    s16 unk108;
    s16 unk10A;
    s16 unk10C;
    u8 pad10E[0x139 - 0x10E];
    s8 unk139;
    u8 unk13A;
    u8 pad13B[0x13C - 0x13B];
    u8 unk13C;
    u8 pad13D[0x13E - 0x13D];
    u8 unk13E;
    u8 pad13F[0x140 - 0x13F];
} ModgfxEffectSlot;


typedef struct ModgfxVertexData {
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
typedef struct ModgfxScaleChannel {
  f32 cur[3];
  f32 step[3];
} ModgfxScaleChannel;

/* per-channel vertex-alpha blend record (state+0xAC, stride 8, 2 channels) */
typedef struct ModgfxAlphaChannel {
  f32 step;
  f32 cur;
} ModgfxAlphaChannel;

typedef struct ModgfxState {
  u8 pad00[4];
  s16 *unk04; /* current vertex-index list */
  u8 pad08[0x24 - 0x08];
  f32 posStepX; /* 0x24: per-step vertex-position delta */
  f32 posStepY;
  f32 posStepZ;
  ModgfxScaleChannel scaleChannels[2];
  f32 posCurX; /* 0x60: accumulated vertex-position offset */
  f32 posCurY;
  f32 posCurZ;
  u8 pad6C[0x78 - 0x6C];
  ModgfxVertexData *vertexBuffers[2];
  ModgfxVertexData *baseVertexData;
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
typedef struct ModgfxVertexGroupCmd {
  u8 unk00[4];
  f32 valueX; /* rgb r / scale x / alpha */
  f32 valueY;
  f32 valueZ;
  s16 *indices; /* vertex indices, stride 2 */
  s16 indexCount;
} ModgfxVertexGroupCmd;

static inline int *Modgfx_GetActiveModel(void *obj) {
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
  return (int *)objAnim->banks[objAnim->bankIndex];
}

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32
#define MODGFX_EFFECT_RENDER_BUFFER_COUNT 7
#define MODGFX_EFFECT_RENDER_BUFFER_BYTES 0x140
#define PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE 0x200000
#define PARTFX_ACTIVE_EFFECT_COUNT 0x32
#define PARTFX_STAGE_COUNT 7
typedef struct ModgfxActiveEffect {
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

typedef struct ModgfxPendingSpawn {
  int modelOrResource;
  float posX;
  float posY;
  float posZ;
  int param10;
  s16 param14;
  u8 sequenceIndex;
  u8 pad17;
} ModgfxPendingSpawn;

typedef struct ModgfxSpawnContext {
  ModgfxPendingSpawn *pendingSpawns;
  void *attachedSource;
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

typedef struct PartfxEffectState {
  void *instanceObject;
  void *sourceObject;
  void *auxSequenceBuffer;
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
  void *vertexBuffers[3];
  void *colorBuffers[3];
  void *baseVertexBuffer;
  void *baseColorBuffer;
  void *textureResource;
  void *emitterCommands;
  void *auxAllocation;
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
  void *inlineData;
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

extern ModgfxActiveEffect *gModgfxActiveEffectRegistry[];
extern int gModgfxEffectRenderBuffers[];

static ModgfxVertexData *modgfx_getActiveVertexBuffer(ModgfxState *state)
{
  return state->vertexBuffers[state->activeVertexBufferIndex];
}

static ModgfxVertexData *modgfx_getInactiveVertexBuffer(ModgfxState *state)
{
  return state->vertexBuffers[1 - (uint)state->activeVertexBufferIndex];
}

static ModgfxActiveEffect **modgfx_getActiveEffectRegistry(void)
{
  return gModgfxActiveEffectRegistry;
}

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern void *memcpy(void *dst, const void *src, u32 n);
extern int FUN_80006714();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d4();
extern undefined4 FUN_80006930();
extern undefined4 FUN_80006974();
extern void* FUN_800069a8();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017704();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern uint FUN_80017830();
extern void *mmAlloc(int size, int heap, int flags);
extern undefined4 FUN_80017970();
extern undefined4 FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017b00();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_8005360c();
extern undefined4 FUN_80053740();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern void fn_8005D108();
extern undefined4 FUN_8005d340();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern void trackDolphin_getCurrentTrackPoint(uint **param_1);
extern void trackDolphin_getCurrentIntersectionList(int *entryCountOut,undefined4 *entryListOut);
extern undefined4 FUN_80071204();
extern undefined4 FUN_800712d4();
extern undefined4 FUN_80071584();
extern undefined4 FUN_80071658();
extern undefined4 FUN_800719dc();
extern undefined4 FUN_80071ab0();
extern undefined4 FUN_80071e78();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_8007f3c8();
extern undefined4 FUN_8007f718();
extern undefined4 FUN_8007f960();
extern undefined4 FUN_80080f8c();
extern undefined4 FUN_80135814();
extern undefined4 FUN_802420e0();
extern void DCFlushRange(void *addr, u32 nBytes);
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025d80c();
extern undefined8 FUN_80286818();
extern undefined4 FUN_80286820();
extern undefined4 FUN_80286824();
extern undefined4 FUN_80286828();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293544();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined DAT_80000100;
extern undefined DAT_80000108;
extern undefined4 DAT_80000119;
extern undefined4 DAT_80000200;
extern undefined DAT_80000201;
extern undefined4 DAT_802c28e0;
extern undefined4 DAT_802c28e4;
extern undefined4 DAT_802c28e8;
extern undefined4 DAT_802c28ec;
extern undefined4 DAT_803109a8;
extern undefined4 DAT_803109ac;
extern undefined4 DAT_803109b0;
extern undefined4 DAT_803109f8;
extern undefined4 DAT_80310a88;
extern undefined4 DAT_80310b18;
extern undefined2 DAT_80310ba8;
extern undefined4 DAT_80310bb2;
extern undefined4 DAT_80310f88;
extern undefined DAT_80310fac;
extern undefined4 DAT_80310fd0;
extern undefined4 DAT_8031105c;
extern undefined4 DAT_80311120;
extern undefined4 DAT_80311124;
extern undefined4 DAT_80311128;
extern undefined4 DAT_8031112c;
extern undefined4 DAT_80311130;
extern undefined4 DAT_80311134;
extern undefined4 DAT_80311138;
extern undefined4 DAT_8031113c;
extern undefined4 DAT_80311140;
extern undefined4 DAT_80311144;
extern undefined4 DAT_80311148;
extern undefined4 DAT_8031114c;
extern undefined4 DAT_80311150;
extern undefined4 DAT_80311154;
extern undefined4 DAT_80311158;
extern undefined4 DAT_8031115c;
extern undefined4 DAT_80311160;
extern undefined4 DAT_80311164;
extern undefined4 DAT_80311168;
extern undefined4 DAT_8031116c;
extern undefined4 DAT_80311170;
extern undefined4 DAT_80311174;
extern undefined4 DAT_80311178;
extern undefined4 DAT_8031117c;
extern undefined4 DAT_80311180;
extern undefined4 DAT_80311184;
extern undefined4 DAT_80311188;
extern undefined4 DAT_8031118c;
extern undefined4 DAT_80311190;
extern undefined4 DAT_80311194;
extern undefined4 DAT_80311198;
extern undefined4 DAT_8031119c;
extern undefined4 DAT_803111a0;
extern undefined4 DAT_803111a4;
extern undefined4 DAT_803111a8;
extern undefined4 DAT_803111ac;
extern undefined4 DAT_803111b0;
extern undefined4 DAT_803111b4;
extern undefined4 DAT_803111b6;
extern undefined4 DAT_803111b8;
extern undefined4 DAT_803111ba;
extern undefined4 DAT_803111bc;
extern undefined4 DAT_803111be;
extern undefined4 DAT_803111c0;
extern undefined4 DAT_803111c1;
extern undefined4 DAT_8031122c;
extern undefined DAT_80380209;
extern int DAT_8039b7b8;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern undefined4 DAT_8039c7d0;
extern undefined4 DAT_8039c7d4;
extern ExpgfxSpawnConfig gExpgfxSpawnConfig;
extern undefined4 DAT_8039cf40;
extern undefined4 DAT_8039cf42;
extern undefined4 DAT_8039cf44;
extern undefined4 DAT_8039cf46;
extern undefined4 DAT_8039cf48;
extern undefined4 DAT_8039cf4a;
extern undefined4 DAT_8039cf4c;
extern undefined4 DAT_8039cf4e;
extern undefined4 DAT_8039cf50;
extern undefined4 DAT_8039cf52;
extern undefined4 DAT_8039cf54;
extern undefined4 DAT_8039cf56;
extern undefined4 DAT_8039cf58;
extern undefined4 DAT_8039cf5a;
extern undefined4 DAT_8039cf5c;
extern undefined4 DAT_8039cf5e;
extern undefined4 DAT_8039cf60;
extern undefined4 DAT_8039cf62;
extern undefined4 DAT_8039cf64;
extern undefined4 DAT_8039cf66;
extern undefined2 DAT_8039cf68;
extern undefined4 DAT_8039cf6a;
extern undefined4 DAT_8039cf6c;
extern undefined4 DAT_8039cf6e;
extern undefined4 DAT_8039cf70;
extern undefined4 DAT_8039cf74;
extern undefined4 DAT_8039cf78;
extern undefined4 DAT_8039cf7c;
extern undefined4 DAT_8039cf80;
extern undefined4 DAT_8039cf82;
extern undefined4 DAT_8039cf84;
extern undefined4 DAT_8039cf88;
extern undefined4 DAT_8039cf8c;
extern undefined4 DAT_8039cf90;
extern undefined4 DAT_8039cf94;
extern undefined4 DAT_8039cf98;
extern undefined4 DAT_8039cf9a;
extern undefined4 DAT_8039cf9c;
extern undefined4 DAT_8039cfa0;
extern undefined4 DAT_8039cfa4;
extern undefined4 DAT_8039cfa8;
extern undefined4 DAT_8039cfac;
extern undefined4 DAT_8039cfb0;
extern undefined4 DAT_8039cfb2;
extern undefined4 DAT_8039cfb4;
extern undefined4 DAT_8039cfb8;
extern undefined4 DAT_8039cfbc;
extern undefined4 DAT_8039cfc0;
extern undefined4 DAT_8039cfc4;
extern undefined4 DAT_8039cfc8;
extern undefined4 DAT_8039cfca;
extern undefined4 DAT_8039cfcc;
extern undefined4 DAT_8039cfd0;
extern undefined4 DAT_8039cfd4;
extern undefined4 DAT_8039cfd8;
extern undefined4 DAT_8039cfdc;
extern undefined4 DAT_8039cfe0;
extern undefined4 DAT_8039cfe2;
extern undefined4 DAT_8039cfe4;
extern undefined4 DAT_8039cfe8;
extern undefined4 DAT_8039cfec;
extern undefined4 DAT_8039cff0;
extern undefined4 DAT_8039cff4;
extern ExpgfxAttachedSourceState gProjgfxDefaultAttachedSource;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd430;
extern EffectInterface **gPartfxInterface;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803ddf00;
extern undefined4 DAT_803ddf02;
extern undefined4 DAT_803ddf08;
extern undefined4 DAT_803ddf0c;
extern undefined4 DAT_803ddf10;
extern undefined4 DAT_803ddf18;
extern undefined4 DAT_803ddf1a;
extern undefined4 DAT_803ddf1c;
extern undefined4 DAT_803ddf20;
extern undefined4 DAT_803ddf24;
extern undefined4 DAT_803ddf28;
extern undefined4 DAT_803ddf30;
extern undefined4 DAT_803ddf34;
extern undefined4 DAT_803ddf38;
extern undefined4 DAT_803ddf3c;
extern undefined4 DAT_803ddf40;
extern undefined4 DAT_803ddf44;
extern undefined4* DAT_803ddf48;
extern undefined4* DAT_803ddf4c;
extern undefined4* DAT_803ddf50;
extern undefined4* DAT_803ddf54;
extern undefined4* DAT_803ddf58;
extern undefined4* DAT_803ddf5c;
extern undefined4* DAT_803ddf60;
extern undefined4* DAT_803ddf64;
extern undefined4* DAT_803ddf68;
extern undefined4* DAT_803ddf6c;
extern undefined4* DAT_803ddf70;
extern undefined4* DAT_803ddf74;
extern undefined4* DAT_803ddf78;
extern undefined4* DAT_803ddf7c;
extern undefined4* DAT_803ddf80;
extern undefined4* DAT_803ddf84;
extern undefined4* DAT_803ddf88;
extern undefined4* DAT_803ddf8c;
extern undefined4* DAT_803ddf90;
extern undefined4* DAT_803ddf94;
extern undefined4 DAT_803ddf98;
extern undefined4 DAT_803ddf9c;
extern undefined4 DAT_803ddfa8;
extern undefined4 DAT_803ddfac;
extern undefined4 DAT_803ddfb8;
extern undefined4 DAT_803ddfbc;
extern undefined4 DAT_803ddfc8;
extern undefined4 DAT_803ddfd0;
extern undefined4 DAT_803ddfd4;
extern undefined4 DAT_803ddfe0;
extern undefined4 DAT_803ddfe4;
extern undefined4 DAT_803ddff0;
extern undefined4 DAT_803ddff4;
extern undefined4 DAT_803de000;
extern undefined4 DAT_803de004;
extern undefined4 DAT_803de010;
extern undefined4 DAT_803de014;
extern undefined4 DAT_803de020;
extern undefined4 DAT_803de024;
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
  int iVar1;
  uint *puVar2;
  
  expgfxRemoveAll();
  iVar1 = 0;
  puVar2 = gExpgfxSlotPoolBases;
  do {
    FUN_80017814(*puVar2);
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < EXPGFX_POOL_COUNT);
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
  ExpgfxRuntimeDataLayout *runtime;
  s16 *poolSlotTypeIds;
  uint allocatedPool;
  u32 *poolActiveMasks;
  s8 *poolActiveCounts;
  int poolIndex;
  uint *slotPoolBases;
  int groupCount;
  
  runtime = EXPGFX_RUNTIME_DATA;
  poolActiveMasks = runtime->poolActiveMasks;
  poolActiveCounts = runtime->poolActiveCounts;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  groupCount = EXPGFX_POOL_GROUP_COUNT;
  do {
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
  } while (groupCount != 0);
  slotPoolBases = gExpgfxSlotPoolBases;
  do {
    allocatedPool = FUN_80017830(EXPGFX_POOL_BYTES,0x14);
    *slotPoolBases = allocatedPool;
    FUN_800033a8(*slotPoolBases,0,EXPGFX_POOL_BYTES);
    FUN_802420e0(*slotPoolBases,EXPGFX_POOL_BYTES);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  FUN_800033a8(-0x7fc63ec8,0,0x500);
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
void modgfx_initExpgfxSpawnConfig(undefined4 param_1,undefined4 param_2,undefined param_3,
                                  undefined4 param_4,undefined4 param_5)
{
  undefined4 uVar1;
  ushort setupValue;
  
  uVar1 = FUN_80286840();
  FUN_800033a8((int)&gExpgfxSpawnConfig,0,EXPGFX_SPAWN_CONFIG_PREFIX_BYTES);
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
  gExpgfxSpawnConfig.quadVertex3Pad06 = (s32)uVar1;
  *(undefined4 *)&gExpgfxSpawnConfig.scale = param_5;
  gExpgfxSpawnConfig.texture.word = param_4;
  gExpgfxSpawnConfig.colorByte0.lowByte = param_3;
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
void modgfx_scrollVertexTexcoords(int param_1,int param_2)
{
  ModgfxState *state;
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  ModgfxVertexData *activeVertexData;
  ModgfxVertexData *inactiveVertexData;
  uint uVar7;
  uint uVar8;
  
  state = (ModgfxState *)param_1;
  fVar2 = lbl_803E00B8 * *(float *)(param_2 + 4) * lbl_803DDF04;
  fVar3 = lbl_803E00B8 * *(float *)(param_2 + 8) * lbl_803DDF04;
  activeVertexData = modgfx_getActiveVertexBuffer(state);
  inactiveVertexData = modgfx_getInactiveVertexBuffer(state);
  uVar7 = 0;
  uVar8 = 0;
  for (iVar4 = 0; iVar4 < state->vertexCount; iVar4 = iVar4 + 1) {
    activeVertexData->texCoordS = inactiveVertexData->texCoordS;
    activeVertexData->texCoordT = inactiveVertexData->texCoordT;
    activeVertexData->texCoordS = activeVertexData->texCoordS + (short)(int)fVar2;
    if (0x100 < activeVertexData->texCoordS) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    if (activeVertexData->texCoordS < -0x100) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    activeVertexData->texCoordT = activeVertexData->texCoordT + (short)(int)fVar3;
    if (0x100 < activeVertexData->texCoordT) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    if (activeVertexData->texCoordT < -0x100) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    activeVertexData = activeVertexData + 1;
    inactiveVertexData = inactiveVertexData + 1;
  }
  activeVertexData = modgfx_getActiveVertexBuffer(state);
  for (iVar4 = 0; iVar4 < state->vertexCount; iVar4 = iVar4 + 1) {
    if (uVar7 == (int)state->vertexCount) {
      sVar1 = activeVertexData->texCoordS;
      if (sVar1 < 0x101) {
        activeVertexData->texCoordS = sVar1 + 0x100;
      }
      else {
        activeVertexData->texCoordS = sVar1 + -0x100;
      }
    }
    if (uVar8 == (int)state->vertexCount) {
      sVar1 = activeVertexData->texCoordT;
      if (sVar1 < 0x101) {
        activeVertexData->texCoordT = sVar1 + 0x100;
      }
      else {
        activeVertexData->texCoordT = sVar1 + -0x100;
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
void modgfx_resetBaseVertexState(int param_1)
{
  ModgfxState *state;
  float fVar1;
  float fVar2;
  int iVar3;
  ModgfxVertexData *baseVertexData;
  ModgfxVertexData *inactiveVertexData;
  
  state = (ModgfxState *)param_1;
  inactiveVertexData = modgfx_getInactiveVertexBuffer(state);
  baseVertexData = state->baseVertexData;
  for (iVar3 = 0; fVar2 = lbl_803E00B4, iVar3 < state->vertexCount; iVar3 = iVar3 + 1) {
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
  state->scaleChannels[0].cur[1] = fVar2;
  state->scaleChannels[0].cur[2] = fVar2;
  fVar1 = lbl_803E00B0;
  state->scaleChannels[0].step[0] = lbl_803E00B0;
  state->scaleChannels[0].step[1] = fVar1;
  state->scaleChannels[0].step[2] = fVar1;
  state->scaleChannels[1].cur[0] = fVar2;
  state->scaleChannels[1].cur[1] = fVar2;
  state->scaleChannels[1].cur[2] = fVar2;
  state->scaleChannels[1].step[0] = fVar1;
  state->scaleChannels[1].step[1] = fVar1;
  state->scaleChannels[1].step[2] = fVar1;
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
void modgfx_updateVertexRgb(int param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  dVar4 = DOUBLE_803e00c0;
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  if (param_3 == 1) {
    fVar1 = ((ModgfxVertexGroupCmd *)param_2)->valueX;
    fVar2 = ((ModgfxVertexGroupCmd *)param_2)->valueY;
    fVar3 = ((ModgfxVertexGroupCmd *)param_2)->valueZ;
    if (((ModgfxState *)param_1)->blendFrameCount == 0) {
      ((ModgfxState *)param_1)->blendColorR = fVar1;
      ((ModgfxState *)param_1)->blendColorG = fVar2;
      ((ModgfxState *)param_1)->blendColorB = fVar3;
      fVar1 = lbl_803E00B0;
      ((ModgfxState *)param_1)->blendColorStepR = lbl_803E00B0;
      ((ModgfxState *)param_1)->blendColorStepG = fVar1;
      ((ModgfxState *)param_1)->blendColorStepB = fVar1;
    }
    else {
      ((ModgfxState *)param_1)->blendColorR =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices * 0x10 +
                                                   0xc)) - DOUBLE_803e00c0);
      ((ModgfxState *)param_1)->blendColorG =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices * 0x10 +
                                                   0xd)) - dVar4);
      ((ModgfxState *)param_1)->blendColorB =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices * 0x10 +
                                                   0xe)) - dVar4);
      dVar5 = DOUBLE_803e00c8;
      ((ModgfxState *)param_1)->blendColorStepR =
           (fVar1 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices *
                                                                     0x10 + 0xc)) - dVar4)) /
           (float)((double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000) -
                  DOUBLE_803e00c8);
      local_18 = (double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000);
      ((ModgfxState *)param_1)->blendColorStepG =
           (fVar2 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices *
                                                                     0x10 + 0xd)) - dVar4)) /
           (float)(local_18 - dVar5);
      local_10 = (double)CONCAT44(0x43300000,
                                  (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices * 0x10 + 0xe)
                                 );
      local_8 = (double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000);
      ((ModgfxState *)param_1)->blendColorStepB = (fVar3 - (float)(local_10 - dVar4)) / (float)(local_8 - dVar5);
    }
  }
  ((ModgfxState *)param_1)->blendColorR = ((ModgfxState *)param_1)->blendColorR + ((ModgfxState *)param_1)->blendColorStepR;
  ((ModgfxState *)param_1)->blendColorG = ((ModgfxState *)param_1)->blendColorG + ((ModgfxState *)param_1)->blendColorStepG;
  ((ModgfxState *)param_1)->blendColorB = ((ModgfxState *)param_1)->blendColorB + ((ModgfxState *)param_1)->blendColorStepB;
  if (lbl_803E00B0 <= ((ModgfxState *)param_1)->blendColorR) {
    if (lbl_803E00BC < ((ModgfxState *)param_1)->blendColorR) {
      ((ModgfxState *)param_1)->blendColorR = lbl_803E00BC;
    }
  }
  else {
    ((ModgfxState *)param_1)->blendColorR = lbl_803E00B0;
  }
  if (lbl_803E00B0 <= ((ModgfxState *)param_1)->blendColorG) {
    if (lbl_803E00BC < ((ModgfxState *)param_1)->blendColorG) {
      ((ModgfxState *)param_1)->blendColorG = lbl_803E00BC;
    }
  }
  else {
    ((ModgfxState *)param_1)->blendColorG = lbl_803E00B0;
  }
  if (lbl_803E00B0 <= ((ModgfxState *)param_1)->blendColorB) {
    if (lbl_803E00BC < ((ModgfxState *)param_1)->blendColorB) {
      ((ModgfxState *)param_1)->blendColorB = lbl_803E00BC;
    }
  }
  else {
    ((ModgfxState *)param_1)->blendColorB = lbl_803E00B0;
  }
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < ((ModgfxVertexGroupCmd *)param_2)->indexCount; iVar8 = iVar8 + 1) {
    *(char *)(iVar6 + *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar7) * 0x10 + 0xc) =
         (char)(int)((ModgfxState *)param_1)->blendColorR;
    *(char *)(iVar6 + *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar7) * 0x10 + 0xd) =
         (char)(int)((ModgfxState *)param_1)->blendColorG;
    *(char *)(iVar6 + *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar7) * 0x10 + 0xe) =
         (char)(int)((ModgfxState *)param_1)->blendColorB;
    iVar7 = iVar7 + 2;
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
void modgfx_updateEffectPosition(int param_1,int command,int mode)
{
  ModgfxState *state;
  double dVar1;
  ushort local_38;
  ushort local_36;
  ushort local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;

  state = (ModgfxState *)param_1;
  dVar1 = DOUBLE_803e00c8;
  if (mode == 1) {
    if (*(s16 *)((u8 *)state + state->activeChannel * 2 + 0xee) == 0) {
      if (((state->flags & 4) != 0) || ((state->flags & 0x80000) != 0)) {
        local_2c = lbl_803E00B0;
        local_28 = lbl_803E00B0;
        local_24 = lbl_803E00B0;
        local_30 = lbl_803E00B4;
        local_38 = *(ushort *)state->unk04;
        local_36 = local_38;
        local_34 = local_38;
        FUN_80017748(&local_38,(float *)(command + 4));
      }
      *(undefined4 *)&state->posStepX = *(undefined4 *)(command + 4);
      *(undefined4 *)&state->posStepY = *(undefined4 *)(command + 8);
      *(undefined4 *)&state->posStepZ = *(undefined4 *)(command + 0xc);
    }
    else {
      state->posStepX =
           *(float *)(command + 4) /
           (float)((double)CONCAT44(0x43300000,(int)state->blendFrameCount ^ 0x80000000) -
                  DOUBLE_803e00c8);
      state->posStepY =
           *(float *)(command + 8) /
           (float)((double)CONCAT44(0x43300000,(int)state->blendFrameCount ^ 0x80000000) - dVar1
                  );
      state->posStepZ =
           *(float *)(command + 0xc) /
           (float)((double)CONCAT44(0x43300000,(int)state->blendFrameCount ^ 0x80000000) - dVar1
                  );
    }
    state->posCurX = state->posCurX + state->posStepX;
    state->posCurY = state->posCurY + state->posStepY;
    state->posCurZ = state->posCurZ + state->posStepZ;
  }
  else {
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
void modgfx_updateEffectRotation(int param_1,int command,int mode)
{
  ModgfxState *state;
  short sVar1;
  short sVar2;
  short sVar3;

  state = (ModgfxState *)param_1;
  if (mode == 1) {
    sVar1 = (short)(int)*(float *)(command + 4);
    sVar2 = (short)(int)*(float *)(command + 8);
    sVar3 = (short)(int)*(float *)(command + 0xc);
    if (state->blendFrameCount == 0) {
      state->rotOffsetZ = sVar1;
      state->rotStepZ = 0;
      state->rotOffsetY = sVar2;
      state->rotStepY = 0;
      state->rotOffsetX = sVar3;
      state->rotStepX = 0;
    }
    else {
      state->rotStepZ =
           (short)(((int)sVar1 - (int)state->rotOffsetZ) / (int)state->blendFrameCount
                  );
      state->rotStepY =
           (short)(((int)sVar2 - (int)state->rotOffsetY) / (int)state->blendFrameCount
                  );
      state->rotStepX =
           (short)(((int)sVar3 - (int)state->rotOffsetX) / (int)state->blendFrameCount
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
void modgfx_updateVertexAlpha(int param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_8;
  
  dVar2 = DOUBLE_803e00c0;
  iVar5 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar6 = (int)((ModgfxState *)param_1)->baseVertexData;
  if (param_3 == 1) {
    fVar1 = ((ModgfxVertexGroupCmd *)param_2)->valueX;
    if ((int)((ModgfxState *)param_1)->blendFrameCount == 0) {
      iVar7 = 0;
      for (iVar3 = 0; iVar3 < ((ModgfxVertexGroupCmd *)param_2)->indexCount; iVar3 = iVar3 + 1) {
        *(char *)(iVar6 + *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar7) * 0x10 + 0xf) =
             (char)(int)fVar1;
        iVar8 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar7) * 0x10 + 0xf;
        *(undefined *)(iVar5 + iVar8) = *(undefined *)(iVar6 + iVar8);
        iVar7 = iVar7 + 2;
      }
      return;
    }
    iVar7 = param_1 + (param_4 & 0xff) * 8;
    *(float *)(iVar7 + 0xac) =
         (fVar1 - (float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices *
                                                                   0x10 + 0xf)) - DOUBLE_803e00c0))
         / (float)((double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000) -
                  DOUBLE_803e00c8);
    local_8 = (double)CONCAT44(0x43300000,
                               (uint)*(byte *)(iVar6 + *((ModgfxVertexGroupCmd *)param_2)->indices * 0x10 + 0xf));
    *(float *)(iVar7 + 0xb0) = (float)(local_8 - dVar2);
  }
  iVar7 = (param_4 & 0xff) * 8;
  iVar3 = param_1 + iVar7;
  *(float *)(iVar3 + 0xb0) = *(float *)(iVar3 + 0xac) * lbl_803DDF04 + *(float *)(iVar3 + 0xb0);
  if (lbl_803E00B0 <= *(float *)(iVar3 + 0xb0)) {
    if (lbl_803E00BC < *(float *)(iVar3 + 0xb0)) {
      *(float *)(iVar3 + 0xb0) = lbl_803E00BC;
    }
  }
  else {
    *(float *)(iVar3 + 0xb0) = lbl_803E00B0;
  }
  iVar3 = 0;
  for (iVar8 = 0; iVar8 < ((ModgfxVertexGroupCmd *)param_2)->indexCount; iVar8 = iVar8 + 1) {
    *(char *)(iVar5 + *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar3) * 0x10 + 0xf) =
         (char)(int)*(float *)(param_1 + iVar7 + 0xb0);
    iVar4 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar3) * 0x10 + 0xf;
    *(undefined *)(iVar6 + iVar4) = *(undefined *)(iVar5 + iVar4);
    iVar3 = iVar3 + 2;
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
void modgfx_updateVertexScale(int param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 local_30;
  undefined8 local_18;
  undefined8 local_10;
  
  dVar4 = DOUBLE_803e00c8;
  if (param_3 == 1) {
    fVar1 = ((ModgfxVertexGroupCmd *)param_2)->valueX;
    fVar2 = ((ModgfxVertexGroupCmd *)param_2)->valueY;
    fVar3 = ((ModgfxVertexGroupCmd *)param_2)->valueZ;
    if ((int)((ModgfxState *)param_1)->blendFrameCount == 0) {
      iVar8 = (int)((ModgfxState *)param_1)->baseVertexData;
      iVar7 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < ((ModgfxVertexGroupCmd *)param_2)->indexCount; iVar5 = iVar5 + 1) {
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar1);
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10 + 2;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar2);
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10 + 4;
        local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + iVar10) ^ 0x80000000);
        *(short *)(iVar8 + iVar10) = (short)(int)((float)(local_18 - dVar4) * fVar3);
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10 + 2;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar6) * 0x10 + 4;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar6 = iVar6 + 2;
      }
      return;
    }
    iVar6 = param_1 + (param_4 & 0xff) * 0x18;
    *(float *)(iVar6 + 0x3c) =
         (fVar1 - *(float *)(iVar6 + 0x30)) /
         (float)((double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000) -
                DOUBLE_803e00c8);
    local_30 = (double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000);
    *(float *)(iVar6 + 0x40) = (fVar2 - *(float *)(iVar6 + 0x34)) / (float)(local_30 - dVar4);
    *(float *)(iVar6 + 0x44) =
         (fVar3 - *(float *)(iVar6 + 0x38)) /
         (float)((double)CONCAT44(0x43300000,(int)((ModgfxState *)param_1)->blendFrameCount ^ 0x80000000) - dVar4);
  }
  iVar5 = param_1 + (param_4 & 0xff) * 0x18;
  *(float *)(iVar5 + 0x30) = *(float *)(iVar5 + 0x3c) * lbl_803DDF04 + *(float *)(iVar5 + 0x30);
  *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x40) * lbl_803DDF04 + *(float *)(iVar5 + 0x34);
  *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x44) * lbl_803DDF04 + *(float *)(iVar5 + 0x38);
  fVar1 = lbl_803E00B4;
  iVar7 = (int)((ModgfxState *)param_1)->baseVertexData;
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar10 = 0;
  for (iVar8 = 0; iVar8 < ((ModgfxVertexGroupCmd *)param_2)->indexCount; iVar8 = iVar8 + 1) {
    if (fVar1 != *(float *)(iVar5 + 0x30)) {
      iVar9 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar10) * 0x10;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x30) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x34)) {
      iVar9 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar10) * 0x10 + 2;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x34) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x38)) {
      iVar9 = *(short *)((int)((ModgfxVertexGroupCmd *)param_2)->indices + iVar10) * 0x10 + 4;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x38) * (float)(local_10 - DOUBLE_803e00c8));
    }
    iVar10 = iVar10 + 2;
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
void modgfx_restoreActiveVertexState(int param_1)
{
  ModgfxState *state;
  int iVar1;
  ModgfxVertexData *activeVertexData;
  ModgfxVertexData *baseVertexData;
  
  state = (ModgfxState *)param_1;
  activeVertexData = modgfx_getActiveVertexBuffer(state);
  baseVertexData = state->baseVertexData;
  for (iVar1 = 0; iVar1 < state->vertexCount; iVar1 = iVar1 + 1) {
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
void modgfx_releaseActiveEffectsByType(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                       undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                       undefined8 param_7,undefined8 param_8,short param_9,
                                       int param_10)
{
  ModgfxActiveEffect *activeEffect;
  ModgfxActiveEffect **activeEffects;
  int iVar3;
  
  activeEffects = modgfx_getActiveEffectRegistry();
  iVar3 = 0;
  do {
    activeEffect = activeEffects[iVar3];
    if ((activeEffect != (ModgfxActiveEffect *)0x0) &&
       ((param_9 == activeEffect->effectType || (param_10 != 0)))) {
      if (activeEffect->releaseTransformSource != 0) {
        param_1 = FUN_80017814(activeEffect->releaseTransformSource);
      }
      if (activeEffect->instanceHandle != 0) {
        FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                    activeEffect->instanceHandle);
      }
      activeEffect->state = 0;
      if ((activeEffect->keepSharedResource == 0) && (activeEffect->sharedResourceHandle != 0)) {
        FUN_80053754();
      }
      if (activeEffect->keepSharedResource == 0) {
        activeEffect->sharedResourceHandle = 0;
      }
      param_1 = FUN_80017814(activeEffect);
      activeEffects[iVar3] = (ModgfxActiveEffect *)0x0;
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < MODGFX_ACTIVE_EFFECT_COUNT);
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
void modgfx_releaseActiveEffectsByOwner(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                        undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                        undefined8 param_7,undefined8 param_8,int param_9)
{
  ModgfxActiveEffect *activeEffect;
  ModgfxActiveEffect **activeEffects;
  int iVar2;
  
  activeEffects = modgfx_getActiveEffectRegistry();
  iVar2 = 0;
  do {
    activeEffect = activeEffects[iVar2];
    if ((activeEffect != (ModgfxActiveEffect *)0x0) && (activeEffect->ownerToken == param_9)) {
      if (activeEffect->instanceHandle != 0) {
        FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                    activeEffect->instanceHandle);
      }
      activeEffect->state = 0;
      if ((activeEffect->keepSharedResource == 0) && (activeEffect->sharedResourceHandle != 0)) {
        FUN_80053754();
      }
      if (activeEffect->keepSharedResource == 0) {
        activeEffect->sharedResourceHandle = 0;
      }
      param_1 = FUN_80017814(activeEffect);
      activeEffects[iVar2] = (ModgfxActiveEffect *)0x0;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < MODGFX_ACTIVE_EFFECT_COUNT);
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
void modgfx_releaseAllActiveEffects(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                    undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                    undefined8 param_7,undefined8 param_8)
{
  modgfx_releaseActiveEffectsByType(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    0,1);
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
void modgfx_resetActiveEffectRegistry(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                      undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                      undefined8 param_7,undefined8 param_8)
{
  ModgfxActiveEffect **activeEffects;
  int iVar1;
  
  modgfx_releaseActiveEffectsByType(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    0,1);
  activeEffects = modgfx_getActiveEffectRegistry();
  for (iVar1 = 0; iVar1 < MODGFX_ACTIVE_EFFECT_COUNT; iVar1 = iVar1 + 1) {
    activeEffects[iVar1] = (ModgfxActiveEffect *)0x0;
  }
  iVar1 = 2;
  {
    ModgfxActiveEffect **tailEffects;

    tailEffects = &activeEffects[MODGFX_ACTIVE_EFFECT_COUNT - 2];
    do {
      *tailEffects = (ModgfxActiveEffect *)0x0;
      tailEffects = tailEffects + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
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
FUN_800a2a98(int param_1,int param_2,ExpgfxAttachedSourceState *param_3,uint param_4,
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
projgfx_spawnPresetEffect(int param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                          uint param_4,undefined param_5,undefined2 *param_6)
{
  undefined4 uVar1;
  uint uVar2;
  int local_b8 [3];
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined2 local_78;
  undefined2 local_76;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  uint local_68;
  uint local_64;
  undefined2 local_60;
  undefined2 local_5e;
  undefined2 local_5c;
  undefined local_5a;
  undefined local_58;
  undefined local_57;
  undefined local_56;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  lbl_803DC450 = lbl_803DC450 + lbl_803E0900;
  if (lbl_803E0908 < lbl_803DC450) {
    lbl_803DC450 = lbl_803E0904;
  }
  lbl_803DC454 = lbl_803DC454 + lbl_803E090C;
  if (lbl_803E0908 < lbl_803DC454) {
    lbl_803DC454 = lbl_803E0910;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0) {
      if (param_3 == (ExpgfxAttachedSourceState *)0x0) {
        return 0xffffffff;
      }
      local_a0 = param_3->sourcePosY.value;
      local_9c = param_3->sourcePosZ.value;
      local_98 = param_3->sourcePosW.value;
      local_a4 = param_3->sourcePosX.bits;
      local_a8 = param_3->sourceVecZ;
      local_aa = param_3->sourceVecY;
      local_ac = param_3->sourceVecX;
      local_56 = param_5;
    }
    local_74 = 0;
    local_70 = 0;
    local_5a = (undefined)param_2;
    local_88 = lbl_803E0914;
    local_84 = lbl_803E0914;
    local_80 = lbl_803E0914;
    local_94 = lbl_803E0914;
    local_90 = lbl_803E0914;
    local_8c = lbl_803E0914;
    local_7c = lbl_803E0914;
    local_b8[2] = 0;
    local_b8[1] = 0xffffffff;
    local_58 = 0xff;
    local_57 = 0;
    local_76 = 0;
    local_60 = 0xffff;
    local_5e = 0xffff;
    local_5c = 0xffff;
    local_6c = 0xffff;
    local_68 = 0xffff;
    local_64 = 0xffff;
    local_78 = 0;
    local_b8[0] = param_1;
    switch(param_2) {
    case 0x422:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = lbl_803E0918;
      local_b8[2] = randomGetRange(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 100;
      local_57 = 0x1e;
      break;
    case 0x423:
      uStack_4c = randomGetRange(0xfffffff6,10);
      local_88 = lbl_803E0910 * (f32)(s32)uStack_4c;
      uStack_44 = randomGetRange(0xfffffff6,10);
      local_84 = lbl_803E0910 * (f32)(s32)uStack_44;
      uStack_3c = randomGetRange(0xfffffff6,10);
      local_80 = lbl_803E0910 * (f32)(s32)uStack_3c;
      uStack_34 = randomGetRange(5,0xb);
      local_7c = lbl_803E0900 * (f32)(s32)uStack_34;
      local_b8[2] = 0x3c;
      local_74 = 0x80110;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x424:
      uStack_34 = randomGetRange(0xfffffff6,10);
      local_88 = lbl_803E0910 * (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0xfffffff6,10);
      local_84 = lbl_803E0910 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(0xfffffff6,10);
      local_80 = lbl_803E0910 * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0xfffffffb,5);
      local_94 = lbl_803E0904 * (f32)(s32)uStack_4c;
      uStack_2c = randomGetRange(3,10);
      local_90 = lbl_803E0904 * (f32)(s32)uStack_2c;
      uStack_24 = randomGetRange(0xfffffffb,5);
      local_8c = lbl_803E0904 * (f32)(s32)uStack_24;
      uStack_1c = randomGetRange(5,0xb);
      local_7c = lbl_803E091C * (f32)(s32)uStack_1c;
      local_b8[2] = 0x3c;
      local_74 = 0x1480200;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x425:
      uStack_1c = randomGetRange(8,10);
      local_90 = lbl_803E0920 * (f32)(s32)uStack_1c;
      uVar2 = randomGetRange(0,0x28);
      if (uVar2 == 0) {
        uStack_1c = randomGetRange(0x15,0x29);
        local_7c = lbl_803E0900 *
                   (f32)(s32)uStack_1c;
        local_b8[2] = 0x1cc;
      }
      else {
        uStack_1c = randomGetRange(8,0x14);
        local_7c = lbl_803E0900 *
                   (f32)(s32)uStack_1c;
        local_b8[2] = randomGetRange(0x5a,0x78);
      }
      local_74 = 0x80180200;
      local_70 = 0x1000020;
      local_76 = 0xc0b;
      local_58 = 0x7f;
      local_5c = 0x3fff;
      local_5e = 0x3fff;
      local_60 = 0x3fff;
      local_64 = 0xffff;
      local_68 = 0xffff;
      local_6c = 0xffff;
      break;
    case 0x426:
      uStack_1c = randomGetRange(0xffffffec,0x14);
      local_94 = lbl_803E0920 * (f32)(s32)uStack_1c;
      uStack_24 = randomGetRange(8,0x14);
      local_90 = lbl_803E0920 * (f32)(s32)uStack_24;
      uStack_2c = randomGetRange(0xffffffec,0x14);
      local_8c = lbl_803E0920 * (f32)(s32)uStack_2c;
      local_7c = lbl_803E0924;
      local_b8[2] = 0x32;
      local_74 = 0x3000200;
      local_70 = 0x200020;
      local_76 = 0x33;
      local_58 = 0xff;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0xffff;
      local_68 = randomGetRange(0,0x8000);
      local_64 = local_68;
      break;
    case 0x427:
      uStack_1c = randomGetRange(0xffffff9c,100);
      local_88 = (f32)(s32)uStack_1c / lbl_803E0928;
      uStack_24 = randomGetRange(0xffffffce,0x32);
      local_84 = (f32)(s32)uStack_24 / lbl_803E092C;
      uStack_2c = randomGetRange(0xffffff9c,100);
      local_80 = (f32)(s32)uStack_2c / lbl_803E0928;
      uStack_34 = randomGetRange(1,4);
      local_90 = lbl_803E0930 * (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0,10);
      local_7c = lbl_803E0938 * (f32)(s32)uStack_3c
                 + lbl_803E0934;
      local_b8[2] = 0xa0;
      local_57 = 0;
      local_74 = 0x100200;
      local_76 = 0x33;
      break;
    default:
      return 0xffffffff;
    case 0x42b:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = lbl_803E093C;
      local_b8[2] = randomGetRange(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 0xc7e;
      local_57 = 0x1e;
      break;
    case 0x42c:
      uStack_1c = randomGetRange(0xfffffff6,10);
      local_94 = lbl_803E0940 * (f32)(s32)uStack_1c;
      uStack_24 = randomGetRange(10,0x14);
      local_90 = lbl_803E0918 * (f32)(s32)uStack_24;
      uStack_2c = randomGetRange(0xfffffff6,10);
      local_8c = lbl_803E0940 * (f32)(s32)uStack_2c;
      local_7c = lbl_803E0944;
      local_b8[2] = 0x6e;
      local_74 = 0x8a100208;
      local_70 = 0x20;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0x400;
      local_68 = 60000;
      local_64 = 0x1000;
      break;
    case 0x42d:
      uStack_1c = randomGetRange(0xffffffec,0x14);
      local_94 = lbl_803E0944 * (f32)(s32)uStack_1c;
      uStack_24 = randomGetRange(0xffffffec,0x14);
      local_8c = lbl_803E0944 * (f32)(s32)uStack_24;
      local_7c = lbl_803E0904;
      local_b8[2] = 600;
      local_58 = 0x7f;
      local_74 = 0xa100100;
      local_70 = 0x20;
      local_76 = 0x62;
      local_60 = 0x400;
      local_5e = 60000;
      local_5c = 0x1000;
      local_6c = 0;
      local_68 = 50000;
      local_64 = 0;
    }
    local_74 = local_74 | param_4;
    if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
      local_74 = local_74 ^ 2;
    }
    if ((local_74 & 1) != 0) {
      if ((param_4 & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) == 0) {
        if (local_b8[0] != 0) {
          local_88 = local_88 + *(float *)(local_b8[0] + 0x18);
          local_84 = local_84 + *(float *)(local_b8[0] + 0x1c);
          local_80 = local_80 + *(float *)(local_b8[0] + 0x20);
        }
      }
      else {
        local_88 = local_88 + local_a0;
        local_84 = local_84 + local_9c;
        local_80 = local_80 + local_98;
      }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(local_b8, -1, param_2, 0);
  }
  return uVar1;
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
FUN_800a3828(int param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,uint param_4,
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
FUN_800a3924(int param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,uint param_4,
             undefined param_5)
{
    return 0;
}



/* Trivial 4b 0-arg blr leaves. */
void projgfx_func07_nop(void) {}
void projgfx_func06_nop(void) {}
void projgfx_func05_nop(void) {}
void projgfx_onMapSetup(void) {}
void projgfx_initialise(void) {}
void playerShadow_func03_nop(void) {}
void playerShadow_release_nop(void) {}
void playerShadow_initialise_nop(void) {}
void boneParticleEffect_func08_nop(void) {}
void boneParticleEffect_func06_nop(void) {}
void boneParticleEffect_func04_nop(void) {}
void boneParticleEffect_func03_nop(void) {}
void partfx_onMapSetup(void) {}
void Effect1_func03_nop(void) {}
void Effect1_release(void) {}
void Effect1_initialise(void) {}
void Effect2_func03_nop(void) {}
void Effect2_release(void) {}
void Effect2_initialise(void) {}
void Effect3_func05_nop(void) {}
void Effect3_func03_nop(void) {}
void Effect3_release(void) {}
void Effect3_initialise(void) {}
void Effect4_func03_nop(void) {}
void Effect4_release(void) {}
void Effect4_initialise(void) {}
void Effect5_func03_nop(void) {}
void Effect5_release(void) {}
void Effect5_initialise(void) {}
void Effect6_func03_nop(void) {}
void Effect6_release(void) {}
void Effect6_initialise(void) {}
void Effect7_func03_nop(void) {}
void Effect7_release(void) {}
void Effect7_initialise(void) {}
void Effect8_func03_nop(void) {}
void Effect8_release(void) {}
void Effect8_initialise(void) {}
void Effect9_func03_nop(void) {}
void Effect9_release(void) {}
void Effect9_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int projgfx_getObjectTypeId(void) { return 0x0; }

/* sda21 accessors. */
extern u8 lbl_8039BE98[];
extern ModgfxPendingSpawn lbl_8039BEF8[];
extern s16 lbl_803DD288;
extern s16 lbl_803DD28A;
extern ModgfxPendingSpawn *lbl_803DD28C;
extern ModgfxPendingSpawn *lbl_803DD290;
#define gModgfxSpawnContext (*(ModgfxSpawnContext *)lbl_8039BE98)
#define gModgfxPendingSpawnQueue lbl_8039BEF8
#define gModgfxLastSpawnHandle lbl_803DD288
#define gModgfxSequenceParamIndex lbl_803DD28A
#define gModgfxPendingSpawnWriteCursor lbl_803DD28C
#define gModgfxPendingSpawnStartCursor lbl_803DD290
#pragma scheduling off
#pragma peephole off
s16 dll_0B_func18(void) { return gModgfxLastSpawnHandle; }
void dll_0B_func17(u32 flags) { gModgfxSpawnContext.flags |= flags; }
void dll_0B_func15(void *params) { memcpy(gModgfxSpawnContext.sequenceParams, params, 0xe); }
void dll_0B_func14(s16 value)
{
  u8 *state = lbl_8039BE98;
  state = state + lbl_803DD28A * 2;
  *(s16 *)(state + 0x46) = value;
}
void dll_0B_func13(s16 x) { gModgfxSequenceParamIndex = x; }
void dll_0B_func12(void) { gModgfxSequenceParamIndex++; }
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
  ModgfxPendingSpawn *cursor = gModgfxPendingSpawnQueue;
  gModgfxPendingSpawnStartCursor = cursor;
  gModgfxPendingSpawnWriteCursor = cursor;
  gModgfxSequenceParamIndex = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* OSReport(literal) wrapper. */
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
void projgfx_release_doUnsupported(void) { OSReport(sProjgfxReleaseDoNoLongerSupported); }
#pragma scheduling reset

/* OSReport-stub returns. */

#define PROJGFX_UNSUPPORTED_FALSE_RETURN 0

#pragma scheduling off
int projgfx_rayhit_doUnsupported(void) { OSReport(sProjgfxRayhitDoNoLongerSupported); return PROJGFX_UNSUPPORTED_FALSE_RETURN; }
int projgfx_setzscale_doUnsupported(void) { OSReport(sProjgfxSetzscaleDoNoLongerSupported); return PROJGFX_UNSUPPORTED_FALSE_RETURN; }
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
static u8 sProjgfxStringPad0[] = { 0, 0, 0 };
char sProjgfxSetzscaleDoNoLongerSupported[] = "<projgfx setzscale  Do>No Longer supported \n";
static u8 sProjgfxStringPad1[] = { 0, 0, 0 };
char sProjgfxReleaseDoNoLongerSupported[] = "<projgfx release Do>No Longer supported \n";
static u8 sProjgfxStringPad2[] = { 0, 0, 0, 0, 0, 0 };

/* Small stub recoveries (drifted unit, add-as-new). */
extern u8 lbl_803DD282;
extern u8 gPlayerShadowMode;
#define gPartfxCachedResourceCount lbl_803DD2C0
extern u8 gPartfxCachedResourceCount;
extern void fn_800A1040(s16 a, int b);
#define gPartfxResourceTimeouts lbl_8039C2E0
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
extern void hitDetect_calcSweptSphereBounds(void *out, void *top, void *bottom, void *params, int count);
extern void hitDetectFn_800691c0(void *obj, void *hitData, int flags, int arg3);
extern void fn_80069968(int *outA, int *outB);
extern void fn_80069958(int **out);
void fn_800A3AF0(void *table, int count, void *ctx, f32 a, f32 b);

void dll_0B_func0B(void) {
    lbl_803DD282 = lbl_803DD282 + 1;
}

#pragma scheduling off
void dll_0B_func06(void) {
    fn_800A1040(0, 1);
}

void dll_0B_release(void) {
    fn_800A1040(0, 1);
}
#pragma scheduling reset

#pragma peephole off
void playerShadow_setMode(u8 v) {
    if (v == 0 || v >= 0xa) {
        gPlayerShadowMode = v;
    }
}
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void playerShadow_renderObject(void *obj)
{
    u32 *defaults;
    u32 params[4];
    int *tileInfo;
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

    if (gPlayerShadowMode == 0) {
        return;
    }

    mode = gPlayerShadowMode - 0xb;
    if (mode <= 6) {
        switch (mode) {
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
    } else {
        radius = lbl_803DF46C;
        height = radius;
    }

    minX = ((GameObject *)obj)->anim.localPosX - radius;
    maxX = ((GameObject *)obj)->anim.localPosX + radius;
    topY = ((GameObject *)obj)->anim.localPosY + height;
    bottomY = ((GameObject *)obj)->anim.localPosY - height;
    minZ = ((GameObject *)obj)->anim.localPosZ - radius;
    maxZ = ((GameObject *)obj)->anim.localPosZ + radius;

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
    fn_800A3AF0((void *)hitTableValue, hitCount, obj,
        ((GameObject *)obj)->anim.localPosX - (f32)tileInfo[0],
        ((GameObject *)obj)->anim.localPosZ - (f32)tileInfo[2]);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DF430;
extern f32 lbl_803DF434;
#define BONE_PARTICLE_EFFECT_BUFFER_COUNT 7
#define BONE_PARTICLE_EFFECT_BUFFER_BYTES 0x140
#define BONE_PARTICLE_EFFECT_SLOT_COUNT 20
#define gBoneParticleEffectBuffers lbl_8039C2C0

extern void *gBoneParticleEffectBuffers[];
extern void *lbl_803DD2A4;
extern void *lbl_803DD2A8;
extern void mm_free(void *p);
extern void textureFree(void *resource);
#define gPartfxActiveEffects lbl_8039C1F8

extern void *gPartfxActiveEffects[];
extern void Obj_FreeObject(void *obj);
#pragma peephole off
#pragma scheduling off
void dll_0B_initialise(void)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        arr[i] = NULL;
    }
}

void dll_0B_func0F(int p1, int p2, int p3, int p4, int p5)
{
    ModgfxSpawnContext *context = &gModgfxSpawnContext;
    f32 fz;
    f32 fz2;
    memset(context, 0, sizeof(*context));
    context->modeByte = p2;
    context->attachedSource = (void *)p1;
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

void dll_0B_func0A(s16 *p)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && *p == arr[i]->sequenceId) {
            arr[i]->releaseRequested = 1;
        }
    }
    *p = -1;
}

void dll_0B_func0C(void *p1, char p2)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && arr[i]->sourceObject == p1) {
            arr[i]->byte13B = p2;
        }
    }
}

void dll_0B_func0D(void *p1)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && arr[i]->sourceObject == p1) {
            arr[i]->releaseRequested = 1;
        }
    }
}

void dll_0B_func07(void *p1)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] == NULL) continue;
        if (arr[i]->sourceObject != p1) continue;
        if (arr[i]->instanceObject != NULL) {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL) {
            textureFree(arr[i]->textureResource);
        }
        if (arr[i]->textureIsBorrowed == 0) {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}

#pragma dont_inline on
void fn_800A1040(s16 p1, int p2)
{
    PartfxEffectState **arr = (PartfxEffectState **)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] == NULL) continue;
        if ((s16)p1 != arr[i]->sequenceId && p2 == 0) continue;
        if (arr[i]->auxAllocation != NULL) {
            mm_free(arr[i]->auxAllocation);
        }
        if (arr[i]->instanceObject != NULL) {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL) {
            textureFree(arr[i]->textureResource);
        }
        if (arr[i]->textureIsBorrowed == 0) {
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
    void **p;
    void *zero;
    i = 0;
    p = gBoneParticleEffectBuffers;
    zero = NULL;
    do {
        if (*p != NULL) mm_free(*p);
        *p = zero;
        p++;
        i++;
    } while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    if (lbl_803DD2A4 != NULL) textureFree(lbl_803DD2A4);
    if (lbl_803DD2A8 != NULL) textureFree(lbl_803DD2A8);
}

extern void Sfx_PlayFromObject(void *obj, int id);
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
typedef struct BoneFxVtx {
    u16 e0;
    u16 de;
    u16 dc;
    u16 pad;
    f32 w;
    f32 vx;
    f32 vy;
    f32 vz;
} BoneFxVtx;
extern void Matrix_TransformPoint(void *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void Camera_LoadModelViewMatrix(void *a, int b, void *c, f32 e, f32 f, int d);
extern void GXSetCullMode(int mode);
extern void setTextColor(void *ctx, int r, int g, int b, int a);
extern void _textSetColor(void *ctx, int r, int g, int b, int a);
extern void textureFn_800541ac(void *ctx, void *tex, int a, int b, int c, int d, int e);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void gxTexColorFn_80079254(void);
extern void textRenderSetupFn_80079804(void);
extern void gxBlendFn_80078b4c(void);
extern void drawFn_8005cf8c(void *a, void *b, int count);

/* EN v1.0 0x800A433C  size: 1764b  per-bone particle vertex update + draw. */
void boneParticleEffect_update(void *ctx, int p2, u8 *o)
{
    BoneFxVtx s;
    u8 *base;
    int *m;
    int slot;
    void **grp;
    void **grp2;
    int row;
    s16 j;
    s16 k;
    u32 id;
    u32 cls;
    u8 *mtx;
    u8 *idp;
    f32 *pa;
    f32 *pb;
    f32 *pc;
    u8 *jb;
    s32 idx;
    f32 dx;
    f32 dy;
    f32 dz;

    base = (u8 *)(int)lbl_8030FE38;
    if (GameBit_Get(0x468) != 0) {
        GameBit_Set(0x468, 0);
        lbl_803DD2BC = 0xf;
        Sfx_PlayFromObject(o, 0x281);
    }
    m = Modgfx_GetActiveModel((void *)o);
    if (lbl_803DD2B4 > 6) {
        lbl_803DD2B4 = 0;
    }
    if (lbl_803DD2B0 > *(u8 *)(*m + 0xf3) - 1) {
        lbl_803DD2B0 = 0;
    }
    lbl_803DD2B8 = lbl_803DD2B8 + framesThisStep;
    if (lbl_803DD2B8 > 0x1f) {
        lbl_803DD2B8 = lbl_803DD2B8 - 0x1f;
    }
    lbl_803DD2AC = lbl_803DB798 * timeDelta + lbl_803DD2AC;
    if (lbl_803DD2AC > lbl_803DF4AC) {
        lbl_803DB798 = lbl_803DB798 * lbl_803DF4B0;
        lbl_803DD2AC = lbl_803DF4AC;
        Sfx_PlayFromObject(o, 0x282);
    } else if (lbl_803DD2AC < lbl_803DF4B4) {
        lbl_803DB798 = lbl_803DB798 * lbl_803DF4B0;
        lbl_803DD2AC = lbl_803DF4B4;
        Sfx_PlayFromObject(o, 0x282);
    }
    slot = 0;
    grp2 = gBoneParticleEffectBuffers;
    grp = gBoneParticleEffectBuffers;
    do {
        if (slot != 5) {
            lbl_803DD2B4 = slot;
            row = 0;
            j = 0;
            idp = base + 0x5b4;
            while (j < 5) {
                s.vx = 0.0f;
                s.vy = 0.0f;
                s.vz = 0.0f;
                s.w = 1.0f;
                s.dc = 0;
                s.de = 0;
                s.e0 = 0;
                id = *(u8 *)(base + lbl_803DD2B4 * 5 + j + 0x5b4);
                jb = (u8 *)((int *)m)[(*(u16 *)((u8 *)m + 0x18) & 1) + 3];
                mtx = (u8 *)((BoneFxJRow *)jb + (id << 4));
                dx = *(f32 *)(mtx + 0x30) + playerMapOffsetX;
                dy = *(f32 *)(mtx + 0x34);
                dz = *(f32 *)(mtx + 0x38) + playerMapOffsetZ;
                dx = dx - *(f32 *)(o + 0xc);
                dy = dy - *(f32 *)(o + 0x10);
                dz = dz - *(f32 *)(o + 0x14);
                dx = dx * 20.02f;
                if (id == 0x1d || id == 0x1d) {
                    dy = 20.02f * (lbl_803DF4C0 + dy);
                } else {
                    dy = dy * 20.02f;
                }
                dz = dz * 20.02f;
                Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                k = 0;
                pa = (f32 *)(base + 0x90);
                pb = (f32 *)(int)lbl_8030FE38;
                pc = (f32 *)(base + 0x120);
                while (k < 4) {
                    u8 *t;
                    u8 *t4;
                    id = *(u8 *)(idp + lbl_803DD2B4 * 5);
                    t = base + id;
                    cls = *(u8 *)(t + 0x590);
                    if (cls == 0) {
                        t4 = base + id * 4;
                        s.vx = pa[0] * *(f32 *)(t4 + 0x5d8);
                        s.vy = pa[1] * *(f32 *)(t4 + 0x5d8);
                        s.vz = pa[2] * *(f32 *)(t4 + 0x664);
                    } else if (cls == 1) {
                        t4 = base + id * 4;
                        s.vx = pb[0] * *(f32 *)(t4 + 0x5d8);
                        s.vy = pb[1] * *(f32 *)(t4 + 0x5d8);
                        s.vz = pb[2] * *(f32 *)(t4 + 0x664);
                    } else if (cls == 2) {
                        t4 = base + id * 4;
                        s.vx = pc[0] * *(f32 *)(t4 + 0x5d8);
                        s.vy = pc[1] * *(f32 *)(t4 + 0x5d8);
                        s.vz = pc[2] * *(f32 *)(t4 + 0x664);
                    }
                    Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                    s.vx = s.vx + playerMapOffsetX;
                    s.vz = s.vz + playerMapOffsetZ;
                    idx = (k + row) * 0x10;
                    *(s16 *)((u8 *)*grp + idx) = (s32)(dx + (s.vx - *(f32 *)(o + 0xc)));
                    *(s16 *)((u8 *)*grp + idx + 2) = (s32)(dy + (s.vy - *(f32 *)(o + 0x10)));
                    *(s16 *)((u8 *)*grp + idx + 4) = (s32)(dz + (s.vz - *(f32 *)(o + 0x14)));
                    *(u8 *)((u8 *)*grp + idx + 0xf) = 0x9b;
                    t = base + idx;
                    *(s16 *)((u8 *)*grp + idx + 0xa) = (s16)(*(s16 *)(t + 0x1ba) - (lbl_803DD2B8 << 2));
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
    } while (slot < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    s.vx = *(f32 *)(o + 0xc);
    s.vy = *(f32 *)(o + 0x10);
    s.vz = *(f32 *)(o + 0x14);
    s.w = lbl_803DF4C4;
    setTextColor(ctx, 0xff, 0xff, 0xff, 0xff);
    if (lbl_803DD2BC != 0) {
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        if ((int)randomGetRange(0, 1) != 0) {
            textureFn_800541ac(ctx, lbl_803DD2A4, 0, 0, 0, 0, 0);
        } else {
            textureFn_800541ac(ctx, lbl_803DD2A8, 0, 0, 0, 0, 0);
        }
        lbl_803DD2BC -= framesThisStep;
        if (lbl_803DD2BC < 0) {
            lbl_803DD2BC = 0;
        }
    } else {
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
        do {
            drawFn_8005cf8c(*grp2, base + 0x2f0, 0x20);
            grp2 += 1;
            i += 1;
        } while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    }
    lbl_803DD2A0 = 1 - lbl_803DD2A0;
}

typedef struct {
    s16 a, b, c;
    u16 pad;
    s16 d, e;
    u8 f, g, h, alpha;
} ParticleSlot;
extern ParticleSlot lbl_8030FFE8[];
extern void *textureLoadAsset(int id);
extern void *mmAlloc(int size, int align, int flag);

void boneParticleEffect_initialise(void) {
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
    for (i = 0; i < BONE_PARTICLE_EFFECT_BUFFER_COUNT; i++) {
        for (j = 0; j < BONE_PARTICLE_EFFECT_SLOT_COUNT; j++) {
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].a = lbl_8030FFE8[j].a;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].b = lbl_8030FFE8[j].b;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].c = lbl_8030FFE8[j].c;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].d = lbl_8030FFE8[j].d;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].e = lbl_8030FFE8[j].e;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].f = lbl_8030FFE8[j].f;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].g = lbl_8030FFE8[j].g;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].h = lbl_8030FFE8[j].h;
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
    for (i = 0; i < (s32)state->vertexCount; i++) {
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
    for (j = 0; j < (s32)state->vertexCount; j++) {
        if ((s32)ovx == (s32)state->vertexCount) {
            if ((s32)slot->texCoordS > 0x100) {
                slot->texCoordS -= 0x100;
            } else {
                slot->texCoordS += 0x100;
            }
        }
        if ((s32)ovy == (s32)state->vertexCount) {
            if ((s32)slot->texCoordT > 0x100) {
                slot->texCoordT -= 0x100;
            } else {
                slot->texCoordT += 0x100;
            }
        }
        slot++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void fn_800A0FD0(ModgfxState *state)
{
    int i;
    ModgfxVertexData *src;
    ModgfxVertexData *dst = state->vertexBuffers[state->activeVertexBufferIndex];
    src = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++) {
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

void fn_800A0478(ModgfxState *state)
{
    int i;
    ModgfxVertexData *dst;
    ModgfxVertexData *src;
    f32 f1;
    f32 f0;
    src = state->vertexBuffers[1 - (u32)state->activeVertexBufferIndex];
    dst = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++) {
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
    f1 = *(f32 *)&lbl_803DF434;
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
void partfx_initialise(void) {
    s16 *p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0) {
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
  extern void vecRotateZXY(void *, f32 *);
  extern f32 lbl_803DD284;
  extern f32 lbl_803DF430;
  extern f32 lbl_803DF434;

  if (mode == 1) {
    if (((ModgfxState *)p1)->channelFrames[((ModgfxState *)p1)->activeChannel] == 0) {
      int flags = ((ModgfxState *)p1)->flags;
      if ((flags & 0x4) != 0 || (flags & 0x80000) != 0) {
        s16 buf[6];
        f32 *fbuf = (f32 *)&buf[2];
        s16 v = *((ModgfxState *)p1)->unk04;
        f32 fill = lbl_803DF430;
        fbuf[3] = fill;
        fbuf[2] = fill;
        fbuf[1] = fill;
        fbuf[0] = lbl_803DF434;
        buf[2] = v;
        buf[1] = v;
        buf[0] = v;
        vecRotateZXY(buf, (f32 *)(p2 + 0x4));
      }
      ((ModgfxState *)p1)->posStepX = ((ModgfxVertexGroupCmd *)p2)->valueX;
      ((ModgfxState *)p1)->posStepY = ((ModgfxVertexGroupCmd *)p2)->valueY;
      ((ModgfxState *)p1)->posStepZ = ((ModgfxVertexGroupCmd *)p2)->valueZ;
    } else {
      ((ModgfxState *)p1)->posStepX = ((ModgfxVertexGroupCmd *)p2)->valueX / (f32)(s32)((ModgfxState *)p1)->blendFrameCount;
      ((ModgfxState *)p1)->posStepY = ((ModgfxVertexGroupCmd *)p2)->valueY / (f32)(s32)((ModgfxState *)p1)->blendFrameCount;
      ((ModgfxState *)p1)->posStepZ = ((ModgfxVertexGroupCmd *)p2)->valueZ / (f32)(s32)((ModgfxState *)p1)->blendFrameCount;
    }
    ((ModgfxState *)p1)->posCurX = ((ModgfxState *)p1)->posCurX + ((ModgfxState *)p1)->posStepX;
    ((ModgfxState *)p1)->posCurY = ((ModgfxState *)p1)->posCurY + ((ModgfxState *)p1)->posStepY;
    ((ModgfxState *)p1)->posCurZ = ((ModgfxState *)p1)->posCurZ + ((ModgfxState *)p1)->posStepZ;
  } else {
    ((ModgfxState *)p1)->posCurX = ((ModgfxState *)p1)->posStepX * lbl_803DD284 + ((ModgfxState *)p1)->posCurX;
    ((ModgfxState *)p1)->posCurY = ((ModgfxState *)p1)->posStepY * lbl_803DD284 + ((ModgfxState *)p1)->posCurY;
    ((ModgfxState *)p1)->posCurZ = ((ModgfxState *)p1)->posStepZ * lbl_803DD284 + ((ModgfxState *)p1)->posCurZ;
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
    if (mode == 1) {
        int tx = (int)params[1];
        int ty = (int)params[2];
        int tz = (int)params[3];
        if (((ModgfxState *)obj)->blendFrameCount != 0) {
            ((ModgfxState *)obj)->rotStepZ = (s16)(((s16)tx - ((ModgfxState *)obj)->rotOffsetZ) / ((ModgfxState *)obj)->blendFrameCount);
            ((ModgfxState *)obj)->rotStepY = (s16)(((s16)ty - ((ModgfxState *)obj)->rotOffsetY) / ((ModgfxState *)obj)->blendFrameCount);
            ((ModgfxState *)obj)->rotStepX = (s16)(((s16)tz - ((ModgfxState *)obj)->rotOffsetX) / ((ModgfxState *)obj)->blendFrameCount);
        } else {
            ((ModgfxState *)obj)->rotOffsetZ = tx;
            ((ModgfxState *)obj)->rotStepZ = 0;
            ((ModgfxState *)obj)->rotOffsetY = ty;
            ((ModgfxState *)obj)->rotStepY = 0;
            ((ModgfxState *)obj)->rotOffsetX = tz;
            ((ModgfxState *)obj)->rotStepX = 0;
        }
    }
    ((ModgfxState *)obj)->rotOffsetZ = ((ModgfxState *)obj)->rotOffsetZ + ((ModgfxState *)obj)->rotStepZ;
    ((ModgfxState *)obj)->rotOffsetY = ((ModgfxState *)obj)->rotOffsetY + ((ModgfxState *)obj)->rotStepY;
    ((ModgfxState *)obj)->rotOffsetX = ((ModgfxState *)obj)->rotOffsetX + ((ModgfxState *)obj)->rotStepX;
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
    PartfxEffectState **effects = (PartfxEffectState **)gPartfxActiveEffects;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++) {
        PartfxEffectState *effect = effects[i];
        GameObject *sourceObject;
        if (effect != NULL) {
            sourceObject = effect->sourceObject;
            if (sourceObject != NULL && (sourceObject->objectFlags & 0x800) != 0) {
                effect->frameUpdated = 1;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#define gPartfxResourceModule00 lbl_803DD2C8
#define gPartfxResourceModule01 lbl_803DD2CC
#define gPartfxResourceModule02 lbl_803DD2D0
#define gPartfxResourceModule03 lbl_803DD2D4
#define gPartfxResourceModule04 lbl_803DD2D8
#define gPartfxResourceModule05 lbl_803DD2DC
#define gPartfxResourceModule16 lbl_803DD2E0
#define gPartfxResourceModule06 lbl_803DD2E4
#define gPartfxResourceModule07 lbl_803DD2E8
#define gPartfxResourceModule08 lbl_803DD2EC
#define gPartfxResourceModule09 lbl_803DD2F0
#define gPartfxResourceModule10 lbl_803DD2F4
#define gPartfxResourceModule11 lbl_803DD2F8
#define gPartfxResourceModule12 lbl_803DD2FC
#define gPartfxResourceModule13 lbl_803DD300
#define gPartfxResourceModule14 lbl_803DD304
#define gPartfxResourceModule15 lbl_803DD308
#define gPartfxResourceModule17 lbl_803DD30C
#define gPartfxResourceModule18 lbl_803DD310
#define gPartfxResourceModule19 lbl_803DD314
extern void *gPartfxResourceModule00;
extern void *gPartfxResourceModule01;
extern void *gPartfxResourceModule02;
extern void *gPartfxResourceModule03;
extern void *gPartfxResourceModule04;
extern void *gPartfxResourceModule05;
extern void *gPartfxResourceModule16;
extern void *gPartfxResourceModule06;
extern void *gPartfxResourceModule07;
extern void *gPartfxResourceModule08;
extern void *gPartfxResourceModule09;
extern void *gPartfxResourceModule10;
extern void *gPartfxResourceModule11;
extern void *gPartfxResourceModule12;
extern void *gPartfxResourceModule13;
extern void *gPartfxResourceModule14;
extern void *gPartfxResourceModule15;
extern void *gPartfxResourceModule17;
extern void *gPartfxResourceModule18;
extern void *gPartfxResourceModule19;

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
void ParticleEffectController_func05(void)
{
    lbl_803DB7A8 = lbl_803DB7A8 + lbl_803DF4C8 * timeDelta;
    if (lbl_803DB7A8 > 1.0f) {
        lbl_803DB7A8 = lbl_803DF4CC;
    }
    lbl_803DB7AC = lbl_803DB7AC + lbl_803DF4C8 * timeDelta;
    if (lbl_803DB7AC > *(f32 *)&lbl_803DF4D0) {
        lbl_803DB7AC = lbl_803DF4D8;
    }
    lbl_803DD318 = lbl_803DD318 + framesThisStep * 100;
    if (lbl_803DD318 > 0x7fff) {
        lbl_803DD318 = 0;
    }
    lbl_803DD324 = mathSinf(lbl_803DF718 * (f32)(s16)lbl_803DD318 / lbl_803DF71C);
    lbl_803DD31C = lbl_803DD31C + framesThisStep * 0x32;
    if (lbl_803DD31C > 0x7fff) {
        lbl_803DD31C = 0;
    }
    lbl_803DD320 = mathSinf(lbl_803DF718 * (f32)(s16)lbl_803DD31C / lbl_803DF71C);
    if (gPartfxResourceTimeouts[0] != 0 && (gPartfxResourceTimeouts[0] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule00 != NULL) Resource_Release(gPartfxResourceModule00);
        gPartfxResourceModule00 = NULL;
        gPartfxResourceTimeouts[0] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[1] != 0 && (gPartfxResourceTimeouts[1] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule01 != NULL) Resource_Release(gPartfxResourceModule01);
        gPartfxResourceModule01 = NULL;
        gPartfxResourceTimeouts[1] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[2] != 0 && (gPartfxResourceTimeouts[2] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule02 != NULL) Resource_Release(gPartfxResourceModule02);
        gPartfxResourceModule02 = NULL;
        gPartfxResourceTimeouts[2] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[3] != 0 && (gPartfxResourceTimeouts[3] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule03 != NULL) Resource_Release(gPartfxResourceModule03);
        gPartfxResourceModule03 = NULL;
        gPartfxResourceTimeouts[3] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[4] != 0 && (gPartfxResourceTimeouts[4] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule04 != NULL) Resource_Release(gPartfxResourceModule04);
        gPartfxResourceModule04 = NULL;
        gPartfxResourceTimeouts[4] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[5] != 0 && (gPartfxResourceTimeouts[5] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule05 != NULL) Resource_Release(gPartfxResourceModule05);
        gPartfxResourceModule05 = NULL;
        gPartfxResourceTimeouts[5] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[16] != 0 && (gPartfxResourceTimeouts[16] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule16 != NULL) Resource_Release(gPartfxResourceModule16);
        gPartfxResourceModule16 = NULL;
        gPartfxResourceTimeouts[16] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[6] != 0 && (gPartfxResourceTimeouts[6] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule06 != NULL) Resource_Release(gPartfxResourceModule06);
        gPartfxResourceModule06 = NULL;
        gPartfxResourceTimeouts[6] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[7] != 0 && (gPartfxResourceTimeouts[7] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule07 != NULL) Resource_Release(gPartfxResourceModule07);
        gPartfxResourceModule07 = NULL;
        gPartfxResourceTimeouts[7] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[8] != 0 && (gPartfxResourceTimeouts[8] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule08 != NULL) Resource_Release(gPartfxResourceModule08);
        gPartfxResourceModule08 = NULL;
        gPartfxResourceTimeouts[8] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[9] != 0 && (gPartfxResourceTimeouts[9] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule09 != NULL) Resource_Release(gPartfxResourceModule09);
        gPartfxResourceModule09 = NULL;
        gPartfxResourceTimeouts[9] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[10] != 0 && (gPartfxResourceTimeouts[10] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule10 != NULL) Resource_Release(gPartfxResourceModule10);
        gPartfxResourceModule10 = NULL;
        gPartfxResourceTimeouts[10] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[11] != 0 && (gPartfxResourceTimeouts[11] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule11 != NULL) Resource_Release(gPartfxResourceModule11);
        gPartfxResourceModule11 = NULL;
        gPartfxResourceTimeouts[11] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[12] != 0 && (gPartfxResourceTimeouts[12] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule12 != NULL) Resource_Release(gPartfxResourceModule12);
        gPartfxResourceModule12 = NULL;
        gPartfxResourceTimeouts[12] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[13] != 0 && (gPartfxResourceTimeouts[13] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule13 != NULL) Resource_Release(gPartfxResourceModule13);
        gPartfxResourceModule13 = NULL;
        gPartfxResourceTimeouts[13] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[14] != 0 && (gPartfxResourceTimeouts[14] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule14 != NULL) Resource_Release(gPartfxResourceModule14);
        gPartfxResourceModule14 = NULL;
        gPartfxResourceTimeouts[14] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[15] != 0 && (gPartfxResourceTimeouts[15] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule15 != NULL) Resource_Release(gPartfxResourceModule15);
        gPartfxResourceModule15 = NULL;
        gPartfxResourceTimeouts[15] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[17] != 0 && (gPartfxResourceTimeouts[17] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule17 != NULL) Resource_Release(gPartfxResourceModule17);
        gPartfxResourceModule17 = NULL;
        gPartfxResourceTimeouts[17] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[18] != 0 && (gPartfxResourceTimeouts[18] -= framesThisStep) <= 0) {
        if (gPartfxResourceModule18 != NULL) Resource_Release(gPartfxResourceModule18);
        gPartfxResourceModule18 = NULL;
        gPartfxResourceTimeouts[18] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[19] != 0 && (gPartfxResourceTimeouts[19] -= framesThisStep) <= 0) {
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
void partfx_release(void) {
    s16 *p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0) {
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
  if (sum > 1.0f) {
    lbl_803DB7B8 = lbl_803DF724;
  }
  sum = lbl_803DB7BC + step;
  lbl_803DB7BC = sum;
  if (sum > 1.0f) {
    lbl_803DB7BC = lbl_803DF730;
  }
  lbl_803DD328 = lbl_803DD328 + framesThisStep * 0x64;
  if (lbl_803DD328 > 0x7fff) {
    lbl_803DD328 = 0;
  }
  lbl_803DD334 = mathSinf(lbl_803DF868 * (f32)(s16)lbl_803DD328 / lbl_803DF86C);
  lbl_803DD32C = lbl_803DD32C + framesThisStep * 0x32;
  if (lbl_803DD32C > 0x7fff) {
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
  if (sum > 1.0f) {
    lbl_803DB7C8 = lbl_803DF874;
  }
  sum = lbl_803DB7CC + step;
  lbl_803DB7CC = sum;
  if (sum > 1.0f) {
    lbl_803DB7CC = lbl_803DF880;
  }
  lbl_803DD338 = lbl_803DD338 + framesThisStep * 0x64;
  if (lbl_803DD338 > 0x7fff) {
    lbl_803DD338 = 0;
  }
  lbl_803DD344 = mathSinf(lbl_803DF9C8 * (f32)(s16)lbl_803DD338 / lbl_803DF9CC);
  lbl_803DD33C = lbl_803DD33C + framesThisStep * 0x32;
  if (lbl_803DD33C > 0x7fff) {
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
  if (sum > 1.0f) {
    lbl_803DB7D8 = lbl_803DFA8C;
  }
  sum = lbl_803DB7DC + step;
  lbl_803DB7DC = sum;
  if (sum > 1.0f) {
    lbl_803DB7DC = lbl_803DFA98;
  }
  lbl_803DD350 = lbl_803DD350 + framesThisStep * 0x64;
  if (lbl_803DD350 > 0x7fff) {
    lbl_803DD350 = 0;
  }
  lbl_803DD35C = mathSinf(lbl_803DFBD8 * (f32)(s16)lbl_803DD350 / lbl_803DFBDC);
  lbl_803DD354 = lbl_803DD354 + framesThisStep * 0x32;
  if (lbl_803DD354 > 0x7fff) {
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
  if (sum > 1.0f) {
    lbl_803DB7E8 = lbl_803DFBE4;
  }
  sum = lbl_803DB7EC + step;
  lbl_803DB7EC = sum;
  if (sum > 1.0f) {
    lbl_803DB7EC = lbl_803DFBF0;
  }
  lbl_803DD360 = lbl_803DD360 + framesThisStep * 0x64;
  if (lbl_803DD360 > 0x7fff) {
    lbl_803DD360 = 0;
  }
  lbl_803DD36C = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD360 / lbl_803DFC7C);
  lbl_803DD364 = lbl_803DD364 + framesThisStep * 0x32;
  if (lbl_803DD364 > 0x7fff) {
    lbl_803DD364 = 0;
  }
  lbl_803DD368 = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD364 / lbl_803DFC7C);
}

typedef struct PartFxSpawn {
    void *f00;
    int f04;
    int f08;
    s16 f0c;
    s16 f0e;
    s16 f10;
    u8  pad12[2];
    f32 f14;
    f32 f18;
    f32 f1c;
    f32 f20;
    f32 f24;
    f32 f28;
    f32 f2c;
    f32 f30;
    f32 f34;
    f32 f38;
    f32 f3c;
    s16 f40;
    s16 f42;
    u32 f44;
    u32 f48;
    u32 f4c;
    u32 f50;
    u32 f54;
    u16 f58;
    u16 f5a;
    u16 f5c;
    u8  f5e;
    u8  pad5f[1];
    u8  f60;
    u8  f61;
    u8  f62;
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

int Effect6_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB7F0 = lbl_803DB7F0 + lbl_803DFC80;
    if (lbl_803DB7F0 > 1.0f) lbl_803DB7F0 = lbl_803DFC84;
    lbl_803DB7F4 = lbl_803DB7F4 + lbl_803DFC8C;
    if (lbl_803DB7F4 > 1.0f) lbl_803DB7F4 = lbl_803DFC90;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFC94;
    cfg.f34 = lbl_803DFC94;
    cfg.f38 = lbl_803DFC94;
    cfg.f24 = lbl_803DFC94;
    cfg.f28 = lbl_803DFC94;
    cfg.f2c = lbl_803DFC94;
    cfg.f3c = lbl_803DFC94;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x422:
        if (param_6 == 0) return 0;
        cfg.f3c = lbl_803DFC98;
        cfg.f08 = randomGetRange(0xa, 0xd);
        cfg.f60 = (u8)*(u16 *)param_6;
        cfg.f44 = 0x80100;
        cfg.f42 = 0x64;
        cfg.f61 = 0x1e;
        break;
    case 0x423:
        cfg.f30 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DFC80 * (f32)(s32)randomGetRange(5, 0xb);
        cfg.f08 = 0x3c;
        cfg.f44 = 0x80110;
        cfg.f61 = 0x10;
        cfg.f42 = 0xde;
        break;
    case 0x424:
        cfg.f30 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFC90 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f24 = lbl_803DFC84 * (f32)(s32)randomGetRange(-5, 5);
        cfg.f28 = lbl_803DFC84 * (f32)(s32)randomGetRange(3, 0xa);
        cfg.f2c = lbl_803DFC84 * (f32)(s32)randomGetRange(-5, 5);
        cfg.f3c = lbl_803DFC9C * (f32)(s32)randomGetRange(5, 0xb);
        cfg.f08 = 0x3c;
        cfg.f44 = 0x1480200;
        cfg.f61 = 0x10;
        cfg.f42 = 0xde;
        break;
    case 0x425:
        cfg.f28 = lbl_803DFCA0 * (f32)(s32)randomGetRange(8, 0xa);
        if ((int)randomGetRange(0, 0x28) != 0) {
            cfg.f3c = lbl_803DFC80 * (f32)(s32)randomGetRange(8, 0x14);
            cfg.f08 = randomGetRange(0x5a, 0x78);
        } else {
            cfg.f3c = lbl_803DFC80 * (f32)(s32)randomGetRange(0x15, 0x29);
            cfg.f08 = 0x1cc;
        }
        cfg.f44 = 0x80180200;
        cfg.f48 = 0x1000020;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x7f;
        cfg.f5c = 0x3fff;
        cfg.f5a = 0x3fff;
        cfg.f58 = 0x3fff;
        cfg.f54 = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f4c = 0xffff;
        break;
    case 0x426:
        cfg.f24 = lbl_803DFCA0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFCA0 * (f32)(s32)randomGetRange(8, 0x14);
        cfg.f2c = lbl_803DFCA0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFCA4;
        cfg.f08 = 0x32;
        cfg.f44 = 0x3000200;
        cfg.f48 = 0x200020;
        cfg.f42 = 0x33;
        cfg.f60 = 0xff;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f50 = cfg.f54 = randomGetRange(0, 0x8000);
        break;
    case 0x427:
        cfg.f30 = (f32)(s32)randomGetRange(-0x64, 0x64) / lbl_803DFCA8;
        cfg.f34 = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803DFCAC;
        cfg.f38 = (f32)(s32)randomGetRange(-0x64, 0x64) / lbl_803DFCA8;
        cfg.f28 = lbl_803DFCB0 * (f32)(s32)randomGetRange(1, 4);
        cfg.f3c = lbl_803DFCB8 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFCB4;
        cfg.f08 = 0xa0;
        cfg.f61 = 0;
        cfg.f44 = 0x100200;
        cfg.f42 = 0x33;
        break;
    case 0x42b:
        if (param_6 == 0) return 0;
        cfg.f3c = lbl_803DFCBC;
        cfg.f08 = randomGetRange(0xa, 0xd);
        cfg.f60 = (u8)*(u16 *)param_6;
        cfg.f44 = 0x80100;
        cfg.f42 = 0xc7e;
        cfg.f61 = 0x1e;
        break;
    case 0x42c:
        cfg.f24 = lbl_803DFCC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFC98 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFCC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DFCC4;
        cfg.f08 = 0x6e;
        cfg.f44 = 0x8A100208;
        cfg.f48 = 0x20;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x400;
        cfg.f50 = 0xEA60;
        cfg.f54 = 0x1000;
        break;
    case 0x42d:
        cfg.f24 = lbl_803DFCC4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFCC4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFC84;
        cfg.f08 = 0x258;
        cfg.f60 = 0x7f;
        cfg.f44 = 0xA100100;
        cfg.f48 = 0x20;
        cfg.f42 = 0x62;
        cfg.f58 = 0x400;
        cfg.f5a = 0xEA60;
        cfg.f5c = 0x1000;
        cfg.f4c = 0;
        cfg.f50 = 0xC350;
        cfg.f54 = 0;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
}

void Effect6_func05(void)
{
  f32 sum;
  f32 step;
  sum = lbl_803DB7F8 + (step = lbl_803DFC80 * timeDelta);
  lbl_803DB7F8 = sum;
  if (sum > 1.0f) {
    lbl_803DB7F8 = lbl_803DFC84;
  }
  sum = lbl_803DB7FC + step;
  lbl_803DB7FC = sum;
  if (sum > 1.0f) {
    lbl_803DB7FC = lbl_803DFC90;
  }
  lbl_803DD370 = lbl_803DD370 + framesThisStep * 0x64;
  if (lbl_803DD370 > 0x7fff) {
    lbl_803DD370 = 0;
  }
  lbl_803DD37C = mathSinf(lbl_803DFCD0 * (f32)(s16)lbl_803DD370 / lbl_803DFCD4);
  lbl_803DD374 = lbl_803DD374 + framesThisStep * 0x32;
  if (lbl_803DD374 > 0x7fff) {
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
  if (sum > 1.0f) {
    lbl_803DB808 = lbl_803DFCDC;
  }
  sum = lbl_803DB80C + step;
  lbl_803DB80C = sum;
  if (sum > 1.0f) {
    lbl_803DB80C = lbl_803DFCE8;
  }
  lbl_803DD380 = lbl_803DD380 + framesThisStep * 0x64;
  if (lbl_803DD380 > 0x7fff) {
    lbl_803DD380 = 0;
  }
  lbl_803DD38C = mathSinf(lbl_803DFD90 * (f32)(s16)lbl_803DD380 / lbl_803DFD94);
  lbl_803DD384 = lbl_803DD384 + framesThisStep * 0x32;
  if (lbl_803DD384 > 0x7fff) {
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
  if (sum > 1.0f) {
    lbl_803DB818 = lbl_803DFD9C;
  }
  sum = lbl_803DB81C + step;
  lbl_803DB81C = sum;
  if (sum > 1.0f) {
    lbl_803DB81C = lbl_803DFDA8;
  }
  lbl_803DD390 = lbl_803DD390 + framesThisStep * 0x64;
  if (lbl_803DD390 > 0x7fff) {
    lbl_803DD390 = 0;
  }
  lbl_803DD39C = mathSinf(lbl_803DFE20 * (f32)(s16)lbl_803DD390 / lbl_803DFE24);
  lbl_803DD394 = lbl_803DD394 + framesThisStep * 0x32;
  if (lbl_803DD394 > 0x7fff) {
    lbl_803DD394 = 0;
  }
  lbl_803DD398 = mathSinf(lbl_803DFE20 * (f32)(s16)lbl_803DD394 / lbl_803DFE24);
}

typedef struct FxNode9 { s16 x, y, z; s16 pad6; f32 f8; f32 fc; f32 f10; f32 f14; } FxNode9;
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
    param_3 = (s16 *)&lbl_8039C398;             \
  } while (0)

int Effect9_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB820 = lbl_803DB820 + lbl_803DFE28;
    if (lbl_803DB820 > 1.0f) lbl_803DB820 = lbl_803DFE2C;
    lbl_803DB824 = lbl_803DB824 + lbl_803DFE34;
    if (lbl_803DB824 > 1.0f) lbl_803DB824 = lbl_803DFE38;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = 0.0f;
    cfg.f34 = 0.0f;
    cfg.f38 = 0.0f;
    cfg.f24 = 0.0f;
    cfg.f28 = 0.0f;
    cfg.f2c = 0.0f;
    cfg.f3c = 0.0f;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2 - 949) {
    case 1:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = 0.0f;
            cfg.f38 = 0.0f;
        }
        cfg.f34 = 0.0f;
        cfg.f28 = lbl_803DFE40 * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.f3c = lbl_803DFE44 * (f32)(s32)randomGetRange(6, 0xa);
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80180100;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0x63bf;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xb1df;
        cfg.f48 = 0x20;
        break;
    case 0:
        cfg.f30 = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFE48 + (f32)(s32)randomGetRange(0x1e, 0x64);
        cfg.f24 = lbl_803DFE4C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFE4C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFE50 * (f32)(s32)randomGetRange(0, 0x32);
        cfg.f3c = lbl_803DFE54 * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.f08 = randomGetRange(0, 0x118) + 0xb4;
        cfg.f60 = 0xfe;
        cfg.f44 = 0x81008000;
        cfg.f04 = 0x284;
        cfg.f42 = 0x208;
        break;
    case 6:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f3c = lbl_803DFE58;
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8000201;
        cfg.f42 = 0x62;
        break;
    case 5:
        if (param_3 == 0) FILL9();
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f28 = lbl_803DFE5C * (f32)(s32)randomGetRange(1, 4);
        cfg.f3c = lbl_803DFE64 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFE60;
        cfg.f08 = 0xa0;
        cfg.f61 = 0;
        cfg.f44 = 0x100201;
        cfg.f42 = 0x63;
        break;
    case 23:
        cfg.f24 = lbl_803DFE68 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803DFE68 * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.f2c = lbl_803DFE68 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f30 = lbl_803DFE6C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFE6C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFE6C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f08 = randomGetRange(0, 0x14) + 0x1e;
        cfg.f61 = 0;
        cfg.f60 = 0xa5;
        cfg.f44 = 0x180108;
        cfg.f3c = lbl_803DFE70 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f42 = 0x167;
        break;
    case 22:
        cfg.f3c = lbl_803DFE74;
        cfg.f08 = randomGetRange(0x32, 0x64);
        cfg.f60 = 0x7f;
        cfg.f44 = 0x1180100;
        cfg.f42 = 0x2b;
        break;
    case 21:
        cfg.f24 = lbl_803DFE78 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803DFE78 * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.f2c = lbl_803DFE78 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f3c = lbl_803DFE64 * (f32)(s32)randomGetRange(0, 0x64) + lbl_803DFE74;
        cfg.f08 = randomGetRange(0x32, 0x46);
        cfg.f60 = 0x7f;
        cfg.f44 = 0x1180100;
        cfg.f42 = 0x2b;
        break;
    case 18:
        if (param_3 != 0) cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f3c = param_3 != 0 ? lbl_803DFE7C * ((PartFxSpawnParams *)param_3)->unk8 : lbl_803DFE80;
        cfg.f08 = 0xf;
        cfg.f60 = 0x7f;
        cfg.f44 = 0x80210;
        cfg.f42 = 0x4f9;
        cfg.f61 = 0x20;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f4c = 0xff00;
        cfg.f50 = 0xff00;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x2000020;
        break;
    case 13:
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = 0.0f;
            cfg.f38 = 0.0f;
        }
        cfg.f34 = 0.0f;
        cfg.f3c = lbl_803DFE44 * (f32)(s32)randomGetRange(6, 0x14);
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80180108;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0x63bf;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xb1df;
        cfg.f48 = 0x20;
        break;
    case 11:
    case 12:
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = 0.0f;
            cfg.f38 = 0.0f;
        }
        cfg.f2c = lbl_803DFE84 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f24 = lbl_803DFE84 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFE68 * (f32)(s32)randomGetRange(0, 0x28);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DFE88;
        cfg.f08 = 0x8c;
        cfg.f44 = 0x81000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x26d;
        if ((int)randomGetRange(0, 3) == 3) {
            cfg.f3c = lbl_803DFE8C * (f32)(s32)randomGetRange(1, 4);
            cfg.f44 |= 0x100100LL;
            cfg.f42 = 0x2b;
            cfg.f60 = 0x9b;
            param_2 = 0x3c1;
        }
        break;
    case 17:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f24 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f28 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f2c = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f24 = lbl_803DFE28 * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f28 = lbl_803DFE74 * (f32)(s32)randomGetRange(5, 0x64);
            cfg.f2c = lbl_803DFE28 * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f34 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f30 = 0.0f;
        cfg.f3c = lbl_803DFE78;
        cfg.f08 = 0x28;
        cfg.f44 = 0x1080006;
        cfg.f42 = 0x60;
        cfg.f60 = 0xa0;
        break;
    case 16:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f3c = lbl_803DFE78;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100201;
        cfg.f42 = 0x60;
        break;
    case 15:
        if (param_3 == 0) FILL9();
        cfg.f08 = (s32)(lbl_803DFE48 * ((PartFxSpawnParams *)param_3)->unk8 + lbl_803DFE90);
        cfg.f3c = lbl_803DFE94 * (f32)(s32)cfg.f08;
        cfg.f44 = 0xe100200;
        cfg.f42 = 0x57;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f0c = *param_3;
        cfg.f0e = 0;
        cfg.f10 = 0;
        break;
    case 14:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f24 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f28 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f2c = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f34 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DFE74;
        cfg.f08 = 0x3c;
        cfg.f44 = 0x1080006;
        cfg.f42 = 0x60;
        cfg.f60 = 0xa0;
        break;
    case 20:
        if (param_3 == 0) FILL9();
        cfg.f24 = lbl_803DFE7C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFE98 * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f2c = lbl_803DFE7C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f30 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unkC : 0.0f;
        cfg.f34 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk10 : 0.0f;
        cfg.f38 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk14 : 0.0f;
        cfg.f34 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.f34;
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.f30;
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.f38;
        cfg.f3c = lbl_803DFE78;
        cfg.f08 = 0x14;
        cfg.f44 = 0x1080006;
        cfg.f42 = 0x60;
        cfg.f60 = 0xa0;
        break;
    case 9:
        cfg.f28 = lbl_803DFE9C * (f32)(s32)randomGetRange(1, 4);
        cfg.f3c = lbl_803DFE64 * (f32)(s32)randomGetRange(0, 0x3c) + lbl_803DFE9C;
        cfg.f08 = 0xa0;
        cfg.f61 = 0;
        cfg.f44 = 0x80100201;
        cfg.f42 = 0x63;
        break;
    case 8:
        if (param_3 == 0) FILL9();
        cfg.f24 = lbl_803DFE74 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFE78 * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f2c = lbl_803DFE74 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x96, 0x96);
        cfg.f38 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk14 : 0.0f;
        cfg.f34 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk10 : lbl_803DFEA0;
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x32, -0xa) + cfg.f38;
        cfg.f3c = lbl_803DFEA4;
        cfg.f08 = 0x1e;
        cfg.f44 = 0x108000e;
        cfg.f42 = 0x60;
        cfg.f60 = 0xbe;
        break;
    case 7:
        if (param_3 == 0) FILL9();
        cfg.f24 = lbl_803DFE68 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFE68 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFE28 * (f32)(s32)randomGetRange(0, 0x12c);
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f3c = lbl_803DFE58 * (f32)(s32)randomGetRange(4, 8);
        cfg.f08 = 0x46;
        cfg.f60 = 0x64;
        cfg.f61 = 0;
        cfg.f44 = 0x180108;
        cfg.f42 = 0x2b;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
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
    param_3 = (s16 *)&lbl_8039C380;             \
  } while (0)

int Effect8_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB810 = lbl_803DB810 + lbl_803DFD98;
    if (lbl_803DB810 > 1.0f) lbl_803DB810 = lbl_803DFD9C;
    lbl_803DB814 = lbl_803DB814 + lbl_803DFDA4;
    if (lbl_803DB814 > 1.0f) lbl_803DB814 = lbl_803DFDA8;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = 0.0f;
    cfg.f34 = 0.0f;
    cfg.f38 = 0.0f;
    cfg.f24 = 0.0f;
    cfg.f28 = 0.0f;
    cfg.f2c = 0.0f;
    cfg.f3c = 0.0f;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x361:
        cfg.f24 = lbl_803DFDB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFDB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f30 = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f38 = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0x258;
        cfg.f60 = 0xc8;
        cfg.f44 = 0xa100100;
        cfg.f42 = 0x62;
        break;
    case 0x362:
        cfg.f24 = lbl_803DFDB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFDB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f30 = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f38 = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0x258;
        cfg.f60 = 0xc8;
        cfg.f44 = 0xa100100;
        cfg.f42 = 0x62;
        break;
    case 0x35f:
        cfg.f30 = lbl_803DFDB4 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f38 = lbl_803DFDB4 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DFDB4 * (f32)(s32)randomGetRange(-0xa, 0x78);
        cfg.f28 = lbl_803DFDB8 * (f32)(s32)randomGetRange(2, 0x64);
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0x3c;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180201;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0x9b00;
        cfg.f4c = 0x9600;
        cfg.f50 = 0x1400;
        cfg.f54 = 0x1400;
        cfg.f48 = 0x20;
        break;
    case 0x360:
        cfg.f30 = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f38 = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f34 = lbl_803DFDBC + (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFDC4 * (f32)(s32)randomGetRange(0, 0x64);
        cfg.f3c = lbl_803DFDC8 * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.f08 = randomGetRange(0, 0x118) + 0xb4;
        cfg.f60 = 0xfe;
        cfg.f44 = 0x81008000;
        cfg.f42 = 0x208;
        break;
    case 0x357:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f58 = (u16)((u8)((PartFxSpawnParams *)param_3)->unk4 << 8);
        cfg.f5a = (u16)((u8)((PartFxSpawnParams *)param_3)->unk2 << 8);
        cfg.f5c = (u16)((u8)((PartFxSpawnParams *)param_3)->unk0 << 8);
        cfg.f4c = 0xfe00;
        cfg.f50 = 0xfe00;
        cfg.f54 = 0xfe00;
        cfg.f3c = lbl_803DFDCC;
        cfg.f08 = 0x1e;
        cfg.f60 = 0x78;
        cfg.f44 = 0x8000201;
        cfg.f48 = 0x20;
        cfg.f42 = 0x71;
        break;
    case 0x359:
        cfg.f30 = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f38 = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f34 = lbl_803DFDBC + (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFDC4 * (f32)(s32)randomGetRange(0, 0x64);
        cfg.f3c = lbl_803DFDC8 * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.f08 = randomGetRange(0, 0x118) + 0xb4;
        cfg.f60 = 0xfe;
        cfg.f44 = 0x81008000;
        cfg.f04 = 0x284;
        cfg.f42 = 0x208;
        break;
    case 0x352:
        cfg.f3c = lbl_803DFDD0;
        cfg.f08 = 0x64;
        cfg.f61 = 0;
        cfg.f44 = 0xa100208;
        cfg.f42 = 0x91;
        break;
    case 0x353:
        cfg.f30 = (f32)(s32)randomGetRange(-2, 2);
        cfg.f38 = (f32)(s32)randomGetRange(-2, 2);
        cfg.f24 = lbl_803DFDD4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFDD4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFDB0 * (f32)(s32)randomGetRange(0, 0x50);
        cfg.f3c = lbl_803DFDD8 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = randomGetRange(0, 0x17c) + 0xb4;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80400109;
        cfg.f42 = 0x47;
        break;
    case 0x354:
        cfg.f30 = (f32)(s32)randomGetRange(-4, 4);
        cfg.f38 = (f32)(s32)randomGetRange(-4, 4);
        cfg.f34 = (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f24 = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DFDC0 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFDC4 * (f32)(s32)randomGetRange(0, 0x64);
        cfg.f3c = lbl_803DFDC8 * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.f08 = randomGetRange(0, 0x118) + 0xb4;
        cfg.f60 = 0xfe;
        cfg.f44 = 0x1000001;
        cfg.f04 = 0x284;
        cfg.f42 = 0x208;
        break;
    case 0x355:
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x580101;
        cfg.f42 = 0x17c;
        break;
    case 0x356:
        cfg.f3c = lbl_803DFDC4;
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f28 = lbl_803DFDDC * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f44 = 0x80201;
        cfg.f42 = 0x62;
        break;
    case 0x35a:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f3c = lbl_803DFDB0 * (lbl_803DFDE0 * (f32)(s32)((PartFxSpawnParams *)param_3)->unk4);
        cfg.f08 = 0x3c;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f4c = ((PartFxSpawnParams *)param_3)->unk4 << 8;
        cfg.f50 = ((PartFxSpawnParams *)param_3)->unk4 << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x60;
        cfg.f60 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f44 = 0x201;
        cfg.f42 = 0x76;
        break;
    case 0x35b:
        if (param_3 == 0) FILL8();
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0xa;
        cfg.f60 = 0xff;
        cfg.f44 = 0x580101;
        cfg.f42 = 0xc22;
        break;
    case 0x35c:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f3c = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)((PartFxSpawnParams *)param_3)->unk0));
        cfg.f08 = 0xa;
        cfg.f58 = (u16)(((PartFxSpawnParams *)param_3)->unk0 << 8);
        cfg.f5a = (u16)(((PartFxSpawnParams *)param_3)->unk0 << 8);
        cfg.f5c = 0xff00;
        cfg.f4c = ((PartFxSpawnParams *)param_3)->unk0 << 8;
        cfg.f50 = ((PartFxSpawnParams *)param_3)->unk0 << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x20;
        cfg.f60 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f42 = 0xc9d;
        break;
    case 0x35d:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f3c = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)((PartFxSpawnParams *)param_3)->unk0));
        cfg.f08 = 0xa;
        cfg.f58 = 0xff00;
        cfg.f5a = (u16)(((PartFxSpawnParams *)param_3)->unk0 << 8);
        cfg.f5c = 0xff00;
        cfg.f4c = 0xff00;
        cfg.f50 = ((PartFxSpawnParams *)param_3)->unk0 << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x20;
        cfg.f60 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f42 = 0xc9d;
        break;
    case 0x35e:
        if (param_3 == 0) FILL8();
        cfg.f3c = lbl_803DFDEC;
        cfg.f34 = lbl_803DFDF0;
        cfg.f08 = 0x46;
        cfg.f60 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk4 : 0xff;
        cfg.f61 = 0;
        cfg.f30 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unkC : 0.0f;
        cfg.f34 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk10 : 0.0f;
        cfg.f38 = param_3 != 0 ? ((PartFxSpawnParams *)param_3)->unk14 : 0.0f;
        cfg.f44 = 0xa100200;
        cfg.f42 = 0x7d;
        break;
    case 0x367:
        cfg.f30 = lbl_803DFD9C * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f34 = lbl_803DFDF4;
        cfg.f38 = lbl_803DFD9C * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f24 = lbl_803DFDF8 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFDC0 * (f32)(s32)randomGetRange(0x64, 0xc8);
        cfg.f2c = lbl_803DFDF8 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFDFC * (f32)(s32)randomGetRange(5, 0x19);
        cfg.f08 = 0x7d0;
        cfg.f60 = 0xe6;
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f0e = randomGetRange(0, 0xffff);
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f18 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f1c = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f20 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f48 = 0x10000000;
        cfg.f44 = 0x8f000000;
        cfg.f42 = 0x56e;
        break;
    case 0x369:
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x580101;
        cfg.f42 = 0x17c;
        break;
    case 0x366:
        cfg.f28 = lbl_803DFDB0 * (f32)(s32)randomGetRange(0x1f4, 0x3e8);
        cfg.f38 = lbl_803DFD9C * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.f30 = lbl_803DFD9C * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.f34 = lbl_803DFE00;
        cfg.f3c = lbl_803DFDB0;
        cfg.f08 = 0x3c;
        cfg.f44 = 0x400000;
        cfg.f48 = 0x100;
        cfg.f42 = 0x62;
        cfg.f60 = 0x50;
        break;
    case 0x365:
        cfg.f28 = lbl_803DFE04 * (f32)(s32)randomGetRange(0x6e, 0xc8);
        cfg.f38 = lbl_803DFE08 * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.f30 = lbl_803DFE08 * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.f3c = lbl_803DFE0C * (f32)(s32)randomGetRange(1, 0x14) + lbl_803DFD98;
        cfg.f60 = 0xff;
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f0e = randomGetRange(0, 0xffff);
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f18 = (f32)(s32)randomGetRange(0, 0x258);
        cfg.f1c = (f32)(s32)randomGetRange(0, 0x258);
        cfg.f20 = (f32)(s32)randomGetRange(0, 0x258);
        {
            u16 r2;
            cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
            cfg.f5a = r2;
            cfg.f5c = 0x3caf;
            cfg.f4c = cfg.f58;
            cfg.f50 = r2;
            cfg.f54 = 0x3caf;
        }
        cfg.f48 = 0x20;
        cfg.f08 = randomGetRange(0, 0x3c) + 0x15e;
        cfg.f61 = 0x10;
        cfg.f44 = 0x86000008;
        cfg.f42 = 0x3a2;
        break;
    case 0x364:
        cfg.f28 = lbl_803DFDB0 * (f32)(s32)randomGetRange(5, 0x64);
        cfg.f3c = lbl_803DFE10;
        cfg.f08 = 0x50;
        {
            u16 r2;
            cfg.f58 = (u16)(randomGetRange(0, 0x2710) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
            cfg.f5a = r2;
            cfg.f5c = 0x3caf;
            cfg.f4c = cfg.f58;
            cfg.f50 = r2;
            cfg.f54 = 0x3caf;
        }
        cfg.f48 = 0x20;
        cfg.f44 = (u32)randFn_80080100;
        cfg.f42 = 0x62;
        cfg.f60 = 0xa0;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
}
#undef FILL8

typedef struct EmitterCfg {
    f32 vel[7][3];
    f32 g08[3];
    f32 f60;
    int emit[6];
    int sub[6];
    u16 col[6];
    u8  b_a0;
    u8  b_a1;
    u8  pad[2];
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
    param_3 = (s16 *)&lbl_8039C338;             \
  } while (0)

extern s32 lbl_80310660[];

/* ---- partfx_update (FUN_800a4df4, v1.0) ---- */
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
extern void vecRotateZXY(void *obj, f32 *vec);
extern char sModgfxAlphaDebugFormat[];
extern void fn_80137948(char *fmt, ...);

int partfx_update(s16 *param_1, u32 p2_, s16 *param_3, u32 param_4,
                  u32 p5_, void *p6_)
{
    int param_5 = (int)p5_;
    int param_2 = (int)p2_;
    f32 *param_6 = (f32 *)p6_;
    int iVar8;
    s16 sVar10;
    u8 cVar4;
    f32 fVar1;
    f32 fVar2;
    f32 fVar3;
    f32 dVar12;
    f32 dVar13;
    f32 dVar14;
    f32 dVar15;
    f32 dVar16;
    struct { s16 x, y, z; f32 m[4]; } rot;
    PartFxSpawn cfg;

  if (((899 < param_2) && (param_2 < 0x3b5)) || ((0x5dc < param_2 && (param_2 < 0x641)))) {
    gPartfxResourceTimeouts[0] = 2000;
    if (gPartfxResourceModule00 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule00 = Resource_Acquire(0x1a,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule00 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x257 < param_2) && (param_2 < 0x2bc)) {
    gPartfxResourceTimeouts[1] = 2000;
    if (gPartfxResourceModule01 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule01 = Resource_Acquire(0x1b,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule01 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x1f3 < param_2) && (param_2 < 0x258)) {
    gPartfxResourceTimeouts[2] = 2000;
    if (gPartfxResourceModule02 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule02 = Resource_Acquire(0x1c,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule02 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x18f < param_2) && (param_2 < 0x1f4)) {
    gPartfxResourceTimeouts[3] = 2000;
    if (gPartfxResourceModule03 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule03 = Resource_Acquire(0x1d,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule03 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0xc7 < param_2) && (param_2 < 0x12c)) {
    gPartfxResourceTimeouts[4] = 2000;
    if (gPartfxResourceModule04 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule04 = Resource_Acquire(0x1e,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule04 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x419 < param_2) && (param_2 < 0x44c)) {
    gPartfxResourceTimeouts[5] = 2000;
    if (gPartfxResourceModule05 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule05 = Resource_Acquire(0x1f,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule05 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x739 < param_2) && (param_2 < 0x76c)) {
    gPartfxResourceTimeouts[16] = 2000;
    if (gPartfxResourceModule16 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule16 = Resource_Acquire(0x2a,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule16 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 - 0x84U < 2) || ((0x89 < param_2 && (param_2 < 200)))) {
    gPartfxResourceTimeouts[6] = 2000;
    if (gPartfxResourceModule06 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule06 = Resource_Acquire(0x20,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule06 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x3b5 < param_2) && (param_2 < 0x3de)) {
    gPartfxResourceTimeouts[8] = 2000;
    if (gPartfxResourceModule08 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule08 = Resource_Acquire(0x22,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule08 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x351 < param_2) && (param_2 < 0x384)) {
    gPartfxResourceTimeouts[7] = 2000;
    if (gPartfxResourceModule07 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule07 = Resource_Acquire(0x21,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule07 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x329 < param_2) && (param_2 < 0x351)) {
    gPartfxResourceTimeouts[9] = 2000;
    if (gPartfxResourceModule09 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule09 = Resource_Acquire(0x23,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule09 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x12b < param_2) && (param_2 < 0x190)) {
    gPartfxResourceTimeouts[10] = 2000;
    if (gPartfxResourceModule10 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule10 = Resource_Acquire(0x24,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule10 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x47d < param_2) && (param_2 < 0x4b0)) {
    gPartfxResourceTimeouts[11] = 2000;
    if (gPartfxResourceModule11 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule11 = Resource_Acquire(0x25,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule11 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x4af < param_2) && (param_2 < 0x4e2)) {
    gPartfxResourceTimeouts[12] = 2000;
    if (gPartfxResourceModule12 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule12 = Resource_Acquire(0x27,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule12 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 >= 0x3e8) && (param_2 <= 0x419)) {
    gPartfxResourceTimeouts[13] = 2000;
    if (gPartfxResourceModule13 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule13 = Resource_Acquire(0x28,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule13 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((0x44b < param_2) && (param_2 < 0x47e)) {
    gPartfxResourceTimeouts[14] = 2000;
    if (gPartfxResourceModule14 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule14 = Resource_Acquire(0x26,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule14 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 >= 0x6d7) && (param_2 <= 0x707)) {
    gPartfxResourceTimeouts[15] = 2000;
    if (gPartfxResourceModule15 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule15 = Resource_Acquire(0x29,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule15 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 >= 0x708) && (param_2 <= 0x739)) {
    gPartfxResourceTimeouts[17] = 2000;
    if (gPartfxResourceModule17 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule17 = Resource_Acquire(0x2b,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule17 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 >= 0x76c) && (param_2 <= 0x79d)) {
    gPartfxResourceTimeouts[18] = 2000;
    if (gPartfxResourceModule18 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule18 = Resource_Acquire(0x2c,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule18 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  if ((param_2 >= 0x79e) && (param_2 <= 0x833)) {
    gPartfxResourceTimeouts[19] = 2000;
    if (gPartfxResourceModule19 == NULL) {
      gPartfxCachedResourceCount += 1;
      gPartfxResourceModule19 = Resource_Acquire(0x2d,2);
    }
    return (*(int (**)())(*(int *)gPartfxResourceModule19 + 8))(param_1,param_2,param_3,param_4,param_5,param_6);
  }
  lbl_803DB7A0 = lbl_803DB7A0 + lbl_803DF4C8;
  if (lbl_803DB7A0 > 1.0f) {
    lbl_803DB7A0 = lbl_803DF4CC;
  }
  lbl_803DB7A4 = lbl_803DB7A4 + lbl_803DF4D4;
  if (lbl_803DB7A4 > 1.0f) {
    lbl_803DB7A4 = lbl_803DF4D8;
  }
  if (param_1 == NULL) {
    return -1;
  }
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == NULL) {
      return -1;
    }
    cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
    cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
    cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
    cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
    cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
    cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
    cfg.f0c = *param_3;
    cfg.f62 = param_5;
  }
  cVar4 = '\0';
  cfg.f44 = 0x0;
  cfg.f48 = 0;
  cfg.f5e = (u8)param_2;
  cfg.f30 = lbl_803DF4DC;
  cfg.f34 = lbl_803DF4DC;
  cfg.f38 = lbl_803DF4DC;
  cfg.f24 = lbl_803DF4DC;
  cfg.f28 = lbl_803DF4DC;
  cfg.f2c = lbl_803DF4DC;
  cfg.f3c = lbl_803DF4DC;
  cfg.f08 = 0;
  cfg.f04 = 0xffffffff;
  cfg.f60 = 0xff;
  cfg.f61 = 0;
  cfg.f42 = 0;
  cfg.f58 = 0xffff;
  cfg.f5a = 0xffff;
  cfg.f5c = 0xffff;
  cfg.f4c = 0xffff;
  cfg.f50 = 0xffff;
  cfg.f54 = 0xffff;
  cfg.f40 = 0;
  cfg.f00 = param_1;
  switch (param_2) {
  case 0x5e:

        cfg.f3c = lbl_803DF4C8 * (f32)(s32)randomGetRange(0x14,0x1e);
        cfg.f08 = 0x1e;
        cfg.f44 = 0x80180000;
        cfg.f42 = 0x60;
        if (param_6 != NULL) {
          cfg.f58 = *(ushort *)((int)param_6 + 6);
          cfg.f5a = *(ushort *)(param_6 + 2);
          cfg.f5c = *(ushort *)((int)param_6 + 10);
          cfg.f4c = (u32)*(ushort *)param_6;
          cfg.f50 = (u32)*(ushort *)((int)param_6 + 2);
          cfg.f54 = (u32)*(ushort *)(param_6 + 1);
        }
        cfg.f48 = 0x8400820;
    break;
  case 0x5f:
cfg.f3c = lbl_803DF4E0;
        cfg.f08 = 4;
        cfg.f44 = 0x80000;
        cfg.f42 = 0x33;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xffff;
        cfg.f48 = 0x8000820;
    break;
  case 0x60:

      cfg.f30 = (f32)(s32)randomGetRange(0xfffffff6,10);
      cfg.f34 = (f32)(s32)randomGetRange(0xfffffff6,10);
      cfg.f38 = (f32)(s32)randomGetRange(0xfffffff6,10);
      cfg.f24 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f28 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f2c = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f3c = lbl_803DF4C8 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f44 = 0x80180202;
      cfg.f42 = 0x60;
      if (param_6 != NULL) {
        cfg.f58 = *(ushort *)param_6;
        cfg.f5a = *(ushort *)((int)param_6 + 2);
        cfg.f5c = *(ushort *)(param_6 + 1);
        cfg.f08 = (u32)*(ushort *)((int)param_6 + 6);
      }
      else {
        cfg.f58 = 0x2000;
        cfg.f5a = 0x2000;
        cfg.f5c = 0x2000;
        cfg.f08 = 0x78;
      }
      cfg.f4c = (u32)cfg.f58;
      cfg.f50 = (u32)cfg.f5a;
      cfg.f54 = (u32)cfg.f5c;
      cfg.f60 = 0x7f;
      cfg.f48 = 0x4080020;
    break;
  case 0x68c:

      cfg.f3c = lbl_803DF4E8;
      cfg.f08 = 0x5f;
      cfg.f44 = 0x1180200;
      cfg.f42 = 0x62;
      cfg.f58 = 0;
      cfg.f5a = 0;
      cfg.f5c = randomGetRange(0x8000, 0xffff);
      cfg.f4c = 0;
      cfg.f50 = randomGetRange(0,0x8000);
      cfg.f54 = randomGetRange(0,0xffff);
      cfg.f48 = 0x20;
    break;
  case 0x68d:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffff9,7);
        cfg.f34 = (f32)(s32)randomGetRange(0xfffffff9,7);
        cfg.f38 = (f32)(s32)randomGetRange(0xfffffff9,7);
        cfg.f24 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
        cfg.f28 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
        cfg.f2c = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
        cfg.f3c = lbl_803DF4E8;
        cfg.f08 = 0x5a;
        cfg.f60 = 0x96;
        cfg.f44 = 0x1080200;
        cfg.f42 = 0x62;
        cfg.f58 = 0;
        cfg.f5a = 0;
        cfg.f5c = randomGetRange(0,0xffff);
        cfg.f4c = 0x7fff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xffff;
        cfg.f48 = 0x20;
    break;
  case 0x68e:
cfg.f3c = lbl_803DF4EC;
        cfg.f08 = 0x5f;
        cfg.f44 = 0x180208;
        cfg.f42 = 0x62;
        cfg.f58 = randomGetRange(0x8000, 0xffff);
        cfg.f5a = 0;
        cfg.f5c = 0;
        cfg.f4c = randomGetRange(0,0xffff);
        cfg.f50 = randomGetRange(0,0x8000);
        cfg.f54 = 0;
        cfg.f48 = 0x20;
    break;
  case 0x68f:

      cfg.f30 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f34 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f38 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f24 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f28 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f2c = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f3c = lbl_803DF4F0;
      cfg.f08 = 100;
      cfg.f60 = 0x96;
      cfg.f44 = 0x1080200;
      cfg.f42 = 0x62;
      cfg.f58 = randomGetRange(0,0xffff);
      cfg.f5a = 0;
      cfg.f5c = 0;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = 0;
      cfg.f48 = 0x20;
    break;
  case 0x690:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f34 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f38 = (f32)(s32)randomGetRange(0xfffffff9,7);
      cfg.f24 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f28 = lbl_803DF4F4 * (f32)(s32)randomGetRange(0x14,0x32);
      cfg.f2c = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
      cfg.f3c = lbl_803DF4F0;
      cfg.f08 = 0x96;
      cfg.f60 = 0x96;
      cfg.f44 = 0x80208;
      cfg.f42 = 0x62;
      cfg.f58 = 0xffff;
      cfg.f5a = 0;
      cfg.f5c = 0;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = 0xffff;
      cfg.f48 = 0x20;
    break;
  case 0x68b:
if (param_3 != NULL) {
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC - *(f32 *)(param_1 + 0xc);
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14 - *(f32 *)(param_1 + 0x10);
        }
        else {
          cfg.f30 = (f32)(s32)randomGetRange(0xfffffff9,7);
          cfg.f38 = (f32)(s32)randomGetRange(0xfffffff9,7);
        }
        cfg.f34 = lbl_803DF4F8;
        cfg.f24 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
        cfg.f28 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0,0x32);
        cfg.f2c = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xffffffce,0x32);
        cfg.f3c = lbl_803DF4E8;
        if (param_3 != NULL) {
          cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8;
        }
        cfg.f08 = 0x32;
        cfg.f60 = 0x96;
        cfg.f44 = 0x80080200;
        cfg.f42 = 0x62;
        cfg.f58 = randomGetRange(0,0xffff);
        cfg.f5a = 0;
        cfg.f5c = 0;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0;
        cfg.f48 = 0x1000020;
    break;
  case 0x556:
cfg.f34 = lbl_803DF4FC;
            cfg.f3c = lbl_803DF500;
            cfg.f08 = 0xaf;
            cfg.f60 = 0xff;
            cfg.f44 = 0x500010;
            cfg.f48 = 0x400200;
            cfg.f42 = 0xe4;
            (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
LAB_800a69a8:
              cfg.f34 = lbl_803DF4FC;
              cfg.f3c = lbl_803DF4E8;
              cfg.f08 = 0xaf;
              cfg.f60 = 0xff;
              cfg.f44 = 0x500010;
              cfg.f48 = 0x400100;
              cfg.f42 = 0xe4;
              (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
LAB_800a6a18:
            cfg.f34 = lbl_803DF4FC;
            cfg.f3c = lbl_803DF504;
            cfg.f08 = 0x2d;
            cfg.f60 = 0xff;
            cfg.f44 = 0x100210;
            cfg.f48 = 0x200;
            cfg.f42 = 0xe4;
            (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
            goto LAB_800a6a6c;
  case 0x55d:
            goto LAB_800aeb28;
  case 0x557:
LAB_800a6a6c:
          cfg.f34 = lbl_803DF4FC;
          if (param_6 != NULL) {
            cfg.f28 = lbl_803DF508;
          }
          else {
            cfg.f28 = lbl_803DF50C;
          }
          cfg.f3c = lbl_803DF510;
          cfg.f08 = 0xaf;
          cfg.f60 = 0xff;
          cfg.f44 = 0x500010;
          cfg.f48 = 0x400200;
          cfg.f42 = 0xe4;
          (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
          goto LAB_800a6aec;
  case 0x558:

LAB_800a6aec:
        cfg.f34 = lbl_803DF4FC;
        if (param_6 != NULL) {
          cfg.f28 = lbl_803DF50C;
        }
        else {
          cfg.f28 = lbl_803DF508;
        }
        cfg.f3c = lbl_803DF510;
        cfg.f08 = 0xaf;
        cfg.f60 = 0xff;
        cfg.f44 = 0x500010;
        cfg.f48 = 0x400200;
        cfg.f42 = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
LAB_800a6b6c:
        cfg.f34 = lbl_803DF4FC;
        if (param_6 != NULL) {
          cfg.f28 = lbl_803DF508;
        }
        else {
          cfg.f28 = lbl_803DF50C;
        }
        cfg.f3c = lbl_803DF4E0;
        cfg.f08 = 0xaf;
        cfg.f60 = 0xff;
        cfg.f44 = 0x500010;
        cfg.f48 = 0x400100;
        cfg.f42 = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
    break;
  case 0x55b:
cfg.f34 = lbl_803DF4FC;
      if (param_6 != NULL) {
        cfg.f28 = lbl_803DF50C;
      }
      else {
        cfg.f28 = lbl_803DF508;
      }
      cfg.f3c = lbl_803DF4E0;
      cfg.f08 = 0xaf;
      cfg.f60 = 0xff;
      cfg.f44 = 0x500010;
      cfg.f48 = 0x400100;
      cfg.f42 = 0xe4;
    break;
  case 0x55e:

      if (param_3 == NULL) {
        *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
        lbl_8039C308[0] = 0;
        lbl_8039C308[1] = 0;
        lbl_8039C308[2] = 0;
        lbl_8039C308[3] = 0;
        param_3 = lbl_8039C308;
      }
      cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10 + (f32)(s32)randomGetRange(0xfffffffa,6);
      cfg.f24 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803DF514;
      cfg.f08 = 0x12;
      cfg.f60 = 0xff;
      cfg.f44 = 0x400010;
      cfg.f48 = 0x400008;
      cfg.f42 = 0xe4;
    break;
  case 0x551:
if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
        }
        cfg.f38 = lbl_803DF518;
        cfg.f3c = lbl_803DF4EC;
        cfg.f08 = 0x23;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x100210;
        cfg.f42 = 0x91;
    break;
  case 0x552:

      if (param_3 == NULL) {
        *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
        lbl_8039C308[0] = 0;
        lbl_8039C308[1] = 0;
        lbl_8039C308[2] = 0;
        lbl_8039C308[3] = 0;
      }
      cfg.f38 = lbl_803DF518;
      cfg.f3c = lbl_803DF4EC;
      cfg.f08 = 0x23;
      cfg.f60 = 0x9b;
      cfg.f44 = 0xa100210;
      cfg.f42 = 0x91;
    break;
  case 0x554:
if (param_3 == NULL) {
                *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
                lbl_8039C308[0] = 0;
                lbl_8039C308[1] = 0;
                lbl_8039C308[2] = 0;
                lbl_8039C308[3] = 0;
              }
              cfg.f38 = lbl_803DF518;
              cfg.f3c = lbl_803DF51C;
              cfg.f08 = 0x37;
              cfg.f60 = 0x9b;
              cfg.f44 = 0xa100210;
              cfg.f42 = 0x73;
    break;
  case 0x553:
if (param_3 == NULL) {
                *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
                lbl_8039C308[0] = 0;
                lbl_8039C308[1] = 0;
                lbl_8039C308[2] = 0;
                lbl_8039C308[3] = 0;
              }
              cfg.f24 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f28 = lbl_803DF4EC * (f32)(s32)randomGetRange(0x14,0x1e);
              cfg.f2c = lbl_803DF4F0 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f38 = lbl_803DF518;
              rot.m[1] = lbl_803DF4DC;
              rot.m[2] = lbl_803DF4DC;
              rot.m[3] = lbl_803DF4DC;
              rot.m[0] = lbl_803DF4D0;
              rot.z = 0;
              rot.y = 0;
              rot.x = *(s16 *)param_1;
              vecRotateZXY((s16 *)&rot,&cfg.f30);
              cfg.f3c = lbl_803DF520;
              cfg.f08 = 0x91;
              cfg.f60 = 0xff;
              cfg.f44 = 0x3000010;
              cfg.f48 = 0x2600000;
              cfg.f42 = 0xe4;
    break;
  case 0x549:

          cfg.f30 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f34 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f38 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f08 = randomGetRange(100,0x96);
          cfg.f60 = 0xff;
          cfg.f44 = 0x80480110;
          if (param_6 != NULL) {
            cfg.f44 = 0xc0480110;
          }
          cfg.f42 = 0x85;
    break;
  case 0x54a:
cfg.f30 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f34 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f38 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f08 = randomGetRange(100,0x96);
          cfg.f60 = 0xff;
          cfg.f44 = 0x80480110;
          if (param_6 != NULL) {
            cfg.f44 = 0xc0480110;
          }
          cfg.f42 = 0x84;
    break;
  case 0x54b:
cfg.f30 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f34 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f38 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f08 = randomGetRange(100,0x96);
          cfg.f60 = 0xff;
          cfg.f44 = 0x80480110;
          if (param_6 != NULL) {
            cfg.f44 = 0xc0480110;
          }
          cfg.f42 = 0xc0f;
    break;
  case 0x54c:

        cfg.f30 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f34 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f38 = lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
        cfg.f08 = randomGetRange(100,0x96);
        cfg.f60 = 0xff;
        cfg.f44 = 0x80480110;
        if (param_6 != NULL) {
          cfg.f44 = 0xc0480110;
        }
        cfg.f42 = 0x157;
    break;
  case 0x54d:
if (param_6 == NULL) {
            cVar4 = '\0';
          }
          else {
            cVar4 = *(u8 *)param_6;
          }
          if (cVar4 == '\x01') {
            cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
            cfg.f44 = 0x4c0800;
            cfg.f48 = 0x202;
          }
          else if (cVar4 == '\x02') {
            cfg.f3c = lbl_803DF528 * (f32)(s32)randomGetRange(10,0x14);
            cfg.f44 = 0x4c0800;
            cfg.f48 = 0x102;
          }
          else {
            cfg.f3c = lbl_803DF52C * (f32)(s32)randomGetRange(0x12,0x14);
            cfg.f44 = 0xc0800;
            cfg.f48 = 2;
          }
          cfg.f08 = 1;
          cfg.f60 = 0x60;
          cfg.f42 = 0x85;
    break;
  case 0x54e:
if (param_6 != NULL) {
            cVar4 = *(u8 *)param_6;
          }
          if (cVar4 == '\x01') {
            cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
            cfg.f44 = 0x4c0800;
            cfg.f48 = 0x202;
          }
          else if (cVar4 == '\x02') {
            cfg.f3c = lbl_803DF528 * (f32)(s32)randomGetRange(10,0x14);
            cfg.f44 = 0x4c0800;
            cfg.f48 = 0x102;
          }
          else {
            cfg.f3c = lbl_803DF52C * (f32)(s32)randomGetRange(0x12,0x14);
            cfg.f44 = 0xc0800;
            cfg.f48 = 2;
          }
          cfg.f08 = 1;
          cfg.f60 = 0x60;
          cfg.f42 = 0x84;
    break;
  case 0x54f:

        if (param_6 != NULL) {
          cVar4 = *(u8 *)param_6;
        }
        if (cVar4 == '\x01') {
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f44 = 0x4c0800;
          cfg.f48 = 0x202;
        }
        else if (cVar4 == '\x02') {
          cfg.f3c = lbl_803DF528 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f44 = 0x4c0800;
          cfg.f48 = 0x102;
        }
        else {
          cfg.f3c = lbl_803DF52C * (f32)(s32)randomGetRange(0x12,0x14);
          cfg.f44 = 0xc0800;
          cfg.f48 = 2;
        }
        cfg.f08 = 1;
        cfg.f60 = 0x60;
        cfg.f42 = 0xc0f;
    break;
  case 0x550:
if (param_6 != NULL) {
          cVar4 = *(u8 *)param_6;
        }
        if (cVar4 == '\x01') {
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f44 = 0x4c0800;
          cfg.f48 = 0x202;
        }
        else if (cVar4 == '\x02') {
          cfg.f3c = lbl_803DF528 * (f32)(s32)randomGetRange(10,0x14);
          cfg.f44 = 0x4c0800;
          cfg.f48 = 0x102;
        }
        else {
          cfg.f3c = lbl_803DF52C * (f32)(s32)randomGetRange(0x12,0x14);
          cfg.f44 = 0xc0800;
          cfg.f48 = 2;
        }
        cfg.f08 = 1;
        cfg.f60 = 0x60;
        cfg.f42 = 0x157;
    break;
  case 0x545:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          cfg.f3c = lbl_803DF530 * ((PartFxSpawnParams *)param_3)->unk8;
          cfg.f08 = 4;
          cfg.f44 = 0x480000;
          cfg.f48 = 2;
          cfg.f42 = 0x527;
          cfg.f60 = 0x69;
    break;
  case 0x546:

        if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        cfg.f3c = lbl_803DF534 * ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f08 = 4;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x2000002;
        cfg.f42 = 0xc0e;
        cfg.f60 = 0x73;
    break;
  case 0x547:
cfg.f30 = lbl_803DF538;
            cfg.f34 = (f32)(s32)randomGetRange(0xffffffb0,0x50);
            cfg.f28 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffff9c,100);
            if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
            }
            cfg.f3c = lbl_803DF53C;
            cfg.f08 = 300;
            cfg.f44 = 0x480000;
            cfg.f48 = 0x2000000;
            cfg.f42 = 0xc0e;
            cfg.f60 = 0xff;
            cfg.f04 = 0x548;
            cfg.f0e = 0;
            cfg.f0c = 0;
            cfg.f18 = lbl_803DF540;
            cfg.f1c = lbl_803DF4DC;
            cfg.f20 = lbl_803DF4DC;
            cfg.f14 = lbl_803DF4D0;
            cfg.f08 = randomGetRange(0,0x14) + 0x28;
            cfg.f61 = 0x10;
            cfg.f44 = (cfg.f44 | 0x20000);
    break;
  case 0x548:
if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
            }
            cfg.f3c = lbl_803DF544;
            cfg.f08 = 0x50;
            cfg.f44 = 0x80201;
            cfg.f48 = 0x2000000;
            cfg.f42 = 0xc0e;
            cfg.f60 = 0xff;
    break;
  case 0x52b: case 0x52c: case 0x52d:
if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        if (param_3 != NULL) {
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
          cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
          cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
        }
        if (randomGetRange(0,0x28) == 0) {
          cfg.f3c = lbl_803DF4D4;
        }
        else {
          cfg.f3c = lbl_803DF514;
        }
        cfg.f08 = 0x14;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80210;
        cfg.f42 = (s16)param_2 + -0x3d5;
    break;
  case 0x52f: case 0x530: case 0x531:
if (param_3 == NULL) {
                *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
                lbl_8039C308[0] = 0;
                lbl_8039C308[1] = 0;
                lbl_8039C308[2] = 0;
                lbl_8039C308[3] = 0;
                param_3 = lbl_8039C308;
              }
              if (param_3 != NULL) {
                cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
                cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
                cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
                cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
                cfg.f2c = lbl_803DF4D8;
              }
              cfg.f3c = lbl_803DF514;
              cfg.f08 = 100;
    break;
  case 0x53c:

          if (param_6 != NULL) {
            iVar8 = (int)(lbl_803DF548 * (lbl_803DF4D0 - *param_6));
            cfg.f60 = (u8)iVar8;
            fn_80137948(sModgfxAlphaDebugFormat, iVar8);
          }
          cfg.f3c = lbl_803DF54C;
          cfg.f44 = 0x80000;
          cfg.f48 = 0x2000002;
          cfg.f08 = 0;
          cfg.f42 = 0xe4;
    break;
  case 0x53d:
cfg.f60 = 0x69;
            cfg.f3c = lbl_803DF550;
            cfg.f44 = 0x80014;
            cfg.f48 = 0x22;
            cfg.f08 = 0;
            cfg.f42 = 0x4fe;
            cfg.f58 = 0xb1df;
            cfg.f5a = 0xb1df;
            cfg.f5c = 0xffff;
            cfg.f4c = 0xb1df;
            cfg.f50 = 0xb1df;
            cfg.f54 = 0xffff;
            (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
            cfg.f38 = lbl_803DF554;
            cfg.f60 = 0x69;
            cfg.f3c = lbl_803DF558;
            cfg.f44 = 0x80014;
            cfg.f48 = 0x22;
            cfg.f58 = 0xffff;
            cfg.f5a = 0xb1df;
            cfg.f5c = 0xffff;
            cfg.f4c = 0xffff;
            cfg.f50 = 0xb1df;
            cfg.f54 = 0xffff;
            cfg.f08 = 0;
            cfg.f42 = 0x4ff;
            (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
            cfg.f38 = lbl_803DF55C;
            cfg.f60 = 0x69;
            cfg.f3c = lbl_803DF560;
            cfg.f44 = 0x80014;
            cfg.f48 = 0x22;
            cfg.f58 = 0xb1df;
            cfg.f5a = 0xffff;
            cfg.f5c = 0xffff;
            cfg.f4c = 0xb1df;
            cfg.f50 = 0xffff;
            cfg.f54 = 0xffff;
            cfg.f08 = 0;
            cfg.f42 = 0x4fe;
    break;
  case 0x53e:
cfg.f30 = lbl_803DF564;
            cfg.f3c = lbl_803DF508;
            cfg.f44 = 0x80010;
            cfg.f48 = 2;
            cfg.f08 = 1;
            cfg.f42 = 100;
    break;
  case 0x53f:

          cfg.f60 = 0x37;
          cfg.f3c = lbl_803DF4CC;
          cfg.f44 = 0x80010;
          cfg.f48 = 2;
          cfg.f08 = 1;
          cfg.f42 = 0x156;
    break;
  case 0x532:

              if (param_3 == NULL) {
                *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
                lbl_8039C308[0] = 0;
                lbl_8039C308[1] = 0;
                lbl_8039C308[2] = 0;
                lbl_8039C308[3] = 0;
                param_3 = lbl_8039C308;
              }
              if (param_3 == NULL) {
                return -1;
              }
              cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
              cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
              cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
              cfg.f24 = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f28 = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f2c = lbl_803DF56C * (f32)(s32)randomGetRange(0x14,0x1e);
              rot.m[1] = lbl_803DF4DC;
              rot.m[2] = lbl_803DF4DC;
              rot.m[3] = lbl_803DF4DC;
              rot.m[0] = lbl_803DF4D0;
              rot.z = param_1[2];
              rot.y = param_1[1];
              rot.x = *(s16 *)param_1;
              vecRotateZXY((s16 *)&rot,&cfg.f24);
              cfg.f60 = 0xcd;
              cfg.f44 = 0x100110;
              cfg.f3c = lbl_803DF570 * (f32)(s32)randomGetRange(0x96,200);
              cfg.f08 = 0x28;
              cfg.f42 = 0x89;
    break;
  case 0x533:
if (param_3 == NULL) {
                *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
                *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
                lbl_8039C308[0] = 0;
                lbl_8039C308[1] = 0;
                lbl_8039C308[2] = 0;
                lbl_8039C308[3] = 0;
                param_3 = lbl_8039C308;
              }
              if (param_3 == NULL) {
                return -1;
              }
              cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
              cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
              cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
              cfg.f24 = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f28 = lbl_803DF4E8 * (f32)(s32)randomGetRange(8,10);
              cfg.f2c = lbl_803DF574 * (f32)(s32)randomGetRange(10,0x1e);
              rot.m[1] = lbl_803DF4DC;
              rot.m[2] = lbl_803DF4DC;
              rot.m[3] = lbl_803DF4DC;
              rot.m[0] = lbl_803DF4D0;
              rot.z = param_1[2];
              rot.y = param_1[1];
              rot.x = *(s16 *)param_1;
              vecRotateZXY((s16 *)&rot,&cfg.f24);
              cfg.f3c = lbl_803DF4D4 * (f32)(s32)randomGetRange(8,0x14);
              cfg.f08 = randomGetRange(0x3c,0x78);
              cfg.f44 = 0x80180000;
              cfg.f48 = 0x1400020;
              cfg.f42 = 0xc0b;
              cfg.f60 = 0x7f;
              cfg.f58 = 0xffff;
              cfg.f5a = 0xffff;
              cfg.f5c = 0xffff;
              cfg.f4c = 0x3caf;
              cfg.f50 = 0x3caf;
              cfg.f54 = 0x3caf;
    break;
  case 0x535:
if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
              param_3 = lbl_8039C308;
            }
            if (param_3 == NULL) {
              return -1;
            }
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f24 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f28 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f2c = lbl_803DF578 * (f32)(s32)randomGetRange(0x14,0x1e);
            rot.m[1] = lbl_803DF4DC;
            rot.m[2] = lbl_803DF4DC;
            rot.m[3] = lbl_803DF4DC;
            rot.m[0] = lbl_803DF4D0;
            rot.z = param_1[2];
            rot.y = param_1[1];
            rot.x = *(s16 *)param_1;
            vecRotateZXY((s16 *)&rot,&cfg.f24);
            cfg.f60 = 0xff;
            cfg.f3c = lbl_803DF57C * (f32)(s32)randomGetRange(0x96,200);
            cfg.f44 = 0x2000110;
            cfg.f48 = 0x2200000;
            cfg.f08 = 0x19;
            cfg.f42 = 0x24;
    break;
  case 0x534:

            cfg.f34 = lbl_803DF580;
            cfg.f24 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0xfffffff1,0xf);
            cfg.f28 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0xfffffff1,0xf);
            cfg.f2c = lbl_803DF584;
            rot.m[1] = lbl_803DF4DC;
            rot.m[2] = lbl_803DF4DC;
            rot.m[3] = lbl_803DF4DC;
            rot.m[0] = lbl_803DF4D0;
            rot.z = param_1[2];
            rot.y = param_1[1];
            rot.x = *(s16 *)param_1;
            vecRotateZXY((s16 *)&rot,&cfg.f24);
            cfg.f60 = 0xff;
            cfg.f3c = lbl_803DF588 * (f32)(s32)randomGetRange(10,0x14);
            cfg.f44 = 0x2000110;
            cfg.f48 = 0x200000;
            cfg.f08 = 0x19;
            cfg.f42 = 0x156;
    break;
  case 0x52a:

        if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        if (param_3 == NULL) {
          return -1;
        }
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f3c = lbl_803DF58C;
        cfg.f08 = 10;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80440202;
        cfg.f42 = 0x4f9;
        cfg.f48 = 0x2000000;
    break;
  case 0x51f:

          cfg.f34 = lbl_803DF590;
          cfg.f3c = lbl_803DF594;
          cfg.f08 = 0x1e;
          cfg.f60 = 0xff;
          cfg.f61 = 0x10;
          cfg.f44 = 0x88140200;
          cfg.f42 = 0x159;
    break;
  case 0x51e:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          if (param_3 == NULL) {
            return -1;
          }
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          cfg.f3c = lbl_803DF598;
          cfg.f08 = 10;
          cfg.f60 = 0xff;
          cfg.f61 = 0x10;
          cfg.f44 = 0x80440202;
          cfg.f42 = 0x156;
    break;
  case 0x51c:
cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
          cfg.f34 = lbl_803DF59C;
          cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
          cfg.f28 = lbl_803DF4E0 * (f32)(s32)randomGetRange(0x19,0x23);
          cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(100,0x96);
          cfg.f08 = randomGetRange(0x5a,0x78);
          cfg.f44 = 0x80100100;
          cfg.f42 = 0x60;
          cfg.f58 = 0x7fff;
          cfg.f5a = 0x7fff;
          cfg.f5c = 0x7fff;
          cfg.f4c = randomGetRange(0,10) * 0xacf;
          cfg.f48 = 0x20;
          cfg.f50 = cfg.f4c;
          cfg.f54 = cfg.f4c;
    break;
  case 0x51b:

          cfg.f3c = lbl_803DF568 * (f32)(s32)randomGetRange(0,0xf) + lbl_803DF550;
          cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffce,0x32);
          cfg.f34 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffce,0x32) + lbl_803DF580;
          cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffce,0x32);
          cfg.f24 = cfg.f30 / lbl_803DF5A4;
          cfg.f28 = cfg.f34 / lbl_803DF5A4;
          cfg.f2c = cfg.f38 / lbl_803DF5A4;
          cfg.f08 = randomGetRange(0,0x14) + 0x14;
          cfg.f60 = 0xff;
          cfg.f44 = 0x100110;
          cfg.f42 = 0xe4;
    break;
  case 0x2bc: case 0x2bd: case 0x2be:
if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
              param_3 = lbl_8039C308;
            }
            if (param_3 != NULL) {
              cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
              cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
              cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
              cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
              cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
              cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
            }
            cfg.f3c = lbl_803DF5A8;
            cfg.f08 = 0x14;
            cfg.f60 = 0xff;
            cfg.f44 = 0x80210;
            cfg.f48 = 0x100;
            cfg.f42 = (s16)param_2 - 0x28c;
    break;
  case 0x4b:

        cfg.f3c = lbl_803DF5AC;
        cfg.f08 = 0x14;
        cfg.f61 = 0;
        cfg.f44 = 0x80100;
        cfg.f42 = 0xdf;
    break;
  case 0x3c:

            cfg.f34 = lbl_803DF5B0;
            cfg.f3c = lbl_803DF5B4 * (f32)(s32)randomGetRange(1,10) + lbl_803DF550;
            cfg.f60 = 0xff;
            cfg.f0c = randomGetRange(0,0xffff);
            cfg.f0e = randomGetRange(0,0xffff);
            cfg.f0c = randomGetRange(0,0xffff);
            cfg.f18 = lbl_803DF4DC;
            cfg.f1c = lbl_803DF4DC;
            cfg.f20 = lbl_803DF4DC;
            cfg.f08 = randomGetRange(0,0x14) + 0x28;
            cfg.f61 = 0x10;
            cfg.f44 = 0x6100214;
            cfg.f42 = 0xc79;
    break;
  case 0x329:
cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f34 = lbl_803DF5B8;
            cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f24 = lbl_803DF4C8 * (f32)(s32)randomGetRange(100,200);
            cfg.f28 = lbl_803DF4C8 * (f32)(s32)randomGetRange(100,200);
            cfg.f2c = lbl_803DF4C8 * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f44 = 0x1081010;
            if (randomGetRange(0,3) == 0) {
              cfg.f3c = lbl_803DF5BC * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f60 = 0x8c;
            }
            else {
              cfg.f3c = lbl_803DF5C0 * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f60 = 10;
              cfg.f44 = (cfg.f44 | 0x100000);
            }
            if (randomGetRange(0,10) == 0) {
              param_4 = param_4 ^ 4 | 1;
            }
            cfg.f08 = 0xdc;
            cfg.f58 = 0xb1df;
            cfg.f5a = 0x8acf;
            cfg.f5c = 0x63bf;
            cfg.f4c = 0x3caf;
            cfg.f50 = 0x30f7;
            cfg.f54 = 10000;
            cfg.f48 = 0x100020;
            cfg.f42 = 0x60;
    break;
  case 0x3b9:

          cfg.f24 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffffec,0x14);
          cfg.f2c = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xffffffec,0x14);
          cfg.f30 = (f32)(s32)randomGetRange(0xffffffce,0x32);
          cfg.f38 = (f32)(s32)randomGetRange(0xffffffce,0x32);
          cfg.f34 = (f32)(s32)randomGetRange(0x1e,100);
          cfg.f3c = lbl_803DF4CC;
          cfg.f08 = 0x4b0;
          cfg.f60 = 200;
          cfg.f44 = 0x180100;
          cfg.f42 = 0x62;
    break;
  case 0x3b8:
          cfg.f30 = lbl_803DF5C4 * (f32)(s32)(0x3c - randomGetRange(0,0x78));
          cfg.f34 = lbl_803DF580;
          cfg.f38 = lbl_803DF5C4 * (f32)(s32)(0x3cU - randomGetRange(0,0x78));
          cfg.f24 = lbl_803DF4E0 * (f32)(s32)(0x28U - randomGetRange(0,0x50));
          cfg.f2c = lbl_803DF4E0 * (f32)(s32)(0x28 - randomGetRange(0,0x50));
          cfg.f28 = lbl_803DF4E0 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f08 = 0xb4;
          cfg.f61 = 0;
          cfg.f44 = 0x80400201;
          cfg.f42 = 0x47;
    break;
  case 0x1:
cfg.f34 = lbl_803DF5C8;
                cfg.f24 = lbl_803DF568 * (lbl_803DB7A8 * (f32)(s32)randomGetRange(0xfffffff1,0xf));
                cfg.f28 = lbl_803DF5B4 * (f32)(s32)randomGetRange(5,0x14);
                cfg.f2c = lbl_803DF568 * (lbl_803DB7A8 * (f32)(s32)randomGetRange(0xfffffff1,0xf));
                cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(0,10) + lbl_803DF5B4;
                cfg.f60 = 0xff;
                cfg.f61 = 0xf;
                cfg.f44 = 0x588008;
                cfg.f48 = 0x10000;
                cfg.f42 = 0x23b;
                cfg.f04 = 4;
    break;
  case 0x4:
cfg.f28 = lbl_803DF5CC * (f32)(s32)randomGetRange(10,0x14);
              cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(0,10) + lbl_803DF5D0;
              cfg.f08 = 0x3c;
              cfg.f60 = 0xcd;
              cfg.f61 = 6;
              cfg.f44 = 0xa100200;
              cfg.f42 = 0x47;
    break;
  case 0x3:
if (param_3 == NULL) {
                return -1;
              }
              cfg.f34 = lbl_803DF4D8 * (f32)(s32)randomGetRange(0x14,0x3c);
              cfg.f3c = lbl_803DF5D4;
              cfg.f08 = 0x23;
              cfg.f60 = 0x96;
              cfg.f61 = 0x14;
              cfg.f44 = 0x9100110;
              cfg.f48 = 0x4000000;
              cfg.f42 = ((PartFxSpawnParams *)param_3)->unk4;
    break;
  case 0x5:

            if (param_3 == NULL) {
              return -1;
            }
            cfg.f30 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f34 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f38 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f28 = lbl_803DF4E4 * (f32)(s32)randomGetRange(0xf,0x23);
            cfg.f3c = lbl_803DF5DC * (f32)(s32)randomGetRange(100,0x96);
            cfg.f08 = randomGetRange(0x32,0x50);
            cfg.f61 = randomGetRange(10,0x1e);
            cfg.f44 = 0x100218;
            cfg.f48 = 0x4000000;
            cfg.f42 = ((PartFxSpawnParams *)param_3)->unk4;
            if (cfg.f42 == 0x4c) {
              cfg.f58 = 0x6400;
              cfg.f5a = 0x3200;
              cfg.f5c = 0xa000;
              cfg.f4c = 500;
              cfg.f50 = 0;
              cfg.f54 = 1000;
              cfg.f48 = 0x4000020;
            }
    break;
  case 0x7:
if (param_3 == NULL) {
                return -1;
              }
              cfg.f30 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f34 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f38 = lbl_803DF5D8 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
              cfg.f24 = lbl_803DF5E0 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f28 = lbl_803DF5E0 * (f32)(s32)randomGetRange(10,0x28);
              cfg.f2c = lbl_803DF5E0 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f3c = lbl_803DF568;
              cfg.f08 = randomGetRange(0x14,0x32);
              cfg.f61 = 0x1e;
              cfg.f44 = 0x511;
              cfg.f48 = 0x4000000;
              cfg.f42 = ((PartFxSpawnParams *)param_3)->unk4;
    break;
  case 0x7b:
cfg.f34 = lbl_803DF5E4 + (f32)(s32)randomGetRange(0,10);
              cfg.f28 = lbl_803DF5E8;
              cfg.f3c = lbl_803DF508;
              cfg.f08 = 0x50;
              cfg.f61 = 0;
              cfg.f44 = 0x8100208;
              cfg.f42 = 0x91;
    break;
  case 0x7f:

          cfg.f3c = lbl_803DF5EC;
          cfg.f08 = 100;
          cfg.f60 = 0x37;
          cfg.f44 = 0x400100;
          switch (cfg.f10) {
          case 0:
            cfg.f42 = 0x15e;
            break;
          case 1:
            cfg.f42 = 0x15f;
            break;
          case 2:
            cfg.f42 = 0x15d;
            break;
          default:
            cfg.f42 = 0x15e;
            break;
          }
          cfg.f10 = 0;
    break;
  case 0x7c:

            cfg.f24 = lbl_803DF5F0 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f2c = lbl_803DF5F0 * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
            cfg.f3c = lbl_803DF5F8;
            cfg.f08 = 300;
            cfg.f61 = 0;
            cfg.f44 = 0x41001c;
            cfg.f42 = 0xc13;
    break;
  case 0x7d:
cfg.f3c = lbl_803DF568;
            cfg.f08 = 0x14;
            cfg.f61 = 0;
            cfg.f60 = 0x32;
            cfg.f44 = 0x400100;
            cfg.f42 = 0xc13;
    break;
  case 0x7e:
cfg.f08 = 0x32;
            cfg.f44 = 0x400100;
            cfg.f24 = lbl_803DF4EC * (f32)(s32)randomGetRange(0xfffffffc,4);
            cfg.f2c = lbl_803DF4EC * (f32)(s32)randomGetRange(0xfffffffc,4);
            cfg.f28 = lbl_803DF5D0 * (f32)(s32)randomGetRange(0x28,0x50);
            cfg.f3c = lbl_803DF5FC * (f32)(s32)randomGetRange(0x28,0x50);
            switch (cfg.f10) {
            case 0:
              cfg.f42 = 0xdd;
              break;
            case 1:
              cfg.f42 = 0x160;
              break;
            case 2:
              cfg.f42 = 0xdf;
              break;
            }
            cfg.f10 = 0;
    break;
  case 0x3e7:

          cfg.f08 = 300;
          cfg.f44 = 0x80400500;
          cfg.f24 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0xfffffffc,4);
          cfg.f2c = lbl_803DF550 * (f32)(s32)randomGetRange(0xfffffffc,4);
          cfg.f28 = lbl_803DF568 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f3c = lbl_803DF5FC * (f32)(s32)randomGetRange(0x28,0x50);
          if (cfg.f10 == 1) {
            cfg.f42 = 0x160;
          }
          else if (cfg.f10 < 1) {
            if (cfg.f10 < 0) {
LAB_800a990c:
              cfg.f42 = 0xdf;
            }
            else {
              cfg.f42 = 0xdd;
            }
          }
          else {
            if (2 < cfg.f10) goto LAB_800a990c;
            cfg.f42 = 0xdf;
          }
          cfg.f10 = 0;
    break;
  case 0x80:
cfg.f3c = lbl_803DF5CC;
              cfg.f08 = 2;
              cfg.f61 = 0;
              cfg.f60 = 0x32;
              cfg.f44 = 0x400110;
              cfg.f42 = 0xdf;
    break;
  case 0x81:

              cfg.f30 = (f32)(s32)randomGetRange(0xffffff1a,0xe6);
              cfg.f34 = (f32)(s32)randomGetRange(0xffffffce,0xfa);
              cfg.f38 = (f32)(s32)randomGetRange(0xffffff1a,0xe6);
              cfg.f3c = lbl_803DF600;
              cfg.f08 = 200;
              cfg.f61 = 0x10;
              cfg.f44 = 0x80000108;
              cfg.f42 = 0x165;
    break;
  case 0x82:
cfg.f30 = (f32)(s32)randomGetRange(0xffffff60,0xa0);
              cfg.f34 = (f32)(s32)randomGetRange(0xffffffce,0xfa);
              cfg.f30 = (f32)(s32)randomGetRange(0xffffff60,0xa0);
              cfg.f3c = lbl_803DF600;
              cfg.f08 = 200;
              cfg.f61 = 0x10;
              cfg.f44 = 0x80000108;
              cfg.f42 = 0x166;
    break;
  case 0x83:

            cfg.f30 = (f32)(s32)randomGetRange(0xffffff60,0xa0);
            cfg.f34 = (f32)(s32)randomGetRange(0xffffffce,0xfa);
            cfg.f30 = (f32)(s32)randomGetRange(0xffffff60,0xa0);
            cfg.f3c = lbl_803DF600;
            cfg.f08 = 200;
            cfg.f61 = 0x10;
            cfg.f44 = 0x80000108;
            cfg.f42 = 0x167;
    break;
  case 0x71:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffffe,2);
      cfg.f34 = lbl_803DF604;
      cfg.f38 = (f32)(s32)randomGetRange(0xfffffff0,0x10);
      cfg.f28 = lbl_803DF608 * (f32)(s32)randomGetRange(0xfffffffd,0xffffffff);
      cfg.f3c = lbl_803DF60C * (f32)(s32)randomGetRange(1,3);
      cfg.f08 = 100;
      cfg.f60 = 0x7d;
      cfg.f61 = 0x10;
      cfg.f44 = 0x80000100;
      cfg.f42 = 0x2c;
    break;
  case 0x6d:

      if (param_3 == NULL) {
        *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
        *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
        lbl_8039C308[0] = 0;
        lbl_8039C308[1] = 0;
        lbl_8039C308[2] = 0;
        lbl_8039C308[3] = 0;
        param_3 = lbl_8039C308;
      }
      if (param_3 == NULL) {
        return -1;
      }
      cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
      cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
      cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
      cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8;
      cfg.f08 = 1;
      cfg.f61 = 0;
      cfg.f60 = 0x19;
      if (((PartFxSpawnParams *)param_3)->unk4 != 0) {
        cfg.f60 = 0x7d;
      }
      cfg.f44 = 0xc0012;
      cfg.f42 = 0x77;
    break;
  case 0x6a:

      cfg.f30 = lbl_803DF4D0 * (f32)(s32)randomGetRange(0xfffffff6,10);
      cfg.f34 = lbl_803DF4DC;
      cfg.f38 = lbl_803DF4D0 * (f32)(s32)randomGetRange(0xfffffff6,10);
      cfg.f24 = lbl_803DF4DC;
      cfg.f28 = lbl_803DF5D4 * (f32)(s32)randomGetRange(1,3);
      cfg.f2c = lbl_803DF4DC;
      cfg.f3c = lbl_803DF4F0;
      cfg.f08 = 0x78;
      cfg.f60 = 0xff;
      cfg.f61 = 0x10;
      cfg.f44 = 0x100200;
      cfg.f42 = 0x5f;
    break;
  case 0x66:
cfg.f61 = 0x20;
          cfg.f3c = lbl_803DF610;
          cfg.f08 = 0x50;
          cfg.f04 = 0x67;
          cfg.f44 = 0x400000;
          cfg.f42 = 0x156;
    break;
  case 0x67:

        cfg.f3c = lbl_803DF610;
        cfg.f08 = 0x1e;
        cfg.f60 = 0xff;
        cfg.f44 = 0x200;
        cfg.f42 = randomGetRange(0,2);
        cfg.f42 = cfg.f42 + 0x156;
    break;
  case 0x68:
cfg.f24 = lbl_803DF5EC * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f28 = lbl_803DF5EC * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f2c = lbl_803DF5EC * (f32)(s32)randomGetRange(0xfffffff6,10);
        cfg.f3c = lbl_803DF614;
        cfg.f08 = 0x69;
        cfg.f44 = 0x480200;
        cfg.f42 = 0x156;
    break;
  case 0x65:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          if (param_3 == NULL) {
            return -1;
          }
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          cfg.f4c = 0xffff;
          cfg.f50 = 0xffff;
          cfg.f54 = 0xffff;
          cfg.f58 = 0;
          cfg.f5a = 0;
          cfg.f5c = 0;
          cfg.f3c = lbl_803DF598;
          cfg.f08 = 100;
          cfg.f60 = 0xff;
          cfg.f48 = 0x20;
          cfg.f42 = 0x30;
    break;
  case 0x72:

    cfg.f3c = lbl_803DF618 * (f32)(s32)randomGetRange(1,4);
    cfg.f08 = randomGetRange(0x1e,0x3c);
    cfg.f44 = 0x80100;
    cfg.f48 = 0x4000802;
    cfg.f61 = 0;
    cfg.f42 = 0xde;
    cfg.f60 = randomGetRange(0x96,0xfa);
    break;
  case 0x73:
cfg.f3c = lbl_803DF61C * (f32)(s32)randomGetRange(4,5) * lbl_803DF530;
                cfg.f08 = randomGetRange(0x1e,0x28);
                cfg.f44 = 0x0;
                cfg.f48 = 2;
                cfg.f61 = 0x10;
                cfg.f42 = 0xdf;
    break;
  case 0x55:
cfg.f3c = lbl_803DF4E8;
          cfg.f08 = 0x78;
          cfg.f60 = 0xff;
          cfg.f61 = 0x20;
          cfg.f44 = 0xa100201;
          cfg.f42 = 0x56;
    break;
  case 0x59:

          cfg.f24 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f28 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f2c = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(1,0x28);
          cfg.f08 = 0x28;
          cfg.f44 = 0x200;
          cfg.f42 = 0x2b;
    break;
  case 0x51:

      cfg.f3c = lbl_803DF4C8;
      cfg.f08 = 10;
      cfg.f44 = 0x200;
      cfg.f42 = 0x2b;
    break;
  case 0x50:
cfg.f3c = lbl_803DF5CC;
        cfg.f08 = 10;
        cfg.f44 = 0x200;
        cfg.f42 = 0x2b;
    break;
  case 0x4d:
cfg.f34 = lbl_803DF620;
        cfg.f3c = lbl_803DF624;
        cfg.f08 = 400;
        cfg.f61 = 0;
        cfg.f04 = 0x4e;
        cfg.f44 = 0x20100;
        cfg.f42 = 0xdf;
        cfg.f18 = lbl_803DF4DC;
        cfg.f1c = lbl_803DF4DC;
        cfg.f20 = lbl_803DF4DC;
        cfg.f14 = lbl_803DF4D0;
        cfg.f10 = randomGetRange(0,200);
        cfg.f10 = 100 - cfg.f10;
        cfg.f0e = randomGetRange(0,200);
        cfg.f0e = 100 - cfg.f0e;
        cfg.f0c = randomGetRange(0,200);
        cfg.f0c = 100 - cfg.f0c;
    break;
  case 0x4e:

        cfg.f24 = lbl_803DF628 * (f32)(s32)(1 - randomGetRange(0,2));
        cfg.f2c = lbl_803DF628 * (f32)(s32)(1U - randomGetRange(0,2));
        cfg.f3c = lbl_803DF62C;
        cfg.f08 = 0x4b;
        cfg.f61 = 0;
        cfg.f44 = 0x200;
        cfg.f42 = 0x7b;
    break;
  case 0x4a:
cfg.f34 = lbl_803DF630;
          cfg.f3c = lbl_803DF634;
          cfg.f08 = 0x78;
          cfg.f61 = 0;
          cfg.f04 = 0x4b;
          cfg.f44 = 0x70000;
          cfg.f42 = randomGetRange(0,3);
          cfg.f42 = cfg.f42 + 0xdd;
          cfg.f18 = lbl_803DF4DC;
          cfg.f1c = lbl_803DF4FC;
          cfg.f20 = lbl_803DF4DC;
          cfg.f14 = lbl_803DF4D0;
          cfg.f10 = 0;
          cfg.f0e = randomGetRange(0,1000);
          cfg.f0e = 500 - cfg.f0e;
          cfg.f0c = randomGetRange(0,1000);
          cfg.f0c = 500 - cfg.f0c;
    break;
  case 0x49:
cfg.f34 = lbl_803DF604;
          cfg.f3c = lbl_803DF530;
          cfg.f08 = 0xe;
          cfg.f60 = 0;
          cfg.f44 = 0x110210;
          cfg.f42 = 0x31;
    break;
  case 0x47:
cfg.f30 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f34 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f38 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
          cfg.f3c = lbl_803DF504;
          cfg.f08 = randomGetRange(4,0xe);
          cfg.f44 = 0x110100;
          cfg.f42 = 0xc22;
    break;
  case 0x42:

        cfg.f30 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
        cfg.f34 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
        cfg.f38 = lbl_803DF4F8 - (f32)(s32)randomGetRange(0,4);
        cfg.f3c = lbl_803DF568;
        cfg.f08 = 1;
        cfg.f44 = 0x70800;
        cfg.f42 = randomGetRange(0,1);
        cfg.f42 = cfg.f42 + 0xdd;
        cfg.f18 = lbl_803DF4DC;
        cfg.f1c = lbl_803DF4DC;
        cfg.f20 = lbl_803DF4DC;
        cfg.f14 = lbl_803DF4D0;
        cfg.f10 = randomGetRange(0,1000);
        cfg.f10 = 500 - cfg.f10;
        cfg.f0e = randomGetRange(0,1000);
        cfg.f0e = 500 - cfg.f0e;
        cfg.f0c = randomGetRange(0,1000);
        cfg.f0c = 500 - cfg.f0c;
    break;
  case 0x40:

          cfg.f34 = (f32)(s32)randomGetRange(0,0x28);
          cfg.f24 = lbl_803DF638 * (f32)(s32)(1U - randomGetRange(0,2));
          cfg.f28 = lbl_803DF638 * (f32)(s32)randomGetRange(1,3);
          cfg.f2c = lbl_803DF638 * (f32)(s32)(1 - randomGetRange(0,2));
          cfg.f3c = lbl_803DF5CC;
          cfg.f08 = 0x96;
          cfg.f44 = 0x108;
          cfg.f42 = 0x5c;
    break;
  case 0x41:
dVar16 = lbl_803DF63C;
dVar15 = lbl_803DF640;
dVar14 = lbl_803DF638;
dVar13 = lbl_803DF5B4;
          for (sVar10 = 0; sVar10 < 0x1e; sVar10 = sVar10 + 1) {
            cfg.f34 = (f32)dVar16;
            cfg.f24 = dVar15 * (f32)(s32)(2 - randomGetRange(0,4));
            cfg.f28 = dVar14 * (f32)(s32)randomGetRange(1,2);
            cfg.f2c = dVar15 * (f32)(s32)(2U - randomGetRange(0,4));
            cfg.f3c = (f32)dVar13;
            cfg.f08 = 0x3c;
            cfg.f44 = 0x108;
            cfg.f42 = 0x5c;
            if ((cfg.f44 & 1) != 0) {
              if (cfg.f00 != NULL) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0xc);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x10);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x14);
              }
              else {
                cfg.f30 = cfg.f30 + cfg.f18;
                cfg.f34 = cfg.f34 + cfg.f1c;
                cfg.f38 = cfg.f38 + cfg.f20;
              }
            }
            (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
          }
    break;
  case 0x55c:
LAB_800aa8ac:
        cfg.f44 = 0x20100100;
        cfg.f08 = 400;
        if (param_2 == 0x3d) {
          cfg.f30 = lbl_803DF580 - (f32)(s32)randomGetRange(0,0x14);
          cfg.f34 = lbl_803DF644;
          cfg.f38 = lbl_803DF580 - (f32)(s32)randomGetRange(0,0x14);
          cfg.f3c = lbl_803DF4EC * (f32)(s32)randomGetRange(1,3);
          cfg.f48 = cfg.f48 | 0x1000000;
        }
        else if (param_2 == 0x3e) {
          cfg.f30 = lbl_803DF580 - (f32)(s32)randomGetRange(0,0x14);
          cfg.f34 = lbl_803DF648;
          cfg.f38 = lbl_803DF580 - (f32)(s32)randomGetRange(0,0x14);
          cfg.f3c = lbl_803DF624 * (f32)(s32)randomGetRange(1,3);
          cfg.f48 = cfg.f48 | 0x1000000;
        }
        else if (param_2 == 0x3f) {
          cfg.f34 = lbl_803DF64C;
          cfg.f08 = 100;
          cfg.f3c = lbl_803DF624 * (f32)(s32)randomGetRange(1,3);
          cfg.f48 = cfg.f48 | 0x1000000;
        }
        else if (param_2 == 0x43) {
          cfg.f30 = lbl_803DF650;
          cfg.f34 = lbl_803DF538;
          cfg.f38 = lbl_803DF564 + (f32)(s32)randomGetRange(0,0x78);
          cfg.f3c = lbl_803DF4E8 * (f32)(s32)randomGetRange(1,8);
          cfg.f44 = (cfg.f44 | 8);
          cfg.f48 = cfg.f48 | 0x1000000;
        }
        else if (param_2 == 0x44) {
          cfg.f30 = lbl_803DF650;
          cfg.f34 = lbl_803DF654;
          cfg.f38 = (f32)(s32)randomGetRange(0,0x78);
          cfg.f28 = lbl_803DF658;
          cfg.f3c = lbl_803DF4E8 * (f32)(s32)randomGetRange(1,8);
          cfg.f48 = cfg.f48 | 0x1000000;
        }
        cfg.f61 = 0x20;
        cfg.f42 = 0x5f;
        cfg.f44 = (cfg.f44 | param_4);
        if ((cfg.f44 & 1) != 0) {
          if (cfg.f00 != NULL) {
            cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
          }
          else {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
          }
        }
        if ((param_2 == 0x3e) || (param_2 == 0x3f)) {
          cfg.f44 = (cfg.f44 | 0x8000000);
        }
    break;
  case 0x3d: case 0x3e: case 0x3f: case 0x43: case 0x44: case 0x4f:
    goto LAB_800aa8ac;
  case 0x48:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
          }
          cfg.f28 = lbl_803DF508 * (f32)(s32)randomGetRange(1,10);
          rot.m[1] = lbl_803DF4DC;
          rot.m[2] = lbl_803DF4DC;
          rot.m[3] = lbl_803DF4DC;
          rot.m[0] = lbl_803DF530;
          rot.z = randomGetRange(0,4000);
          rot.z = 2000 - rot.z;
          rot.y = randomGetRange(0,4000);
          rot.y = 2000 - rot.y;
          rot.x = randomGetRange(0,4000);
          rot.x = 2000 - rot.x;
          vecRotateZXY((s16 *)&rot,&cfg.f24);
          cfg.f3c = lbl_803DF65C;
          cfg.f08 = 0x50;
          cfg.f61 = 8;
          cfg.f44 = 0x100;
          cfg.f42 = 0xdd;
    break;
  case 0x38:
srand(0x4233d);
dVar13 = lbl_803DF644;
dVar14 = lbl_803DF4E8;
dVar15 = lbl_803DF600;
dVar16 = lbl_803DF660;
            for (sVar10 = 0; sVar10 < 0x28; sVar10 = sVar10 + 1) {
              cfg.f34 = (f32)dVar13;
              cfg.f24 = dVar14 * (f32)(s32)(0x50 - randomGetRange(0,0xa0));
              cfg.f2c = dVar14 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
              cfg.f3c = (f32)dVar15;
              cfg.f08 = (u32)(dVar16 * (f32)(s32)randomGetRange(1,4));
              cfg.f44 = 0x100011;
              cfg.f42 = 0x30;
              fVar1 = cfg.f18;
              fVar2 = cfg.f1c;
              fVar3 = cfg.f20;
              if (cfg.f00 != NULL) {
                fVar1 = *(f32 *)((char *)cfg.f00 + 0xc);
                fVar2 = *(f32 *)((char *)cfg.f00 + 0x10);
                fVar3 = *(f32 *)((char *)cfg.f00 + 0x14);
              }
              cfg.f38 = cfg.f38 + fVar3;
              cfg.f34 = cfg.f34 + fVar2;
              cfg.f30 = cfg.f30 + fVar1;
              (*gExpgfxInterface)->spawnEffect(&cfg,0,param_2,0);
            }
    break;
  case 0x35:
              cfg.f30 = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0,0x3c));
              cfg.f34 = lbl_803DF668;
              cfg.f38 = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0,0x3c));
              cfg.f28 = lbl_803DF66C * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f3c = lbl_803DF670 * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f08 = randomGetRange(0x28,0x50);
              cfg.f61 = 0;
              cfg.f44 = 0x80400001;
              cfg.f42 = 0x47;
    break;
  case 0x3a:

          cfg.f30 = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0,0x3c));
          cfg.f34 = lbl_803DF580;
          cfg.f38 = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0,0x3c));
          cfg.f28 = lbl_803DF66C * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f3c = lbl_803DF670 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f08 = 0xb4;
          cfg.f61 = 0;
          cfg.f44 = 0x80400200;
          cfg.f42 = 0x47;
    break;
  case 0x3b:
            cfg.f30 = lbl_803DF624 * (f32)(s32)(0x1e - randomGetRange(0,0x3c));
            cfg.f34 = lbl_803DF604;
            cfg.f38 = lbl_803DF624 * (f32)(s32)(0x1eU - randomGetRange(0,0x3c));
            cfg.f28 = lbl_803DF66C * (f32)(s32)randomGetRange(0x28,0x50);
            cfg.f3c = lbl_803DF670 * (f32)(s32)randomGetRange(0x28,0x50);
            cfg.f08 = 0x78;
            cfg.f61 = 0;
            cfg.f44 = 0x80400201;
            cfg.f42 = 0x47;
    break;
  case 0x53:
          cfg.f30 = lbl_803DF664 * (f32)(s32)(0x1e - randomGetRange(0,0x3c));
          cfg.f38 = lbl_803DF664 * (f32)(s32)(0x1eU - randomGetRange(0,0x3c));
          cfg.f28 = lbl_803DF514 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f3c = lbl_803DF670 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f08 = 0xd2;
          cfg.f44 = 0x80000201;
          cfg.f42 = randomGetRange(0,3);
          cfg.f42 = cfg.f42 + 0xdd;
    break;
  case 0x2e:

        cfg.f3c = lbl_803DF4CC;
        cfg.f08 = 0x30;
        cfg.f61 = 0;
        cfg.f44 = 0x8100210;
        cfg.f42 = 0x5e;
    break;
  case 0x78:
cfg.f34 = (f32)(s32)randomGetRange(0,100);
              cfg.f3c = lbl_803DF4CC;
              cfg.f08 = 0x30;
              cfg.f61 = 0;
              cfg.f44 = 0x8100210;
              cfg.f42 = 0x5e;
    break;
  case 0x3e6:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffffc,4);
          cfg.f38 = (f32)(s32)randomGetRange(0xfffffffc,4);
          cfg.f28 = lbl_803DF674 * (f32)(s32)randomGetRange(4,10);
          cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(0x28,0x50);
          cfg.f08 = 0x15e;
          cfg.f04 = 0x85;
          cfg.f60 = 0xff;
          cfg.f44 = 0x80400201;
          cfg.f42 = 0xdf;
    break;
  case 0x77:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffffc,4);
              cfg.f34 = (f32)(s32)randomGetRange(0,0x28);
              cfg.f38 = (f32)(s32)randomGetRange(0xfffffffc,4);
              cfg.f24 = lbl_803DF600 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f28 = lbl_803DF66C * (f32)(s32)randomGetRange(0,0x50);
              cfg.f2c = lbl_803DF600 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f08 = randomGetRange(0,0x118) + 0x96;
              cfg.f60 = 0xff;
              cfg.f44 = 0x400101;
              cfg.f42 = 0xdf;
    break;
  case 0x7a:
cfg.f30 = (f32)(s32)randomGetRange(0xfffffffc,4);
              cfg.f34 = (f32)(s32)randomGetRange(0,0x23);
              cfg.f38 = (f32)(s32)randomGetRange(0xfffffffc,4);
              cfg.f24 = lbl_803DF600 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f2c = lbl_803DF600 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
              cfg.f28 = lbl_803DF600 * (f32)(s32)randomGetRange(0,0x50);
              cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(0x28,0x50);
              cfg.f08 = randomGetRange(0,0x118) + 0xb4;
              cfg.f60 = 0;
              cfg.f44 = 0xc80404;
              cfg.f42 = 0xdf;
    break;
  case 0x76:

              cfg.f3c = lbl_803DF678 * (f32)(s32)randomGetRange(1,8);
              cfg.f08 = randomGetRange(0,0x32) + 0x26;
              cfg.f60 = 0xff;
              cfg.f18 = lbl_803DF4DC;
              cfg.f1c = lbl_803DF4DC;
              cfg.f20 = lbl_803DF4DC;
              cfg.f44 = 0x6100110;
              cfg.f42 = 0x159;
    break;
  case 0x2f:
cfg.f3c = lbl_803DF608;
          cfg.f08 = 0x32;
          cfg.f61 = 0x20;
          cfg.f44 = 0x400010;
          cfg.f42 = 0x71;
    break;
  case 0x34:

      cfg.f3c = lbl_803DF608;
      cfg.f08 = 0x1e;
      cfg.f61 = 0x20;
      cfg.f44 = 0x400210;
      cfg.f42 = 0x71;
    break;
  case 0x30:
cfg.f3c = lbl_803DF4D0;
          cfg.f08 = 0x14;
          cfg.f44 = 0x400010;
          cfg.f42 = 0x7c;
    break;
  case 0x39:
            if (randomGetRange(0,1) != 0) {
              cfg.f38 = lbl_803DF55C;
            }
            else {
              cfg.f38 = lbl_803DF67C;
            }
            cfg.f3c = lbl_803DF680 * (f32)(s32)randomGetRange(1,4);
            cfg.f08 = randomGetRange(0,0x18) + 0x18;
            cfg.f60 = 0xff;
            cfg.f44 = 0x100;
            cfg.f42 = 0x33;
    break;
  case 0x79:

            if (randomGetRange(0,1) != 0) {
              cfg.f30 = lbl_803DF64C;
            }
            else {
              cfg.f30 = lbl_803DF684;
            }
            cfg.f34 = (f32)(s32)randomGetRange(10,0x3c);
            cfg.f38 = (f32)(s32)randomGetRange(0xfffffffd,3);
            cfg.f28 = lbl_803DF4E8 * (f32)(s32)randomGetRange(1,0x14);
            cfg.f3c = lbl_803DF5D0 * (f32)(s32)randomGetRange(1,7);
            cfg.f08 = randomGetRange(0,0xf) + 0xf;
            cfg.f60 = 0x9b;
            cfg.f44 = 0x100100;
            cfg.f42 = 0x156;
    break;
  case 0x75:
cfg.f3c = lbl_803DF638;
                cfg.f08 = 0x62;
                cfg.f60 = 0xff;
                cfg.f40 = 0xa9;
                cfg.f61 = 0;
                cfg.f44 = 0x8100210;
                cfg.f42 = 0x159;
    break;
  case 0x32:
cfg.f3c = lbl_803DF5E0;
        cfg.f08 = 0x96;
        cfg.f44 = 0x400012;
        cfg.f42 = 0x7c;
    break;
  case 0x33:
cfg.f34 = lbl_803DF644;
        cfg.f3c = lbl_803DF62C;
        cfg.f08 = 0x55;
        cfg.f44 = 0x400012;
        cfg.f42 = 0x7c;
    break;
  case 0x69:
cfg.f3c = lbl_803DF688;
        cfg.f08 = 0x44;
        cfg.f44 = 0x100201;
        cfg.f42 = 0x60;
    break;
  case 0x2:

              cfg.f30 = lbl_803DF638 * (f32)(s32)randomGetRange(0xffffffec,0x14);
              cfg.f34 = lbl_803DF638 * (f32)(s32)randomGetRange(0xffffffec,0x14);
              cfg.f38 = lbl_803DF638 * (f32)(s32)randomGetRange(0xffffffec,0x14);
              cfg.f3c = lbl_803DF4C8 * (f32)(s32)randomGetRange(0,0x1e) + lbl_803DF68C;
              cfg.f08 = randomGetRange(0,8) + 8;
              cfg.f60 = 0xff;
              cfg.f44 = 0x100100;
              cfg.f42 = 0x33;
    break;
  case 0x2a:
cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
          cfg.f34 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
          cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffffe2,0x1e);
          cfg.f3c = lbl_803DF4D4 * (f32)(s32)randomGetRange(0,10) + lbl_803DF62C;
          cfg.f08 = randomGetRange(0x14,0x32);
          cfg.f60 = 0x9b;
          cfg.f61 = 0xe;
          cfg.f44 = 0x100110;
          if (param_6 == NULL) {
            cfg.f42 = 0x88;
          }
          else {
            cfg.f42 = 0x78;
          }
    break;
  case 0x37:

            cfg.f3c = lbl_803DF4E4;
            cfg.f08 = 0x14;
            cfg.f40 = 0x9a;
            cfg.f44 = 0x100210;
            cfg.f42 = 0x87;
    break;
  case 0x2b:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
          }
          cfg.f24 = lbl_803DF608;
          dVar12 = (f32)(s32)randomGetRange(0,0xfffe);
          dVar13 = (f32)(s32)randomGetRange(0,0xfffe);
          dVar14 = (f32)(s32)randomGetRange(0,0xfffe);
          rot.m[1] = lbl_803DF4DC;
          rot.m[2] = lbl_803DF4DC;
          rot.m[3] = lbl_803DF4DC;
          rot.m[0] = lbl_803DF4D0;
          rot.z = dVar14;
          rot.y = dVar13;
          rot.x = dVar12;
          vecRotateZXY((s16 *)&rot,&cfg.f24);
          cfg.f3c = lbl_803DF690;
          cfg.f08 = 0x32;
          cfg.f40 = 0;
          cfg.f44 = 0x100;
          cfg.f42 = 0x30;
    break;
  case 0x2c:
cfg.f3c = lbl_803DF4E8;
          cfg.f08 = 10;
          cfg.f61 = 0;
          cfg.f44 = 0x80211;
          cfg.f42 = 0x3ff;
    break;
  case 0x28:

        cfg.f3c = lbl_803DF4CC;
        cfg.f08 = 0x46;
        cfg.f44 = 0xb100200;
        cfg.f42 = 0x74;
    break;
  case 0x31:

        cfg.f3c = lbl_803DF694;
        cfg.f08 = 0x46;
        cfg.f61 = 0;
        cfg.f44 = 0xb100200;
        cfg.f42 = 0x74;
    break;
  case 0x2d:
cfg.f34 = lbl_803DF644;
          cfg.f24 = lbl_803DF4E8 * (f32)(s32)(0x50 - randomGetRange(0,0xa0));
          cfg.f2c = lbl_803DF4E8 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
          cfg.f3c = lbl_803DF600;
          cfg.f08 = (u32)(lbl_803DF660 * (f32)(s32)randomGetRange(1,4));
          cfg.f44 = 0x100000;
          cfg.f42 = 0x30;
    break;
  case 0x25:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          if (param_3 == NULL) {
            return -1;
          }
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC + (f32)(s32)randomGetRange(0,6);
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14 + (f32)(s32)randomGetRange(0,6);
          cfg.f28 = lbl_803DF634 * (f32)(s32)randomGetRange(0,10);
          cfg.f3c = lbl_803DF5B4 * (f32)(s32)randomGetRange(4,8);
          cfg.f08 = 0x24;
          cfg.f60 = 0x41;
          cfg.f44 = 0x100112;
          cfg.f42 = 0x61;
    break;
  case 0x36:
if (param_6 == NULL) {
                return -1;
              }
              cfg.f3c = lbl_803DF568;
              cfg.f08 = 0x20;
              cfg.f60 = 0xff;
              cfg.f61 = 0x20;
              cfg.f44 = 0x1100201;
              cfg.f42 = 0x249;
    break;
  case 0x26:
cfg.f30 = (f32)(s32)randomGetRange(0xffffffff,1);
          if (param_6 != NULL) {
            cfg.f30 = cfg.f30 + param_6[1];
          }
          cfg.f34 = lbl_803DF4DC;
          cfg.f38 = (f32)(s32)randomGetRange(0xffffffff,1);
          cfg.f28 = lbl_803DF608;
          cfg.f3c = lbl_803DF4E0;
          if (param_6 == NULL) {
            cfg.f08 = 0x78;
          }
          else {
            cfg.f08 = (u32)*param_6;
          }
          cfg.f61 = 0;
          cfg.f44 = 0x100201;
          cfg.f42 = 99;
          rot.m[1] = lbl_803DF4DC;
          rot.m[2] = lbl_803DF4DC;
          rot.m[3] = lbl_803DF4DC;
          rot.m[0] = lbl_803DF4D0;
          rot.z = 0;
          rot.y = 0;
          rot.x = *(s16 *)param_1;
          vecRotateZXY((s16 *)&rot,&cfg.f30);
    break;
  case 0xc:
cfg.f3c = lbl_803DF4F0;
              cfg.f08 = 0x8a;
              cfg.f44 = 0x10000;
              cfg.f42 = 0x30;
    break;
  case 0xd:

              cfg.f3c = lbl_803DF4F0;
              cfg.f08 = 0x8a;
              cfg.f44 = 0x10000;
              cfg.f42 = 0x30;
    break;
  case 0xe:
cfg.f34 = lbl_803DF604;
              cfg.f3c = lbl_803DF4F0;
              cfg.f08 = 0x8a;
              cfg.f44 = 0x10002;
              cfg.f42 = 0x30;
    break;
  case 0x0:

                cfg.f3c = lbl_803DF4E8;
                cfg.f08 = 6;
                cfg.f40 = 0;
                cfg.f44 = 0x10;
                cfg.f42 = 0x87;
    break;
  case 0xf:

            cfg.f30 = lbl_803DF698;
            cfg.f34 = lbl_803DF630;
            cfg.f38 = lbl_803DF590;
            cfg.f24 = lbl_803DF4E4 * (f32)(s32)(0x50 - randomGetRange(0,0xa0));
            cfg.f2c = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
            cfg.f3c = lbl_803DF4E0;
            cfg.f08 = (u32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0,3) + 1U));
            cfg.f44 = 0x110214;
            cfg.f42 = 0x30;
    break;
  case 0x11:
            cfg.f24 = lbl_803DF4E4 * (f32)(s32)(0x50 - randomGetRange(0,0xa0));
            cfg.f28 = lbl_803DF608 * (f32)(s32)randomGetRange(0,0x50);
            cfg.f2c = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
            cfg.f3c = lbl_803DF4E0;
            cfg.f08 = (u32)(lbl_803DF660 * (f32)(s32)(randomGetRange(0,3) + 1U));
            cfg.f44 = 0x1110214;
            cfg.f42 = 0x33;
    break;
  case 0x19:

          cfg.f24 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f28 = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f2c = lbl_803DF4E8 * (f32)(s32)randomGetRange(0xfffffff6,10);
          cfg.f3c = lbl_803DF4C8;
          cfg.f08 = 0x32;
          cfg.f44 = 0x211;
          cfg.f42 = 0x30;
    break;
  case 0x1a:
          cfg.f24 = lbl_803DF4F0 * (f32)(s32)(10 - randomGetRange(0,0x14));
          cfg.f28 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0,0x3c);
          cfg.f2c = lbl_803DF4F0 * (f32)(s32)(10U - randomGetRange(0,0x14));
          cfg.f3c = lbl_803DF690 * (f32)(s32)randomGetRange(0,4);
          cfg.f08 = (u32)(lbl_803DF69C * (f32)(s32)(randomGetRange(0,3) + 1U));
          cfg.f44 = 0x1000211;
          cfg.f42 = 0x30;
    break;
  case 0x1b:

        cfg.f28 = lbl_803DF4F0 * (f32)(s32)randomGetRange(0,0x3c);
        cfg.f3c = lbl_803DF690 * (f32)(s32)randomGetRange(0,4);
        cfg.f08 = (u32)(lbl_803DF6A0 * (f32)(s32)(randomGetRange(0,3) + 1U));
        cfg.f61 = 5;
        cfg.f44 = 0x1000211;
        cfg.f42 = 0x30;
    break;
  case 0x20:
cfg.f34 = lbl_803DF5B8;
            cfg.f3c = lbl_803DF62C;
            cfg.f08 = 200;
            cfg.f60 = 0x9b;
            cfg.f44 = 0x12;
            cfg.f42 = 0x22d;
    break;
  case 0x21:
            cfg.f30 = (f32)(s32)(10 - randomGetRange(0,0x14));
            cfg.f38 = (f32)(s32)(10U - randomGetRange(0,0x14));
            cfg.f24 = lbl_803DF628;
            cfg.f28 = lbl_803DF6A4;
            cfg.f2c = lbl_803DF628;
            cfg.f3c = lbl_803DF62C;
            cfg.f08 = 0x32;
            cfg.f44 = 0x201;
            cfg.f42 = 0x321;
    break;
  case 0x22:

          cfg.f38 = lbl_803DF4FC;
          cfg.f3c = lbl_803DF4C8;
          cfg.f08 = 0x178e;
          cfg.f60 = 0xff;
          cfg.f61 = 0x10;
          cfg.f44 = 0x14;
          cfg.f42 = 0x30;
    break;
  case 0x23:
cfg.f34 = lbl_803DF580;
            cfg.f3c = lbl_803DF6A8;
            cfg.f08 = 0x69;
            cfg.f44 = 0x400010;
            cfg.f42 = 0x4b;
    break;
  case 0x24:
cfg.f3c = lbl_803DF6A8;
            cfg.f08 = 0x5f;
            cfg.f44 = 0x400212;
            cfg.f42 = 0x4b;
    break;
  case 0x1c:
cfg.f30 = (f32)(s32)randomGetRange(0xffffff38,200);
              cfg.f34 = lbl_803DF6AC;
              cfg.f38 = (f32)(s32)randomGetRange(0xffffff38,200);
              cfg.f24 = lbl_803DF4EC * (f32)(s32)(10U - randomGetRange(0,0x14));
              cfg.f2c = lbl_803DF4EC * (f32)(s32)(10 - randomGetRange(0,0x14));
              cfg.f28 = lbl_803DF68C * (f32)(s32)(10 - randomGetRange(0,0x14));
              cfg.f3c = lbl_803DF6B0;
              cfg.f08 = 0x104;
              cfg.f44 = 0x1000202;
              cfg.f04 = 0x1e;
              cfg.f30 = lbl_803DF4DC;
              cfg.f34 = lbl_803DF540;
              cfg.f38 = lbl_803DF4DC;
              cfg.f2c = lbl_803DF4EC * (f32)(s32)(10 - randomGetRange(0,0x14));
              cfg.f3c = lbl_803DF600;
              cfg.f08 = 0xa0;
              cfg.f44 = 0x11000204;
              cfg.f42 = 0x151;
    break;
  case 0x74:

                cfg.f30 = (f32)(s32)randomGetRange(0xffffffb0,0x50);
                cfg.f34 = lbl_803DF4DC;
                cfg.f38 = (f32)(s32)randomGetRange(0xffffffb0,0x50);
                cfg.f28 = lbl_803DF4CC * (f32)(s32)randomGetRange(1,4);
                cfg.f3c = lbl_803DF5AC;
                cfg.f08 = 0x140;
                cfg.f60 = 0xff;
                cfg.f44 = 0x1000204;
                cfg.f42 = 0x151;
    break;
  case 0x1d:

              cfg.f34 = lbl_803DF6B4;
              cfg.f38 = lbl_803DF6B8;
              cfg.f24 = lbl_803DF68C * (f32)(s32)(10 - randomGetRange(0,0x14));
              cfg.f28 = lbl_803DF68C * (f32)(s32)(10U - randomGetRange(0,0x14));
              cfg.f3c = lbl_803DF6BC;
              cfg.f08 = 0x78;
              cfg.f44 = 0x204;
              cfg.f42 = 0x1f0;
    break;
  case 0x1e:
cfg.f3c = lbl_803DF5B4 * (f32)(s32)randomGetRange(1,4);
              cfg.f08 = 0x5a;
              cfg.f60 = 0xff;
              cfg.f44 = 0xa100100;
              cfg.f42 = 0x56;
              cfg.f61 = 0;
    break;
  case 0x1f:

            cfg.f3c = lbl_803DF4F0 * (f32)(s32)randomGetRange(2,4);
            cfg.f08 = 200;
            cfg.f44 = 0xa100201;
            cfg.f42 = 0x56;
    break;
  case 0x54:

          cfg.f30 = (f32)(s32)(5 - randomGetRange(0,10));
          cfg.f38 = (f32)(s32)(5U - randomGetRange(0,10));
          cfg.f3c = lbl_803DF5CC * (f32)(s32)randomGetRange(2,0xc);
          cfg.f08 = 0x78;
          cfg.f44 = 0xa100201;
          cfg.f42 = 0x56;
    break;
  case 0x27:
cfg.f34 = lbl_803DF580;
          cfg.f3c = lbl_803DF624 * (f32)(s32)randomGetRange(1,2);
          cfg.f08 = 200;
          cfg.f44 = 0xa100201;
          cfg.f42 = 0x6b;
    break;
  case 0x13:
cfg.f3c = lbl_803DF6C0;
            cfg.f08 = 0xd05;
            cfg.f60 = 0;
            cfg.f44 = 0x11;
            cfg.f42 = 0x30;
    break;
  case 0x14:

            cfg.f3c = lbl_803DF530;
            cfg.f08 = 0xd;
            cfg.f44 = 0x110212;
            cfg.f42 = 0x33;
    break;
  case 0x12:

          cfg.f34 = lbl_803DF630;
          cfg.f3c = lbl_803DF4E0;
          cfg.f08 = 0x14d;
          cfg.f44 = 0x10012;
          cfg.f42 = 0x33;
    break;
  case 0x10:
            cfg.f34 = (f32)(s32)(0x14 - randomGetRange(0,0x28));
            cfg.f24 = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
            cfg.f2c = lbl_803DF4E4 * (f32)(s32)(0x50U - randomGetRange(0,0xa0));
            cfg.f3c = lbl_803DF4E0;
            cfg.f08 = (u32)(lbl_803DF6C4 * (f32)(s32)(randomGetRange(0,3) + 1U));
            cfg.f44 = 0x110204;
            cfg.f42 = 0x30;
    break;
  case 0x6:
cfg.f3c = lbl_803DF624;
              cfg.f08 = 0x12;
              cfg.f44 = 0x300200;
              cfg.f42 = 0x33;
    break;
  case 0x8:

            cfg.f34 = lbl_803DF644;
            cfg.f3c = lbl_803DF4EC;
            cfg.f08 = 0x30;
            cfg.f60 = 200;
            cfg.f44 = 0x300002;
            cfg.f42 = 0x2c;
    break;
  case 0x9:
cfg.f34 = lbl_803DF644;
            cfg.f38 = lbl_803DF5B8;
            cfg.f3c = lbl_803DF4EC;
            cfg.f08 = 0x3c;
            cfg.f60 = 200;
            cfg.f44 = 0x300000;
            cfg.f42 = 0x2c;
    break;
  case 0xa:
cfg.f3c = lbl_803DF4EC;
            cfg.f08 = 0x3c;
            cfg.f60 = 200;
            cfg.f44 = 0x300000;
            cfg.f42 = 0x2c;
    break;
  case 0x6b:
if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        if (param_6 == NULL) {
          return -1;
        }
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f24 = *param_6;
        cfg.f28 = param_6[1];
        cfg.f2c = param_6[2];
        cfg.f3c = lbl_803DF4C8;
        cfg.f08 = 0x28;
        cfg.f60 = (u8)(int)((PartFxSpawnParams *)param_3)->unk8;
        cfg.f61 = 10;
        cfg.f44 = 0x200;
        cfg.f42 = 0xc13;
        cfg.f18 = lbl_803DF4DC;
        cfg.f1c = lbl_803DF4DC;
        cfg.f20 = lbl_803DF4DC;
        cfg.f14 = lbl_803DF4D0;
        cfg.f10 = 0;
        cfg.f0e = 0;
        cfg.f0c = *param_3;
    break;
  case 0x6c:
cfg.f3c = lbl_803DF568;
        cfg.f08 = 1;
        cfg.f61 = 0;
        cfg.f44 = 0x11;
        cfg.f48 = 2;
        cfg.f42 = 0xdd;
    break;
  case 0x56:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          cfg.f30 = (f32)(s32)randomGetRange(0xfffffffa,6);
          cfg.f38 = (f32)(s32)randomGetRange(0xfffffffa,6);
          cfg.f24 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffffe,2));
          cfg.f28 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF4CC * (f32)(s32)randomGetRange(0,4));
          cfg.f2c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF508 * (f32)(s32)randomGetRange(0xfffffffe,2));
          cfg.f3c = lbl_803DF634 * ((PartFxSpawnParams *)param_3)->unk8;
          cfg.f08 = 0x18;
          cfg.f44 = 0x1080000;
          cfg.f48 = 0x1000000;
          cfg.f60 = 0xa5;
          if (param_6 != NULL) {
            cfg.f4c = (u32)*(byte *)param_6 << 8;
            cfg.f58 = (ushort)cfg.f4c;
            cfg.f50 = (u32)*(byte *)((int)param_6 + 1) << 8;
            cfg.f5a = (ushort)cfg.f50;
            cfg.f54 = (u32)*(byte *)((int)param_6 + 2) << 8;
            cfg.f5c = (ushort)cfg.f54;
            cfg.f48 = 0x1000020;
          }
          cfg.f42 = 0x60;
    break;
  case 0x57:

        if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        cfg.f34 = (f32)(s32)randomGetRange(0,10);
        cfg.f24 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF5B4 * (f32)(s32)randomGetRange(0xffffff9c,100));
        cfg.f28 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF5B4 * (f32)(s32)randomGetRange(200,400));
        cfg.f2c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF5B4 * (f32)(s32)randomGetRange(0xffffff9c,100));
        cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF524 * (f32)(s32)randomGetRange(8,0xb));
        cfg.f60 = 0xbe;
        cfg.f08 = (u32)(lbl_803DF6C8 * ((PartFxSpawnParams *)param_3)->unk8);
        cfg.f44 = 0x1200000;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x77;
        if (param_6 != NULL) {
          cfg.f4c = (u32)*(byte *)param_6 << 8;
          cfg.f58 = (ushort)cfg.f4c;
          cfg.f50 = (u32)*(byte *)((int)param_6 + 1) << 8;
          cfg.f5a = (ushort)cfg.f50;
          cfg.f54 = (u32)*(byte *)((int)param_6 + 2) << 8;
          cfg.f5c = (ushort)cfg.f54;
          cfg.f48 = 0x1000020;
        }
    break;
  case 0x58:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          cfg.f24 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF4F0 * (f32)(s32)randomGetRange(0xffffff9c,100));
          cfg.f28 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF4F0 * (f32)(s32)randomGetRange(10,200));
          cfg.f2c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF4F0 * (f32)(s32)randomGetRange(0xffffff9c,100));
          cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF524 * (f32)(s32)randomGetRange(8,0xb));
          cfg.f08 = 0x4b;
          cfg.f44 = 0x1080000;
          cfg.f48 = 0x1000000;
          cfg.f42 = 0x77;
          if (param_6 != NULL) {
            cfg.f4c = (u32)*(byte *)param_6 << 8;
            cfg.f58 = (ushort)cfg.f4c;
            cfg.f50 = (u32)*(byte *)((int)param_6 + 1) << 8;
            cfg.f5a = (ushort)cfg.f50;
            cfg.f54 = (u32)*(byte *)((int)param_6 + 2) << 8;
            cfg.f5c = (ushort)cfg.f54;
            cfg.f48 = 0x1000020;
          }
    break;
  case 0x323:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
          }
          cfg.f30 = lbl_803DF6CC * (f32)(s32)randomGetRange(0xffffffea,0x15) + cfg.f30;
          cfg.f34 = lbl_803DF6D0 * (f32)(s32)randomGetRange(0xffffffe9,0x16) + cfg.f34;
          cfg.f38 = lbl_803DF6D4 * (f32)(s32)randomGetRange(0xffffffe9,0x19) + cfg.f38;
          cfg.f3c = lbl_803DF6D8 * (f32)(s32)randomGetRange(1,6);
          iVar8 = randomGetRange(7,0xf);
          cfg.f08 = iVar8 + 5;
          cfg.f42 = 0xc9a;
          cfg.f44 = 0x100210;
          cfg.f48 = 0x4000800;
          if (param_6 != NULL) {
            cVar4 = *(u8 *)param_6;
            if (cVar4 == '\x01') {
              cfg.f4c = 0x2898;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0x6574;
              cfg.f5a = 0x9f9;
              cfg.f5c = 0xffff;
              cfg.f48 |= 0x20;
            }
            else if (cVar4 == '\x02') {
              cfg.f4c = 0xff65;
              cfg.f50 = 0xd23c;
              cfg.f54 = 0x7fff;
              cfg.f58 = 0xffc4;
              cfg.f5a = 0xdc81;
              cfg.f5c = 0x2603;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6DC;
              cfg.f08 = iVar8 + 0xc;
            }
            else if (cVar4 == '\x03') {
              cfg.f4c = 0xfebe;
              cfg.f50 = 0x5cb2;
              cfg.f54 = 0xfd01;
              cfg.f58 = 0xfd2c;
              cfg.f5a = 0x8e5;
              cfg.f5c = 0x1f5;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
              cfg.f08 = iVar8 + 0x19;
            }
            else if (cVar4 == '\x04') {
              cfg.f4c = 0xffff;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0;
              cfg.f5a = 0xffff;
              cfg.f5c = 0;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
            }
            else if (cVar4 == '\x05') {
              cfg.f4c = 0xffff;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0xffff;
              cfg.f5a = 0;
              cfg.f5c = 0;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
            }
            else if (cVar4 == '\x06') {
              cfg.f4c = 0xffff;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0xffff;
              cfg.f5a = 0x7fff;
              cfg.f5c = 0;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
            }
            else if (cVar4 == '\a') {
              cfg.f4c = 0xffff;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0xffff;
              cfg.f5a = 0xffff;
              cfg.f5c = 0;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
            }
            else if (cVar4 == '\b') {
              cfg.f4c = 0xffff;
              cfg.f50 = 0xffff;
              cfg.f54 = 0xffff;
              cfg.f58 = 0;
              cfg.f5a = 0xffff;
              cfg.f5c = 0xffff;
              cfg.f48 |= 0x20;
              cfg.f3c = cfg.f3c * lbl_803DF6E0;
            }
          }
    break;
  case 0x325:

        if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
        }
        cfg.f38 = lbl_803DF6E4;
        rot.m[1] = lbl_803DF4DC;
        rot.m[2] = lbl_803DF4DC;
        rot.m[3] = lbl_803DF4DC;
        rot.m[0] = lbl_803DF4D0;
        rot.z = randomGetRange(0xffff8001,0x7fff);
        rot.y = randomGetRange(0xffff8001,0x7fff);
        rot.x = randomGetRange(0xffff8001,0x7fff);
        vecRotateZXY((s16 *)&rot,&cfg.f30);
        cfg.f24 = -(cfg.f30 / lbl_803DF4FC);
        cfg.f28 = -(cfg.f34 / lbl_803DF4FC);
        cfg.f2c = -(cfg.f38 / lbl_803DF4FC);
        cfg.f3c = lbl_803DF6E8 * (f32)(s32)randomGetRange(0x9e,0x240);
        cfg.f08 = randomGetRange(7,0x12) + 0xc;
        cfg.f42 = 0xc98;
        cfg.f44 = 0x480110;
        if (param_6 != NULL) {
          cVar4 = *(u8 *)param_6;
          if (cVar4 == '\x01') {
            cfg.f4c = 0x2898;
            cfg.f50 = 0xffff;
            cfg.f54 = 0xffff;
            cfg.f58 = 0x6574;
            cfg.f5a = 0x9f9;
            cfg.f5c = 0xffff;
            cfg.f48 = cfg.f48 | 0x20;
          }
          else if (cVar4 == '\x02') {
            cfg.f4c = 0xff65;
            cfg.f50 = 0xd23c;
            cfg.f54 = 0x7fff;
            cfg.f58 = 0xffc4;
            cfg.f5a = 0xdc81;
            cfg.f5c = 0x2603;
            cfg.f48 = cfg.f48 | 0x20;
            cfg.f3c = cfg.f3c * lbl_803DF6DC;
          }
          else if (cVar4 == '\x03') {
            cfg.f4c = 0xfebe;
            cfg.f50 = 0x5cb2;
            cfg.f54 = 0xfd01;
            cfg.f58 = 0xfd2c;
            cfg.f5a = 0x8e5;
            cfg.f5c = 0x1f5;
            cfg.f48 = cfg.f48 | 0x20;
            cfg.f3c = cfg.f3c * lbl_803DF6EC;
          }
        }
    break;
  case 0x326:
randomGetRange(1,1);
            cfg.f24 = lbl_803DF4DC;
            randomGetRange(1,1);
            cfg.f28 = lbl_803DF4DC;
            randomGetRange(1,1);
            cfg.f2c = lbl_803DF4DC;
            randomGetRange(1,1);
            cfg.f30 = lbl_803DF4DC;
            randomGetRange(1,1);
            cfg.f34 = lbl_803DF4DC;
            randomGetRange(1,1);
            cfg.f38 = lbl_803DF4DC;
            cfg.f3c = lbl_803DF6F0 * (f32)(s32)randomGetRange(10,0x1e);
            cfg.f08 = randomGetRange(1,1) + 0x17;
            cfg.f42 = 0xc99;
            cfg.f44 = 0x180210;
            cfg.f60 = 0x7d;
            if (param_6 != NULL) {
              cVar4 = *(u8 *)param_6;
              if (cVar4 == '\x01') {
                cfg.f4c = 0x2898;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0x6574;
                cfg.f5a = 0x9f9;
                cfg.f5c = 0xffff;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6F4;
              }
              else if (cVar4 == '\x02') {
                cfg.f4c = 0xff65;
                cfg.f50 = 0xd23c;
                cfg.f54 = 0x7fff;
                cfg.f58 = 0xffc4;
                cfg.f5a = 0xdc81;
                cfg.f5c = 0x2603;
                cfg.f48 = cfg.f48 | 0x20;
              }
              else if (cVar4 == '\x03') {
                cfg.f4c = 0xfebe;
                cfg.f50 = 0x5cb2;
                cfg.f54 = 0xfd01;
                cfg.f58 = 0xfd2c;
                cfg.f5a = 0x8e5;
                cfg.f5c = 0x1f5;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6F8;
              }
              else if (cVar4 == '\x04') {
                cfg.f4c = 0xffff;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0;
                cfg.f5a = 0xffff;
                cfg.f5c = 0;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6E0;
              }
              else if (cVar4 == '\x05') {
                cfg.f4c = 0xffff;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0xffff;
                cfg.f5a = 0;
                cfg.f5c = 0;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6E0;
              }
              else if (cVar4 == '\x06') {
                cfg.f4c = 0xffff;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0xffff;
                cfg.f5a = 0x7fff;
                cfg.f5c = 0;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6E0;
              }
              else if (cVar4 == '\a') {
                cfg.f4c = 0xffff;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0xffff;
                cfg.f5a = 0xffff;
                cfg.f5c = 0;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6E0;
              }
              else if (cVar4 == '\b') {
                cfg.f4c = 0xffff;
                cfg.f50 = 0xffff;
                cfg.f54 = 0xffff;
                cfg.f58 = 0;
                cfg.f5a = 0xffff;
                cfg.f5c = 0xffff;
                cfg.f48 = cfg.f48 | 0x20;
                cfg.f3c = cfg.f3c * lbl_803DF6E0;
              }
            }
    break;
  case 0x328:

            cfg.f24 = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f28 = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f2c = lbl_803DF568 * (f32)(s32)randomGetRange(0xffffff9c,100);
            cfg.f08 = randomGetRange(4,0xd);
            cfg.f44 = 0x180210;
            cfg.f48 = 0x4000800;
            cfg.f3c = lbl_803DF6FC;
            cfg.f42 = 0xc9d;
    break;
  case 0x3de:
if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          if (param_3 == NULL) {
            cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xfffffff6,10);
            cfg.f34 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xfffffff6,10);
            cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xfffffff6,10);
          }
          else {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          }
          cfg.f24 = lbl_803DF4DC;
          cfg.f28 = lbl_803DF508;
          cfg.f2c = lbl_803DF4DC;
          cfg.f3c = lbl_803DF504;
          cfg.f08 = 0x96;
          cfg.f61 = 0x1e;
          cfg.f60 = 0xff;
          cfg.f44 = 0x80080209;
          cfg.f48 = 0x1000020;
          cfg.f42 = 0x5f;
          cfg.f58 = 0xffff;
          cfg.f5a = 0xffff;
          cfg.f5c = 0xa000;
          cfg.f4c = 0xffff;
          cfg.f50 = 0xffff;
          cfg.f54 = 0xc000;
    break;
  case 0x3df:

        cfg.f30 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffff9c,100);
        cfg.f34 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffff9c,100);
        cfg.f38 = lbl_803DF4CC * (f32)(s32)randomGetRange(0xffffff9c,100);
        cfg.f28 = lbl_803DF608 * (f32)(s32)randomGetRange(8,10);
        if (randomGetRange(0,0x28) != 0) {
          cfg.f3c = lbl_803DF4C8 * (f32)(s32)randomGetRange(8,0x14);
          cfg.f08 = randomGetRange(0x5a,0x78);
        }
        else {
          cfg.f3c = lbl_803DF4C8 * (f32)(s32)randomGetRange(0x15,0x29);
          cfg.f08 = 0x1cc;
        }
        cfg.f44 = 0x80380209;
        cfg.f48 = 0x5000820;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x7f;
        cfg.f4c = 0x62c0;
        cfg.f50 = 0xd310;
        cfg.f54 = 0x2800;
        cfg.f58 = 0x44c0;
        cfg.f5a = 0xd310;
        cfg.f5c = 0xb00;
    break;
  case 0x320:

            if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
              param_3 = lbl_8039C308;
            }
            cfg.f24 = lbl_803DF608 * (f32)(s32)randomGetRange(0xfffffffe,2);
            cfg.f28 = lbl_803DF674 * (f32)(s32)randomGetRange(2,5);
            cfg.f2c = lbl_803DF700 * (f32)(s32)randomGetRange(1,3);
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f3c = lbl_803DF550;
            cfg.f08 = 0x28;
            cfg.f48 = 0x5000000;
            cfg.f44 = 0x180208;
            cfg.f42 = 0xc8f;
    break;
  case 0x321:
if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
              param_3 = lbl_8039C308;
            }
            cfg.f28 = lbl_803DF4CC * (f32)(s32)randomGetRange(0,4);
            cfg.f2c = lbl_803DF704 * (f32)(s32)randomGetRange(2,4);
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f3c = lbl_803DF4E8;
            cfg.f08 = 100;
            cfg.f44 = 0x1180200;
            cfg.f48 = 0x5000000;
            cfg.f42 = 0xc90;
    break;
  case 0x322:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          cfg.f3c = lbl_803DF504;
          cfg.f08 = 0x50;
          cfg.f44 = 0x180200;
          cfg.f48 = 0x5000000;
          cfg.f42 = 0xc90;
          cfg.f60 = 0xa5;
    break;
  case 0x351:

          if (param_3 == NULL) {
            *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
            *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
            lbl_8039C308[0] = 0;
            lbl_8039C308[1] = 0;
            lbl_8039C308[2] = 0;
            lbl_8039C308[3] = 0;
            param_3 = lbl_8039C308;
          }
          cfg.f2c = lbl_803DF708;
          cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
          cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
          cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
          cfg.f3c = lbl_803DF618 * (f32)(s32)randomGetRange(0x32,100);
          cfg.f08 = randomGetRange(0x28,0x50);
          cfg.f44 = 0x8100200;
          cfg.f48 = 0x5000000;
          cfg.f42 = 0xc8f;
    break;
  case 0x51d:

        if (param_3 == NULL) {
          *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
          *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
          lbl_8039C308[0] = 0;
          lbl_8039C308[1] = 0;
          lbl_8039C308[2] = 0;
          lbl_8039C308[3] = 0;
          param_3 = lbl_8039C308;
        }
        cfg.f0c = 700;
        cfg.f42 = 0xc09;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f3c = lbl_803DF524 * (f32)(s32)randomGetRange(10,0x14);
        cfg.f08 = 0xaa;
        cfg.f44 = 0xa0104;
        cfg.f18 = lbl_803DF4DC;
        cfg.f1c = lbl_803DF4DC;
        cfg.f20 = lbl_803DF4DC;
        cfg.f0e = 0;
        cfg.f10 = 0;
        cfg.f14 = lbl_803DF4D0;
    break;
  case 0x55a:
          {
            if (param_3 == NULL) {
              *(f32 *)(lbl_8039C308 + 6) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 8) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 10) = lbl_803DF4DC;
              *(f32 *)(lbl_8039C308 + 4) = lbl_803DF4D0;
              lbl_8039C308[0] = 0;
              lbl_8039C308[1] = 0;
              lbl_8039C308[2] = 0;
              lbl_8039C308[3] = 0;
            }
            cfg.f24 = lbl_803DF5CC * (f32)(s32)randomGetRange(0xffffffd8,0x28);
            cfg.f28 = lbl_803DF568 * (f32)(s32)randomGetRange(10,0x50);
            cfg.f2c = lbl_803DF5CC * (f32)(s32)randomGetRange(0xffffffd8,0x28);
            cfg.f3c = lbl_803DF528 * (f32)(s32)randomGetRange(5,0x19);
            cfg.f08 = randomGetRange(0x122,0x15e);
            cfg.f60 = 0xff;
            cfg.f0c = randomGetRange(0,0xffff);
            cfg.f0e = randomGetRange(0,0xffff);
            cfg.f0c = randomGetRange(0,0xffff);
            cfg.f18 = (f32)(s32)randomGetRange(0xe6,800);
            cfg.f1c = (f32)(s32)randomGetRange(0xe6,800);
            cfg.f20 = (f32)(s32)randomGetRange(0xe6,800);
            cfg.f48 = 0x1000020;
            cfg.f44 = 0x86000008;
            cfg.f4c = randomGetRange(0,0xfff) + 0xf000;
            cfg.f58 = (ushort)cfg.f4c;
            cfg.f50 = 0xe000;
            cfg.f5a = 0xe000;
            cfg.f54 = 0xe000;
            cfg.f5c = 0xe000;
            cfg.f42 = 0x567;
            goto LAB_800aeb30;
          }
  case 0x564:
cfg.f3c = lbl_803DF5A0 * (f32)(s32)randomGetRange(0x32,100);
        cfg.f08 = 0x2d;
        cfg.f44 = 0x80580210;
        cfg.f60 = 0xff;
        cfg.f42 = 0xc0f;
    break;
  case 0x565:

        cfg.f3c = lbl_803DF4D0;
        cfg.f08 = 0x14;
        cfg.f61 = 0;
        cfg.f44 = 0x210;
        cfg.f48 = 0x800;
        cfg.f42 = 0x5b1;
    break;
  case 0x324:
goto LAB_800aeb30;
  case 0xb: case 0x327: case 0x52e: case 0x555:
  default:
LAB_800aeb28:
    return -1;
  }
LAB_800aeb30:
  cfg.f44 = (cfg.f44 | param_4);
  if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) {
    cfg.f44 ^= 2LL;
  }
  if ((cfg.f44 & 1) != 0) {
    if ((param_4 & 0x200000) != 0) {
      cfg.f30 = cfg.f30 + cfg.f18;
      cfg.f34 = cfg.f34 + cfg.f1c;
      cfg.f38 = cfg.f38 + cfg.f20;
    }
    else {
      if (cfg.f00 != NULL) {
        cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
        cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
        cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
      }
    }
  }
  return (*gExpgfxInterface)->spawnEffect(&cfg,0xffffffff,param_2,0);
}


int Effect2_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    int i;
    PartFxSpawn cfg;

    lbl_803DB7C0 = lbl_803DB7C0 + lbl_803DF870;
    if (lbl_803DB7C0 > 1.0f) lbl_803DB7C0 = lbl_803DF874;
    lbl_803DB7C4 = lbl_803DB7C4 + lbl_803DF87C;
    if (lbl_803DB7C4 > 1.0f) lbl_803DB7C4 = lbl_803DF880;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DF884;
    cfg.f34 = lbl_803DF884;
    cfg.f38 = lbl_803DF884;
    cfg.f24 = lbl_803DF884;
    cfg.f28 = lbl_803DF884;
    cfg.f2c = lbl_803DF884;
    cfg.f3c = lbl_803DF884;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x2b0:
        cfg.f24 = lbl_803DF888 * (f32)(s32)randomGetRange(-0x7c, 0x7c);
        cfg.f28 = lbl_803DF88C * (f32)(s32)randomGetRange(0x392, 0x4d6);
        cfg.f2c = lbl_803DF890 * (f32)(s32)randomGetRange(-0x7c, 0x7c);
        cfg.f30 = lbl_803DF894 * (f32)(s32)randomGetRange(-0x1d0, 0x1d0);
        cfg.f34 = lbl_803DF884;
        cfg.f38 = lbl_803DF898 * (f32)(s32)randomGetRange(-0x1c8, 0x1c8);
        cfg.f3c = lbl_803DF89C * (f32)(s32)randomGetRange(0x1d, 0x21);
        cfg.f08 = 0x13f;
        cfg.f42 = 0x26d;
        cfg.f44 = 0x400100;
        break;
    case 0x2b1:
        cfg.f24 = lbl_80310560.vel[0][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[0][1], (s32)lbl_80310560.vel[0][2]);
        cfg.f28 = lbl_80310560.vel[1][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[1][1], (s32)lbl_80310560.vel[1][2]);
        cfg.f2c = lbl_80310560.vel[2][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[2][1], (s32)lbl_80310560.vel[2][2]);
        cfg.f30 = lbl_80310560.vel[3][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[3][1], (s32)lbl_80310560.vel[3][2]);
        cfg.f34 = lbl_80310560.vel[4][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[4][1], (s32)lbl_80310560.vel[4][2]);
        cfg.f38 = lbl_80310560.vel[5][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[5][1], (s32)lbl_80310560.vel[5][2]);
        cfg.f3c = lbl_80310560.vel[6][0] * (f32)(s32)randomGetRange((s32)lbl_80310560.vel[6][1], (s32)lbl_80310560.vel[6][2]);
        cfg.f08 = randomGetRange((s32)lbl_80310560.g08[1], (s32)lbl_80310560.g08[2]) + (s32)lbl_80310560.g08[0];
        cfg.f58 = lbl_80310560.col[0];
        cfg.f5a = lbl_80310560.col[1];
        cfg.f5c = lbl_80310560.col[2];
        cfg.f4c = lbl_80310560.col[3];
        cfg.f50 = lbl_80310560.col[4];
        cfg.f54 = lbl_80310560.col[5];
        for (i = 0; i < 6; i++) if (lbl_80310560.emit[i] != 0) cfg.f44 |= 1 << (lbl_80310560.emit[i] - 1);
        cfg.f48 = 0x2000000;
        for (i = 0; i < 6; i++) if (lbl_80310560.sub[i] != 0) cfg.f48 |= 1 << (lbl_80310560.sub[i] - 1);
        cfg.f42 = (s32)lbl_80310560.f60;
        cfg.f60 = randomGetRange(lbl_80310560.b_a0, lbl_80310560.b_a1);
        break;
    case 0x2b2:
        cfg.f24 = lbl_803DF8A0 * (f32)(s32)randomGetRange(-0x128, 0xf9);
        cfg.f28 = lbl_803DF8A4 * (f32)(s32)randomGetRange(0x150, 0x2de);
        cfg.f2c = lbl_803DF8A8 * (f32)(s32)randomGetRange(-0xfc, 0xf9);
        randomGetRange(0, 0);
        cfg.f30 = lbl_803DF884;
        randomGetRange(1, 1);
        cfg.f34 = lbl_803DF884;
        cfg.f38 = lbl_803DF8AC * (f32)(s32)randomGetRange(0, 0);
        cfg.f3c = lbl_803DF8B0 * (f32)(s32)randomGetRange(0xa, 0x30);
        cfg.f08 = randomGetRange(1, 0x26) + 0xe;
        cfg.f42 = 0x1f;
        cfg.f44 = 0x1000200;
        break;
    case 0x2af:
        cfg.f3c = lbl_803DF8B4;
        cfg.f08 = 0x30;
        cfg.f61 = 0;
        if ((int)randomGetRange(0, 1) != 0) cfg.f44 = 0x8100210;
        else cfg.f44 = 0x180210;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x205;
        break;
    case 0x2ae:
        cfg.f34 = lbl_803DF8B8;
        cfg.f3c = lbl_803DF8B4;
        cfg.f08 = 0x30;
        cfg.f61 = 0;
        cfg.f44 = 0x8100210;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x205;
        break;
    case 0x2ad:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803DF8BC * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.f3c = lbl_803DF8C0;
        cfg.f08 = 0x82;
        cfg.f60 = 0xff;
        cfg.f44 = 0x400200;
        cfg.f48 = 0x100;
        cfg.f42 = 0x156;
        break;
    case 0x2ac:
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0x3e8, 0x640);
        cfg.f28 = lbl_803DF8C4 * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.f3c = lbl_803DF8C0;
        cfg.f08 = 0x82;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x400100;
        cfg.f42 = 0xc0e;
        break;
    case 0x2ab:
        cfg.f24 = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = lbl_803DF8C8 * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.f2c = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DF8CC;
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80000200;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x23b;
        break;
    case 0x2aa:
        cfg.f24 = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = lbl_803DF8D0 * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.f2c = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DF8CC;
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80000200;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x23b;
        break;
    case 0x2a9:
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x1f4);
        cfg.f3c = lbl_803DF8D4;
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100200;
        cfg.f42 = 0x26d;
        break;
    case 0x2a8:
        cfg.f24 = lbl_803DF8D8 * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f28 = lbl_803DF8DC * (f32)(s32)randomGetRange(5, 0x10);
        cfg.f2c = lbl_803DF8E0 * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f3c = lbl_803DF8E4;
        cfg.f08 = 0x12;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x2000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x201;
        break;
    case 0x2a7:
        cfg.f30 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f38 = (f32)(s32)randomGetRange(-0x3c, 0x14);
        cfg.f24 = lbl_803DF870 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF8E8 * (f32)(s32)randomGetRange(7, 0xa);
        cfg.f28 = lbl_803DF8EC * (f32)(s32)randomGetRange(-0x28, -0x1e);
        cfg.f3c = lbl_803DF8F0 * (f32)(s32)randomGetRange(5, 0x19);
        cfg.f08 = randomGetRange(0x186, 0x1c2);
        cfg.f60 = 0xff;
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f0e = randomGetRange(0, 0xffff);
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f18 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f1c = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f20 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f4c = cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.f50 = cfg.f5a = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.f54 = cfg.f5c = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.f48 = 0x1000020;
        cfg.f44 = 0x86000000;
        cfg.f42 = 0x3a2;
        break;
    case 0x2a6:
        cfg.f30 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f38 = (f32)(s32)randomGetRange(-0x3c, 0x14);
        cfg.f24 = lbl_803DF870 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF8E8 * (f32)(s32)randomGetRange(7, 0xa);
        cfg.f28 = lbl_803DF8F4 * (f32)(s32)randomGetRange(-0x28, -0x1e);
        cfg.f3c = lbl_803DF8F8 * (f32)(s32)randomGetRange(0x64, 0x78);
        cfg.f08 = 0x3b6;
        cfg.f60 = 0xff;
        cfg.f44 = (u32)randFn_80080100;
        cfg.f42 = 0x5c;
        break;
    case 0x2a5:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.f2c = lbl_803DF8BC * (f32)(s32)randomGetRange(-2, 2);
        cfg.f28 = lbl_803DF8FC * (f32)(s32)randomGetRange(2, 5);
        cfg.f2c = lbl_803DF8BC * (f32)(s32)randomGetRange(-2, 2);
        cfg.f3c = lbl_803DF900 * (f32)(s32)randomGetRange(0x50, 0x78);
        cfg.f08 = 0x50;
        cfg.f44 = 0x180208;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x5f;
        break;
    case 0x2a4:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x5a, 0x5a);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x64);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f24 = lbl_803DF904 * (f32)(s32)randomGetRange(-2, 2);
        cfg.f28 = lbl_803DF908 * (f32)(s32)randomGetRange(2, 5);
        cfg.f2c = lbl_803DF90C * (f32)(s32)randomGetRange(-2, 2);
        cfg.f3c = lbl_803DF87C * (f32)(s32)randomGetRange(0x50, 0xc8);
        cfg.f08 = 0x50;
        cfg.f44 = 0x180208;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x5f;
        break;
    case 0x2a3:
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f2c = lbl_803DF910 * (f32)(s32)randomGetRange(0x46, 0x64);
        cfg.f3c = lbl_803DF8F4 * (f32)(s32)randomGetRange(1, 0xa);
        cfg.f08 = 0x32;
        cfg.f60 = 0x2d;
        cfg.f44 = 0x100;
        cfg.f42 = 0x16c;
        break;
    case 0x2a2:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f34 = lbl_803DF914;
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f28 = lbl_803DF918 * (f32)(s32)randomGetRange(0xc, 0x10);
        cfg.f2c = lbl_803DF91C * (f32)(s32)randomGetRange(0xc, 0x10);
        cfg.f3c = lbl_803DF920;
        cfg.f08 = 0x82;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x2000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0xc9d;
        break;
    case 0x29d:
        if (param_3 == 0) FILL338();
        cfg.f0c = 0x3e8;
        cfg.f0e = 0x3e8;
        cfg.f10 = 0x3e8;
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f08 = 6;
        cfg.f60 = 0xe1;
        cfg.f44 = 0x4a0010;
        if ((int)randomGetRange(0, 1) != 0) cfg.f48 = 0x202;
        else cfg.f48 = 0x102;
        if (0.0f == ((PartFxSpawnParams *)param_3)->unk8) {
            cfg.f3c = lbl_803DF87C * (f32)(s32)randomGetRange(0, 3) + lbl_803DF870;
            cfg.f42 = 0xc0f;
        } else {
            cfg.f3c = lbl_803DF87C * (f32)(s32)randomGetRange(0, 3) + lbl_803DF924;
            cfg.f42 = 0xc0f;
        }
        break;
    case 0x29e:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480010;
        if (0.0f == ((PartFxSpawnParams *)param_3)->unk8) {
            cfg.f3c = lbl_803DF928;
            cfg.f42 = 0x74;
        } else {
            cfg.f3c = lbl_803DF92C;
            cfg.f42 = 0x74;
        }
        cfg.f48 = 2;
        break;
    case 0x29f:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480010;
        cfg.f48 = 2;
        if (0.0f == ((PartFxSpawnParams *)param_3)->unk8) {
            cfg.f3c = lbl_803DF8C8;
            cfg.f42 = 0xc22;
        } else {
            cfg.f3c = lbl_803DF930;
            cfg.f42 = 0xdc;
        }
        break;
    case 0x2a0:
        if (param_3 == 0) FILL338();
        cfg.f08 = 0x1e;
        cfg.f61 = 0;
        cfg.f60 = 0x37;
        cfg.f44 = 0x180010;
        if (0.0f == ((PartFxSpawnParams *)param_3)->unk8) {
            cfg.f3c = lbl_803DF934 * (f32)(s32)randomGetRange(0x14, 0x32);
            cfg.f42 = 0x73;
        } else {
            cfg.f3c = lbl_803DF938 * (f32)(s32)randomGetRange(0x14, 0x32);
            cfg.f42 = 0x73;
        }
        break;
    case 0x2a1:
        if (param_3 == 0) FILL338();
        cfg.f08 = 0x3c;
        cfg.f61 = 0;
        cfg.f60 = 0x37;
        cfg.f44 = 0x480010;
        cfg.f48 = 2;
        if (0.0f == ((PartFxSpawnParams *)param_3)->unk8) {
            cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(0x46, 0x50);
            cfg.f42 = 0x73;
        } else {
            cfg.f3c = lbl_803DF940 * (f32)(s32)randomGetRange(0x46, 0x50);
            cfg.f42 = 0x73;
        }
        break;
    case 0x297:
        cfg.f24 = lbl_803DF944 * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f28 = lbl_803DF948 * (f32)(s32)randomGetRange(5, 0x10);
        cfg.f2c = lbl_803DF94C * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f3c = lbl_803DF950;
        cfg.f08 = 0x54;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x2000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x1fe;
        break;
    case 0x25b:
        cfg.f3c = lbl_803DF954;
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x400;
        cfg.f42 = 0x7b;
        break;
    case 0x25c:
    case 0x269:
    case 0x27d:
        cfg.f30 = lbl_803DF8B4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DF8FC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF958 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f24 = lbl_803DF95C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF960 * (f32)(s32)randomGetRange(0xe, 0x12);
        cfg.f3c = lbl_803DF964;
        cfg.f08 = randomGetRange(0x28, 0x50);
        cfg.f60 = 0xff;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x400;
        if (param_2 == 0x25c) {
            cfg.f42 = 0x7a;
            cfg.f04 = 0x25d;
        } else if (param_2 == 0x272) {
            cfg.f42 = 0x202;
            cfg.f04 = 0x273;
        } else if (param_2 == 0x27d) {
            cfg.f42 = 0x7a;
            cfg.f04 = 0x27e;
        } else {
            cfg.f42 = 0x1fe;
            cfg.f04 = 0x26a;
        }
        break;
    case 0x25d:
    case 0x26a:
    case 0x273:
    case 0x27e:
        cfg.f3c = lbl_803DF964;
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x400;
        cfg.f42 = 0x7a;
        if (param_2 == 0x25d) {
            cfg.f42 = 0x7a;
        } else if (param_2 == 0x273) {
            cfg.f42 = 0x202;
        } else if (param_2 == 0x27e) {
            cfg.f42 = 0x7a;
        } else {
            cfg.f42 = 0x1fe;
        }
        break;
    case 0x25e:
    case 0x26b:
    case 0x27b:
        cfg.f30 = lbl_803DF8B4 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DF8FC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF958 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f24 = lbl_803DF8EC * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF95C * (f32)(s32)randomGetRange(0xe, 0x12);
        cfg.f3c = lbl_803DF968;
        cfg.f08 = randomGetRange(0x28, 0x50);
        cfg.f60 = 0xff;
        cfg.f04 = 0x25f;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x400;
        if (param_2 == 0x25e) {
            cfg.f42 = 0x79;
            cfg.f04 = 0x25d;
        } else if (param_2 == 0x27b) {
            cfg.f42 = 0x1fb;
            cfg.f04 = 0x27c;
        } else if (param_2 == 0x274) {
            cfg.f42 = 0x202;
            cfg.f04 = 0x275;
        } else {
            cfg.f42 = 0x1ff;
            cfg.f04 = 0x26c;
        }
        break;
    case 0x25f:
    case 0x26c:
    case 0x275:
    case 0x27c:
        cfg.f3c = lbl_803DF968;
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x400;
        if (param_2 == 0x25f) {
            cfg.f42 = 0x79;
        } else if (param_2 == 0x275) {
            cfg.f42 = 0x202;
        } else if (param_2 == 0x27c) {
            cfg.f42 = 0x1fb;
        } else {
            cfg.f42 = 0x1ff;
        }
        break;
    case 0x260:
    case 0x261:
    case 0x262:
    case 0x278:
        cfg.f30 = (f32)(s32)randomGetRange(-0x26, 0x26);
        cfg.f34 = (f32)(s32)randomGetRange(0xa, 0x50);
        cfg.f38 = (f32)(s32)randomGetRange(-0x6c, 0x6c);
        cfg.f24 = lbl_803DF8EC * (f32)(s32)randomGetRange(-3, 3);
        cfg.f28 = lbl_803DF95C * (f32)(s32)randomGetRange(-6, 6);
        cfg.f2c = lbl_803DF95C * (f32)(s32)randomGetRange(-3, 3);
        cfg.f3c = lbl_803DF96C;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480110;
        if (param_2 == 0x278) cfg.f42 = (s16)lbl_80310660[3];
        else cfg.f42 = (s16)lbl_80310660[param_2 - 0x260];
        break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
        cfg.f30 = (f32)(s32)randomGetRange(-8, 8);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x50);
        cfg.f38 = (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DF904 * (f32)(s32)randomGetRange(-3, 3);
        cfg.f3c = lbl_803DF96C;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x480110;
        if (param_2 == 0x276) cfg.f42 = (s16)lbl_80310660[3];
        else cfg.f42 = (s16)lbl_80310660[param_2 - 0x263];
        break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
        cfg.f30 = (f32)(s32)randomGetRange(-8, 8);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x50);
        cfg.f38 = (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DF904 * (f32)(s32)randomGetRange(-3, 3);
        cfg.f3c = lbl_803DF96C;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x480100;
        if (param_2 == 0x277) cfg.f42 = (s16)lbl_80310660[3];
        else cfg.f42 = (s16)lbl_80310660[param_2 - 0x266];
        break;
    case 0x26d:
        cfg.f30 = (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.f34 = (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.f38 = (f32)(s32)randomGetRange(-0x12, 0x12);
        cfg.f2c = lbl_803DF970 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f3c = lbl_803DF974;
        cfg.f08 = 0xc8;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x2000200;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x1fe;
        break;
    case 0x26e:
        cfg.f3c = lbl_803DF974;
        cfg.f08 = 0x55;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x2000200;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x1fe;
        break;
    case 0x26f:
        cfg.f28 = lbl_803DF95C * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f3c = lbl_803DF978;
        cfg.f08 = 0x7d;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80200;
        cfg.f42 = 0x125;
        break;
    case 0x270:
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 5);
        cfg.f3c = lbl_803DF97C;
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x810020c;
        cfg.f42 = 0x167;
        break;
    case 0x271:
        cfg.f34 = lbl_803DF884;
        cfg.f28 = lbl_803DF95C * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f3c = lbl_803DF980;
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100204;
        cfg.f48 = 0x800;
        cfg.f42 = 0x167;
        break;
    case 0x286:
    case 0x287:
    case 0x288:
        cfg.f34 = (f32)(s32)randomGetRange(-6, 2);
        cfg.f24 = lbl_803DF96C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF96C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DF984;
        cfg.f08 = 0x50;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80480208;
        if (param_2 == 0x286) cfg.f42 = 0x160;
        else if (param_2 == 0x287) cfg.f42 = 0x200;
        else if (param_2 == 0x288) cfg.f42 = 0xdd;
        break;
    case 0x27f:
        cfg.f3c = lbl_803DF988 * *(f32 *)((char *)param_1 + 8);
        cfg.f08 = 0x28;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x80080208;
        cfg.f42 = 0x5f;
        cfg.f58 = 0x6400;
        cfg.f5a = 0x3200;
        cfg.f5c = 0xa000;
        cfg.f4c = 0x1f4;
        cfg.f50 = 0;
        cfg.f54 = 0x3e8;
        cfg.f48 = 0x20;
        break;
    case 0x280:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = lbl_803DF98C + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-0x14, 0x14);
            cfg.f34 = lbl_803DF98C;
            cfg.f38 = (f32)(s32)randomGetRange(-0x14, 0x14);
        }
        cfg.f24 = lbl_803DF95C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF8FC * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f2c = lbl_803DF95C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DF994 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF990;
        cfg.f08 = randomGetRange(0xbe, 0xfa);
        cfg.f60 = 0x9b;
        cfg.f04 = 0x281;
        cfg.f44 = 0x81488000;
        cfg.f42 = randomGetRange(0, 2) + 0x208;
        break;
    case 0x281:
        cfg.f28 = lbl_803DF998 * (f32)(s32)randomGetRange(2, 0x14);
        cfg.f3c = lbl_803DF99C;
        cfg.f08 = randomGetRange(0, 0x1e) + 0xa;
        cfg.f60 = 0xff;
        cfg.f44 = 0x180200;
        cfg.f42 = 0x5f;
        cfg.f58 = 0x5000;
        cfg.f5a = 0x1e00;
        cfg.f5c = 0x7800;
        cfg.f4c = 0x5000;
        cfg.f50 = 0x1e00;
        cfg.f54 = 0x7800;
        cfg.f48 = 0x20;
        break;
    case 0x282:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
            cfg.f34 = (f32)(s32)randomGetRange(1, 0xa);
            cfg.f38 = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.f24 = lbl_803DF95C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803DF970 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DF95C * (f32)(s32)randomGetRange(4, 4);
        cfg.f3c = lbl_803DF900 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.f08 = randomGetRange(0xe6, 0x118);
        cfg.f60 = 0xff;
        cfg.f04 = 0x284;
        cfg.f44 = 0x81488200;
        cfg.f42 = 0xc0a;
        break;
    case 0x283:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
            cfg.f34 = (f32)(s32)randomGetRange(1, 0xa);
            cfg.f38 = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.f28 = lbl_803DF960 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f3c = lbl_803DF900 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.f08 = randomGetRange(0xe6, 0x118);
        cfg.f60 = 0x9b;
        cfg.f44 = 0x80480200;
        cfg.f42 = 0xc0d;
        break;
    case 0x284:
        cfg.f28 = lbl_803DF998 * (f32)(s32)randomGetRange(2, 0x14);
        cfg.f3c = lbl_803DF9A4;
        cfg.f08 = 0x1e;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180200;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0x9b00;
        cfg.f4c = 0x9600;
        cfg.f50 = 0x1400;
        cfg.f54 = 0x1400;
        cfg.f48 = 0x20;
        break;
    case 0x285:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
            cfg.f34 = (f32)(s32)randomGetRange(1, 0xa);
            cfg.f38 = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.f28 = lbl_803DF998 * (f32)(s32)randomGetRange(2, 4);
        cfg.f2c = lbl_803DF8D0 * (f32)(s32)randomGetRange(2, 4);
        cfg.f3c = lbl_803DF870 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF9A8;
        cfg.f08 = randomGetRange(0, 0x32) + 0x32;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180200;
        cfg.f42 = 0xc0a;
        break;
    case 0x258:
        cfg.f24 = lbl_803DF998 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF998 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DF998 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DF9AC;
        cfg.f08 = randomGetRange(0x50, 0x82);
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180200;
        cfg.f42 = 0x7b;
        break;
    case 0x289:
        cfg.f30 = lbl_803DF8B4 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f38 = lbl_803DF8B4 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF95C * (f32)(s32)randomGetRange(0x28, 0x3c) + lbl_803DF880;
        cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = randomGetRange(0x14, 0x8c);
        cfg.f44 = 0x80400209;
        cfg.f61 = 0;
        cfg.f42 = 0x23b;
        break;
    case 0x28a:
        cfg.f30 = lbl_803DF884;
        cfg.f34 = lbl_803DF884;
        cfg.f38 = lbl_803DF9B0;
        cfg.f3c = lbl_803DF904;
        cfg.f60 = 0x55;
        cfg.f08 = randomGetRange(0x32, 0x40);
        cfg.f44 = 0x200;
        cfg.f42 = 0xc9d;
        break;
    case 0x28b:
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0x12c);
        cfg.f3c = lbl_803DF978;
        cfg.f08 = 0x14;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100200;
        cfg.f42 = 0x159;
        break;
    case 0x28c:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0, 0xc8);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f24 = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803DF870 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DF9B4 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = randomGetRange(0, 0x1e) + 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x88108;
        cfg.f42 = 0x159;
        break;
    case 0x28d:
        cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.f08 = randomGetRange(0, 0x14) + 0xa;
        cfg.f60 = 0x7d;
        cfg.f44 = 0x500200;
        cfg.f42 = 0x159;
        break;
    case 0x28e:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0x12c, 0x708);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.f24 = lbl_803DB7C8 * (lbl_803DF970 * (f32)(s32)randomGetRange(-0x28, 0x28));
        cfg.f2c = -lbl_803DB7C8 * (lbl_803DF970 * (f32)(s32)randomGetRange(-0x28, 0x28));
        cfg.f3c = lbl_803DF96C;
        cfg.f08 = 0x118;
        cfg.f60 = 0xff;
        cfg.f48 = 0x300020;
        cfg.f44 = 0x2008000;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x63bf;
        cfg.f50 = 0x9e7;
        cfg.f54 = 0x3e8;
        cfg.f42 = 0x23b;
        break;
    case 0x28f:
    case 0x290:
    case 0x291:
    case 0x292:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x64);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(5, 0x19);
        cfg.f08 = 0x230;
        cfg.f60 = 0xff;
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f0e = randomGetRange(0, 0xffff);
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f18 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f1c = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f20 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f48 = 0x20;
        cfg.f44 = 0x86000008;
        cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.f5a = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.f5c = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.f4c = cfg.f58;
        cfg.f50 = cfg.f5a;
        cfg.f54 = cfg.f5c;
        cfg.f42 = param_2 + 0x113;
        break;
    case 0x293:
    case 0x294:
    case 0x295:
    case 0x296:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f34 = lbl_803DF9B8;
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f24 = lbl_803DF9BC * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF870 * (f32)(s32)randomGetRange(0x64, 0xc8);
        cfg.f2c = lbl_803DF9BC * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(5, 0x19);
        cfg.f08 = 0x7d0;
        cfg.f60 = 0xff;
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f0e = randomGetRange(0, 0xffff);
        cfg.f0c = randomGetRange(0, 0xffff);
        cfg.f18 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f1c = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f20 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f48 = 0x31000020;
        cfg.f44 = 0x8e000108;
        cfg.f58 = (u16)(randomGetRange(0, (param_2 - 0x292) * 0x2710) + 0x63bf);
        cfg.f5a = (u16)(randomGetRange(0, (param_2 - 0x292) * 0x2710) + 0x3caf);
        cfg.f5c = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.f4c = cfg.f58;
        cfg.f50 = cfg.f5a;
        cfg.f54 = cfg.f5c;
        cfg.f42 = param_2 + 0x10f;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    lbl_803DD348 = lbl_803DD2C4;
    return uVar1;
}
#undef FILL338

extern void *Obj_GetPlayerObject();
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
    param_3 = (s16 *)&lbl_8039C368;             \
  } while (0)

int Effect7_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    void *player;
    PartFxSpawn cfg;

    player = Obj_GetPlayerObject();
    lbl_803DB800 += 0.001f;
    if (lbl_803DB800 > 1.0f) lbl_803DB800 = 0.1f;
    lbl_803DB804 += 0.0003f;
    if (lbl_803DB804 > 1.0f) lbl_803DB804 = 0.3f;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFCEC;
    cfg.f34 = lbl_803DFCEC;
    cfg.f38 = lbl_803DFCEC;
    cfg.f24 = lbl_803DFCEC;
    cfg.f28 = lbl_803DFCEC;
    cfg.f2c = lbl_803DFCEC;
    cfg.f3c = lbl_803DFCEC;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0xae:
        cfg.f24 = lbl_803DFCF0 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f2c = lbl_803DFCF4 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f28 = lbl_803DFCF0 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f3c = lbl_803DFCF8 * (f32)(s32)randomGetRange(0x1e, 0x50);
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x100200;
        cfg.f42 = 0x88;
        break;
    case 0xaf:
        cfg.f24 = lbl_803DFCFC * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f2c = lbl_803DFCF4 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f28 = lbl_803DFCFC * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f3c = lbl_803DFD00 * (f32)(s32)randomGetRange(0x3c, 0x50);
        cfg.f08 = 0x46;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x400000;
        cfg.f48 = 8;
        cfg.f42 = 0xe4;
        break;
    case 0xad:
        cfg.f24 = lbl_803DFD04 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803DFD08 * (f32)(s32)randomGetRange(6, 0x16);
        cfg.f2c = lbl_803DFD04 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f30 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f34 = lbl_803DFCEC;
        cfg.f38 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f3c = lbl_803DFD0C;
        cfg.f08 = 0x91;
        cfg.f60 = 0xff;
        cfg.f58 = 0xffff;
        cfg.f5a = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
        cfg.f5c = 0x3caf;
        cfg.f4c = 0xf52f;
        cfg.f50 = 0xf52f;
        cfg.f54 = 0xf52f;
        cfg.f44 = 0x3000020;
        cfg.f48 = 0x2600020;
        cfg.f42 = 0xe4;
        break;
    case 0xac:
        cfg.f30 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f34 = lbl_803DFCEC;
        cfg.f38 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f24 = lbl_803DFD04 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DFD10 * (f32)(s32)randomGetRange(9, 0xc);
        cfg.f2c = lbl_803DFD04 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f3c = lbl_803DFD14 * (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.f08 = randomGetRange(0, 0x14) + 0x5f;
        cfg.f60 = 0xff;
        cfg.f42 = 0x60;
        cfg.f58 = 0x3caf;
        cfg.f5a = 0x3caf;
        cfg.f5c = 0x3caf;
        cfg.f4c = 0xa70f;
        cfg.f50 = 0xa70f;
        cfg.f54 = 0xa70f;
        cfg.f61 = 0;
        cfg.f44 = 0x80180100;
        cfg.f48 = 0x20;
        break;
    case 0x84:
        cfg.f24 = lbl_803DFD18 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFD04 * (f32)(s32)randomGetRange(4, 0xa);
        cfg.f2c = lbl_803DFD1C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFD20 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f44 = 0x1400211;
        cfg.f42 = 0xdf;
        break;
    case 0x85:
        if (param_6 == 0) return 0;
        cfg.f30 = ((GameObject *)player)->anim.worldPosX;
        cfg.f34 = ((GameObject *)player)->anim.worldPosY;
        cfg.f38 = ((GameObject *)player)->anim.worldPosZ;
        cfg.f3c = lbl_803DFD24;
        cfg.f08 = 0x28;
        cfg.f60 = 0xff;
        cfg.f44 = 0x110;
        cfg.f42 = ((PartFxSpawnParams *)param_3)->unk4 + 0x170;
        break;
    case 0x8a:
        cfg.f30 = lbl_803DFD28;
        cfg.f34 = (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f38 = (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f24 = lbl_803DFD2C;
        cfg.f3c = lbl_803DFD30 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0x10e;
        cfg.f61 = 0x10;
        cfg.f60 = 0xf;
        cfg.f44 = 0x2000011;
        cfg.f42 = 0x5f;
        break;
    case 0x8b:
        cfg.f30 = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.f34 = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.f38 = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.f24 = lbl_803DFD34 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFD34 * (f32)(s32)randomGetRange(4, 0xa);
        cfg.f2c = lbl_803DFD34 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFD38 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f04 = 0x378;
        cfg.f44 = 0x80000119;
        cfg.f42 = 0x125;
        break;
    case 0x8e:
        cfg.f24 = lbl_803DFD3C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFD3C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DFD3C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFD3C;
        cfg.f08 = 0x50;
        cfg.f60 = 0xff;
        cfg.f44 = 0x100110;
        cfg.f42 = 0x30;
        break;
    case 0x8f:
        cfg.f30 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f34 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f38 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f24 = lbl_803DFD1C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFD1C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DFD1C * (f32)(s32)randomGetRange(-0x28, 0x28);
        if ((int)randomGetRange(0, 0xc) == 0) {
            cfg.f3c = lbl_803DFD40 * (f32)(s32)randomGetRange(0xf, 0x1e);
            cfg.f60 = 0x5f;
        } else {
            cfg.f3c = lbl_803DFD44 * (f32)(s32)randomGetRange(0xf, 0x1e);
            cfg.f60 = 0xff;
        }
        cfg.f08 = 0x1e;
        cfg.f44 = 0x400108;
        cfg.f42 = 0x33;
        break;
    case 0x9a:
        cfg.f30 = lbl_803DFD48;
        cfg.f34 = lbl_803DFD4C + (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.f38 = (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.f3c = lbl_803DFD04 * (f32)(s32)randomGetRange(1, 0xa);
        cfg.f08 = randomGetRange(0x50, 0x78);
        cfg.f60 = 0xff;
        cfg.f44 = 0x100210;
        cfg.f42 = 0x125;
        cfg.f61 = 5;
        break;
    case 0x9b:
        cfg.f30 = (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.f34 = lbl_803DFD4C - (f32)(s32)randomGetRange(0, 0x42);
        cfg.f38 = (f32)(s32)randomGetRange(-0x60, 0x60);
        cfg.f28 = lbl_803DFD50 * (f32)(s32)randomGetRange(0, 0x28);
        cfg.f3c = lbl_803DFD54 * (f32)(s32)randomGetRange(0xa, 0x28);
        cfg.f08 = randomGetRange(0, 0x1e) + 0x1e;
        cfg.f60 = 0xff;
        cfg.f44 = 0x100200;
        cfg.f42 = 0x125;
        break;
    case 0x9c:
        cfg.f24 = lbl_803DFD50 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFD50 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DFD50 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFD58;
        cfg.f08 = 0x1e;
        cfg.f60 = 0xff;
        cfg.f44 = 0x110;
        cfg.f42 = 0xdd;
        break;
    case 0x9f:
        cfg.f24 = lbl_803DFD5C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = lbl_803DFD5C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803DFD5C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFD54;
        cfg.f08 = randomGetRange(0x23, 0x4b);
        cfg.f44 = 0x81480000;
        cfg.f48 = 0x410800;
        cfg.f42 = 0x167;
        break;
    case 0xa0:
        if (param_3 == 0) FILL368();
        cfg.f30 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.f34 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFCDC * (f32)(s32)randomGetRange(-0xa, 0);
        cfg.f60 = 0xff;
        if (param_3 != 0) {
            cfg.f30 = cfg.f30 + ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = cfg.f34 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = cfg.f38 + ((PartFxSpawnParams *)param_3)->unk14;
            if (lbl_803DFCE0 == ((PartFxSpawnParams *)param_3)->unk8) {
                cfg.f60 = 0xff;
            } else {
                cfg.f60 = (u8)(s32)(lbl_803DFD60 * ((PartFxSpawnParams *)param_3)->unk8);
            }
        }
        cfg.f3c = lbl_803DFD64 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = 0x2d;
        cfg.f44 = 0x200;
        cfg.f42 = 0x125;
        cfg.f61 = randomGetRange(0, 0x14) + 4;
        break;
    case 0xa1:
        cfg.f28 = lbl_803DFD68 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f24 = lbl_803DFD6C * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.f38 = lbl_803DFD70 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DFD70 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFD74 * (f32)(s32)randomGetRange(0x32, 0xc8);
        cfg.f08 = 0x96;
        cfg.f42 = 0xc10;
        cfg.f44 = (u32)randFn_80080100;
        cfg.f48 = 0x4020020;
        cfg.f60 = randomGetRange(0x7f, 0xff);
        cfg.f58 = cfg.f4c = 0xa70f;
        cfg.f5a = cfg.f50 = 0xa70f;
        cfg.f5c = cfg.f54 = 0xc350;
        break;
    case 0xa3:
        if (param_3 == 0) break;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f2c = lbl_803DFD78 * (f32)(s32)randomGetRange(0x64, 0x78);
        cfg.f3c = lbl_803DFD7C * (f32)(s32)randomGetRange(0x3c, 0x50);
        {
            int t = randomGetRange(0, 5);
            t += ((PartFxSpawnParams *)param_3)->unk6;
            cfg.f08 = t + 7;
        }
        cfg.f42 = 0x185;
        cfg.f44 = 0xc0080004;
        cfg.f48 = 0x4420800;
        break;
    case 0xa7:
        cfg.f24 = lbl_803DFD80 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = lbl_803DFD80 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803DFD80 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFD20 * (f32)(s32)randomGetRange(0x23, 0x32);
        cfg.f08 = randomGetRange(0xa, 0x28) + 0xa;
        cfg.f42 = 0xc13;
        cfg.f44 = 0x81080010;
        cfg.f48 = 0x482800;
        break;
    case 0xa8:
        cfg.f3c = lbl_803DFCDC;
        cfg.f08 = 0xe;
        cfg.f44 = 0x480100;
        cfg.f48 = 0x4000800;
        cfg.f42 = 0x5fd;
        cfg.f60 = 0x64;
        break;
    case 0xa9:
        if (param_3 != 0) {
            cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DFD20 * (f32)(s32)randomGetRange(0x4b, 0x64));
        } else {
            cfg.f3c = lbl_803DFD20 * (f32)(s32)randomGetRange(0x4b, 0x64);
        }
        cfg.f08 = 1;
        cfg.f44 = 0x80010;
        cfg.f48 = 0x800;
        cfg.f42 = 0xc7e;
        cfg.f60 = 0x96;
        break;
    case 0xaa:
        cfg.f3c = lbl_803DFD84 * (f32)(s32)randomGetRange(0x96, 0xc8);
        cfg.f08 = randomGetRange(0xf, 0x19);
        cfg.f42 = 0x185;
        cfg.f44 = 0x80180200;
        cfg.f48 = 0x4000000;
        cfg.f60 = 0x96;
        break;
    case 0xab:
        cfg.f3c = lbl_803DFD84 * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.f08 = randomGetRange(0x19, 0x2d);
        cfg.f42 = 0x185;
        cfg.f44 = 0x80180210;
        cfg.f48 = 0x4000800;
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
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
}
#undef FILL368

typedef struct MtxBuildArg {
    s16 rx;
    s16 ry;
    s16 rz;
    u8  pad6[2];
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

int Effect5_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7E0 = lbl_803DB7E0 + lbl_803DFBE0;
    if (lbl_803DB7E0 > 1.0f) lbl_803DB7E0 = lbl_803DFBE4;
    lbl_803DB7E4 = lbl_803DB7E4 + lbl_803DFBEC;
    if (lbl_803DB7E4 > 1.0f) lbl_803DB7E4 = lbl_803DFBF0;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFBF4;
    cfg.f34 = lbl_803DFBF4;
    cfg.f38 = lbl_803DFBF4;
    cfg.f24 = lbl_803DFBF4;
    cfg.f28 = lbl_803DFBF4;
    cfg.f2c = lbl_803DFBF4;
    cfg.f3c = lbl_803DFBF4;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0xc8:
        cfg.f30 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f34 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f38 = (f32)(s32)randomGetRange(-6, 6);
        cfg.f3c = lbl_803DFBF8 * (f32)(s32)randomGetRange(4, 8);
        cfg.f08 = 0x24;
        cfg.f60 = 0x41;
        cfg.f44 = 0x100111;
        cfg.f42 = 0xc10;
        break;
    case 0xca:
        if (param_3 == 0) return 0;
        cfg.f24 = lbl_803DFBFC * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFBFC * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFC00 * (f32)(s32)randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = *param_3;
        vecRotateZXY(&es, &cfg.f24);
        cfg.f3c = lbl_803DFC04 * (f32)(s32)randomGetRange(4, 8);
        cfg.f08 = 0x46;
        cfg.f60 = 0x64;
        cfg.f61 = 0;
        cfg.f44 = 0x180108;
        cfg.f48 = 0x5000000;
        if (((PartFxSpawnParams *)param_3)->unk4 == 0) {
            cfg.f42 = 0x2b;
        } else if (((PartFxSpawnParams *)param_3)->unk4 == 1) {
            cfg.f42 = 0x1a1;
        } else if (((PartFxSpawnParams *)param_3)->unk4 == 2) {
            cfg.f42 = 0xc10;
            cfg.f48 = cfg.f48 | 0x800;
        } else {
            cfg.f42 = 0x2b;
        }
        break;
    case 0xcb:
        if (param_3 == 0) return 0;
        cfg.f24 = lbl_803DFC08 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFC0C * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFC08 * (f32)(s32)randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = *param_3;
        vecRotateZXY(&es, &cfg.f24);
        cfg.f3c = lbl_803DFC10 * (f32)(s32)randomGetRange(4, 8);
        cfg.f08 = 0x46;
        cfg.f60 = 0xff;
        cfg.f61 = 0;
        cfg.f44 = 0x1080100;
        cfg.f48 = 0x5000000;
        if (((PartFxSpawnParams *)param_3)->unk4 == 0) {
            cfg.f42 = 0x2b;
        } else if (((PartFxSpawnParams *)param_3)->unk4 == 1) {
            cfg.f42 = 0x1a1;
        } else if (((PartFxSpawnParams *)param_3)->unk4 == 2) {
            cfg.f42 = 0xc10;
            cfg.f48 = cfg.f48 | 0x800;
        } else {
            cfg.f42 = 0x2b;
        }
        break;
    case 0xcc:
        cfg.f30 = (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f34 = lbl_803DFC14 * (f32)(s32)randomGetRange(1, 2);
        cfg.f38 = (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f24 = lbl_803DFC18 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DFC18 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803DFC1C * (f32)(s32)randomGetRange(4, 8);
        cfg.f08 = 0xfa;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80108;
        cfg.f42 = 0x5c;
        break;
    case 0xcd:
        cfg.f30 = (f32)(s32)randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = lbl_803DFC20 + cfg.f30 / lbl_803DFC20;
            cfg.f34 = v + rnd;
        }
        cfg.f38 = lbl_803DFC24 * cfg.f30;
        cfg.f3c = lbl_803DFC28 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0xfa;
        cfg.f60 = 0x7d;
        cfg.f44 = 0x80080118;
        cfg.f42 = 0x5c;
        break;
    case 0xce:
        cfg.f30 = lbl_803DFC2C + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFC30 + (f32)(s32)randomGetRange(-8, 8);
        cfg.f38 = lbl_803DFC34 + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFC38 * (f32)(s32)randomGetRange(0, 0xa);
        cfg.f3c = lbl_803DFBEC * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.f60 = 0x37;
        cfg.f44 = 0x180100;
        cfg.f42 = 0x4c;
        break;
    case 0xcf:
        cfg.f30 = -(f32)(s32)randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = lbl_803DFC20 + cfg.f30 / lbl_803DFC20;
            cfg.f34 = v + rnd;
        }
        cfg.f38 = -cfg.f30;
        cfg.f3c = lbl_803DFC28 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0xfa;
        cfg.f60 = 0x7d;
        cfg.f44 = 0x80080118;
        cfg.f42 = 0x5c;
        break;
    case 0xd0:
        cfg.f30 = lbl_803DFC40 + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803DFC30 + (f32)(s32)randomGetRange(-8, 8);
        cfg.f38 = lbl_803DFC44 + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DFC38 * (f32)(s32)randomGetRange(0, 0xa);
        cfg.f3c = lbl_803DFBEC * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.f60 = 0x37;
        cfg.f44 = 0x180100;
        cfg.f42 = 0x4c;
        break;
    case 0xd1:
        cfg.f3c = lbl_803DFBEC * (f32)(s32)randomGetRange(0x46, 0x50);
        cfg.f08 = randomGetRange(0, 0xf) + 0x14;
        cfg.f61 = 0;
        cfg.f60 = 0xff;
        cfg.f44 = 0x180210;
        cfg.f42 = 0x159;
        break;
    case 0xd2:
        cfg.f3c = lbl_803DFBFC;
        cfg.f08 = 0x50;
        cfg.f44 = 0x400000;
        cfg.f42 = 0x159;
        break;
    case 0xd3:
        cfg.f30 = -(f32)(s32)randomGetRange(0, 0xfa);
        cfg.f34 = lbl_803DFC48 + (f32)(s32)randomGetRange(-5, 5);
        cfg.f38 = (f32)(s32)randomGetRange(-5, 5);
        cfg.f2c = lbl_803DFBE4 * (f32)(s32)randomGetRange(-5, 5);
        cfg.f3c = lbl_803DFC4C * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0xa0;
        cfg.f60 = 0x7d;
        cfg.f44 = 0x180108;
        cfg.f42 = 0x5c;
        break;
    case 0xd4:
        cfg.f30 = (f32)(s32)randomGetRange(-0xa, 0x14);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x1c);
        cfg.f38 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFC50 * (f32)(s32)randomGetRange(0, 0xa);
        cfg.f3c = lbl_803DFC54 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = (s32)(lbl_803DFC58 + (f32)(s32)randomGetRange(0, 0x14));
        cfg.f60 = 0x37;
        cfg.f44 = 0x180100;
        cfg.f42 = 0x4c;
        break;
    case 0xd5:
        cfg.f3c = lbl_803DFC5C;
        cfg.f04 = 0xd6;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80000;
        cfg.f42 = 0x159;
        break;
    case 0xd6:
        cfg.f3c = lbl_803DFC5C;
        cfg.f08 = 0x28;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80100;
        cfg.f42 = 0x159;
        break;
    case 0xd7:
        cfg.f30 = lbl_803DFC60 * (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.f34 = lbl_803DFC60 * (f32)(s32)randomGetRange(-0x32, 0xa);
        cfg.f38 = lbl_803DFC60 * (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.f28 = lbl_803DFC64 * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.f3c = lbl_803DFC68 * (f32)(s32)randomGetRange(1, 0xa);
        cfg.f08 = 0x8c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80180100;
        cfg.f42 = 0x5f;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
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
    param_3 = (s16 *)&lbl_8039C350;             \
  } while (0)

int Effect3_func04(void *param_1, int param_2, void *param_3v, u32 param_4,
                   u8 param_5, void *param_6v)
{
    int uVar1;
    PartFxSpawn cfg;
    s16 *param_6 = (s16 *)param_6v;
    s16 *param_3 = (s16 *)param_3v;

    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DF9D0;
    cfg.f34 = lbl_803DF9D0;
    cfg.f38 = lbl_803DF9D0;
    cfg.f24 = lbl_803DF9D0;
    cfg.f28 = lbl_803DF9D0;
    cfg.f2c = lbl_803DF9D0;
    cfg.f3c = lbl_803DF9D0;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x1f4:
        if (param_3 == 0) FILL350();
        cfg.f30 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.f34 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xa, 0);
        if (param_3 != 0) {
            cfg.f30 = cfg.f30 + ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = cfg.f34 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = cfg.f38 + ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f3c = lbl_803DF9DC * (f32)(s32)randomGetRange(0xd, 0x14);
        cfg.f08 = 0x19;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80200;
        cfg.f48 = 0x4000800;
        cfg.f42 = 0x184;
        cfg.f61 = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f5:
        if (param_3 == 0) FILL350();
        cfg.f30 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.f34 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xa, 0);
        if (param_3 != 0) {
            cfg.f30 = cfg.f30 + ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = cfg.f34 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = cfg.f38 + ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f3c = lbl_803DF9E0 * (f32)(s32)randomGetRange(1, 4);
        cfg.f08 = 0x19;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80200;
        cfg.f42 = 0x184;
        cfg.f61 = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f6:
        cfg.f3c = lbl_803DF9E4 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = 0x14;
        cfg.f60 = 0x40;
        cfg.f44 = 0x80000;
        cfg.f48 = 0x80;
        cfg.f42 = 0x16d;
        cfg.f61 = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f7:
        if (param_3 == 0) FILL350();
        if (param_3 != 0) cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f3c = lbl_803DF9E8;
        cfg.f08 = randomGetRange(0, 0x1e) + 0x46;
        cfg.f60 = 0x7f;
        cfg.f44 = 0x80110;
        cfg.f42 = 0xc13;
        cfg.f61 = 0x20;
        break;
    case 0x1f8:
        if (param_3 == 0) FILL350();
        if (param_3 != 0) {
            cfg.f3c = lbl_803DF9E8 * ((PartFxSpawnParams *)param_3)->unk8;
        } else {
            cfg.f3c = lbl_803DF9E8;
        }
        cfg.f08 = randomGetRange(0, 0x1e) + 0x46;
        cfg.f60 = 0x64;
        cfg.f44 |= 0x80100LL;
        cfg.f42 = 0xc79;
        cfg.f61 = 0;
        cfg.f58 = 0xe600;
        cfg.f5a = 0x8800;
        cfg.f5c = 0xa100;
        cfg.f4c = 0xe600;
        cfg.f50 = 0x8800;
        cfg.f54 = 0xa100;
        cfg.f48 = 0x20;
        break;
    case 0x1fb:
        cfg.f3c = lbl_803DF9EC;
        cfg.f08 = 0x10;
        cfg.f60 = 0xff;
        cfg.f44 = 0x100114;
        cfg.f42 = 0x17c;
        break;
    case 0x1fc:
        cfg.f3c = lbl_803DF9E8;
        cfg.f08 = 0x44;
        cfg.f44 = 0x100201;
        cfg.f42 = 0x4c;
        break;
    case 0x1fd:
        cfg.f30 = lbl_803DF9D0;
        cfg.f34 = (f32)(s32)randomGetRange(-3, 3);
        cfg.f38 = (f32)(s32)randomGetRange(-3, 3);
        cfg.f24 = lbl_803DF9F0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF9F0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DF9F0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DF9F4;
        cfg.f08 = 0x1e;
        cfg.f60 = 0xc8;
        cfg.f44 = 0x140101;
        if ((int)randomGetRange(0, 1) != 0) {
            cfg.f42 = 0x33;
        } else {
            cfg.f42 = 0xc7e;
        }
        break;
    case 0x1fe:
        if (param_3 == 0) FILL350();
        if (param_6 == 0) return -1;
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        if (param_6 != 0) {
            cfg.f24 = *(f32 *)param_6;
            cfg.f28 = lbl_803DF9E8 * (f32)(s32)randomGetRange(0, 0x14);
            cfg.f2c = *(f32 *)(param_6 + 2);
        }
        cfg.f3c = lbl_803DF9FC * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF9F8;
        cfg.f08 = randomGetRange(0xbe, 0xfa);
        cfg.f60 = 0x9b;
        cfg.f44 = 0x81088000;
        cfg.f44 = 0x1000000;
        cfg.f42 = 0x23c;
        break;
    case 0x1ff:
        cfg.f34 = lbl_803DFA00;
        cfg.f3c = lbl_803DF9E0;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x11000004;
        cfg.f42 = 0x151;
        cfg.f04 = 0x200;
        break;
    case 0x200:
        Sfx_PlayFromObject(param_1, SFXsc_snort02);
        cfg.f08 = 0x64;
        cfg.f3c = lbl_803DFA04 * (f32)cfg.f08;
        cfg.f44 = 0xa100201;
        cfg.f42 = 0x56;
        break;
    case 0x201:
        cfg.f30 = (f32)(s32)randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.f34 = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803DFA0C;
        cfg.f38 = (f32)(s32)randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.f28 = lbl_803DF9E8 * (f32)(s32)randomGetRange(1, 5);
        cfg.f3c = lbl_803DFA10;
        cfg.f08 = 0x64;
        cfg.f61 = 0;
        cfg.f44 = 0x100201;
        cfg.f42 = 0x63;
        break;
    case 0x202:
        cfg.f28 = lbl_803DF9D8 * (f32)(s32)randomGetRange(0x96, 0xc8) / lbl_803DFA14;
        cfg.f3c = lbl_803DFA1C * ((f32)(s32)randomGetRange(0x32, 0x64) / lbl_803DFA14) + lbl_803DFA18;
        cfg.f08 = (s32)(((PartFxSpawnParams *)param_3)->unk8 / cfg.f28);
        if (cfg.f08 < 0xa) cfg.f08 = 0xa;
        if (cfg.f08 > 0x78) cfg.f08 = 0x78;
        cfg.f61 = 0;
        cfg.f44 = 0x201;
        cfg.f48 = 0x4000000;
        cfg.f42 = 0xc9f;
        cfg.f60 = 0x60;
        break;
    case 0x203:
        if (param_3 == 0) FILL350();
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f28 = lbl_803DFA20;
        switch (randomGetRange(0, 3)) {
        case 0:
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 1:
            cfg.f30 = -((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 2:
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        case 3:
            cfg.f38 = -((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        }
        cfg.f3c = lbl_803DFA24;
        cfg.f08 = 0x3c;
        cfg.f44 = 0x100210;
        cfg.f42 = 0x184;
        cfg.f60 = 0xc4;
        break;
    case 0x204:
        if (param_3 == 0) FILL350();
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f28 = lbl_803DFA20;
        switch (randomGetRange(0, 3)) {
        case 0:
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 1:
            cfg.f30 = -((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 2:
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        case 3:
            cfg.f38 = -((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        }
        cfg.f28 = lbl_803DFA28 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f3c = lbl_803DFA2C * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f08 = 0x78;
        cfg.f61 = 0;
        cfg.f44 = 0x80400110;
        cfg.f42 = 0x47;
        break;
    case 0x205:
        if (param_3 == 0) FILL350();
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f28 = lbl_803DFA20;
        switch (randomGetRange(0, 3)) {
        case 0:
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 1:
            cfg.f30 = -((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 2:
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        case 3:
            cfg.f38 = -((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        }
        cfg.f28 = lbl_803DFA28 * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.f3c = lbl_803DF9FC * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.f08 = 0x96;
        cfg.f60 = 0x9b;
        cfg.f48 = 0x20;
        cfg.f44 = 0x180210;
        cfg.f58 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.f5a = cfg.f58 / (int)randomGetRange(1, 3);
        cfg.f5c = 0;
        cfg.f4c = randomGetRange(0, 0x2710);
        cfg.f50 = (int)cfg.f4c / (int)randomGetRange(1, 3);
        cfg.f54 = 0;
        cfg.f42 = 0x60;
        break;
    case 0x206:
        if (param_3 == 0) FILL350();
        cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10 - lbl_803DFA30;
        cfg.f28 = lbl_803DFA20;
        switch (randomGetRange(0, 3)) {
        case 0:
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 1:
            cfg.f30 = -((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unk14, (s16)(s32) * (f32 *)(param_3 + 10));
            break;
        case 2:
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        case 3:
            cfg.f38 = -((PartFxSpawnParams *)param_3)->unk14;
            cfg.f30 = (f32)(s32)randomGetRange((s16)(s32)-((PartFxSpawnParams *)param_3)->unkC, (s16)(s32) * (f32 *)(param_3 + 6));
            break;
        }
        cfg.f28 = lbl_803DFA34 * (f32)(s32)randomGetRange(0x50, 0x64);
        cfg.f3c = lbl_803DFA1C * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80080110;
        cfg.f42 = 0x60;
        break;
    case 0x208:
        cfg.f30 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.f34 = lbl_803DFA38;
        cfg.f38 = lbl_803DF9D8 * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.f28 = lbl_803DFA3C * (f32)(s32)randomGetRange(0x190, 0x258);
        cfg.f24 = lbl_803DFA04 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803DFA04 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFA44 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFA40;
        cfg.f08 = 0xb4;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80080000;
        cfg.f48 = 0x100000;
        cfg.f42 = 0xe7;
        break;
    case 0x209:
        cfg.f34 = (f32)(s32)randomGetRange(1, 5);
        cfg.f28 = lbl_803DFA48 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f3c = lbl_803DFA4C * (lbl_803DF9FC * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFA50);
        cfg.f08 = randomGetRange(0x73, 0x8c);
        cfg.f60 = 0xff;
        cfg.f44 = 0x80480200;
        cfg.f42 = 0xc0d;
        break;
    case 0x20a:
        {
            f32 a;
            f32 b;
            if (param_3 == 0) FILL350();
            cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
            cfg.f34 = (f32)(s32)randomGetRange(1, 5);
            cfg.f38 = (f32)(s32)randomGetRange(-5, 5);
            a = lbl_803DF9E0 * (f32)(s32)randomGetRange(0, 0x258) + lbl_803DFA54;
            cfg.f28 = lbl_803DFA10 * (f32)(s32)randomGetRange(0, 0xc8) + lbl_803DF9D4;
            cfg.f24 = mathSinf(lbl_803DFA58 * (f32)*(s16 *)param_1 / lbl_803DFA5C);
            cfg.f2c = mathCosf(lbl_803DFA58 * (f32)*(s16 *)param_1 / lbl_803DFA5C);
            b = a * (lbl_803DFA60 * (f32)(s32)randomGetRange(0, 0x14)) + lbl_803DF9D8;
            cfg.f24 = cfg.f24 * b;
            cfg.f2c = cfg.f2c * b;
            cfg.f28 = cfg.f28 * a;
            cfg.f3c = lbl_803DFA68 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFA64;
            cfg.f08 = randomGetRange(0xb4, 0xc8);
            cfg.f60 = 0xff;
            cfg.f44 = 0x3000120;
            cfg.f48 = 0x200000;
            cfg.f42 = 0xc0a;
            cfg.f04 = 0x20b;
        }
        break;
    case 0x20b:
        cfg.f28 = lbl_803DF9F0 * (f32)(s32)randomGetRange(2, 0x14);
        cfg.f3c = lbl_803DFA6C;
        cfg.f08 = 0x1e;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180100;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.f5c = 0;
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = cfg.f5a;
        cfg.f54 = 0;
        cfg.f48 = 0x20;
        break;
    case 0x20c:
        cfg.f30 = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.f34 = (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.f38 = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.f24 = lbl_803DFA24 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DF9D8 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFA24 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f3c = lbl_803DF9FC * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFA70;
        cfg.f08 = randomGetRange(0x78, 0x8c);
        cfg.f60 = 0xff;
        cfg.f04 = 0x20b;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x1001100;
        cfg.f42 = 0xc0a;
        break;
    case 0x20d:
        cfg.f24 = lbl_803DFA74 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803DFA78 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DFA74 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f34 = lbl_803DF9D8 * (f32)(s32)randomGetRange(0, 0x190);
        cfg.f3c = lbl_803DFA04 * (f32)(s32)randomGetRange(0xf, 0x19);
        cfg.f08 = 0x64;
        cfg.f44 = 0x4a0104;
        cfg.f48 = 0x40008;
        cfg.f18 = lbl_803DF9D0;
        cfg.f1c = lbl_803DF9D0;
        cfg.f20 = lbl_803DF9D0;
        cfg.f0c = 0x46;
        cfg.f0e = 0;
        cfg.f10 = 0;
        cfg.f14 = lbl_803DF9D4;
        cfg.f42 = 0xe0;
        break;
    case 0x20e:
        cfg.f34 = lbl_803DFA38;
        cfg.f3c = lbl_803DF9F0;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x11800004;
        cfg.f60 = 0xa0;
        cfg.f42 = 0x151;
        cfg.f04 = 0x200;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
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

int Effect4_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    int iVar1;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7D0 = lbl_803DB7D0 + lbl_803DFA88;
    if (lbl_803DB7D0 > 1.0f) lbl_803DB7D0 = lbl_803DFA8C;
    lbl_803DB7D4 = lbl_803DB7D4 + lbl_803DFA94;
    if (lbl_803DB7D4 > 1.0f) lbl_803DB7D4 = lbl_803DFA98;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFA9C;
    cfg.f34 = lbl_803DFA9C;
    cfg.f38 = lbl_803DFA9C;
    cfg.f24 = lbl_803DFA9C;
    cfg.f28 = lbl_803DFA9C;
    cfg.f2c = lbl_803DFA9C;
    cfg.f3c = lbl_803DFA9C;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x1c8:
        cfg.f34 = lbl_803DFA8C * (f32)(s32)randomGetRange(0, 0x64);
        cfg.f24 = lbl_803DFAA0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = cfg.f24 * (lbl_803DFAA0 * (f32)(s32)randomGetRange(-0x1e, 0x1e));
        cfg.f3c = lbl_803DFAA4 * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80118;
        cfg.f48 = 0x8;
        cfg.f42 = 0x566;
        break;
    case 0x1c9:
        cfg.f38 = lbl_803DFAA8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f30);
        cfg.f3c = lbl_803DFAAC * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.f08 = 0x14;
        cfg.f60 = 0xe1;
        cfg.f44 = 0x400000;
        cfg.f42 = 0x4f9;
        break;
    case 0x1ca:
        cfg.f24 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.f3c = lbl_803DFAB4 * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.f08 = 0xc8;
        cfg.f60 = 0xe1;
        cfg.f44 = 0x400110;
        if ((int)randomGetRange(0, 2) == 0) {
            cfg.f48 = cfg.f48 | 0x100;
        } else {
            cfg.f48 = cfg.f48 | 0x400;
        }
        cfg.f42 = 0x4f9;
        break;
    case 0x1c7:
        cfg.f24 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.f28 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.f30 = (f32)(s32)randomGetRange(-0x46, 0x46);
        cfg.f34 = (f32)(s32)randomGetRange(0x82, 0xaa);
        cfg.f38 = (f32)(s32)randomGetRange(-0x46, 0x46);
        cfg.f3c = lbl_803DFAB0;
        cfg.f08 = 0x190;
        cfg.f60 = 0xff;
        cfg.f58 = 0;
        cfg.f5a = 0;
        cfg.f5c = 0;
        cfg.f4c = 0;
        cfg.f50 = 0;
        cfg.f54 = 0;
        cfg.f44 = 0x80480108;
        cfg.f48 = 0x20;
        cfg.f42 = 0x33;
        break;
    case 0x1c5:
        cfg.f30 = lbl_803DFAB8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f30);
        cfg.f3c = lbl_803DFABC;
        cfg.f08 = 0xc8;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480100;
        cfg.f42 = 0x33;
        break;
    case 0x1c4:
        cfg.f30 = lbl_803DFAC0;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f30);
        cfg.f3c = lbl_803DFAC4;
        cfg.f08 = 0xc8;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480100;
        cfg.f42 = 0x26c;
        break;
    case 0x1c6:
        cfg.f30 = lbl_803DFAC8 + (f32)(s32)randomGetRange(0, 0x5a);
        cfg.f34 = (f32)(s32)randomGetRange(-0xa, 0xa);
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f30);
        cfg.f3c = lbl_803DFACC * (f32)(s32)randomGetRange(1, 0x14);
        cfg.f08 = 0xc8;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480100;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x23c;
        break;
    case 0x1c3:
        cfg.f28 = lbl_803DFA8C;
        cfg.f3c = lbl_803DFAC4;
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0xa100110;
        cfg.f42 = 0x23b;
        break;
    case 0x190:
        cfg.f3c = lbl_803DFAD0 * (f32)(s32)randomGetRange(1, 5);
        cfg.f08 = randomGetRange(0xa, 0x14);
        cfg.f48 = 0x2;
        cfg.f61 = 0;
        cfg.f42 = 0xdf;
        break;
    case 0x191:
        cfg.f30 = (f32)(s32)randomGetRange(-0x8, 0x8);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x50);
        cfg.f38 = (f32)(s32)randomGetRange(-0x8, 0x8);
        cfg.f28 = lbl_803DFAD4 * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.f3c = lbl_803DFA88;
        cfg.f08 = 0x64;
        cfg.f60 = 0x7d;
        cfg.f61 = 0x10;
        cfg.f44 = 0x110;
        cfg.f42 = 0xde;
        break;
    case 0x192:
        cfg.f30 = (f32)(s32)randomGetRange(-0x9e, 0x9e);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x78);
        cfg.f38 = (f32)(s32)randomGetRange(-0xd0, 0xd0);
        cfg.f28 = lbl_803DFAD8 * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.f3c = lbl_803DFADC;
        cfg.f08 = 0xc8;
        cfg.f60 = 0x7d;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80080112;
        cfg.f42 = 0x1dd;
        break;
    case 0x193:
        cfg.f30 = (f32)(s32)randomGetRange(-0x9e, 0x9e);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x78);
        cfg.f38 = (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.f28 = lbl_803DFAD4 * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.f3c = lbl_803DFADC;
        cfg.f08 = 0x64;
        cfg.f60 = 0x7d;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80080112;
        cfg.f42 = 0xde;
        break;
    case 0x194:
        cfg.f24 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.f28 = lbl_803DFAB0 * (f32)(s32)randomGetRange(0, 0x78);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.f30 = (f32)(s32)randomGetRange(-0x5, 0x5);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x50);
        cfg.f38 = (f32)(s32)randomGetRange(-0x5, 0x5);
        cfg.f3c = lbl_803DFAE0;
        cfg.f08 = 0x96;
        cfg.f60 = 0x7d;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480110;
        cfg.f48 = 0x8;
        cfg.f42 = 0xde;
        break;
    case 0x195:
        cfg.f3c = lbl_803DFAE4;
        cfg.f08 = 0x14;
        cfg.f60 = 0x9b;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480214;
        cfg.f42 = 0xde;
        break;
    case 0x196:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f24 = lbl_803DFAE8 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f28 = lbl_803DFAEC * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.f2c = lbl_803DFAE8 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f3c = lbl_803DFAF0;
        cfg.f08 = 0x78;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0x8acf;
        cfg.f4c = 0xafc8;
        cfg.f50 = 0x3a98;
        cfg.f54 = 0x5dc;
        cfg.f44 = 0x81080200;
        cfg.f48 = 0x24;
        cfg.f42 = 0x1dd;
        break;
    case 0x197:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f24 = lbl_803DFAF4 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f28 = lbl_803DFAF8 * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.f2c = lbl_803DFAF4 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f3c = lbl_803DFAB0;
        cfg.f08 = 0x50;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f58 = 0xf82f;
        cfg.f5a = 0xf447;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xa7f8;
        cfg.f50 = 0;
        cfg.f54 = 0;
        cfg.f44 = 0x80080610;
        cfg.f48 = 0x24;
        cfg.f42 = 0x1de;
        break;
    case 0x198:
        cfg.f34 = lbl_803DFAFC * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.f3c = lbl_803DFB00;
        cfg.f08 = 0x1e;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100200;
        cfg.f42 = 0x91;
        break;
    case 0x199:
        cfg.f3c = lbl_803DFB08 * (f32)(s32)randomGetRange(0, 0x32) + lbl_803DFB04;
        cfg.f08 = 0;
        cfg.f60 = (u8)(randomGetRange(0, 0x37) + 0xc8);
        cfg.f61 = 0;
        iVar1 = randomGetRange(0, 2);
        if (iVar1 == 0) {
            cfg.f42 = 0x156;
        } else if (iVar1 == 1) {
            cfg.f42 = 0x157;
        } else if (iVar1 == 2) {
            cfg.f42 = 0xc0e;
        }
        cfg.f44 = 0x80011;
        cfg.f48 = 0x2;
        break;
    case 0x19a:
        cfg.f3c = lbl_803DFB08 * (f32)(s32)randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.f08 = 0xc;
        cfg.f60 = 0x37;
        cfg.f61 = 0;
        cfg.f42 = 0x153;
        cfg.f44 = 0x180011;
        cfg.f48 = 0x2;
        break;
    case 0x19b:
        cfg.f3c = lbl_803DFB08 * (f32)(s32)randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.f08 = 0;
        cfg.f60 = 0x9b;
        cfg.f61 = 0;
        cfg.f42 = 0x153;
        cfg.f44 = 0x80011;
        cfg.f48 = 0x2;
        break;
    case 0x19c:
        cfg.f3c = lbl_803DFB10;
        cfg.f08 = 0x2;
        cfg.f60 = 0x9b;
        cfg.f61 = 0;
        iVar1 = randomGetRange(0, 2);
        if (iVar1 == 0) {
            cfg.f42 = 0x156;
        } else if (iVar1 == 1) {
            cfg.f42 = 0x157;
        } else if (iVar1 == 2) {
            cfg.f42 = 0xc0e;
        }
        cfg.f44 = 0x480001;
        break;
    case 0x19d:
        cfg.f3c = lbl_803DFB14;
        cfg.f08 = 0xf;
        cfg.f60 = 0x9b;
        cfg.f61 = 0;
        cfg.f42 = 0x153;
        cfg.f44 = 0x180201;
        break;
    case 0x19f:
        cfg.f30 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f38 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFB18 * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.f08 = randomGetRange(0x37, 0x4b);
        cfg.f60 = 0x37;
        cfg.f42 = 0xdb;
        cfg.f44 = 0x80080000;
        cfg.f48 = 0x4402800;
        break;
    case 0x1a0:
        cfg.f3c = lbl_803DFB1C * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.f60 = 0x37;
        cfg.f08 = 0xf;
        cfg.f61 = 0x10;
        cfg.f42 = 0xdb;
        cfg.f44 = 0x80100;
        cfg.f48 = 0x4000800;
        break;
    case 0x1bc:
        cfg.f30 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f38 = lbl_803DFABC * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DFB18 * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.f08 = randomGetRange(0x8c, 0xa5);
        cfg.f60 = 0x37;
        cfg.f42 = 0x167;
        cfg.f44 = 0x80000;
        cfg.f48 = 0x4400000;
        break;
    case 0x1bd:
        cfg.f3c = lbl_803DFB1C * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.f60 = 0x37;
        cfg.f08 = 0xf;
        cfg.f61 = 0x10;
        cfg.f42 = 0x64;
        cfg.f44 = 0x4080100;
        break;
    case 0x1a1:
        cfg.f30 = lbl_803DFB20 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DFB20 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f24 = lbl_803DFAEC * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFB24 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f3c = lbl_803DFB28;
        cfg.f08 = randomGetRange(0x28, 0x50);
        cfg.f60 = 0xff;
        cfg.f04 = 0x1a2;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x200;
        cfg.f42 = 0x7b;
        break;
    case 0x1a2:
        cfg.f3c = lbl_803DFB28;
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x2000104;
        cfg.f48 = 0x200;
        cfg.f42 = 0x7b;
        break;
    case 0x1a3:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFAB0 * (f32)(s32)randomGetRange(0, 0x1e) + lbl_803DFB20;
        cfg.f3c = lbl_803DFB2C * (f32)(s32)randomGetRange(1, 0xa);
        cfg.f08 = randomGetRange(0x5a, 0x8c);
        cfg.f44 = 0x80500209;
        cfg.f61 = 0;
        cfg.f42 = 0x23b;
        break;
    case 0x1a4:
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = lbl_803DFB30 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f34 = lbl_803DFB34;
            cfg.f38 = (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f24 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFB38 * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB40 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFB3C;
        cfg.f08 = randomGetRange(0xbe, 0xfa);
        cfg.f60 = 0x9b;
        cfg.f04 = 0x281;
        cfg.f44 = 0x81488000;
        iVar1 = randomGetRange(0, 2);
        if (iVar1 == 0) {
            cfg.f42 = 0x208;
        } else if (iVar1 == 1) {
            cfg.f42 = 0x209;
        } else if (iVar1 == 2) {
            cfg.f42 = 0x20a;
        }
        break;
    case 0x1a5:
        if (param_3 != 0) {
            if (((PartFxSpawnParams *)param_3)->unk8 <= lbl_803DFAB0) {
                ((PartFxSpawnParams *)param_3)->unk8 = *(f32 *)&lbl_803DFAB0;
            }
            cfg.f28 = -((PartFxSpawnParams *)param_3)->unk8;
        } else {
            cfg.f28 = lbl_803DFB44 * (f32)(s32)randomGetRange(0, 0x14);
        }
        cfg.f24 = lbl_803DFB48 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFB48 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB4C * (f32)(s32)randomGetRange(2, 0xa);
        cfg.f08 = randomGetRange(0x3c, 0x46);
        cfg.f60 = 0xff;
        cfg.f44 = 0x80480108;
        cfg.f42 = 0xc13;
        break;
    case 0x1a6:
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f34 = lbl_803DFB34;
            cfg.f38 = (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f24 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFB38 * (f32)(s32)randomGetRange(0, 0x14);
        cfg.f2c = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB40 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFB3C;
        cfg.f08 = randomGetRange(0xbe, 0xfa);
        cfg.f60 = 0x9b;
        cfg.f04 = 0x281;
        cfg.f44 = 0x81488000;
        iVar1 = randomGetRange(0, 2);
        if (iVar1 == 0) {
            cfg.f42 = 0x208;
        } else if (iVar1 == 1) {
            cfg.f42 = 0x209;
        } else if (iVar1 == 2) {
            cfg.f42 = 0x20a;
        }
        cfg.f58 = 0x3200;
        cfg.f5a = 0x3200;
        cfg.f5c = 0x7800;
        cfg.f4c = 0x3200;
        cfg.f50 = 0x3200;
        cfg.f54 = 0x7800;
        cfg.f48 = 0x20;
        break;
    case 0x1b6:
        if (param_3 != 0) {
            cfg.f28 = ((PartFxSpawnParams *)param_3)->unk8;
        } else {
            cfg.f28 = lbl_803DFAD8 * (f32)(s32)randomGetRange(-3, 3);
        }
        cfg.f3c = lbl_803DFB00;
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f61 = 0x10;
        cfg.f44 = 0x88100200;
        cfg.f42 = 0xc79;
        break;
    case 0x1a7:
        cfg.f3c = lbl_803DFB50;
        cfg.f08 = randomGetRange(0, 0xfa) + 0x96;
        cfg.f61 = 0;
        cfg.f04 = 0x1a8;
        cfg.f44 = 0x80490008;
        cfg.f42 = 0x167;
        break;
    case 0x1a8:
        cfg.f3c = lbl_803DFB54;
        cfg.f08 = 0xa;
        cfg.f61 = 0;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80480100;
        cfg.f42 = 0x167;
        break;
    case 0x1a9:
        if ((int)randomGetRange(0, 0x50) == 0) {
            cfg.f08 = 0xf0;
            cfg.f24 = lbl_803DFB58;
        } else {
            cfg.f08 = 0x78;
            cfg.f24 = lbl_803DFB5C;
        }
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f24);
        cfg.f3c = lbl_803DFABC;
        cfg.f61 = 0x10;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80100;
        cfg.f42 = 0xdf;
        break;
    case 0x1b3:
        if (param_3 == 0) return -1;
        cfg.f24 = lbl_803DFB60 * (f32)(s32)randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.f28 = lbl_803DFB60 * (f32)(s32)randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.f2c = lbl_803DFB60 * (f32)(s32)randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.f34 = lbl_803DFB64;
        vecRotateZXY(param_3, &cfg.f24);
        cfg.f3c = lbl_803DFB68 * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f60 = 0xff;
        cfg.f08 = 0x64;
        cfg.f61 = 0x10;
        cfg.f04 = 0x1b4;
        cfg.f44 = 0x480200;
        cfg.f48 = 0x100000;
        cfg.f42 = 0x159;
        break;
    case 0x1b4:
        cfg.f3c = lbl_803DFB6C * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f60 = 0x37;
        cfg.f08 = 0x14;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80201;
        cfg.f48 = 0x2;
        cfg.f42 = 0x159;
        break;
    case 0x1aa:
        if (param_3 == 0) return -1;
        cfg.f24 = lbl_803DFA88 * (f32)(s32)randomGetRange(0, 0x640) + lbl_803DFB70;
        vecRotateZXY(param_3, &cfg.f24);
        if ((int)randomGetRange(0, 1) != 0) {
            cfg.f3c = lbl_803DFABC;
            cfg.f60 = 0xff;
        } else {
            cfg.f3c = lbl_803DFAF8;
            cfg.f60 = 0x9b;
        }
        cfg.f08 = 0xf0;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480200;
        cfg.f42 = 0xdf;
        break;
    case 0x1af:
        if (param_3 == 0) return -1;
        cfg.f24 = ((PartFxSpawnParams *)param_3)->unkC * (f32)(s32)randomGetRange(-1, 1);
        cfg.f28 = ((PartFxSpawnParams *)param_3)->unkC * (f32)(s32)randomGetRange(-1, 1);
        cfg.f2c = ((PartFxSpawnParams *)param_3)->unkC * (f32)(s32)randomGetRange(-1, 1);
        cfg.f3c = lbl_803DFB74 * (f32)(s32)randomGetRange(0x190, 0x1f4);
        cfg.f60 = 0xff;
        cfg.f08 = randomGetRange(0, 0x14) + 0xa0;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80080404;
        cfg.f42 = 0x5c;
        cfg.f58 = 0xfffe;
        cfg.f5a = 0x8ace;
        cfg.f5c = 0;
        cfg.f4c = 0x4e20;
        cfg.f50 = 0x9c40;
        cfg.f54 = 0xfffe;
        cfg.f48 = 0x20;
        break;
    case 0x1b0:
        if (param_3 == 0) return -1;
        cfg.f30 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB7C;
        cfg.f60 = 0xff;
        cfg.f0c = (s16)randomGetRange(0, 0xffff);
        cfg.f0e = (s16)randomGetRange(0, 0xffff);
        cfg.f0c = (s16)randomGetRange(0, 0xffff);
        cfg.f18 = lbl_803DFA9C;
        cfg.f1c = lbl_803DFA9C;
        cfg.f20 = lbl_803DFA9C;
        cfg.f08 = 0xa0;
        cfg.f61 = 0x10;
        cfg.f44 = 0x6100214;
        cfg.f42 = 0x167;
        break;
    case 0x1b1:
        if (param_3 == 0) return -1;
        cfg.f30 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = ((PartFxSpawnParams *)param_3)->unkC * (lbl_803DFB80 * (f32)(s32)randomGetRange(1, 5));
        cfg.f60 = 0xff;
        cfg.f0c = (s16)randomGetRange(0, 0xffff);
        cfg.f0e = (s16)randomGetRange(0, 0xffff);
        cfg.f0c = (s16)randomGetRange(0, 0xffff);
        cfg.f18 = lbl_803DFA9C;
        cfg.f1c = lbl_803DFA9C;
        cfg.f20 = lbl_803DFA9C;
        cfg.f08 = 0xa0;
        cfg.f61 = 0x10;
        cfg.f44 = 0x6100214;
        cfg.f42 = 0x30;
        break;
    case 0x1b2:
        cfg.f24 = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB74 * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.f60 = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.f08 = randomGetRange(0, 0x28) + 0x3c;
        cfg.f61 = 0x10;
        cfg.f44 = 0x81480204;
        cfg.f42 = 0x30;
        break;
    case 0x1ae:
        cfg.f24 = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803DFB84 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB74 * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.f60 = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.f08 = randomGetRange(0, 0x28) + 0x3c;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480104;
        cfg.f48 = 8;
        cfg.f42 = 0x30;
        break;
    case 0x1ab:
        cfg.f30 = lbl_803DFB88;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = (s16)randomGetRange(0, 0xffff);
        es.ry = (s16)randomGetRange(0, 0xffff);
        es.rx = (s16)randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.f30);
        cfg.f24 = cfg.f30 / lbl_803DFB30;
        cfg.f28 = cfg.f34 / lbl_803DFB30;
        cfg.f2c = cfg.f38 / lbl_803DFB30;
        cfg.f3c = lbl_803DFB8C * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.f60 = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.f08 = 0x50;
        cfg.f61 = 0x10;
        cfg.f44 = 0x80480504;
        cfg.f42 = 0x30;
        break;
    case 0x1ac:
        cfg.f30 = lbl_803DFB90 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DFB90 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DFB90 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB94 * (f32)(s32)randomGetRange(0x1f4, 0x3e8);
        cfg.f60 = randomGetRange(0x9b, 0xff);
        cfg.f08 = randomGetRange(0, 0x28) + 0x1e;
        cfg.f61 = 0;
        cfg.f44 = 0x80180104;
        cfg.f42 = 0x60;
        cfg.f4c = 0x6400;
        cfg.f50 = (randomGetRange(0, 0x55) + 0xaa) << 8;
        cfg.f54 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f48 = 0x20;
        break;
    case 0x1ad:
        cfg.f30 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DFB78 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803DFB6C * (f32)(s32)randomGetRange(0xc8, 0x5dc);
        cfg.f08 = randomGetRange(0, 0x28) + 0x1e;
        cfg.f60 = (u8)(randomGetRange(0xb4, 0xc8) + 0x37);
        cfg.f61 = 0;
        cfg.f44 = 0x80580104;
        cfg.f42 = 0xc22;
        cfg.f4c = 0xc800;
        cfg.f50 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.f54 = (randomGetRange(0, 0x19) + 0xe6) << 8;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f48 = 0x20;
        break;
    case 0x1b9:
        cfg.f38 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f30 = lbl_803DFB9C * (f32)(s32)randomGetRange(0, 0x3e8) + lbl_803DFB98;
        cfg.f34 = lbl_803DFBA0 * cfg.f30;
        cfg.f24 = lbl_803DFBA8 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DFBA4;
        cfg.f28 = lbl_803DFBA0 * cfg.f24;
        cfg.f3c = lbl_803DFBAC * (f32)(s32)randomGetRange(1, 6);
        cfg.f08 = 0xbe;
        cfg.f60 = 0xff;
        cfg.f44 = 0x6000100;
        cfg.f42 = 0x20;
        cfg.f10 = 0;
        cfg.f0e = 0x5fb4;
        cfg.f0c = -0x3fff;
        cfg.f18 = lbl_803DFA9C;
        cfg.f1c = lbl_803DFA9C;
        cfg.f20 = lbl_803DFA9C;
        break;
    case 0x1bf:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DFA8C * (f32)(s32)randomGetRange(0, 0x3e8);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f24 = lbl_803DFB38 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DFBB0 * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.f2c = lbl_803DFB38 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DFBB4;
        cfg.f08 = 0x15e;
        cfg.f60 = 0xff;
        cfg.f48 = 0x300020;
        cfg.f44 = 0x3008000;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x63bf;
        cfg.f50 = 0x9e7;
        cfg.f54 = 0x3e8;
        cfg.f42 = 0x23b;
        break;
    case 0x1c0:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f28 = lbl_803DFBB0 * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.f3c = lbl_803DFBB4;
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x2000200;
        cfg.f42 = 0x23b;
        break;
    case 0x1c1:
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.f28 = lbl_803DFBB8 * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.f3c = lbl_803DFB48 * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.f08 = 0x96;
        cfg.f60 = 0x9b;
        cfg.f48 = 0x20;
        cfg.f44 = 0x80100;
        cfg.f58 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.f5a = cfg.f58 / (int)randomGetRange(1, 3);
        cfg.f5c = 0;
        cfg.f4c = randomGetRange(0, 0x2710);
        cfg.f50 = (int)cfg.f4c / (int)randomGetRange(1, 3);
        cfg.f54 = 0;
        cfg.f42 = 0x60;
        break;
    case 0x1c2:
        cfg.f38 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f34 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f2c = lbl_803DFBB0 * (f32)(s32)randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0) {
            cfg.f2c = cfg.f2c * lbl_803DFBBC;
        }
        cfg.f28 = lbl_803DFBB0 * (f32)(s32)randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0) {
            cfg.f28 = cfg.f28 * lbl_803DFBBC;
        }
        cfg.f3c = lbl_803DFAC4;
        cfg.f08 = randomGetRange(0, 0x1e) + 0x14;
        cfg.f60 = 0xff;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x2000200;
        cfg.f42 = 0x23b;
        break;
    case 0x1ba:
        cfg.f34 = lbl_803DFBC0;
        cfg.f30 = lbl_803DFA8C * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.f38 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f34 = lbl_803DFBA0 * cfg.f30;
        cfg.f3c = lbl_803DFBC4 * (f32)(s32)randomGetRange(1, 6);
        cfg.f08 = 0x82;
        cfg.f60 = 0xff;
        cfg.f44 = 0x1000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x20;
        break;
    case 0x1b8:
        cfg.f30 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.f38 = lbl_803DFAB0 * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.f3c = lbl_803DFBC8 * (f32)(s32)randomGetRange(1, 4);
        cfg.f08 = 0x5a;
        cfg.f60 = 0xff;
        cfg.f44 = 0xa100100;
        cfg.f42 = 0x56;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
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
    param_3 = (s16 *)&lbl_8039C320;             \
  } while (0)

/* ===== (3) function ===== */
int Effect1_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7B0 = lbl_803DB7B0 + lbl_803DF720;
    if (lbl_803DB7B0 > 1.0f) lbl_803DB7B0 = lbl_803DF724;
    lbl_803DB7B4 = lbl_803DB7B4 + lbl_803DF72C;
    if (lbl_803DB7B4 > 1.0f) lbl_803DB7B4 = lbl_803DF730;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f1c = ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f20 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f14 = ((PartFxSpawnParams *)param_3)->unk8;
        cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        cfg.f0e = ((PartFxSpawnParams *)param_3)->unk2;
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = 0.0f;
    cfg.f34 = 0.0f;
    cfg.f38 = 0.0f;
    cfg.f24 = 0.0f;
    cfg.f28 = 0.0f;
    cfg.f2c = 0.0f;
    cfg.f3c = 0.0f;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x5fc: /* L_800AF9D8 */
        cfg.f3c = lbl_803DF738;
        cfg.f08 = 0xa;
        cfg.f60 = 0xff;
        cfg.f42 = 0x5c;
        break;
    case 0x5fb: /* L_800AF9F8 */
        cfg.f3c = lbl_803DF738;
        cfg.f08 = 0xa;
        cfg.f60 = 0xff;
        cfg.f42 = 0xe7;
        break;
    case 0x5fa: /* L_800AFA18 */
        cfg.f30 = lbl_803DF73C * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f38 = lbl_803DF73C * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f28 = lbl_803DF740 * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.f3c = lbl_803DF744;
        cfg.f08 = 0x28;
        cfg.f60 = 0xff;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x26c;
        break;
    case 0x5f9: /* L_800AFAE0 */
        cfg.f30 = lbl_803DF748 * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f38 = lbl_803DF748 * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f28 = lbl_803DF74C * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.f3c = lbl_803DF750;
        cfg.f08 = 0xb4;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8048100;
        cfg.f48 = 0x2000000;
        cfg.f04 = 0x5e9;
        cfg.f42 = 0x26c;
        break;
    case 0x5e9: /* L_800AFBBC */
        cfg.f3c = lbl_803DF750;
        cfg.f08 = 0x14;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480200;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x26c;
        break;
    case 0x3a7: /* L_800AFBF0 */
        cfg.f3c = lbl_803DF754;
        cfg.f08 = 0x50;
        cfg.f60 = 0xff;
        cfg.f44 = 0x1c0100;
        cfg.f42 = 0x73;
        break;
    case 0x3a5: /* L_800AFC1C */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        } else {
            cfg.f38 = lbl_803DF758;
            cfg.f34 = lbl_803DF75C;
        }
        cfg.f2c = lbl_803DF760 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.f3c = lbl_803DF768 * (f32)(s32)randomGetRange(0xa, 0x32);
        cfg.f08 = randomGetRange(0, 0xa) + 0x50;
        cfg.f60 = 0xff;
        cfg.f42 = 0x8e;
        cfg.f44 = 0x40180100;
        break;
    case 0x3a6: /* L_800AFD80 */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        } else {
            cfg.f38 = lbl_803DF758;
            cfg.f34 = lbl_803DF75C;
        }
        cfg.f2c = lbl_803DF76C * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.f3c = lbl_803DF770 * (f32)(s32)randomGetRange(0x28, 0x32);
        cfg.f08 = randomGetRange(0, 0x3c) + 0x50;
        cfg.f60 = 0xff;
        cfg.f42 = 0xc0a;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x42000100;
        break;
    case 0x3a3: /* L_800AFEEC */
        cfg.f3c = lbl_803DF73C;
        cfg.f08 = 0x4;
        cfg.f44 = 0x80000;
        cfg.f48 = 0x800;
        cfg.f42 = 0x64;
        cfg.f60 = 0x9b;
        break;
    case 0x3a4: /* L_800AFF20 */
        cfg.f24 = lbl_803DF774 * (f32)(s32)randomGetRange(0x19, 0x64);
        cfg.f28 = lbl_803DF778 * (f32)(s32)randomGetRange(0x42, 0x64);
        cfg.f2c = lbl_803DF77C * (f32)(s32)randomGetRange(0x11, 0x64);
        cfg.f30 = lbl_803DF780 * (f32)(s32)randomGetRange(-0x64, 0x64);
        randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DF734;
        cfg.f38 = lbl_803DF784 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = lbl_803DF788 * (f32)(s32)randomGetRange(0x27, 0x50);
        cfg.f08 = randomGetRange(0x14, 0x20) + 0xdb;
        cfg.f42 = 0x20c;
        cfg.f58 = 0x10000 - 0x1d0b;
        cfg.f5a = 0x5308;
        cfg.f5c = 0x42d9;
        cfg.f4c = 0x10000 - 0x7502;
        cfg.f50 = 0x5866;
        cfg.f54 = 0x40c3;
        cfg.f60 = randomGetRange(0xd, 0x53);
        cfg.f44 = 0x480208;
        cfg.f48 = 0x8002820;
        break;
    case 0x3a8: /* L_800B00EC */
    case 0x3a2:
        if (param_3 == 0) FILL320();
        if (param_3 == 0) return -1;
        cfg.f24 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF78C * (f32)(s32)randomGetRange(-0x64, 0x64));
        cfg.f28 = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF790 * (f32)(s32)randomGetRange(0x50, 0x8c));
        cfg.f2c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF794 * (f32)(s32)randomGetRange(-0x64, 0x64));
        cfg.f30 = lbl_803DF798 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f34 = lbl_803DF75C;
        cfg.f38 = lbl_803DF79C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f3c = ((PartFxSpawnParams *)param_3)->unk8 * (lbl_803DF7A0 * (f32)(s32)randomGetRange(0x16, 0x46));
        cfg.f08 = randomGetRange(0xe, 0x30) + 0x29;
        cfg.f42 = 0x60;
        cfg.f58 = 0x10000 - 0x108b;
        cfg.f5a = 0x10000 - 0x3d92;
        cfg.f5c = 0x4aab;
        cfg.f4c = 0x10000 - 0x161;
        cfg.f50 = 0x796c;
        cfg.f54 = 0x57a0;
        cfg.f60 = randomGetRange(0x29, 0x64);
        cfg.f44 = 0x80080108;
        if (param_2 == 0x3a2) {
            cfg.f44 |= 0x20000000LL;
        }
        cfg.f48 = 0x8400820;
        break;
    case 0x3a1: /* L_800B032C */
        if (param_3 == 0) FILL320();
        if (param_3 == 0) return -1;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = lbl_803DF7A4 + ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f2c = lbl_803DF724 * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f24 = lbl_803DF7A8 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF7A8 * (f32)(s32)randomGetRange(-0x14, 0x14);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16 *)param_1)[2];
        es.ry = ((s16 *)param_1)[1];
        es.rx = *(s16 *)param_1;
        vecRotateZXY(&es, &cfg.f24);
        cfg.f3c = lbl_803DF740;
        cfg.f08 = 0x32;
        cfg.f60 = 0xff;
        cfg.f42 = 0x167;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x2000110;
        break;
    case 0x3a0: /* L_800B04A0 */
        if (param_3 == 0) FILL320();
        if (param_3 == 0) return -1;
        cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
        cfg.f34 = lbl_803DF7A4 + ((PartFxSpawnParams *)param_3)->unk10;
        cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        cfg.f2c = lbl_803DF7AC * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.f24 = lbl_803DF760 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803DF7B0 * (f32)(s32)randomGetRange(2, 6);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16 *)param_1)[2];
        es.ry = ((s16 *)param_1)[1];
        es.rx = *(s16 *)param_1;
        vecRotateZXY(&es, &cfg.f24);
        cfg.f3c = lbl_803DF764 * (f32)(s32)randomGetRange(8, 0x14);
        cfg.f08 = randomGetRange(0x3c, 0x78);
        cfg.f44 = 0x80180000;
        cfg.f48 = 0x1400020;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x7f;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x3caf;
        cfg.f50 = 0x3caf;
        cfg.f54 = 0x3caf;
        break;
    case 0x39f: /* L_800B066C */
        cfg.f28 = lbl_803DF7B4 * (f32)(s32)randomGetRange(0xa, 0xe);
        cfg.f3c = lbl_803DF7B8;
        cfg.f08 = 0x1;
        cfg.f60 = 0x23;
        cfg.f48 = 0x2;
        cfg.f42 = 0x64;
        break;
    case 0x39a: /* L_800B06CC */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7BC;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x200;
        cfg.f42 = 0x17c;
        break;
    case 0x39b: /* L_800B06FC */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF740;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x17c;
        break;
    case 0x39c: /* L_800B0724 */
        cfg.f60 = 0x37;
        cfg.f3c = lbl_803DF7A8;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x17c;
        break;
    case 0x39d: /* L_800B0750 */
        cfg.f60 = 0x87;
        cfg.f3c = lbl_803DF740;
        cfg.f08 = 0x1e;
        cfg.f44 = 0x480200;
        cfg.f48 = 0x2000;
        cfg.f42 = 0x17c;
        break;
    case 0x39e: /* L_800B0788 */
        cfg.f24 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DF764 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f60 = 0x87;
        cfg.f3c = lbl_803DF7C0 * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.f08 = 0x64;
        cfg.f44 = 0x1480200;
        cfg.f48 = 0x100000;
        cfg.f42 = 0x17c;
        break;
    case 0x399: /* L_800B0888 */
        if (param_3 == 0) FILL320();
        cfg.f0e = 0;
        cfg.f0c = 0;
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f14 = 1.0f;
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = lbl_803DF7C4 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f0c = *param_3;
            cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        }
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7C8;
        cfg.f08 = randomGetRange(0, 0xa) + 0x3c;
        cfg.f44 = 0x6100100;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x64;
        break;
    case 0x397: /* L_800B095C */
        cfg.f30 = lbl_803DF738 * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f38 = lbl_803DF738 * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f28 = lbl_803DF7CC * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.f3c = lbl_803DF7D0;
        cfg.f08 = 0xb4;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80080110;
        cfg.f04 = 0x398;
        cfg.f42 = 0xc0d;
        break;
    case 0x398: /* L_800B0A30 */
        cfg.f3c = lbl_803DF7D0;
        cfg.f08 = 0x1e;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8000210;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0xc0d;
        break;
    case 0x5f7: /* L_800B0A64 */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7D4;
        cfg.f08 = 0x73;
        cfg.f44 = 0x8100110;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x77;
        break;
    case 0x5f6: /* L_800B0A98 */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7D8;
        cfg.f08 = 0xa;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x202;
        cfg.f42 = 0x26c;
        uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, 0, param_2, 0);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7DC;
        cfg.f08 = 0xa;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x2;
        cfg.f42 = 0x528;
        uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, 0, param_2, 0);
        cfg.f60 = 0x37;
        cfg.f3c = lbl_803DF7B0;
        cfg.f08 = 0xa;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x2;
        cfg.f42 = 0x528;
        uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, 0, param_2, 0);
        cfg.f60 = 0x87;
        cfg.f3c = lbl_803DF7DC;
        cfg.f08 = 0xa;
        cfg.f44 = 0x480200;
        cfg.f48 = 0x2002;
        cfg.f42 = 0x528;
        break;
    case 0x5f5: /* L_800B0BC8 */
        cfg.f24 = lbl_803DF7E0 * (f32)(s32)randomGetRange(-0x384, 0x384);
        cfg.f2c = lbl_803DF7E0 * (f32)(s32)randomGetRange(-0x384, 0x384);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7E4;
        cfg.f08 = 0x3c;
        cfg.f44 = 0x110;
        cfg.f48 = 0x100;
        cfg.f42 = 0xe4;
        break;
    case 0x5f4: /* L_800B0C64 */
        cfg.f30 = lbl_803DF740 * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f34 = lbl_803DF740 * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f2c = lbl_803DF7E0 * (f32)(s32)randomGetRange(0x12c, 0x190);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7E0;
        cfg.f08 = 0x8c;
        cfg.f44 = 0x480100;
        cfg.f42 = 0x528;
        break;
    case 0x5f0: /* L_800B0D2C */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7BC;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x200;
        cfg.f42 = 0x26c;
        break;
    case 0x5f1: /* L_800B0D5C */
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF740;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x528;
        break;
    case 0x5f2: /* L_800B0D84 */
        cfg.f60 = 0x37;
        cfg.f3c = lbl_803DF7A8;
        cfg.f08 = 0x12c;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x528;
        break;
    case 0x5f3: /* L_800B0DB0 */
        cfg.f60 = 0x87;
        cfg.f3c = lbl_803DF740;
        cfg.f08 = 0x1e;
        cfg.f44 = 0x480200;
        cfg.f48 = 0x2000;
        cfg.f42 = 0x528;
        break;
    case 0x5ef: /* L_800B0DE8 */
        cfg.f30 = lbl_803DF720 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f38 = lbl_803DF720 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f28 = lbl_803DF7E8;
        cfg.f60 = 0x9b;
        cfg.f3c = lbl_803DF7EC;
        cfg.f08 = randomGetRange(0, 0xa) + 0x3c;
        cfg.f44 = 0x80100;
        cfg.f48 = 0x100;
        cfg.f42 = 0x3f2;
        break;
    case 0x5ee: /* L_800B0E9C */
        cfg.f2c = lbl_803DF7F0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF7F0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7F4;
        cfg.f08 = randomGetRange(0, 0xa) + 0x3c;
        cfg.f44 = 0x2000100;
        cfg.f48 = 0x200;
        cfg.f42 = 0x33;
        break;
    case 0x5f8: /* L_800B0F48 */
        cfg.f24 = lbl_803DF7F0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF7F0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7F4;
        cfg.f08 = randomGetRange(0, 0xa) + 0x3c;
        cfg.f44 = 0x2000100;
        cfg.f48 = 0x400;
        cfg.f42 = 0x33;
        break;
    case 0x5ed: /* L_800B0FF4 */
        if (param_3 == 0) FILL320();
        cfg.f0e = 0;
        cfg.f0c = 0;
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f14 = 1.0f;
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = lbl_803DF7C4 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f0c = *param_3;
            cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        }
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7C8;
        cfg.f08 = 0x3c;
        cfg.f44 = 0x6100100;
        cfg.f42 = 0x5fe;
        break;
    case 0x5fd: /* L_800B10B4 */
        if (param_3 == 0) FILL320();
        cfg.f0e = 0;
        cfg.f0c = 0;
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f14 = 1.0f;
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = lbl_803DF7C4 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
            cfg.f0c = *param_3;
            cfg.f10 = ((PartFxSpawnParams *)param_3)->unk4;
        }
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803DF7C8 * (f32)(s32)randomGetRange(1, 3);
        cfg.f08 = randomGetRange(0, 0x64) + 0x78;
        cfg.f44 = 0x6100000;
        cfg.f48 = 0x10000 - 0x8000;
        cfg.f42 = 0x5ff;
        break;
    case 0x5eb: /* L_800B11B4 */
        cfg.f2c = lbl_803DF7F8 * (f32)(s32)randomGetRange(0xb4, 0xc8);
        cfg.f24 = lbl_803DF7F0 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF740 * (f32)(s32)randomGetRange(0, 0x28);
        cfg.f60 = 0x9b;
        cfg.f3c = lbl_803DF7AC;
        cfg.f08 = randomGetRange(0x8c, 0xa5);
        cfg.f44 = 0x8110000;
        cfg.f48 = (u32)(0x410000 - 0x7fe0);
        cfg.f58 = 0x7d0;
        cfg.f5a = 0x7d0;
        cfg.f5c = randomGetRange(-0x1388, 0x1388) + 0x2710;
        cfg.f4c = 0x1f40;
        cfg.f50 = 0x1f40;
        cfg.f54 = randomGetRange(-0x1388, 0x1388) + 0x2ee0;
        cfg.f42 = 0x639;
        break;
    case 0x5ea: /* L_800B12D4 */
        cfg.f30 = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.f38 = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.f60 = 0x9b;
        cfg.f3c = lbl_803DF7B0;
        cfg.f08 = randomGetRange(0x46, 0x64);
        cfg.f44 = 0x8110000;
        cfg.f48 = (u32)(0x410000 - 0x7fe0);
        cfg.f58 = 0x7d0;
        cfg.f5a = 0x7d0;
        cfg.f5c = randomGetRange(-0x1388, 0x1388) + 0x4e20;
        cfg.f4c = 0x1f40;
        cfg.f50 = 0x1f40;
        cfg.f54 = randomGetRange(-0x1388, 0x1388) + 0x7d00;
        cfg.f42 = 0x639;
        break;
    case 0x5e3: /* L_800B13B0 */
        cfg.f3c = lbl_803DF7FC * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.f08 = 0xf0;
        cfg.f60 = 0x55;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x200;
        cfg.f42 = 0x156;
        break;
    case 0x5e4: /* L_800B1410 */
        cfg.f3c = lbl_803DF7FC * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.f08 = 0xf0;
        cfg.f60 = 0x55;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x100;
        cfg.f42 = 0x156;
        break;
    case 0x5e5: /* L_800B1470 */
        cfg.f3c = lbl_803DF800;
        cfg.f08 = 0xf0;
        cfg.f60 = 0xb9;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x156;
        break;
    case 0x5e6: /* L_800B149C */
        cfg.f3c = lbl_803DF7FC * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.f08 = 0x12c;
        cfg.f60 = 0x55;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x200;
        cfg.f42 = 0x156;
        break;
    case 0x5e7: /* L_800B14FC */
        cfg.f3c = lbl_803DF7FC * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.f08 = 0x6;
        cfg.f60 = 0x55;
        cfg.f44 = 0x480000;
        cfg.f48 = 0x100;
        cfg.f42 = 0x156;
        break;
    case 0x5e8: /* L_800B155C */
        cfg.f3c = lbl_803DF800;
        cfg.f08 = 0x6;
        cfg.f60 = 0x55;
        cfg.f44 = 0x480000;
        cfg.f42 = 0x156;
        break;
    case 0x5dd: /* L_800B1588 */
        cfg.f38 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f34 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f24 = lbl_803DF804 * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f28 = cfg.f34 / lbl_803DF808;
        cfg.f2c = cfg.f38 / lbl_803DF808;
        cfg.f3c = lbl_803DF80C * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f08 = 0xfa;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x480100;
        cfg.f42 = 0xc79;
        break;
    case 0x5de: /* L_800B168C */
        cfg.f38 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f34 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f24 = lbl_803DF804 * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f28 = cfg.f34 / lbl_803DF808;
        cfg.f2c = cfg.f38 / lbl_803DF808;
        cfg.f3c = lbl_803DF80C * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f08 = 0xfa;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x480100;
        cfg.f42 = 0x166;
        break;
    case 0x5df: /* L_800B1790 */
        cfg.f38 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f34 = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.f24 = lbl_803DF804 * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f28 = cfg.f34 / lbl_803DF808;
        cfg.f2c = cfg.f38 / lbl_803DF808;
        cfg.f3c = lbl_803DF80C * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f08 = 0xfa;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x480100;
        cfg.f42 = 0x528;
        break;
    case 0x5e0: /* L_800B1894 */
        cfg.f24 = lbl_803DF810 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = 0.0f;
        cfg.f2c = 0.0f;
        cfg.f30 = 0.0f;
        cfg.f34 = 0.0f;
        cfg.f38 = 0.0f;
        cfg.f3c = lbl_803DF814;
        cfg.f08 = 0x39;
        cfg.f42 = 0xc76;
        cfg.f58 = 0x7fff;
        cfg.f5a = 0x7fff;
        cfg.f5c = 0x7fff;
        cfg.f4c = 0x7fff;
        cfg.f50 = 0x7fff;
        cfg.f54 = 0x7fff;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8050100;
        cfg.f48 = 0x8000800;
        break;
    case 0x5e1: /* L_800B1938 */
        cfg.f24 = lbl_803DF810 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = 0.0f;
        cfg.f2c = 0.0f;
        cfg.f30 = 0.0f;
        cfg.f34 = 0.0f;
        cfg.f38 = 0.0f;
        cfg.f3c = lbl_803DF814;
        cfg.f08 = 0x39;
        cfg.f42 = 0xc74;
        cfg.f58 = 0x7fff;
        cfg.f5a = 0x7fff;
        cfg.f5c = 0x7fff;
        cfg.f4c = 0x7fff;
        cfg.f50 = 0x7fff;
        cfg.f54 = 0x7fff;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8050100;
        cfg.f48 = 0x8000800;
        break;
    case 0x5e2: /* L_800B19DC */
        cfg.f24 = lbl_803DF810 * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f28 = 0.0f;
        cfg.f2c = 0.0f;
        cfg.f30 = 0.0f;
        cfg.f34 = 0.0f;
        cfg.f38 = 0.0f;
        cfg.f3c = lbl_803DF814;
        cfg.f08 = 0x39;
        cfg.f42 = 0xc75;
        cfg.f58 = 0x7fff;
        cfg.f5a = 0x7fff;
        cfg.f5c = 0x7fff;
        cfg.f4c = 0x7fff;
        cfg.f50 = 0x7fff;
        cfg.f54 = 0x7fff;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8050100;
        cfg.f48 = 0x8000800;
        break;
    case 0x396: /* L_800B1A80 */
        cfg.f3c = lbl_803DF754;
        cfg.f08 = 0x50;
        cfg.f60 = 0xff;
        cfg.f44 = 0x1c0100;
        cfg.f42 = 0x159;
        break;
    case 0x394: /* L_800B1AAC */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f0c = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f0e = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f0c = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f3c = lbl_803DF818 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f08 = randomGetRange(0x1e, 0x2f);
        cfg.f60 = 0xff;
        cfg.f44 = 0x6100100;
        cfg.f42 = 0xc79;
        break;
    case 0x395: /* L_800B1BBC */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f0c = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f0e = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f0c = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.f18 = 0.0f;
        cfg.f1c = 0.0f;
        cfg.f20 = 0.0f;
        cfg.f3c = lbl_803DF740 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f08 = randomGetRange(0x50, 0x64);
        cfg.f60 = 0xff;
        cfg.f44 = 0x6100110;
        cfg.f42 = 0xc79;
        break;
    case 0x393: /* L_800B1CCC */
        cfg.f38 = (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x14);
        cfg.f30 = lbl_803DF730 * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.f28 = lbl_803DF7B4 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f3c = lbl_803DF81C;
        cfg.f08 = randomGetRange(0x212, 0x2a8);
        cfg.f60 = 0xff;
        cfg.f44 = 0x8048208;
        cfg.f42 = 0xc0d;
        break;
    case 0x392: /* L_800B1DC4 */
        cfg.f30 = lbl_803DF724 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = lbl_803DF724 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f24 = lbl_803DF7A8 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803DF7A8 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f2c = lbl_803DF7A8 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f3c = lbl_803DF820 * (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.f08 = randomGetRange(0x5a, 0x8c);
        cfg.f44 = 0x8040201;
        cfg.f61 = 0;
        cfg.f42 = 0x23b;
        break;
    case 0x390: /* L_800B1F2C */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        } else {
            cfg.f38 = lbl_803DF758;
            cfg.f34 = lbl_803DF75C;
        }
        cfg.f2c = lbl_803DF760 * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.f3c = lbl_803DF768 * (f32)(s32)randomGetRange(0xa, 0x32);
        cfg.f08 = randomGetRange(0, 0xa) + 0x50;
        cfg.f60 = 0xff;
        cfg.f42 = 0x8e;
        cfg.f44 = 0x40180100;
        break;
    case 0x391: /* L_800B2090 */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = ((PartFxSpawnParams *)param_3)->unk10;
        } else {
            cfg.f38 = lbl_803DF758;
            cfg.f34 = lbl_803DF75C;
        }
        cfg.f2c = lbl_803DF76C * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.f3c = lbl_803DF770 * (f32)(s32)randomGetRange(0x28, 0x32);
        cfg.f08 = randomGetRange(0, 0x3c) + 0x50;
        cfg.f60 = 0xff;
        cfg.f42 = 0xc0a;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x42000100;
        break;
    case 0x38f: /* L_800B21FC */
        cfg.f30 = (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.f34 = (f32)(s32)randomGetRange(-0x28, 0x8c);
        cfg.f38 = (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.f24 = lbl_803DF73C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803DF824 * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DF73C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DF7E4;
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f42 = 0x167;
        cfg.f48 = 0x300000;
        cfg.f44 = 0x2000110;
        break;
    case 0x38a: /* L_800B2354 */
        if (param_3 == 0) FILL320();
        cfg.f30 = lbl_803DF724 * (f32)(s32)randomGetRange(-0xa, -0xa);
        cfg.f34 = lbl_803DF724 * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.f38 = lbl_803DF724 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f24 = lbl_803DF7DC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803DF7DC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f60 = 0xff;
        if (param_3 != 0) {
            cfg.f30 = cfg.f30 + ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f34 = cfg.f34 + ((PartFxSpawnParams *)param_3)->unk10;
            cfg.f38 = cfg.f38 + ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f3c = lbl_803DF828 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = 0x55;
        cfg.f44 = 0x100200;
        cfg.f42 = 0x125;
        cfg.f61 = randomGetRange(0, 0x14) + 4;
        cfg.f58 = 0xffff;
        cfg.f5a = (randomGetRange(0, 0x2710) + 0x10000) - 0x2711;
        cfg.f5c = 0;
        cfg.f4c = (u16)cfg.f58 / 10;
        cfg.f50 = cfg.f5a / 10;
        cfg.f54 = 0;
        cfg.f48 = 0xa0;
        break;
    case 0x38b: /* L_800B25A8 */
        cfg.f3c = lbl_803DF82C;
        cfg.f08 = 0x4b;
        cfg.f44 = 0x82000108;
        cfg.f48 = 0x80;
        cfg.f42 = 0xc0a;
        cfg.f60 = 0xff;
        break;
    case 0x38c: /* L_800B25DC */
        cfg.f34 = lbl_803DF830;
        cfg.f3c = lbl_803DF834;
        cfg.f08 = 0x190;
        cfg.f48 = 0x100;
        cfg.f42 = 0x167;
        cfg.f60 = 0x9b;
        break;
    case 0x38d: /* L_800B2610 */
        if (param_3 == 0) FILL320();
        if (param_3 != 0) {
            cfg.f30 = ((PartFxSpawnParams *)param_3)->unkC;
            cfg.f38 = ((PartFxSpawnParams *)param_3)->unk14;
        }
        cfg.f34 = lbl_803DF838;
        cfg.f24 = lbl_803DF7B0 * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.f28 = lbl_803DF738 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f2c = lbl_803DF7B0 * (f32)(s32)randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.f3c = lbl_803DF83C;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x3010000 - 0x8000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x167;
        cfg.f60 = 0xff;
        break;
    case 0x38e: /* L_800B2740 */
        cfg.f24 = lbl_803DF840 * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.f28 = lbl_803DF7A8 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f2c = lbl_803DF840 * (f32)(s32)randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.f3c = lbl_803DF83C;
        cfg.f08 = 0x50;
        cfg.f44 = 0x3000000;
        cfg.f48 = 0x200000;
        cfg.f42 = 0x167;
        cfg.f60 = 0xff;
        break;
    case 0x389: /* L_800B2818 */
        if (param_3 == 0) FILL320();
        cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
        cfg.f34 = (f32)(s32)randomGetRange(1, 5);
        cfg.f38 = (f32)(s32)randomGetRange(-5, 5);
        es.a = lbl_803DF7DC * (f32)(s32)randomGetRange(0, 0x258) + lbl_803DF844;
        cfg.f28 = lbl_803DF720 * (f32)(s32)randomGetRange(0, 0xc8) + 1.0f;
        cfg.f24 = lbl_803DF7B0 * (f32)(s32)randomGetRange(0, 0x14) + lbl_803DF724;
        cfg.f28 = cfg.f28 * es.a;
        cfg.f24 = cfg.f24 * es.a;
        cfg.f3c = lbl_803DF84C * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF848;
        cfg.f08 = randomGetRange(0xb4, 0xc8);
        cfg.f60 = 0xff;
        cfg.f44 = 0x3000120;
        cfg.f48 = 0x200800;
        cfg.f42 = 0xc0a;
        cfg.f04 = 0x385;
        break;
    case 0x388: /* L_800B2A08 */
        cfg.f30 = (f32)(s32)randomGetRange(0, 0x10);
        cfg.f38 = (f32)(s32)randomGetRange(-0x2e, 0x2e);
        cfg.f28 = lbl_803DF748 * (f32)(s32)randomGetRange(0x10, 0x1e);
        cfg.f3c = lbl_803DF7EC;
        cfg.f08 = 0x64;
        cfg.f60 = 0x37;
        cfg.f61 = 0x10;
        cfg.f44 = 0x100;
        cfg.f48 = 0x100;
        cfg.f42 = 0x1fb;
        break;
    case 0x384: /* L_800B2ACC */
        cfg.f30 = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.f34 = (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.f38 = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DF724 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DF738 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f3c = lbl_803DF768 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.f08 = randomGetRange(0x78, 0x8c);
        cfg.f60 = 0xff;
        cfg.f04 = 0x385;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x1001100;
        cfg.f42 = 0xc0a;
        break;
    case 0x387: /* L_800B2C64 */
        cfg.f30 = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.f34 = (f32)(s32)randomGetRange(1, 5);
        cfg.f38 = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.f24 = lbl_803DF738 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f28 = lbl_803DF724 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803DF738 * (f32)(s32)randomGetRange(-8, 8);
        cfg.f3c = lbl_803DF768 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.f08 = randomGetRange(0x78, 0x8c);
        cfg.f60 = 0xff;
        cfg.f04 = 0x385;
        cfg.f48 = 0x200000;
        cfg.f44 = 0x8100120;
        cfg.f42 = 0xc0a;
        break;
    case 0x385: /* L_800B2DFC */
        cfg.f28 = lbl_803DF764 * (f32)(s32)randomGetRange(2, 0x14);
        cfg.f3c = lbl_803DF854;
        cfg.f08 = 0x1e;
        cfg.f60 = 0x9b;
        cfg.f44 = 0x180100;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.f5c = 0;
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = cfg.f5a;
        cfg.f54 = 0;
        cfg.f48 = 0x20;
        break;
    case 0x386: /* L_800B2EA4 */
        cfg.f34 = (f32)(s32)randomGetRange(1, 5);
        cfg.f28 = lbl_803DF7A8 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f3c = lbl_803DF768 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF858;
        cfg.f08 = randomGetRange(0xe6, 0x118);
        cfg.f60 = 0x9b;
        cfg.f44 = 0x8048200;
        cfg.f42 = 0xc0d;
        break;
    default: /* L_800B2F6C */
        return -1;
    }
    /* ===== common dispatch tail (L_800B2F74) ===== */
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 ^= 2LL;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*gExpgfxInterface)->spawnEffect(&cfg, -1, param_2, 0);
    return uVar1;
}
#undef FILL320

void Effect9_func05(void)
{
  f32 sum;
  f32 step;
  sum = lbl_803DB828 + (step = lbl_803DFE28 * timeDelta);
  lbl_803DB828 = sum;
  if (sum > 1.0f) {
    lbl_803DB828 = lbl_803DFE2C;
  }
  sum = lbl_803DB82C + step;
  lbl_803DB82C = sum;
  if (sum > 1.0f) {
    lbl_803DB82C = lbl_803DFE38;
  }
  lbl_803DD3A0 = lbl_803DD3A0 + framesThisStep * 0x64;
  if (lbl_803DD3A0 > 0x7fff) {
    lbl_803DD3A0 = 0;
  }
  lbl_803DD3AC = mathSinf(lbl_803DFEB0 * (f32)(s16)lbl_803DD3A0 / lbl_803DFEB4);
  lbl_803DD3A4 = lbl_803DD3A4 + framesThisStep * 0x32;
  if (lbl_803DD3A4 > 0x7fff) {
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
  for (i = 0; i < 0x32; i++) {
    lbl_8039C1F8[i] = NULL;
  }
}
#pragma peephole reset
#pragma scheduling reset

extern void *Obj_GetActiveModel(void);
extern void *ObjModel_GetJointMatrix(void *model, int joint);
extern void PSMTXMultVec(void *m, void *src, void *dst);

typedef struct BoneSpawnData {
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
void boneParticleEffect_spawnAtBones(void *obj, int effectId, void *extraArg, u8 prob, short *src)
{
  void *model;
  int i;
  BoneSpawnData data;

  model = Obj_GetActiveModel();
  for (i = 0; i < *(u8 *)(*(int *)model + 0xf3); i++) {
    if ((int)randomGetRange(1, 0x64) <= prob) {
      void *mtx;
      data.x = lbl_803DF4A8;
      data.y = lbl_803DF4A8;
      data.z = lbl_803DF4A8;
      data.scale = lbl_803DF4B8;
      data.unk4 = 0;
      data.unk2 = 0;
      data.unk0 = 0;
      mtx = ObjModel_GetJointMatrix(model, i);
      PSMTXMultVec(mtx, &data.x, &data.x);
      data.x = data.x - ((GameObject *)obj)->anim.worldPosX;
      data.y = data.y - ((GameObject *)obj)->anim.worldPosY;
      data.z = data.z - ((GameObject *)obj)->anim.worldPosZ;
      data.x = data.x + playerMapOffsetX;
      data.z = data.z + playerMapOffsetZ;
      if (src != NULL) {
        data.scale = *(f32 *)((char *)src + 0x8);
        data.unk0 = src[0];
        data.unk4 = src[2];
        data.unk2 = src[1];
        data.unk6 = src[3];
      } else {
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

extern void *Camera_GetCurrentViewSlot(void);
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
void fn_800A3AF0(void *table, int count, void *ctx, f32 a, f32 b)
{
    BoneSpawnData data;
    void *cam;
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
    lbl_803DD29A = *(s16 *)cam;
    lbl_803DD29C = ((GameObject *)cam)->anim.rotY;
    dx = ((GameObject *)cam)->anim.localPosX - ((GameObject *)ctx)->anim.localPosX;
    dy = ((GameObject *)cam)->anim.localPosY - ((GameObject *)ctx)->anim.localPosY;
    dz = ((GameObject *)cam)->anim.localPosZ - ((GameObject *)ctx)->anim.localPosZ;
    for (i = 0; i < count; i++) {
        int t = *(s8 *)((char *)table + i * 0x4c + 0x48);
        if (t == 0x12 || (u8)(t - 0x10) <= 1 || (u8)(t - 0x14) <= 1 || t == 0x17) {
            lbl_8030FDE8[0] = dx;
            lbl_8030FDE8[1] = dy;
            lbl_8030FDE8[2] = dz;
            len = sqrtf(dy * dy + dx * dx + dz * dz);
            sc = lbl_803DF468 * len;
            if (lbl_803DF46C != len) {
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
    if (found) {
        int j;
        char *e = (char *)table;
        for (j = 0; j < count; j++) {
            int t = *(s8 *)(e + 0x48);
            if (t == 0x12 || (u8)(t - 0x10) <= 1 || (u8)(t - 0x14) <= 1 || t == 0x17) {
                int rt;
                p0x = ((GameObject *)ctx)->anim.localPosX + ((f32)*(s16 *)(e + 0x10) - a);
                p0y = (f32)*(s16 *)(e + 0x16);
                p0z = ((GameObject *)ctx)->anim.localPosZ + ((f32)*(s16 *)(e + 0x1c) - b);
                p1x = ((GameObject *)ctx)->anim.localPosX + ((f32)*(s16 *)(e + 0x12) - a);
                p1y = (f32)*(s16 *)(e + 0x18);
                p1z = ((GameObject *)ctx)->anim.localPosZ + ((f32)*(s16 *)(e + 0x1e) - b);
                p2x = ((GameObject *)ctx)->anim.localPosX + ((f32)*(s16 *)(e + 0x14) - a);
                p2y = (f32)*(s16 *)(e + 0x1a);
                p2z = ((GameObject *)ctx)->anim.localPosZ + ((f32)*(s16 *)(e + 0x20) - b);
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
                rt = *(s8 *)(e + 0x48);
                if (rt == 0x12 || rt == 0x10) {
                    if (randomGetRange(0, 0x1e) == 1) {
                        (*gPartfxInterface)->spawnObject(ctx, 0x72, &data, 0x200001, -1, NULL);
                    }
                } else if (rt == 0x11) {
                    if (randomGetRange(0, 8) == 2) {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x14) {
                    if (randomGetRange(0, 8) == 2) {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x15) {
                    if (randomGetRange(0, 8) == 2) {
                        (*gPartfxInterface)->spawnObject(ctx, 0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x17) {
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
void dll_0B_func08(void *param)
{
  int **arr = (int **)lbl_8039C1F8;
  int i;

  for (i = 0; i < 0x32; i++) {
    if (arr[i] != NULL && *(void **)((char *)arr[i] + 0x4) == param) {
      if (*(int *)((char *)arr[i] + 0xa4) & 0x10000) {
        fn_800A1040(*(s16 *)((char *)arr[i] + 0x10c), 0);
      } else {
        *(f32 *)((char *)arr[i] + 0x18) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x18);
        *(f32 *)((char *)arr[i] + 0x1c) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x1c);
        *(f32 *)((char *)arr[i] + 0x20) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x20);
        *(f32 *)((char *)arr[i] + 0x14) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x8);
        *(s16 *)((char *)arr[i] + 0x10) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x4);
        *(s16 *)((char *)arr[i] + 0xe) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x2);
        *(s16 *)((char *)arr[i] + 0xc) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x0);
        if (*(int *)((char *)arr[i] + 0xa4) & 0x2) {
          *(f32 *)((char *)arr[i] + 0x6c) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x24);
          *(f32 *)((char *)arr[i] + 0x70) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x28);
          *(f32 *)((char *)arr[i] + 0x74) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x2c);
        }
        if (!(*(int *)((char *)arr[i] + 0xa4) & 0x200000)) {
          *(u32 *)((char *)arr[i] + 0xa4) |= 0x200000;
        }
        *(int *)((char *)arr[i] + 0x4) = 0;
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

extern int dll_0B_func04(void *base, int z, int c, void *b, int e, void *d, int f, void *g);

#pragma scheduling off
#pragma peephole off
void dll_0B_func16(void *a, void *b, void *c, void *d, void *e, int f, void *g)
{
  ModgfxSpawnContext *context = &gModgfxSpawnContext;

  context->pendingSpawns = gModgfxPendingSpawnQueue;
  context->pendingSpawnCount = gModgfxPendingSpawnWriteCursor - gModgfxPendingSpawnStartCursor;
  if (g == NULL && f == 0) {
    context->flags |= 0x2000000;
  } else {
    context->flags |= 0x4000000;
  }
  if (context->flags & 1) {
    if (context->attachedSource != NULL) {
      context->posX += ((ExpgfxSourceObject *)context->attachedSource)->worldPosX;
      context->posY += ((ExpgfxSourceObject *)context->attachedSource)->worldPosY;
      context->posZ += ((ExpgfxSourceObject *)context->attachedSource)->worldPosZ;
    } else {
      context->posX += ((ExpgfxSourceObject *)a)->localPosX;
      context->posY += ((ExpgfxSourceObject *)a)->localPosY;
      context->posZ += ((ExpgfxSourceObject *)a)->localPosZ;
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
int dll_0B_func04(void *base, int z, int c, void *b, int e, void *d, int f, void *g)
{
    u8 *st = (u8 *)base;
    int slot;
    int found;
    int i;
    int n;
    int divThresh;
    int total;
    int base0;
    f32 fz430;
    f32 fz434;
    PartfxEffectState **effects;
    PartfxEffectState *effect;

    effects = (PartfxEffectState **)gPartfxActiveEffects;
    total = 0;
    found = 0;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT && found == 0; i++) {
        if (effects[i] == NULL) found = 1;
    }
    if (found) {
        slot = i - 1;
    } else {
        slot = -1;
    }
    if (slot == -1) {
        return 0;
    }

    n = *(s8 *)(st + 0x5d);
    for (i = 0; i < n; i++) {
        u8 *item = *(u8 **)st + i * 0x18;
        if ((*(u32 *)item & 0xf7fff180) == 0 && *(s16 *)(item + 0x14) != 0) {
            total += *(s16 *)(item + 0x14);
        }
    }

    base0 = 0;
    if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
        base0 = ((e * 3) << 4) + (int)(long)((c * 3) << 4);
    }

    effects[slot] = (PartfxEffectState *)mmAlloc(base0 + n * 0x18 + total * 2 + 0x240, 0x15, 0);
    effect = effects[slot];
    if (effect == NULL) {
        fn_800A1040(0, 0);
        return -1;
    }

    effect->inlineData = (u8 *)effect + sizeof(PartfxEffectState);
    {
        u8 *bufp = effect->inlineData;
        if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
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

    if (*(int *)(st + 0x40) != 0) {
        divThresh = e / *(int *)(st + 0x40);
    } else {
        divThresh = e;
    }
    if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4) {
            u8 *dstc = effect->colorBuffers[k];
            int bias = 0;
            int j;
            s16 *sd = (s16 *)d;
            for (j = 0; j < e; j++) {
                if ((*(u32 *)(st + 0x54) & 0x8000000) && j == divThresh) {
                    bias = *(int *)(st + 0x3c);
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
    if (g != NULL) {
        effect->textureResource = g;
        effect->textureIsBorrowed = 1;
    } else if (f != 0) {
        effect->textureResource = textureLoadAsset(f);
        effect->textureIsBorrowed = 0;
    }

    if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4) {
            u8 *dstv = effect->vertexBuffers[k];
            int j;
            s16 *sb = (s16 *)b;
            for (j = 0; j < c; j++) {
                *(s16 *)(dstv + 0) = sb[0];
                *(s16 *)(dstv + 2) = sb[1];
                *(s16 *)(dstv + 4) = sb[2];
                if (effect->textureResource != NULL) {
                    *(s16 *)(dstv + 8) = lbl_803DF460 * ((f32)sb[3] / (f32)*(u16 *)((u8 *)effect->textureResource + 0xa));
                    *(s16 *)(dstv + 0xa) = lbl_803DF460 * ((f32)sb[4] / (f32)*(u16 *)((u8 *)effect->textureResource + 0xc));
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
    effect->stageDurations[0] = *(s16 *)(st + 0x46);
    effect->stageDurations[1] = *(s16 *)(st + 0x48);
    effect->stageDurations[2] = *(s16 *)(st + 0x4a);
    effect->stageDurations[3] = *(s16 *)(st + 0x4c);
    effect->stageDurations[4] = *(s16 *)(st + 0x4e);
    effect->stageDurations[5] = *(s16 *)(st + 0x50);
    effect->stageDurations[6] = *(s16 *)(st + 0x52);
    effect->emitterCommands = (u8 *)effect->inlineData + base0 + 0x100;
    effect->auxSequenceBuffer = NULL;
    if (total != 0) {
        effect->auxSequenceBuffer = (u8 *)effect->emitterCommands + effect->emitterCount * 0x18;
    }

    {
        u8 *dst = effect->auxSequenceBuffer;
        int m;
        int off;
        for (m = 0, off = 0; m < effect->emitterCount; m++, off += 0x18) {
            ((u8 *)effect->emitterCommands)[off + 0x16] = (*(u8 **)st)[off + 0x16];
            *(s16 *)((u8 *)effect->emitterCommands + off + 0x14) = *(s16 *)(*(u8 **)st + off + 0x14);
            *(int *)((u8 *)effect->emitterCommands + off + 0x10) = 0;
            *(int *)((u8 *)effect->emitterCommands + off) = *(int *)(*(u8 **)st + off);
            if ((*(int *)((u8 *)effect->emitterCommands + off) & 0xf7fff180) == 0 &&
                *(s16 *)((u8 *)effect->emitterCommands + off + 0x14) != 0) {
                int k;
                *(int *)((u8 *)effect->emitterCommands + off + 0x10) = 0;
                *(u8 **)((u8 *)effect->emitterCommands + off + 0x10) = dst;
                dst += *(s16 *)((u8 *)effect->emitterCommands + off + 0x14) * 2;
                for (k = 0; k < *(s16 *)((u8 *)effect->emitterCommands + off + 0x14); k++) {
                    *(s16 *)(*(u8 **)((u8 *)effect->emitterCommands + off + 0x10) + k * 2) =
                        *(s16 *)(*(u8 **)(*(u8 **)st + off + 0x10) + k * 2);
                }
            }
            *(f32 *)((u8 *)effect->emitterCommands + off + 4) = *(f32 *)(*(u8 **)st + off + 4);
            *(f32 *)((u8 *)effect->emitterCommands + off + 8) = *(f32 *)(*(u8 **)st + off + 8);
            *(f32 *)((u8 *)effect->emitterCommands + off + 0xc) = *(f32 *)(*(u8 **)st + off + 0xc);
        }
    }

    effect->currentStage = -1;
    effect->stageFrameCountdown = effect->colorVertexCount;
    effect->flags = *(int *)(st + 0x54);
    effect->drawPosX = *(f32 *)(st + 0x2c);
    effect->drawPosY = *(f32 *)(st + 0x30);
    effect->drawPosZ = *(f32 *)(st + 0x34);
    effect->renderScale = *(f32 *)(st + 0x38);
    if (effect->flags & 1) {
        effect->sourcePosX = *(f32 *)(st + 0x2c);
        effect->sourcePosY = *(f32 *)(st + 0x30);
        effect->sourcePosZ = *(f32 *)(st + 0x34);
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
    effect->velocityX = *(f32 *)(st + 0x20);
    effect->velocityY = *(f32 *)(st + 0x24);
    effect->velocityZ = *(f32 *)(st + 0x28);
    lbl_803DD280 = lbl_803DD280 + 1;
    if (lbl_803DD280 > 0x4e20) {
        lbl_803DD280 = 0;
    }
    effect->sequenceId = lbl_803DD280;
    effect->byte126 = lbl_803DD282;
    effect->vertexCount = (s16)c;
    effect->colorVertexCount = (s16)e;
    effect->sourceObject = *(void **)(st + 4);
    effect->instanceObject = NULL;
    effect->sourceYawIndex = st[0x5c];
    effect->drawGroupCount = *(int *)(st + 0x40);
    effect->drawGroupStride = *(int *)(st + 0x3c);
    effect->initialStateByte = st[0x59];
    effect->soundHandle = 0;
    effect->activeVertexBufferIndex = 0;
    effect->byte13B = 0;
    effect->frameUpdated = 0;
    effect->textureFrameTimer = st[0x5b];
    if (effect->textureFrameTimer != 0) {
        effect->textureFrameStep = 0x3c / effect->textureFrameTimer;
    } else {
        effect->textureFrameStep = 0;
    }
    if (effect->textureFrameStep != 0) {
        effect->textureFrameFadeStep = 0xff / effect->textureFrameStep;
    } else {
        effect->textureFrameFadeStep = 0;
    }
    effect->textureFrame = 0;
    effect->initialDelayFrames = *(s16 *)(st + 0x44);
    return effect->sequenceId;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 renderModeSetOrGet(int mode);
extern void *Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(void *mtx, int id);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void selectTexture(void *tex, int slot);
extern int getAngle(f32 dx, f32 dz);
extern void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, s8 yawIndex);
extern void setMatrixFromObjectPos(f32 *mtx, s16 *src);
extern void mtx44Transpose(f32 *src, f32 *dst);
extern void gxTevAddTextureFrameBlendStages(void);
extern void fn_80078DFC(void);
extern void fn_80078ED0(void);
extern void textBlendSetupFn_80078a7c(void);
extern void fn_800542F4(void);
extern f32 lbl_803DF450;
extern f32 lbl_803DF454;
extern f32 lbl_803DF458;
extern f32 lbl_803DF45C;

typedef struct {
    s16 ang[3];
    s16 pad;
    f32 scale;
    f32 pos[3];
} EffXform;

#pragma scheduling off
#pragma peephole off
int dll_0B_func09(void *a0, int a1, int a2, u8 a3, void *a4)
{
    u8 ar;
    u8 ag;
    u8 ab;
    f32 rot[3];
    f32 pos[3];
    EffXform xf;
    f32 mtxA[12];
    f32 mtxB[16];
    int **p;
    int slot;
    void *view;
    void *buf1;
    void *buf2;
    u8 aligned;
    void *tex;
    int texCount;
    int n131;
    int n131p1;
    f32 dirX;
    f32 dirZ;
    f32 dscale;

    n131 = 0;
    n131p1 = 0;
    if (a4 != NULL) {
        getAmbientColor(*(u8 *)((char *)a4 + 0xf2), &ar, &ag, &ab);
    } else {
        getAmbientColor(0, &ar, &ag, &ab);
    }
    GXSetCullMode(0);
    if (renderModeSetOrGet(-1) == 1) {
        return 1;
    }
    view = Camera_GetCurrentViewSlot();
    p = (int **)lbl_8039C1F8;
    for (slot = 0; slot < 50; slot++, p++) {
        if (*p == NULL) continue;
        if (*(s16 *)((char *)*p + 0x10c) == -1) continue;
        if (a3) {
            if ((*(int *)((char *)*p + 0xa4) & 0x2000) == 0) continue;
        }
        if (a3) {
            if (*(void **)((char *)*p + 4) != a4) continue;
        }
        if (!a3) {
            if (*(int *)((char *)*p + 0xa4) & 0x2000) continue;
        }
        if (*(int *)((char *)*p + 0xa4) & 0x800) {
            *(u8 *)((char *)*p + 0x13e) = 0;
        }
        aligned = 0;
        buf1 = *(void **)((char *)*p + (int)*(u8 *)((char *)*p + 0x130) * 4 + 0x78);
        buf2 = *(void **)((char *)*p + (int)*(u8 *)((char *)*p + 0x130) * 4 + 0x84);
        xf.pos[0] = lbl_803DF430;
        xf.pos[1] = lbl_803DF430;
        xf.pos[2] = lbl_803DF430;
        xf.scale = lbl_803DF434;
        xf.ang[2] = 0;
        xf.ang[1] = 0;
        pos[0] = *(f32 *)((char *)*p + 0x60);
        pos[1] = *(f32 *)((char *)*p + 0x64);
        pos[2] = *(f32 *)((char *)*p + 0x68);
        if (*(int *)((char *)*p + 0xa4) & 0x4) {
            if (lbl_803DF430 == pos[2] + (pos[0] + pos[1])) {
                aligned = 1;
            }
            if (!aligned) {
                if (*(void **)((char *)*p + 4) != NULL) {
                    xf.ang[0] = *(s16 *)(*(char **)((char *)*p + 4));
                    xf.ang[1] = *(s16 *)(*(char **)((char *)*p + 4) + 2);
                    xf.ang[2] = *(s16 *)(*(char **)((char *)*p + 4) + 4);
                    vecRotateZXY(&xf.ang[0], &pos[0]);
                }
            }
        }
        rot[0] = lbl_803DF430;
        rot[1] = lbl_803DF430;
        rot[2] = lbl_803DF430;
        if ((*(int *)((char *)*p + 0xa4) & 1) == 0) {
            if (*(void **)((char *)*p + 4) != NULL) {
                rot[0] = *(f32 *)(*(char **)((char *)*p + 4) + 0x18);
                rot[1] = *(f32 *)(*(char **)((char *)*p + 4) + 0x1c);
                rot[2] = *(f32 *)(*(char **)((char *)*p + 4) + 0x20);
            } else {
                rot[0] = *(f32 *)((char *)*p + 0x18);
                rot[1] = *(f32 *)((char *)*p + 0x1c);
                rot[2] = *(f32 *)((char *)*p + 0x20);
                Obj_RotateLocalOffsetByYaw((f32 *)((char *)*p + 0x18), &rot[0], *(s8 *)((char *)*p + 0x135));
            }
        }
        if (rot[0] > lbl_803DF450 || rot[0] < lbl_803DF454) {
            rot[0] = -playerMapOffsetX;
        }
        if (rot[1] > lbl_803DF450 || rot[1] < lbl_803DF454) {
            rot[1] = lbl_803DF430;
        }
        if (rot[2] > lbl_803DF450 || rot[2] < lbl_803DF454) {
            rot[2] = -playerMapOffsetZ;
        }
        xf.pos[0] = rot[0] + pos[0];
        xf.pos[1] = rot[1] + pos[1];
        xf.pos[2] = rot[2] + pos[2];
        if (*(int *)((char *)*p + 0xa4) & 0x400000) {
            dscale = lbl_803DF458 * *(f32 *)((char *)*p + 0xd4);
            xf.scale = dscale + dscale / (f32)randomGetRange(1, 10);
        } else {
            xf.scale = lbl_803DF45C * *(f32 *)((char *)*p + 0xd4);
        }
        if (*(int *)((char *)*p + 0xa4) & 0x80000) {
            xf.ang[2] = *(s16 *)(*(char **)((char *)*p + 4) + 4);
            xf.ang[1] = *(s16 *)(*(char **)((char *)*p + 4) + 2);
            xf.ang[0] = *(s16 *)(*(char **)((char *)*p + 4));
        } else if (aligned && *(void **)((char *)*p + 4) != NULL) {
            xf.ang[2] = *(s16 *)((char *)*p + 0x106) + *(s16 *)(*(char **)((char *)*p + 4) + 4);
            xf.ang[1] = *(s16 *)((char *)*p + 0x108) + *(s16 *)(*(char **)((char *)*p + 4) + 2);
            xf.ang[0] = *(s16 *)((char *)*p + 0x10a) + *(s16 *)(*(char **)((char *)*p + 4));
        } else if (aligned) {
            xf.ang[2] = *(s16 *)((char *)*p + 0x106) + *(s16 *)((char *)*p + 0x10);
            xf.ang[1] = *(s16 *)((char *)*p + 0x108) + *(s16 *)((char *)*p + 0xe);
            xf.ang[0] = *(s16 *)((char *)*p + 0x10a) + *(s16 *)((char *)*p + 0xc);
        } else {
            xf.ang[2] = *(s16 *)((char *)*p + 0x106);
            xf.ang[1] = *(s16 *)((char *)*p + 0x108);
            xf.ang[0] = *(s16 *)((char *)*p + 0x10a);
        }
        if (*(int *)((char *)*p + 0xa4) & 0x1000) {
            if (*(void **)((char *)*p + 4) != NULL) {
                dirX = *(f32 *)((char *)view + 0x44) - *(f32 *)(*(char **)((char *)*p + 4) + 0x18);
                dirZ = *(f32 *)&((GameObject *)view)->anim.placementData - *(f32 *)(*(char **)((char *)*p + 4) + 0x20);
                dscale = sqrtf(dirX * dirX + dirZ * dirZ);
                if (dscale != lbl_803DF430) {
                    dirX = dirX / dscale;
                    dirZ = dirZ / dscale;
                }
                xf.ang[0] = xf.ang[0] + (int)(f32)(u16)getAngle(dirX, dirZ);
            }
        }
        xf.pos[0] = xf.pos[0] - playerMapOffsetX;
        xf.pos[2] = xf.pos[2] - playerMapOffsetZ;
        setMatrixFromObjectPos(mtxB, &xf.ang[0]);
        mtx44Transpose(mtxB, mtxA);
        PSMTXConcat((f32 *)Camera_GetViewMatrix(), mtxA, mtxA);
        GXLoadPosMtxImm(mtxA, 0);
        tex = *(void **)((char *)*p + 0x98);
        if (tex != NULL) {
            texCount = (u8)(*(u16 *)((char *)tex + 0x10) >> 8);
        }
        if (tex != NULL && *(u8 *)((char *)*p + 0x132) != 0) {
            *(u8 *)((char *)*p + 0x133) = *(u8 *)((char *)*p + 0x133) - 1;
            if (*(u8 *)((char *)*p + 0x133) == 0) {
                *(u8 *)((char *)*p + 0x133) = 0x3c / *(u8 *)((char *)*p + 0x132);
                *(u8 *)((char *)*p + 0x131) = *(u8 *)((char *)*p + 0x131) + 1;
                if ((u8)*(u8 *)((char *)*p + 0x131) >= (u32)texCount) {
                    *(u8 *)((char *)*p + 0x131) = 0;
                }
            }
        }
        if (*(int *)((char *)*p + 0xa4) & 0x8) {
            setTextColor(a0, ar, ag, ab, 0xff);
        } else if (*(void **)((char *)*p + 4) != NULL && (*(int *)((char *)*p + 0xa4) & 0x4000)) {
            setTextColor(a0, 0xff, 0xff, 0xff, *(u8 *)(*(char **)((char *)*p + 4) + 0x37));
        } else {
            setTextColor(a0, 0xff, 0xff, 0xff, 0xff);
        }
        tex = *(void **)((char *)*p + 0x98);
        if (tex != NULL) {
            n131 = *(u8 *)((char *)*p + 0x131);
            n131p1 = (u8)(n131 + 1);
            if (n131p1 > texCount - 1) {
                n131p1 = 0;
            }
        }
        if (*(int *)((char *)*p + 0xa4) & 0x1000000) {
            if (*(u8 *)((char *)*p + 0x13e) != 0 || (*(int *)((char *)*p + 0xa4) & 0x400)) {
                int j;
                for (j = 0; j < (u8)n131p1; j++) {
                    tex = *(void **)tex;
                }
                _textSetColor(a0, 0xff, 0xff, 0xff,
                              (u8)(0xff - *(u8 *)((char *)*p + 0x133) * *(u8 *)((char *)*p + 0x134)));
                textureSetupFn_800799c0();
                gxTevAddTextureFrameBlendStages();
                fn_80078DFC();
                textRenderSetupFn_80079804();
                selectTexture(tex, 1);
            }
        } else if (*(int *)((char *)*p + 0xa4) & 0x2000000) {
            textureSetupFn_800799c0();
            fn_80078ED0();
            textRenderSetupFn_80079804();
        } else if (*(int *)((char *)*p + 0xa4) & 0x4000000) {
            textureSetupFn_800799c0();
            geomDrawFn_800796f0();
            gxTexColorFn_80079254();
            textRenderSetupFn_80079804();
        }
        if (*(int *)((char *)*p + 0xa4) & 0x05000000) {
            if (*(u8 *)((char *)*p + 0x13e) != 0 || (*(int *)((char *)*p + 0xa4) & 0x400)) {
                int j;
                tex = *(void **)((char *)*p + 0x98);
                for (j = 0; j < (u8)n131; j++) {
                    tex = *(void **)tex;
                }
                selectTexture(tex, 0);
            }
        }
        if (*(int *)((char *)*p + 0xa4) & 0x100) {
            gxBlendFn_80078b4c();
        } else if ((*(int *)((char *)*p + 0xa4) & 0x10) && (*(int *)((char *)*p + 0xa4) & 0x80)) {
            textBlendSetupFn_80078a7c();
        } else if (*(int *)((char *)*p + 0xa4) & 0x80) {
            gxBlendFn_80078b4c();
        } else if (*(int *)((char *)*p + 0xa4) & 0x10) {
            textBlendSetupFn_80078a7c();
        } else {
            gxBlendFn_80078b4c();
        }
        if (*(int *)((char *)*p + 0xa4) & 0x40) {
            GXSetCullMode(1);
        } else {
            GXSetCullMode(0);
        }
        if (*(u8 *)((char *)*p + 0x13e) != 0 || (*(int *)((char *)*p + 0xa4) & 0x400)) {
            int di;
            for (di = 0; di < (u8)*(u8 *)((char *)*p + 0x136); di++) {
                if (*(int *)((char *)*p + 0xa4) & 0x8000000) {
                    drawFn_8005cf8c(buf1, buf2, *(s16 *)((char *)*p + 0xec) / (u8)*(u8 *)((char *)*p + 0x136));
                } else {
                    drawFn_8005cf8c(buf1, buf2, *(s16 *)((char *)*p + 0xec));
                }
                buf1 = (char *)buf1 + ((u8)*(u8 *)((char *)*p + 0x137) << 4);
                if (*(int *)((char *)*p + 0xa4) & 0x8000000) {
                    buf2 = (char *)buf2 + ((*(s16 *)((char *)*p + 0xec) / (u8)*(u8 *)((char *)*p + 0x136)) << 4);
                }
            }
            fn_800542F4();
            *(u8 *)((char *)*p + 0x130) = 1 - *(u8 *)((char *)*p + 0x130);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0AB4(void *state, void *p, int mode, u8 idx)
{
  extern f32 lbl_803DD284;
  extern f32 lbl_803DF430;
  extern f32 lbl_803DF43C;
  int k = idx * 2;
  char *slots = (char *)state + 0x78;
  u8 *bufB = *(u8 **)(slots + *(u8 *)((char *)state + 0x130) * 4);
  u8 *bufA = *(u8 **)((char *)state + 0x80);
  int j;

  if (mode == 1) {
    f32 target = *(f32 *)((char *)p + 0x4);
    s16 frames = *(s16 *)((char *)state + 0xfe);
    if (frames != 0) {
      ((f32 *)((char *)state + 0xac))[k] =
          (target - (f32)(u32)bufA[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xf]) / (f32)frames;
      ((f32 *)((char *)state + 0xac))[k + 1] =
          (f32)(u32)bufA[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xf];
      goto animate;
    }
    for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
      bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] = (int)target;
      bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] =
          bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf];
    }
    return;
  }
animate:
  ((f32 *)((char *)state + 0xac))[k + 1] =
      ((f32 *)((char *)state + 0xac))[k + 1] +
      ((f32 *)((char *)state + 0xac))[k] * lbl_803DD284;
  if (((f32 *)((char *)state + 0xac))[k + 1] < lbl_803DF430) {
    ((f32 *)((char *)state + 0xac))[k + 1] = lbl_803DF430;
  } else if (((f32 *)((char *)state + 0xac))[k + 1] > lbl_803DF43C) {
    ((f32 *)((char *)state + 0xac))[k + 1] = lbl_803DF43C;
  }
  {
    int ofs = k * 4 + 0xb0;
    for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
      bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] = (int)*(f32 *)((char *)state + ofs);
      bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] =
          bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf];
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0524(void *state, void *p, int mode)
{
  extern f32 lbl_803DF430;
  extern f32 lbl_803DF43C;
  u8 *buf = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
  int j;

  if (mode == 1) {
    f32 tr = *(f32 *)((char *)p + 0x4);
    f32 tg = *(f32 *)((char *)p + 0x8);
    f32 tb = *(f32 *)((char *)p + 0xc);
    if (*(s16 *)((char *)state + 0xfe) != 0) {
      *(f32 *)((char *)state + 0xbc) = (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xc];
      *(f32 *)((char *)state + 0xc0) = (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xd];
      *(f32 *)((char *)state + 0xc4) = (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xe];
      *(f32 *)((char *)state + 0xc8) =
          (tr - (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xc]) / (f32)*(s16 *)((char *)state + 0xfe);
      *(f32 *)((char *)state + 0xcc) =
          (tg - (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xd]) / (f32)*(s16 *)((char *)state + 0xfe);
      *(f32 *)((char *)state + 0xd0) =
          (tb - (f32)(u32)buf[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xe]) / (f32)*(s16 *)((char *)state + 0xfe);
    } else {
      *(f32 *)((char *)state + 0xbc) = tr;
      *(f32 *)((char *)state + 0xc0) = tg;
      *(f32 *)((char *)state + 0xc4) = tb;
      *(f32 *)((char *)state + 0xc8) = lbl_803DF430;
      *(f32 *)((char *)state + 0xcc) = lbl_803DF430;
      *(f32 *)((char *)state + 0xd0) = lbl_803DF430;
    }
  }
  *(f32 *)((char *)state + 0xbc) += *(f32 *)((char *)state + 0xc8);
  *(f32 *)((char *)state + 0xc0) += *(f32 *)((char *)state + 0xcc);
  *(f32 *)((char *)state + 0xc4) += *(f32 *)((char *)state + 0xd0);
  if (*(f32 *)((char *)state + 0xbc) < lbl_803DF430) {
    *(f32 *)((char *)state + 0xbc) = lbl_803DF430;
  } else if (*(f32 *)((char *)state + 0xbc) > lbl_803DF43C) {
    *(f32 *)((char *)state + 0xbc) = lbl_803DF43C;
  }
  if (*(f32 *)((char *)state + 0xc0) < lbl_803DF430) {
    *(f32 *)((char *)state + 0xc0) = lbl_803DF430;
  } else if (*(f32 *)((char *)state + 0xc0) > lbl_803DF43C) {
    *(f32 *)((char *)state + 0xc0) = lbl_803DF43C;
  }
  if (*(f32 *)((char *)state + 0xc4) < lbl_803DF430) {
    *(f32 *)((char *)state + 0xc4) = lbl_803DF430;
  } else if (*(f32 *)((char *)state + 0xc4) > lbl_803DF43C) {
    *(f32 *)((char *)state + 0xc4) = lbl_803DF43C;
  }
  for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
    buf[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xc] = (int)*(f32 *)((char *)state + 0xbc);
    buf[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xd] = (int)*(f32 *)((char *)state + 0xc0);
    buf[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xe] = (int)*(f32 *)((char *)state + 0xc4);
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_800A0C78(void *state, void *p, int mode, u8 idx)
{
  extern f32 lbl_803DD284;
  extern f32 lbl_803DF434;
  char *base = (char *)state + idx * 2 * 0xc;
  int j;

  if (mode == 1) {
    f32 tx = ((ModgfxVertexGroupCmd *)p)->valueX;
    f32 ty = ((ModgfxVertexGroupCmd *)p)->valueY;
    f32 tz = ((ModgfxVertexGroupCmd *)p)->valueZ;
    if (((ModgfxState *)state)->blendFrameCount != 0) {
      *(f32 *)(base + 0x3c) = (tx - *(f32 *)(base + 0x30)) / (f32)((ModgfxState *)state)->blendFrameCount;
      *(f32 *)(base + 0x40) = (ty - *(f32 *)(base + 0x34)) / (f32)((ModgfxState *)state)->blendFrameCount;
      *(f32 *)(base + 0x44) = (tz - *(f32 *)(base + 0x38)) / (f32)((ModgfxState *)state)->blendFrameCount;
    } else {
      u8 *buf = (u8 *)((ModgfxState *)state)->baseVertexData;
      u8 *buf2 = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
      for (j = 0; j < ((ModgfxVertexGroupCmd *)p)->indexCount; j++) {
        s16 v = ((ModgfxVertexGroupCmd *)p)->indices[j];
        *(s16 *)(buf + v * 16 + 0) = (int)((f32)*(s16 *)(buf + v * 16 + 0) * tx);
        *(s16 *)(buf + v * 16 + 2) = (int)((f32)*(s16 *)(buf + v * 16 + 2) * ty);
        *(s16 *)(buf + v * 16 + 4) = (int)((f32)*(s16 *)(buf + v * 16 + 4) * tz);
        *(s16 *)(buf2 + v * 16 + 0) = *(s16 *)(buf + v * 16 + 0);
        *(s16 *)(buf2 + v * 16 + 2) = *(s16 *)(buf + v * 16 + 2);
        *(s16 *)(buf2 + v * 16 + 4) = *(s16 *)(buf + v * 16 + 4);
      }
      return;
    }
  }
  *(f32 *)(base + 0x30) = *(f32 *)(base + 0x30) + *(f32 *)(base + 0x3c) * lbl_803DD284;
  *(f32 *)(base + 0x34) = *(f32 *)(base + 0x34) + *(f32 *)(base + 0x40) * lbl_803DD284;
  *(f32 *)(base + 0x38) = *(f32 *)(base + 0x38) + *(f32 *)(base + 0x44) * lbl_803DD284;
  {
    u8 *buf = (u8 *)((ModgfxState *)state)->baseVertexData;
    u8 *buf2 = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
    for (j = 0; j < ((ModgfxVertexGroupCmd *)p)->indexCount; j++) {
      s16 v = ((ModgfxVertexGroupCmd *)p)->indices[j];
      if (lbl_803DF434 != *(f32 *)(base + 0x30)) {
        *(s16 *)(buf2 + v * 16 + 0) = (int)(*(f32 *)(base + 0x30) * (f32)*(s16 *)(buf + v * 16 + 0));
      }
      if (lbl_803DF434 != *(f32 *)(base + 0x34)) {
        *(s16 *)(buf2 + v * 16 + 2) = (int)(*(f32 *)(base + 0x34) * (f32)*(s16 *)(buf + v * 16 + 2));
      }
      if (lbl_803DF434 != *(f32 *)(base + 0x38)) {
        *(s16 *)(buf2 + v * 16 + 4) = (int)(*(f32 *)(base + 0x38) * (f32)*(s16 *)(buf + v * 16 + 4));
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int size, int type);
extern int *Obj_SetupObject(int *obj, int a, int b, int c, int d);
extern void ObjList_GetObjects(int *idx, int *count);
extern void Sfx_StopObjectChannel(void *obj, int ch);
extern f32 lbl_803DF43C;

typedef void (*ExpFn2)(void *, int);
typedef void (*ExpFn3)(void *, void *, int);
typedef void (*ExpFn4)(void *, void *, int, int);
typedef void (*ExpResFn6)(void *, int, void *, int, int, void *);

#define E9 ((char *)*(int **)((char *)eff + 0x9c))

#pragma scheduling off
#pragma peephole off
void dll_0B_func05(void)
{
    int slot;
    int **pp;
    int *eff;
    int reprocess;
    int active;
    int emIdx;
    int emOff;
    int feFlag;
    int cntC;
    int cntA;
    int k;
    void *res;
    s16 ang[3];
    f32 q[4];
    BoneSpawnData tmpl;
    int objIdx;
    int objCount;

    emIdx = 0;
    gExpgfxUpdatingActivePools = 2;
    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    lbl_803DD284 = timeDelta;
    pp = (int **)lbl_8039C1F8;
    for (slot = 0; slot < 50; slot++, pp++) {
        reprocess = 1;
        while (reprocess) {
            reprocess = 0;
            eff = *pp;
            if (eff == NULL) break;
            if (((ModgfxEffectSlot *)eff)->unk10C == -1) break;
            active = 0;
            ((ModgfxEffectSlot *)eff)->unk13E = 0;
            if (((ModgfxEffectSlot *)eff)->unkFE < 0 || ((ModgfxEffectSlot *)eff)->counterFC == -1) {
                ((ModgfxEffectSlot *)eff)->counterFC += 1;
                if (((ModgfxEffectSlot *)eff)->counterFC > 6) {
                    fn_800A1040(((ModgfxEffectSlot *)eff)->unk10C, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot *)eff)->unkFE = *(s16 *)((char *)eff + ((ModgfxEffectSlot *)eff)->counterFC * 2 + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            } else if (((ModgfxEffectSlot *)eff)->unk13C != 0) {
                ((ModgfxEffectSlot *)eff)->counterFC = ((ModgfxEffectSlot *)eff)->unk13C;
                ((ModgfxEffectSlot *)eff)->unk13C = 0;
                if (((ModgfxEffectSlot *)eff)->counterFC > 6) {
                    fn_800A1040(((ModgfxEffectSlot *)eff)->unk10C, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot *)eff)->unkFE = *(s16 *)((char *)eff + ((ModgfxEffectSlot *)eff)->counterFC * 2 + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            cntC = 0;
            cntA = 0;
            ((ExpFn3)fn_800A0FD0)(eff, E9 + emIdx * 0x18, active);
            feFlag = 0;
            emIdx = 0;
            emOff = 0;
            for (; emIdx < ((ModgfxEffectSlot *)eff)->unk139; emIdx++, emOff += 0x18) {
                int flags;
                if (*(s16 *)((char *)eff + 0xfc) != *(u8 *)(E9 + emOff + 0x16)) continue;
                flags = *(int *)(E9 + emOff);
                if ((flags & 0x1000) && *(f32 *)(E9 + emOff + 0x4) > lbl_803DF430 && ((ModgfxEffectSlot *)eff)->counterFC > 0) {
                    ((ModgfxEffectSlot *)eff)->counterFC = *(s16 *)(E9 + emIdx * 0x18 + 0x14);
                    *(f32 *)(E9 + emIdx * 0x18 + 0x4) = *(f32 *)(E9 + emIdx * 0x18 + 0x4) - lbl_803DF434;
                    ((ModgfxEffectSlot *)eff)->unkFE = -1;
                    break;
                }
                if (flags & 0x2000) {
                    if (((ModgfxEffectSlot *)eff)->unk13A != 0) {
                        ((ModgfxEffectSlot *)eff)->unk13A = 0;
                        *(int *)(E9 + emIdx * 0x18) = 0;
                        *(int *)(E9 + emIdx * 0x18) = 0x20;
                        ((ModgfxEffectSlot *)eff)->unkFE = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (*(s16 *)((char *)eff + 0xfc) > 0) {
                        feFlag = 1;
                        ((ModgfxEffectSlot *)eff)->counterFC = *(s16 *)(E9 + emIdx * 0x18 + 0x14);
                        ((ModgfxEffectSlot *)eff)->unkFE = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000) {
                    tmpl.x = ((ModgfxEffectSlot *)eff)->unk60;
                    tmpl.y = ((ModgfxEffectSlot *)eff)->unk64;
                    tmpl.z = ((ModgfxEffectSlot *)eff)->unk68;
                    q[1] = lbl_803DF430;
                    q[2] = lbl_803DF430;
                    q[3] = lbl_803DF430;
                    q[0] = lbl_803DF434;
                    if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                        ang[0] = *(s16 *)((char *)eff + 0xc);
                    } else {
                        ang[0] = *(s16 *)(*(int **)&((ModgfxEffectSlot *)eff)->unk4);
                    }
                    ang[1] = 0;
                    ang[2] = 0;
                    vecRotateZXY(&ang[0], &tmpl.x);
                    if (*(int *)eff == 0) {
                        if (Obj_IsLoadingLocked()) {
                            int *o;
                            if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                                tmpl.x += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x18);
                                tmpl.y += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x1c);
                                tmpl.z += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x20);
                            } else {
                                tmpl.x += ((ModgfxEffectSlot *)eff)->unk18;
                                tmpl.y += ((ModgfxEffectSlot *)eff)->unk1C;
                                tmpl.z += ((ModgfxEffectSlot *)eff)->unk20;
                            }
                            o = Obj_AllocObjectSetup(0x20, 0x66);
                            ((GameObject *)o)->anim.rootMotionScale = tmpl.x;
                            ((GameObject *)o)->anim.localPosX = tmpl.y;
                            *(f32 *)&((ObjDef *)o)->jointData = tmpl.z;
                            *(int *)eff = (int)Obj_SetupObject(o, 5, -1, -1, 0);
                            *(int *)(*(int *)eff + 0xf8) = 1;
                        }
                    } else if (*(int *)eff != 0) {
                        if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                            tmpl.x += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x18);
                            tmpl.y += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x1c);
                            tmpl.z += *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x20);
                        } else {
                            tmpl.x += ((ModgfxEffectSlot *)eff)->unk18;
                            tmpl.y += ((ModgfxEffectSlot *)eff)->unk1C;
                            tmpl.z += ((ModgfxEffectSlot *)eff)->unk20;
                        }
                        *(f32 *)(*(int *)eff + 0x18) = tmpl.x;
                        *(f32 *)(*(int *)eff + 0x1c) = tmpl.y;
                        *(f32 *)(*(int *)eff + 0x20) = tmpl.z;
                    }
                    if (*(int *)eff != 0) {
                        int *o = *(int **)eff;
                        int *list = *(int **)((char *)*(int **)&((GameObject *)o)->anim.hitReactState + 0x50);
                        if (list != NULL) {
                            if (*(s16 *)((char *)list + 0x44) == (int)*(f32 *)(E9 + emOff + 0x4)) {
                                Obj_FreeObject(o);
                                *(int *)eff = 0;
                                *(int *)(E9 + emIdx * 0x18) ^= 0x10000000;
                                if (*(f32 *)(E9 + emIdx * 0x18 + 0xc) >= lbl_803DF430 && *(int **)&((ModgfxEffectSlot *)eff)->unk4 != NULL) {
                                    (*gPartfxInterface)->spawnObject(
                                        *(int **)&((ModgfxEffectSlot *)eff)->unk4,
                                        (int)*(f32 *)(E9 + emIdx * 0x18 + 0xc),
                                        &tmpl, 0x200001, -1, NULL);
                                }
                                ((ModgfxEffectSlot *)eff)->unk13C = (int)*(f32 *)(E9 + emIdx * 0x18 + 0x8);
                                break;
                            }
                        }
                    }
                }
                ObjList_GetObjects(&objIdx, &objCount);
                if (*(int *)(E9 + emOff) & 0x2) {
                    fn_800A0C78(eff, E9 + emOff, active, (u8)cntC);
                    cntC++;
                }
                if (*(int *)(E9 + emOff) & 0x4) {
                    fn_800A0AB4(eff, E9 + emOff, active, (u8)cntA);
                    cntA++;
                }
                if (*(int *)(E9 + emOff) & 0x8) {
                    ((ExpFn4)fn_800A0524)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x100) {
                    ((ModgfxEffectSlot *)eff)->unk106 = ((ModgfxEffectSlot *)eff)->unk106 + (int)(*(f32 *)(E9 + emOff + 0x4) * lbl_803DD284);
                    ((ModgfxEffectSlot *)eff)->unk108 = ((ModgfxEffectSlot *)eff)->unk108 + (int)(*(f32 *)(E9 + emOff + 0x8) * lbl_803DD284);
                    ((ModgfxEffectSlot *)eff)->unk10A = ((ModgfxEffectSlot *)eff)->unk10A + (int)(*(f32 *)(E9 + emOff + 0xc) * lbl_803DD284);
                }
                if (*(int *)(E9 + emOff) & 0x80) {
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x8000000) {
                    *(f32 *)(E9 + emOff + 0xc) = (f32)randomGetRange(0, 0xffff);
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x4000) {
                    ((ExpFn4)fn_800A02DC)(eff, E9 + emOff, active, 0);
                }
                if ((*(int *)(E9 + emOff) & 0x10000) && active != 0) {
                    if (*(s16 *)(E9 + emOff + 0x14) == -1) {
                        Sfx_StopObjectChannel(*(int **)&((ModgfxEffectSlot *)eff)->unk4, 0x40);
                    } else {
                        Sfx_PlayFromObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, (u16)*(s16 *)(E9 + emOff + 0x14));
                    }
                }
                if (*(int *)(E9 + emOff) & 0x100000) {
                    GameObject *obj = *(GameObject **)&((ModgfxEffectSlot *)eff)->unk4;
                    if (active == 1) {
                        if (((ModgfxEffectSlot *)eff)->unkFE != 0) {
                            ((ModgfxEffectSlot *)eff)->unkBC =
                                (*(f32 *)(E9 + emOff + 0x4) - (f32)(u32)obj->anim.alpha) /
                                (f32)((ModgfxEffectSlot *)eff)->unkFE;
                            ((ModgfxEffectSlot *)eff)->unkC0 = (f32)(u32)obj->anim.alpha;
                        } else {
                            ((ModgfxEffectSlot *)eff)->unkBC =
                                *(f32 *)(E9 + emOff + 0x4) - (f32)(u32)obj->anim.alpha;
                            ((ModgfxEffectSlot *)eff)->unkC0 = lbl_803DF430;
                        }
                    }
                    ((ModgfxEffectSlot *)eff)->unkC0 = ((ModgfxEffectSlot *)eff)->unkC0 + ((ModgfxEffectSlot *)eff)->unkBC;
                    if (((ModgfxEffectSlot *)eff)->unkC0 > lbl_803DF43C) {
                        ((ModgfxEffectSlot *)eff)->unkC0 = lbl_803DF43C;
                    } else if (((ModgfxEffectSlot *)eff)->unkC0 < lbl_803DF430) {
                        ((ModgfxEffectSlot *)eff)->unkC0 = lbl_803DF430;
                    }
                    obj->anim.alpha = (int)((ModgfxEffectSlot *)eff)->unkC0;
                }
                if (*(int *)(E9 + emOff) & 0x400000) {
                    ((ExpFn4)fn_800A081C)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x80000000) {
                    ((ModgfxEffectSlot *)eff)->unk24 = *(f32 *)(E9 + emOff + 0x4) * lbl_803DD284 + ((ModgfxEffectSlot *)eff)->unk24;
                    ((ModgfxEffectSlot *)eff)->unk28 = *(f32 *)(E9 + emOff + 0x8) * lbl_803DD284 + ((ModgfxEffectSlot *)eff)->unk28;
                    ((ModgfxEffectSlot *)eff)->unk2C = *(f32 *)(E9 + emOff + 0xc) * lbl_803DD284 + ((ModgfxEffectSlot *)eff)->unk2C;
                }
                if (*(int *)(E9 + emOff) & 0x800000) {
                    if ((*(int *)(E9 + emOff) & 0x1000000) && lbl_803DF430 == *(f32 *)(E9 + emOff + 0x8)) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (randomGetRange(0, (int)*(f32 *)(E9 + emOff + 0xc)) == 0) {
                                if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                                    (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), NULL, 0x10001, -1, NULL);
                                } else {
                                    (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), NULL, 0x10001, -1, NULL);
                                }
                            }
                        }
                    } else if (lbl_803DF430 == *(f32 *)(E9 + emOff + 0x8)) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                                (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), (char *)eff + 0xc, 0x10002, -1, NULL);
                            } else {
                                (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), NULL, 0x10002, -1, NULL);
                            }
                        }
                    } else if (lbl_803DF434 == *(f32 *)(E9 + emOff + 0x8)) {
                        if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                            tmpl.x = ((ModgfxEffectSlot *)eff)->unk60;
                            tmpl.y = ((ModgfxEffectSlot *)eff)->unk64;
                            tmpl.z = ((ModgfxEffectSlot *)eff)->unk68;
                            if (*(int **)&((ModgfxEffectSlot *)eff)->unk4 != NULL) {
                                (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        } else {
                            tmpl.x = *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x18) + ((ModgfxEffectSlot *)eff)->unk60;
                            tmpl.y = *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x1c) + ((ModgfxEffectSlot *)eff)->unk64;
                            tmpl.z = *(f32 *)((char *)*(int **)&((ModgfxEffectSlot *)eff)->unk4 + 0x20) + ((ModgfxEffectSlot *)eff)->unk68;
                            if (*(int **)&((ModgfxEffectSlot *)eff)->unk4 != NULL) {
                                (*gPartfxInterface)->spawnObject(*(int **)&((ModgfxEffectSlot *)eff)->unk4, *(s16 *)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        }
                    }
                }
                if (*(int *)(E9 + emOff) & 0x4000000) {
                    res = Resource_Acquire((u16)(*(s16 *)(E9 + emOff + 0x14) + 0x58), 1);
                    if (*(int *)(E9 + emOff) & 0x1000000) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (randomGetRange(0, 5) == 0) {
                                if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                                    (*(ExpResFn6 *)(*(int *)res + 4))(NULL, 0, (char *)eff + 0xc, 1, -1, NULL);
                                } else {
                                    (*(ExpResFn6 *)(*(int *)res + 4))(*(int **)&((ModgfxEffectSlot *)eff)->unk4, 0, NULL, 1, -1, NULL);
                                }
                            }
                        }
                    } else {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (((ModgfxEffectSlot *)eff)->unkA4 & 1) {
                                (*(ExpResFn6 *)(*(int *)res + 4))(NULL, 0, (char *)eff + 0xc, 1, -1, NULL);
                            } else {
                                (*(ExpResFn6 *)(*(int *)res + 4))(*(int **)&((ModgfxEffectSlot *)eff)->unk4, 0, NULL, 1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0) {
                ((ModgfxEffectSlot *)eff)->unkFE = ((ModgfxEffectSlot *)eff)->unkFE - framesThisStep;
            }
        }
    slot_done:
        gExpgfxUpdatingActivePools = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
