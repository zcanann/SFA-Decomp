#include "ghidra_import.h"
#include "main/expgfx_internal.h"
#include "main/dll/modgfx.h"
#include "main/object_descriptor.h"

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

typedef struct ModgfxState {
  u8 pad00[0x78];
  ModgfxVertexData *vertexBuffers[2];
  ModgfxVertexData *baseVertexData;
  u8 pad84[0xA4 - 0x84];
  u32 flags;
  u8 padA8[0xEA - 0xA8];
  s16 vertexCount;
  u8 padEC[0xFE - 0xEC];
  s16 blendFrameCount;
  s16 colorStepR;
  s16 colorStepG;
  s16 colorStepB;
  s16 colorValueR;
  s16 colorValueG;
  s16 colorValueB;
  s16 effectId;
  u8 pad10E[0x130 - 0x10E];
  u8 activeVertexBufferIndex;
} ModgfxState;

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32
#define PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE 0x200000

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

extern uint DAT_8039ce58;

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
  return (ModgfxActiveEffect **)&DAT_8039ce58;
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
extern void expgfxRemoveAll();
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
extern undefined2 gExpgfxPoolSlotTypeIds;
extern undefined gExpgfxPoolFrameFlags;
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
extern u8 gExpgfxRuntimeData[];
extern s16 gExpgfxStaticPoolSlotTypeIds[];
extern undefined gExpgfxPoolSourceModes;
extern undefined4 gExpgfxPoolSourceIds;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern undefined4 DAT_8039c7d0;
extern undefined4 DAT_8039c7d4;
extern undefined gExpgfxPoolActiveCounts;
extern undefined4 gExpgfxPoolActiveMasks;
extern uint gExpgfxSlotPoolBases[];
extern ExpgfxSpawnConfig gExpgfxSpawnConfig;
extern undefined4 DAT_8039cb18;
extern undefined4 DAT_8039cb1c;
extern undefined4 DAT_8039cb20;
extern undefined4 DAT_8039cb24;
extern undefined4 DAT_8039cb28;
extern undefined4 DAT_8039cb2c;
extern undefined4 DAT_8039cb30;
extern undefined4 DAT_8039cb34;
extern undefined4 DAT_8039cb38;
extern undefined4 DAT_8039cb3c;
extern undefined4 DAT_8039cb4c;
extern undefined4 DAT_8039cb50;
extern undefined4 DAT_8039cb51;
extern undefined4 DAT_8039cb52;
extern undefined4 DAT_8039cb53;
extern undefined4 DAT_8039cb55;
extern undefined4 DAT_8039cb58;
extern uint DAT_8039ce58;
extern undefined4 DAT_8039ce5c;
extern undefined4 DAT_8039ce60;
extern undefined4 DAT_8039ce64;
extern undefined4 DAT_8039ce68;
extern undefined4 DAT_8039ce6c;
extern undefined4 DAT_8039ce70;
extern undefined4 DAT_8039ce74;
extern undefined4 DAT_8039ce78;
extern undefined4 DAT_8039ce7c;
extern undefined4 DAT_8039ce80;
extern undefined4 DAT_8039ce84;
extern undefined4 DAT_8039ce88;
extern undefined4 DAT_8039ce8c;
extern undefined4 DAT_8039ce90;
extern undefined4 DAT_8039ce94;
extern undefined4 DAT_8039ce98;
extern undefined4 DAT_8039ce9c;
extern undefined4 DAT_8039cea0;
extern undefined4 DAT_8039cea4;
extern undefined4 DAT_8039cea8;
extern undefined4 DAT_8039ceac;
extern undefined4 DAT_8039ceb0;
extern undefined4 DAT_8039ceb4;
extern undefined4 DAT_8039ceb8;
extern undefined4 DAT_8039cebc;
extern undefined4 DAT_8039cec0;
extern undefined4 DAT_8039cec4;
extern undefined4 DAT_8039cec8;
extern undefined4 DAT_8039cecc;
extern undefined4 DAT_8039ced0;
extern undefined4 DAT_8039ced4;
extern undefined4 DAT_8039ced8;
extern undefined4 DAT_8039cedc;
extern undefined4 DAT_8039cee0;
extern undefined4 DAT_8039cee4;
extern undefined4 DAT_8039cee8;
extern undefined4 DAT_8039ceec;
extern undefined4 DAT_8039cef0;
extern undefined4 DAT_8039cef4;
extern undefined4 DAT_8039cef8;
extern undefined4 DAT_8039cefc;
extern undefined4 DAT_8039cf00;
extern undefined4 DAT_8039cf04;
extern undefined4 DAT_8039cf08;
extern undefined4 DAT_8039cf0c;
extern undefined4 DAT_8039cf10;
extern undefined4 DAT_8039cf14;
extern undefined4 DAT_8039cf18;
extern int DAT_8039cf20;
extern undefined4 DAT_8039cf24;
extern undefined4 DAT_8039cf28;
extern undefined4 DAT_8039cf2c;
extern undefined4 DAT_8039cf30;
extern undefined4 DAT_8039cf34;
extern undefined4 DAT_8039cf38;
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
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
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
 * Function: expgfx_initialise
 * EN v1.0 Address: 0x8009FED0
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x8009FF68
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_initialise(void)
{
  u8 *expgfxBase;
  u32 *poolActiveMasks;
  u8 *poolActiveCounts;
  s16 *poolSlotTypeIds;
  u32 *slotPoolBases;
  int poolIndex;
  int groupCount;

  expgfxBase = gExpgfxRuntimeData;
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  groupCount = EXPGFX_POOL_GROUP_COUNT;
  do {
    poolIndex = 0;
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
    groupCount--;
  } while (groupCount != 0);

  slotPoolBases = (u32 *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  poolIndex = 0;
  do {
    *slotPoolBases = (u32)mmAlloc(EXPGFX_POOL_BYTES, 0x14, 0);
    memset((void *)*slotPoolBases, 0, EXPGFX_POOL_BYTES);
    DCFlushRange((void *)*slotPoolBases, EXPGFX_POOL_BYTES);
    slotPoolBases++;
    poolIndex++;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  memset(expgfxBase + EXPGFX_EXPTAB_OFFSET, 0, 0x500);
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
void modgfx_releaseExpgfxPools(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                               undefined8 param_4,undefined8 param_5,undefined8 param_6,
                               undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint *puVar2;
  
  expgfxRemoveAll(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
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
  undefined2 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  
  puVar3 = &gExpgfxPoolActiveMasks;
  puVar4 = &gExpgfxPoolActiveCounts;
  puVar1 = &gExpgfxPoolSlotTypeIds;
  iVar7 = EXPGFX_POOL_GROUP_COUNT;
  do {
    iVar5 = 0;
    *puVar3 = 0;
    *puVar4 = 0;
    *puVar1 = 0xffff;
    puVar3[1] = 0;
    puVar4[1] = 0;
    puVar1[1] = 0xffff;
    puVar3[2] = 0;
    puVar4[2] = 0;
    puVar1[2] = 0xffff;
    puVar3[3] = 0;
    puVar4[3] = 0;
    puVar1[3] = 0xffff;
    puVar3[4] = 0;
    puVar4[4] = 0;
    puVar1[4] = 0xffff;
    puVar3[5] = 0;
    puVar4[5] = 0;
    puVar1[5] = 0xffff;
    puVar3[6] = 0;
    puVar4[6] = 0;
    puVar1[6] = 0xffff;
    puVar3[7] = 0;
    puVar4[7] = 0;
    puVar1[7] = 0xffff;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  puVar6 = gExpgfxSlotPoolBases;
  do {
    uVar2 = FUN_80017830(EXPGFX_POOL_BYTES,0x14);
    *puVar6 = uVar2;
    FUN_800033a8(*puVar6,0,EXPGFX_POOL_BYTES);
    FUN_802420e0(*puVar6,EXPGFX_POOL_BYTES);
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < EXPGFX_POOL_COUNT);
  FUN_800033a8(-0x7fc63ec8,0,0x500);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a024c
 * EN v1.0 Address: 0x800A024C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A029C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a024c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
                 undefined2 *param_10,int param_11,undefined2 *param_12,int param_13,uint param_14,
                 int param_15)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a0250
 * EN v1.0 Address: 0x800A0250
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x800A03EC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0250(uint param_1)
{
  FUN_80003494(0x8039cb3e,param_1,0xe);
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
  ushort extraout_r4;
  
  uVar1 = FUN_80286840();
  FUN_800033a8((int)&gExpgfxSpawnConfig,0,EXPGFX_SPAWN_CONFIG_PREFIX_BYTES);
  DAT_8039cb50 = (undefined)extraout_r4;
  DAT_8039cb3c = extraout_r4 & 0xff;
  DAT_8039cb24 = lbl_803E00B0;
  DAT_8039cb28 = lbl_803E00B0;
  DAT_8039cb2c = lbl_803E00B0;
  DAT_8039cb18 = lbl_803E00B0;
  DAT_8039cb1c = lbl_803E00B0;
  DAT_8039cb20 = lbl_803E00B0;
  DAT_8039cb30 = lbl_803E00B4;
  DAT_8039cb52 = 0;
  DAT_8039cb53 = 0;
  gExpgfxSpawnConfig.quadVertex3Pad06 = (s32)uVar1;
  DAT_8039cb34 = param_5;
  DAT_8039cb38 = param_4;
  DAT_8039cb51 = param_3;
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
  *(float *)(param_1 + 0x30) = lbl_803E00B4;
  *(float *)(param_1 + 0x34) = fVar2;
  *(float *)(param_1 + 0x38) = fVar2;
  fVar1 = lbl_803E00B0;
  *(float *)(param_1 + 0x3c) = lbl_803E00B0;
  *(float *)(param_1 + 0x40) = fVar1;
  *(float *)(param_1 + 0x44) = fVar1;
  *(float *)(param_1 + 0x48) = fVar2;
  *(float *)(param_1 + 0x4c) = fVar2;
  *(float *)(param_1 + 0x50) = fVar2;
  *(float *)(param_1 + 0x54) = fVar1;
  *(float *)(param_1 + 0x58) = fVar1;
  *(float *)(param_1 + 0x5c) = fVar1;
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
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(float *)(param_1 + 0xbc) = fVar1;
      *(float *)(param_1 + 0xc0) = fVar2;
      *(float *)(param_1 + 0xc4) = fVar3;
      fVar1 = lbl_803E00B0;
      *(float *)(param_1 + 200) = lbl_803E00B0;
      *(float *)(param_1 + 0xcc) = fVar1;
      *(float *)(param_1 + 0xd0) = fVar1;
    }
    else {
      *(float *)(param_1 + 0xbc) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xc)) - DOUBLE_803e00c0);
      *(float *)(param_1 + 0xc0) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xd)) - dVar4);
      *(float *)(param_1 + 0xc4) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xe)) - dVar4);
      dVar5 = DOUBLE_803e00c8;
      *(float *)(param_1 + 200) =
           (fVar1 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xc)) - dVar4)) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
      local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xcc) =
           (fVar2 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xd)) - dVar4)) /
           (float)(local_18 - dVar5);
      local_10 = (double)CONCAT44(0x43300000,
                                  (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xe)
                                 );
      local_8 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xd0) = (fVar3 - (float)(local_10 - dVar4)) / (float)(local_8 - dVar5);
    }
  }
  *(float *)(param_1 + 0xbc) = *(float *)(param_1 + 0xbc) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc0) = *(float *)(param_1 + 0xc0) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  if (lbl_803E00B0 <= *(float *)(param_1 + 0xbc)) {
    if (lbl_803E00BC < *(float *)(param_1 + 0xbc)) {
      *(float *)(param_1 + 0xbc) = lbl_803E00BC;
    }
  }
  else {
    *(float *)(param_1 + 0xbc) = lbl_803E00B0;
  }
  if (lbl_803E00B0 <= *(float *)(param_1 + 0xc0)) {
    if (lbl_803E00BC < *(float *)(param_1 + 0xc0)) {
      *(float *)(param_1 + 0xc0) = lbl_803E00BC;
    }
  }
  else {
    *(float *)(param_1 + 0xc0) = lbl_803E00B0;
  }
  if (lbl_803E00B0 <= *(float *)(param_1 + 0xc4)) {
    if (lbl_803E00BC < *(float *)(param_1 + 0xc4)) {
      *(float *)(param_1 + 0xc4) = lbl_803E00BC;
    }
  }
  else {
    *(float *)(param_1 + 0xc4) = lbl_803E00B0;
  }
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xc) =
         (char)(int)*(float *)(param_1 + 0xbc);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xd) =
         (char)(int)*(float *)(param_1 + 0xc0);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xe) =
         (char)(int)*(float *)(param_1 + 0xc4);
    iVar7 = iVar7 + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a08fc
 * EN v1.0 Address: 0x800A08FC
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x800A0AA8
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a08fc(int param_1,int param_2,int param_3)
{
  double dVar1;
  ushort local_38;
  ushort local_36;
  ushort local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  dVar1 = DOUBLE_803e00c8;
  if (param_3 == 1) {
    if (*(short *)(param_1 + *(short *)(param_1 + 0xfc) * 2 + 0xee) == 0) {
      if (((*(uint *)(param_1 + 0xa4) & 4) != 0) || ((*(uint *)(param_1 + 0xa4) & 0x80000) != 0)) {
        local_2c = lbl_803E00B0;
        local_28 = lbl_803E00B0;
        local_24 = lbl_803E00B0;
        local_30 = lbl_803E00B4;
        local_38 = **(ushort **)(param_1 + 4);
        local_36 = local_38;
        local_34 = local_38;
        FUN_80017748(&local_38,(float *)(param_2 + 4));
      }
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_2 + 4);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_2 + 8);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_2 + 0xc);
    }
    else {
      *(float *)(param_1 + 0x24) =
           *(float *)(param_2 + 4) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
      *(float *)(param_1 + 0x28) =
           *(float *)(param_2 + 8) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
      *(float *)(param_1 + 0x2c) =
           *(float *)(param_2 + 0xc) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
    }
    *(float *)(param_1 + 0x60) = *(float *)(param_1 + 0x60) + *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 100) = *(float *)(param_1 + 100) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x68) = *(float *)(param_1 + 0x68) + *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x60) =
         *(float *)(param_1 + 0x24) * lbl_803DDF04 + *(float *)(param_1 + 0x60);
    *(float *)(param_1 + 100) =
         *(float *)(param_1 + 0x28) * lbl_803DDF04 + *(float *)(param_1 + 100);
    *(float *)(param_1 + 0x68) =
         *(float *)(param_1 + 0x2c) * lbl_803DDF04 + *(float *)(param_1 + 0x68);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0a88
 * EN v1.0 Address: 0x800A0A88
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x800A0C50
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0a88(int param_1,int param_2,int param_3)
{
  short sVar1;
  short sVar2;
  short sVar3;
  
  if (param_3 == 1) {
    sVar1 = (short)(int)*(float *)(param_2 + 4);
    sVar2 = (short)(int)*(float *)(param_2 + 8);
    sVar3 = (short)(int)*(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(short *)(param_1 + 0x106) = sVar1;
      *(undefined2 *)(param_1 + 0x100) = 0;
      *(short *)(param_1 + 0x108) = sVar2;
      *(undefined2 *)(param_1 + 0x102) = 0;
      *(short *)(param_1 + 0x10a) = sVar3;
      *(undefined2 *)(param_1 + 0x104) = 0;
    }
    else {
      *(short *)(param_1 + 0x100) =
           (short)(((int)sVar1 - (int)*(short *)(param_1 + 0x106)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x102) =
           (short)(((int)sVar2 - (int)*(short *)(param_1 + 0x108)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x104) =
           (short)(((int)sVar3 - (int)*(short *)(param_1 + 0x10a)) / (int)*(short *)(param_1 + 0xfe)
                  );
    }
  }
  *(short *)(param_1 + 0x106) = *(short *)(param_1 + 0x106) + *(short *)(param_1 + 0x100);
  *(short *)(param_1 + 0x108) = *(short *)(param_1 + 0x108) + *(short *)(param_1 + 0x102);
  *(short *)(param_1 + 0x10a) = *(short *)(param_1 + 0x10a) + *(short *)(param_1 + 0x104);
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
  iVar6 = *(int *)(param_1 + 0x80);
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar7 = 0;
      for (iVar3 = 0; iVar3 < *(short *)(param_2 + 0x14); iVar3 = iVar3 + 1) {
        *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf) =
             (char)(int)fVar1;
        iVar8 = *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf;
        *(undefined *)(iVar5 + iVar8) = *(undefined *)(iVar6 + iVar8);
        iVar7 = iVar7 + 2;
      }
      return;
    }
    iVar7 = param_1 + (param_4 & 0xff) * 8;
    *(float *)(iVar7 + 0xac) =
         (fVar1 - (float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                   0x10 + 0xf)) - DOUBLE_803e00c0))
         / (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
    local_8 = (double)CONCAT44(0x43300000,
                               (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xf));
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
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar5 + *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf) =
         (char)(int)*(float *)(param_1 + iVar7 + 0xb0);
    iVar4 = *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf;
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
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar8 = *(int *)(param_1 + 0x80);
      iVar7 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < *(short *)(param_2 + 0x14); iVar5 = iVar5 + 1) {
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar1);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar2);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + iVar10) ^ 0x80000000);
        *(short *)(iVar8 + iVar10) = (short)(int)((float)(local_18 - dVar4) * fVar3);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar6 = iVar6 + 2;
      }
      return;
    }
    iVar6 = param_1 + (param_4 & 0xff) * 0x18;
    *(float *)(iVar6 + 0x3c) =
         (fVar1 - *(float *)(iVar6 + 0x30)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                DOUBLE_803e00c8);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
    *(float *)(iVar6 + 0x40) = (fVar2 - *(float *)(iVar6 + 0x34)) / (float)(local_30 - dVar4);
    *(float *)(iVar6 + 0x44) =
         (fVar3 - *(float *)(iVar6 + 0x38)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar4);
  }
  iVar5 = param_1 + (param_4 & 0xff) * 0x18;
  *(float *)(iVar5 + 0x30) = *(float *)(iVar5 + 0x3c) * lbl_803DDF04 + *(float *)(iVar5 + 0x30);
  *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x40) * lbl_803DDF04 + *(float *)(iVar5 + 0x34);
  *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x44) * lbl_803DDF04 + *(float *)(iVar5 + 0x38);
  fVar1 = lbl_803E00B4;
  iVar7 = *(int *)(param_1 + 0x80);
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar10 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    if (fVar1 != *(float *)(iVar5 + 0x30)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x30) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x34)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 2;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x34) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x38)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 4;
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
 * Function: FUN_800a1338
 * EN v1.0 Address: 0x800A1338
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A1750
 * EN v1.1 Size: 2512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a1338(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a133c
 * EN v1.0 Address: 0x800A133C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A2120
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a133c(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
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
 * Function: FUN_800a15d0
 * EN v1.0 Address: 0x800A15D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A238C
 * EN v1.1 Size: 3420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a15d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a15d4
 * EN v1.0 Address: 0x800A15D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A30E8
 * EN v1.1 Size: 2432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a15d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined2 *param_12,
                 int param_13,undefined2 *param_14,uint param_15,int param_16)
{
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
    undefined4 *puVar2;

    puVar2 = &DAT_8039cf18;
    do {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1804
 * EN v1.0 Address: 0x800A1804
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800A3B98
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a1804(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  modgfx_releaseActiveEffectsByType(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                    param_8,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1954
 * EN v1.0 Address: 0x800A1954
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x800A3CCC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800a1954(void)
{
  FUN_800723a0();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1978
 * EN v1.0 Address: 0x800A1978
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x800A3CFC
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800a1978(void)
{
  FUN_800723a0();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800a199c
 * EN v1.0 Address: 0x800A199C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x800A3D4C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a199c(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a19bc
 * EN v1.0 Address: 0x800A19BC
 * EN v1.0 Size: 1064b
 * EN v1.1 Address: 0x800A3D7C
 * EN v1.1 Size: 1580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a19bc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)
{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  undefined2 *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double extraout_f1;
  double in_f20;
  double dVar10;
  double in_f21;
  double in_f22;
  double dVar11;
  double dVar12;
  double in_f23;
  double dVar13;
  double dVar14;
  double in_f24;
  double dVar15;
  double dVar16;
  double in_f25;
  double dVar17;
  double in_f26;
  double dVar18;
  double in_f27;
  double dVar19;
  double in_f28;
  double dVar20;
  double in_f29;
  double dVar21;
  double in_f30;
  double dVar22;
  double in_f31;
  double dVar23;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar24;
  undefined2 local_148;
  undefined2 local_146;
  undefined2 local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  undefined4 local_130;
  uint uStack_12c;
  undefined4 local_128;
  uint uStack_124;
  undefined4 local_120;
  uint uStack_11c;
  undefined4 local_118;
  uint uStack_114;
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  uVar24 = FUN_80286840();
  iVar9 = (int)((ulonglong)uVar24 >> 0x20);
  iVar7 = (int)uVar24;
  bVar4 = false;
  dVar10 = extraout_f1;
  puVar5 = FUN_800069a8();
  DAT_803ddf1c = puVar5[1];
  DAT_803ddf1a = *puVar5;
  dVar11 = (double)(*(float *)(puVar5 + 6) - *(float *)(param_5 + 0xc));
  dVar13 = (double)(*(float *)(puVar5 + 8) - *(float *)(param_5 + 0x10));
  dVar15 = (double)(*(float *)(puVar5 + 10) - *(float *)(param_5 + 0x14));
  for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
    cVar1 = *(char *)(iVar9 + iVar8 * 0x4c + 0x48);
    if ((((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) || ((byte)(cVar1 - 0x14U) < 2)) ||
       (cVar1 == '\x17')) {
      DAT_803109a8 = (float)dVar11;
      DAT_803109ac = (float)dVar13;
      DAT_803109b0 = (float)dVar15;
      dVar12 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                           (double)(float)(dVar11 * dVar11 +
                                                          (double)(float)(dVar13 * dVar13))));
      dVar14 = (double)(float)((double)lbl_803E00E8 * dVar12);
      if ((double)lbl_803E00EC != dVar12) {
        dVar11 = (double)(float)(dVar11 / dVar12);
        dVar13 = (double)(float)(dVar13 / dVar12);
        dVar15 = (double)(float)(dVar15 / dVar12);
      }
      dVar11 = (double)(float)(dVar11 * dVar14);
      dVar13 = (double)(float)(dVar13 * dVar14);
      dVar15 = (double)(float)(dVar15 * dVar14);
      local_13c = lbl_803E00EC;
      local_138 = lbl_803E00EC;
      local_134 = lbl_803E00EC;
      local_140 = lbl_803E00F0;
      local_144 = 0;
      local_146 = 0;
      local_148 = 0;
      bVar4 = true;
      iVar8 = iVar7;
    }
  }
  if (bVar4) {
    for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
      cVar1 = *(char *)(iVar9 + 0x48);
      if (((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) ||
         (((byte)(cVar1 - 0x14U) < 2 || (cVar1 == '\x17')))) {
        fVar2 = *(float *)(param_5 + 0xc);
        uStack_12c = (int)*(short *)(iVar9 + 0x10) ^ 0x80000000;
        local_130 = 0x43300000;
        dVar23 = (double)(fVar2 + (float)((f64)(f32)(s32)uStack_12c - dVar10));
        uStack_124 = (int)*(short *)(iVar9 + 0x16) ^ 0x80000000;
        local_128 = 0x43300000;
        dVar22 = (double)(f32)(s32)uStack_124;
        fVar3 = *(float *)(param_5 + 0x14);
        uStack_11c = (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000;
        local_120 = 0x43300000;
        dVar21 = (double)(fVar3 + (float)((f64)(f32)(s32)uStack_11c - param_2));
        uStack_114 = (int)*(short *)(iVar9 + 0x12) ^ 0x80000000;
        local_118 = 0x43300000;
        dVar20 = (double)(fVar2 + (float)((f64)(f32)(s32)uStack_114 - dVar10));
        uStack_10c = (int)*(short *)(iVar9 + 0x18) ^ 0x80000000;
        local_110 = 0x43300000;
        dVar19 = (double)(f32)(s32)uStack_10c;
        uStack_104 = (int)*(short *)(iVar9 + 0x1e) ^ 0x80000000;
        local_108 = 0x43300000;
        dVar18 = (double)(fVar3 + (float)((f64)(f32)(s32)uStack_104 - param_2));
        uStack_fc = (int)*(short *)(iVar9 + 0x14) ^ 0x80000000;
        local_100 = 0x43300000;
        dVar17 = (double)(fVar2 + (float)((f64)(f32)(s32)uStack_fc - dVar10));
        uStack_f4 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar16 = (double)(f32)(s32)uStack_f4;
        uStack_ec = (int)*(short *)(iVar9 + 0x20) ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar14 = (double)(fVar3 + (float)((f64)(f32)(s32)uStack_ec - param_2));
        uStack_e4 = randomGetRange(1,1000);
        dVar12 = (double)((f32)(s32)uStack_e4 /
                         lbl_803E00F4);
        uStack_dc = randomGetRange(1,1000);
        dVar11 = FUN_80293900((double)((float)((double)CONCAT44(0x43300000,uStack_dc) -
                                              DOUBLE_803e0100) / lbl_803E00F4));
        dVar13 = (double)(float)((double)lbl_803E00F0 - dVar11);
        dVar15 = (double)(float)((double)(float)((double)lbl_803E00F0 - dVar12) * dVar11);
        dVar11 = (double)(float)(dVar12 * dVar11);
        local_13c = (float)(dVar11 * dVar17 +
                           (double)(float)(dVar13 * dVar23 + (double)(float)(dVar15 * dVar20)));
        local_134 = (float)(dVar11 * dVar14 +
                           (double)(float)(dVar13 * dVar21 + (double)(float)(dVar15 * dVar18)));
        local_138 = (float)(dVar11 * dVar16 +
                           (double)(float)(dVar13 * dVar22 + (double)(float)(dVar15 * dVar19))) +
                    lbl_803E00F8;
        cVar1 = *(char *)(iVar9 + 0x48);
        if ((cVar1 == '\x12') || (cVar1 == '\x10')) {
          uVar6 = randomGetRange(0,0x1e);
          if (uVar6 == 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x72,&local_148,0x200001,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x11') {
          uVar6 = randomGetRange(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x14') {
          uVar6 = randomGetRange(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x15') {
          uVar6 = randomGetRange(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x17') {
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
        }
      }
      iVar9 = iVar9 + 0x4c;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1de4
 * EN v1.0 Address: 0x800A1DE4
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x800A43A8
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a1de4(int param_1)
{
  undefined4 uVar1;
  int local_b8;
  undefined4 local_b4;
  uint *local_b0;
  float local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  uint auStack_9c [6];
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_ac = DAT_802c28e0;
  local_a8 = DAT_802c28e4;
  local_a4 = DAT_802c28e8;
  local_a0 = DAT_802c28ec;
  local_b4 = 0;
  if (DAT_803ddf18 != '\0') {
    local_6c = lbl_803E00EC;
    local_50 = lbl_803E00EC;
    switch(DAT_803ddf18) {
    case '\v':
      local_6c = lbl_803E0108;
      local_50 = lbl_803E0108;
      break;
    case '\f':
      local_6c = lbl_803E010C;
      local_50 = lbl_803E0110;
      break;
    case '\r':
      local_6c = lbl_803E0114;
      local_50 = lbl_803E0108;
      break;
    case '\x0e':
      local_6c = lbl_803E0114;
      local_50 = lbl_803E0108;
      break;
    case '\x0f':
      local_6c = lbl_803E0118;
      local_50 = lbl_803E0110;
      break;
    case '\x10':
      local_6c = lbl_803E011C;
      local_50 = lbl_803E0120;
      break;
    case '\x11':
      local_6c = lbl_803E0124;
      local_50 = lbl_803E0124;
    }
    local_84 = *(float *)(param_1 + 0xc) - local_6c;
    local_80 = *(float *)(param_1 + 0x10) + local_50;
    local_7c = *(float *)(param_1 + 0x14) - local_6c;
    local_70 = *(float *)(param_1 + 0x14) + local_6c;
    local_6c = *(float *)(param_1 + 0xc) + local_6c;
    local_50 = *(float *)(param_1 + 0x10) - local_50;
    local_78 = local_84;
    local_74 = local_80;
    local_68 = local_80;
    local_64 = local_70;
    local_60 = local_6c;
    local_5c = local_80;
    local_58 = local_7c;
    local_54 = local_84;
    local_4c = local_7c;
    local_48 = local_84;
    local_44 = local_50;
    local_40 = local_70;
    local_3c = local_6c;
    local_38 = local_50;
    local_34 = local_70;
    local_30 = local_6c;
    local_2c = local_50;
    local_28 = local_7c;
    trackDolphin_buildSweptBounds(auStack_9c,&local_84,&local_54,&local_ac,4);
    FUN_80063a74(param_1,auStack_9c,0x84,'\0');
    trackDolphin_getCurrentIntersectionList(&local_b8,&local_b4);
    uVar1 = local_b4;
    trackDolphin_getCurrentTrackPoint(&local_b0);
    uStack_1c = *local_b0 ^ 0x80000000;
    local_20 = 0x43300000;
    uStack_14 = local_b0[2] ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_800a19bc((double)(*(float *)(param_1 + 0xc) -
                         (f32)(s32)uStack_1c),
                 (double)(*(float *)(param_1 + 0x14) -
                         (f32)(s32)uStack_14),uVar1,
                 local_b8,param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1f80
 * EN v1.0 Address: 0x800A1F80
 * EN v1.0 Size: 1696b
 * EN v1.1 Address: 0x800A45C8
 * EN v1.1 Size: 1768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a1f80(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined *puVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  int iVar13;
  short sVar14;
  short sVar15;
  int *piVar16;
  double in_f26;
  double in_f27;
  double dVar17;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar23;
  ushort local_e0 [4];
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  int local_b0;
  int *local_ac;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar23 = FUN_80286818();
  uVar6 = (undefined4)((ulonglong)uVar23 >> 0x20);
  uVar7 = GameBit_Get(0x468);
  if (uVar7 != 0) {
    GameBit_Set(0x468,0);
    DAT_803ddf3c = 0xf;
    FUN_80006824(param_3,0x281);
  }
  piVar16 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (6 < DAT_803ddf34) {
    DAT_803ddf34 = 0;
  }
  if ((int)(*(byte *)(*piVar16 + 0xf3) - 1) < DAT_803ddf30) {
    DAT_803ddf30 = 0;
  }
  DAT_803ddf38 = DAT_803ddf38 + (uint)DAT_803dc070;
  if (0x1f < DAT_803ddf38) {
    DAT_803ddf38 = DAT_803ddf38 + -0x1f;
  }
  lbl_803DDF2C = lbl_803DC3F8 * lbl_803DC074 + lbl_803DDF2C;
  if (lbl_803DDF2C <= lbl_803E012C) {
    if (lbl_803DDF2C < lbl_803E0134) {
      lbl_803DC3F8 = lbl_803DC3F8 * lbl_803E0130;
      lbl_803DDF2C = lbl_803E0134;
      FUN_80006824(param_3,0x282);
    }
  }
  else {
    lbl_803DC3F8 = lbl_803DC3F8 * lbl_803E0130;
    lbl_803DDF2C = lbl_803E012C;
    FUN_80006824(param_3,0x282);
  }
  local_b0 = 0;
  piVar5 = &DAT_8039cf20;
  local_ac = &DAT_8039cf20;
  do {
    if (local_b0 != 5) {
      DAT_803ddf34 = (short)local_b0;
      iVar13 = 0;
      puVar8 = &DAT_80310fac;
      dVar20 = (double)lbl_803E0128;
      dVar21 = (double)lbl_803E0138;
      dVar22 = (double)lbl_803E013C;
      for (sVar15 = 0; sVar15 < 5; sVar15 = sVar15 + 1) {
        local_d4 = (float)dVar20;
        local_d0 = (float)dVar20;
        local_cc = (float)dVar20;
        local_d8 = (float)dVar21;
        local_e0[2] = 0;
        local_e0[1] = 0;
        local_e0[0] = 0;
        uVar7 = (uint)(byte)(&DAT_80310fac)[DAT_803ddf34 * 5 + (int)sVar15];
        pfVar12 = (float *)(piVar16[(*(ushort *)(piVar16 + 6) & 1) + 3] + uVar7 * 0x100);
        dVar17 = (double)(pfVar12[0xd] - *(float *)(param_3 + 0x10));
        dVar19 = (double)(float)((double)((pfVar12[0xc] + lbl_803DDA58) -
                                         *(float *)(param_3 + 0xc)) * dVar22);
        if ((uVar7 == 0x1d) || (uVar7 == 0x1d)) {
          fVar2 = lbl_803E013C * (float)((double)lbl_803E0140 + dVar17);
        }
        else {
          fVar2 = (float)(dVar17 * dVar22);
        }
        dVar18 = (double)fVar2;
        dVar17 = (double)(float)((double)((pfVar12[0xe] + lbl_803DDA5C) -
                                         *(float *)(param_3 + 0x14)) * dVar22);
        FUN_80017778((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,&local_d0,
                     &local_cc);
        pfVar11 = (float *)&DAT_80310a88;
        pfVar9 = (float *)&DAT_80310b18;
        pfVar10 = (float *)&DAT_803109f8;
        for (sVar14 = 0; sVar14 < 4; sVar14 = sVar14 + 1) {
          uVar7 = (uint)(byte)puVar8[DAT_803ddf34 * 5];
          cVar3 = (&DAT_80310f88)[uVar7];
          if (cVar3 == '\0') {
            local_d4 = *pfVar11 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar11[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar11[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x01') {
            local_d4 = *pfVar10 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar10[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar10[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x02') {
            local_d4 = *pfVar9 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar9[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar9[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          FUN_80017778((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,
                       &local_d0,&local_cc);
          local_d4 = local_d4 + lbl_803DDA58;
          local_cc = local_cc + lbl_803DDA5C;
          iVar1 = (int)(dVar19 + (double)(local_d4 - *(float *)(param_3 + 0xc)));
          local_c8 = (longlong)iVar1;
          iVar4 = (sVar14 + iVar13) * 0x10;
          *(short *)(*piVar5 + iVar4) = (short)iVar1;
          iVar1 = (int)(dVar18 + (double)(local_d0 - *(float *)(param_3 + 0x10)));
          local_c0 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 2) = (short)iVar1;
          iVar1 = (int)(dVar17 + (double)(local_cc - *(float *)(param_3 + 0x14)));
          local_b8 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 4) = (short)iVar1;
          *(undefined *)(*piVar5 + iVar4 + 0xf) = 0x9b;
          *(short *)(*piVar5 + iVar4 + 10) =
               (&DAT_80310bb2)[(sVar14 + iVar13) * 8] - (short)(DAT_803ddf38 << 2);
          pfVar11 = pfVar11 + 3;
          pfVar10 = pfVar10 + 3;
          pfVar9 = pfVar9 + 3;
        }
        iVar13 = iVar13 + 4;
        puVar8 = puVar8 + 1;
      }
    }
    piVar5 = piVar5 + 1;
    local_b0 = local_b0 + 1;
  } while (local_b0 < 7);
  local_d4 = *(float *)(param_3 + 0xc);
  local_d0 = *(float *)(param_3 + 0x10);
  local_cc = *(float *)(param_3 + 0x14);
  local_d8 = lbl_803E0144;
  FUN_8005d370(uVar6,0xff,0xff,0xff,0xff);
  if (DAT_803ddf3c == 0) {
    FUN_8005360c(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    uVar7 = randomGetRange(0,1);
    if (uVar7 == 0) {
      FUN_8005360c(uVar6,DAT_803ddf28,(undefined4 *)0x0,0,0);
    }
    else {
      FUN_8005360c(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
    }
    DAT_803ddf3c = DAT_803ddf3c - (ushort)DAT_803dc070;
    if (DAT_803ddf3c < 0) {
      DAT_803ddf3c = 0;
    }
  }
  FUN_80006930((double)lbl_803E0138,uVar6,(int)uVar23,local_e0,(float *)0x0);
  FUN_80259288(0);
  FUN_8005d340(uVar6,0xff,0xff,0xff,0xff);
  FUN_80071f90();
  FUN_80071e78();
  FUN_800719dc();
  FUN_80071f8c();
  FUN_800712d4();
  iVar13 = 0;
  do {
    fn_8005D108(*local_ac,-0x7fcef318,0x20);
    local_ac = local_ac + 1;
    iVar13 = iVar13 + 1;
  } while (iVar13 < 7);
  DAT_803ddf20 = 1 - DAT_803ddf20;
  FUN_80286864();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2620
 * EN v1.0 Address: 0x800A2620
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x800A4CB0
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2620(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,
                 undefined2 *param_5)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  uVar6 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  piVar2 = (int *)FUN_80017a54(iVar1);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*piVar2 + 0xf3); iVar5 = iVar5 + 1) {
    uVar3 = randomGetRange(1,100);
    if ((int)uVar3 <= (int)(param_4 & 0xff)) {
      local_2c = lbl_803E0128;
      local_28 = lbl_803E0128;
      local_24 = lbl_803E0128;
      local_30 = lbl_803E0138;
      local_34 = 0;
      local_36 = 0;
      local_38 = 0;
      pfVar4 = (float *)FUN_80017970(piVar2,iVar5);
      FUN_80247bf8(pfVar4,&local_2c,&local_2c);
      local_28 = local_28 - *(float *)(iVar1 + 0x1c);
      local_2c = (local_2c - *(float *)(iVar1 + 0x18)) + lbl_803DDA58;
      local_24 = (local_24 - *(float *)(iVar1 + 0x20)) + lbl_803DDA5C;
      if (param_5 == (undefined2 *)0x0) {
        local_30 = lbl_803E0138;
        local_38 = 0;
        local_34 = 0;
        local_36 = 0;
        local_32 = 0;
      }
      else {
        local_30 = *(float *)(param_5 + 4);
        local_38 = *param_5;
        local_34 = param_5[2];
        local_36 = param_5[1];
        local_32 = param_5[3];
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar1,(int)uVar6,&local_38,2,0xffffffff,param_3);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2730
 * EN v1.0 Address: 0x800A2730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A4E3C
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2730(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2734
 * EN v1.0 Address: 0x800A2734
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x800A4EC4
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2734(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined2 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  DAT_803ddf24 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x16b,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803ddf28 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x201,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_8039cf20 = FUN_80017830(0x140,0x15);
  DAT_8039cf24 = FUN_80017830(0x140,0x15);
  DAT_8039cf28 = FUN_80017830(0x140,0x15);
  DAT_8039cf2c = FUN_80017830(0x140,0x15);
  DAT_8039cf30 = FUN_80017830(0x140,0x15);
  DAT_8039cf34 = FUN_80017830(0x140,0x15);
  DAT_8039cf38 = FUN_80017830(0x140,0x15);
  piVar3 = &DAT_8039cf20;
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar5 = 0x14;
    puVar1 = &DAT_80310ba8;
    do {
      *(undefined2 *)(*piVar3 + iVar2) = *puVar1;
      *(undefined2 *)(*piVar3 + iVar2 + 2) = puVar1[1];
      *(undefined2 *)(*piVar3 + iVar2 + 4) = puVar1[2];
      *(undefined2 *)(*piVar3 + iVar2 + 8) = puVar1[4];
      *(undefined2 *)(*piVar3 + iVar2 + 10) = puVar1[5];
      *(undefined *)(*piVar3 + iVar2 + 0xc) = *(undefined *)(puVar1 + 6);
      *(undefined *)(*piVar3 + iVar2 + 0xd) = *(undefined *)((int)puVar1 + 0xd);
      *(undefined *)(*piVar3 + iVar2 + 0xe) = *(undefined *)(puVar1 + 7);
      *(undefined *)(*piVar3 + iVar2 + 0xf) = 0xff;
      puVar1 = puVar1 + 8;
      iVar2 = iVar2 + 0x10;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 7);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2994
 * EN v1.0 Address: 0x800A2994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800A5080
 * EN v1.1 Size: 40540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2994(undefined4 param_1,undefined4 param_2,short *param_3,uint param_4,
                 undefined4 param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2998
 * EN v1.0 Address: 0x800A2998
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800AEEDC
 * EN v1.1 Size: 1996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2998(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a299c
 * EN v1.0 Address: 0x800A299C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800AF6A8
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a299c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a29a0
 * EN v1.0 Address: 0x800A29A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800AF914
 * EN v1.1 Size: 14816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a29a0(undefined4 param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                 uint param_4,undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a29a4
 * EN v1.0 Address: 0x800A29A4
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800B32F4
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a29a4(void)
{
  double dVar1;
  
  lbl_803DC418 = lbl_803DC418 + lbl_803E03A0 * lbl_803DC074;
  if (lbl_803E03A8 < lbl_803DC418) {
    lbl_803DC418 = lbl_803E03A4;
  }
  lbl_803DC41C = lbl_803DC41C + lbl_803E03A0 * lbl_803DC074;
  if (lbl_803E03A8 < lbl_803DC41C) {
    lbl_803DC41C = lbl_803E03B0;
  }
  DAT_803ddfa8 = DAT_803ddfa8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfa8) {
    DAT_803ddfa8 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFB4 = (float)dVar1;
  DAT_803ddfac = DAT_803ddfac + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfac) {
    DAT_803ddfac = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFB0 = (float)dVar1;
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
 * Function: FUN_800a2aa0
 * EN v1.0 Address: 0x800A2AA0
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800B7050
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2aa0(void)
{
  double dVar1;
  
  lbl_803DC428 = lbl_803DC428 + lbl_803E04F0 * lbl_803DC074;
  if (lbl_803E04F8 < lbl_803DC428) {
    lbl_803DC428 = lbl_803E04F4;
  }
  lbl_803DC42C = lbl_803DC42C + lbl_803E04F0 * lbl_803DC074;
  if (lbl_803E04F8 < lbl_803DC42C) {
    lbl_803DC42C = lbl_803E0500;
  }
  DAT_803ddfb8 = DAT_803ddfb8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfb8) {
    DAT_803ddfb8 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFC4 = (float)dVar1;
  DAT_803ddfbc = DAT_803ddfbc + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfbc) {
    DAT_803ddfbc = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFC0 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2b94
 * EN v1.0 Address: 0x800A2B94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800B7184
 * EN v1.1 Size: 7812b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2b94(undefined4 param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                 uint param_4,undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2b98
 * EN v1.0 Address: 0x800A2B98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800B9008
 * EN v1.1 Size: 13204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2b98(undefined4 param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                 uint param_4,undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2b9c
 * EN v1.0 Address: 0x800A2B9C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800BC39C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2b9c(void)
{
  double dVar1;
  
  lbl_803DC438 = lbl_803DC438 + lbl_803E0708 * lbl_803DC074;
  if (lbl_803E0710 < lbl_803DC438) {
    lbl_803DC438 = lbl_803E070C;
  }
  lbl_803DC43C = lbl_803DC43C + lbl_803E0708 * lbl_803DC074;
  if (lbl_803E0710 < lbl_803DC43C) {
    lbl_803DC43C = lbl_803E0718;
  }
  DAT_803ddfd0 = DAT_803ddfd0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfd0) {
    DAT_803ddfd0 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFDC = (float)dVar1;
  DAT_803ddfd4 = DAT_803ddfd4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfd4) {
    DAT_803ddfd4 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFD8 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2c90
 * EN v1.0 Address: 0x800A2C90
 * EN v1.0 Size: 1448b
 * EN v1.1 Address: 0x800BC4D0
 * EN v1.1 Size: 4292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2c90(undefined4 param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                 uint param_4,undefined param_5)
{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar4;
  ushort local_d8 [4];
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  int local_c0 [3];
  ushort local_b4;
  ushort local_b2;
  ushort local_b0;
  undefined4 local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined2 local_80;
  undefined2 local_7e;
  uint local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  undefined local_60;
  undefined local_5f;
  undefined local_5e;
  undefined8 local_58;
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
  undefined8 local_28;
  
  uVar4 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  lbl_803DC440 = lbl_803DC440 + lbl_803E0860;
  if (lbl_803E0868 < lbl_803DC440) {
    lbl_803DC440 = lbl_803E0864;
  }
  lbl_803DC444 = lbl_803DC444 + lbl_803E086C;
  if (lbl_803E0868 < lbl_803DC444) {
    lbl_803DC444 = lbl_803E0870;
  }
  if (iVar2 != 0) {
    if ((param_4 & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0) {
      if (param_3 == (ExpgfxAttachedSourceState *)0x0) goto LAB_800bd57c;
      local_a8 = param_3->velocityX;
      local_a4 = param_3->velocityY;
      local_a0 = param_3->velocityZ;
      local_ac = param_3->sourcePosXBits;
      local_b0 = param_3->sourceVecZ;
      local_b2 = param_3->sourceVecY;
      local_b4 = param_3->sourceVecX;
      local_5e = param_5;
    }
    local_7c = 0;
    local_78 = 0;
    local_62 = (undefined)uVar4;
    local_90 = lbl_803E0874;
    local_8c = lbl_803E0874;
    local_88 = lbl_803E0874;
    local_9c = lbl_803E0874;
    local_98 = lbl_803E0874;
    local_94 = lbl_803E0874;
    local_84 = lbl_803E0874;
    local_c0[2] = 0;
    local_c0[1] = 0xffffffff;
    local_60 = 0xff;
    local_5f = 0;
    local_7e = 0;
    local_68 = 0xffff;
    local_66 = 0xffff;
    local_64 = 0xffff;
    local_74 = 0xffff;
    local_70 = 0xffff;
    local_6c = 0xffff;
    local_80 = 0;
    local_c0[0] = iVar2;
    switch((int)uVar4) {
    case 200:
      uVar3 = randomGetRange(0xfffffffa,6);
      local_90 = (f32)(s32)(uVar3);
      uStack_4c = randomGetRange(0xfffffffa,6);
      local_8c = (f32)(s32)uStack_4c;
      uStack_44 = randomGetRange(0xfffffffa,6);
      local_88 = (f32)(s32)uStack_44;
      uStack_3c = randomGetRange(4,8);
      local_84 = lbl_803E0878 * (f32)(s32)uStack_3c;
      local_c0[2] = 0x24;
      local_60 = 0x41;
      local_7c = 0x100111;
      local_7e = 0xc10;
      break;
    default:
      goto LAB_800bd57c;
    case 0xca:
      if (param_3 == (ExpgfxAttachedSourceState *)0x0) goto LAB_800bd57c;
      uStack_3c = randomGetRange(0xffffffec,0x14);
      local_9c = lbl_803E087C * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(10,0x14);
      local_98 = lbl_803E087C * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0x14,0x1e);
      local_94 = lbl_803E0880 * (f32)(s32)uStack_4c;
      local_cc = lbl_803E0874;
      local_c8 = lbl_803E0874;
      local_c4 = lbl_803E0874;
      local_d0 = lbl_803E0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = param_3->sourceVecX;
      FUN_80017748(local_d8,&local_9c);
      uVar3 = randomGetRange(4,8);
      local_84 = lbl_803E0884 * (f32)(s32)(uVar3);
      local_c0[2] = 0x46;
      local_60 = 100;
      local_5f = 0;
      local_7c = 0x180108;
      local_78 = 0x5000000;
      uVar1 = param_3->sourceVecZ;
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcb:
      if (param_3 == (ExpgfxAttachedSourceState *)0x0) goto LAB_800bd57c;
      uStack_3c = randomGetRange(0xffffffec,0x14);
      local_9c = lbl_803E0888 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(10,0x14);
      local_98 = lbl_803E088C * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0x14,0x1e);
      local_94 = lbl_803E0888 * (f32)(s32)uStack_4c;
      local_cc = lbl_803E0874;
      local_c8 = lbl_803E0874;
      local_c4 = lbl_803E0874;
      local_d0 = lbl_803E0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = param_3->sourceVecX;
      FUN_80017748(local_d8,&local_9c);
      uVar3 = randomGetRange(4,8);
      local_84 = lbl_803E0890 * (f32)(s32)(uVar3);
      local_c0[2] = 0x46;
      local_60 = 0xff;
      local_5f = 0;
      local_7c = 0x1080100;
      local_78 = 0x5000000;
      uVar1 = param_3->sourceVecZ;
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcc:
      uStack_3c = randomGetRange(0xffffffd8,0x28);
      local_90 = (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(1,2);
      local_8c = lbl_803E0894 * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0xffffffd8,0x28);
      local_88 = (f32)(s32)uStack_4c;
      uVar3 = randomGetRange(0xfffffff6,10);
      local_9c = lbl_803E0898 * (f32)(s32)(uVar3);
      uStack_34 = randomGetRange(0xfffffff6,10);
      local_94 = lbl_803E0898 * (f32)(s32)uStack_34;
      uStack_2c = randomGetRange(4,8);
      local_84 = lbl_803E089C * (f32)(s32)uStack_2c;
      local_c0[2] = 0xfa;
      local_60 = 0xff;
      local_7c = 0x80108;
      local_7e = 0x5c;
      break;
    case 0xcd:
      uStack_2c = randomGetRange(0,0xfa);
      local_90 = (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xfffffffb,5);
      local_8c = lbl_803E08A0 + local_90 / lbl_803E08A0 +
                 (f32)(s32)uStack_34;
      local_88 = lbl_803E08A4 * local_90;
      uStack_3c = randomGetRange(0x28,0x50);
      local_84 = lbl_803E08A8 * (f32)(s32)uStack_3c;
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xce:
      uStack_2c = randomGetRange(0xfffffff6,10);
      local_90 = lbl_803E08AC + (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xfffffff8,8);
      local_8c = lbl_803E08B0 + (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0xfffffff6,10);
      local_88 = lbl_803E08B4 + (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(0,10);
      local_98 = lbl_803E08B8 * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0x28,0x50);
      local_84 = lbl_803E086C * (f32)(s32)uStack_4c;
      uVar3 = randomGetRange(0,0x14);
      local_c0[2] = (int)(lbl_803E08BC + (f32)(s32)(uVar3));
      local_28 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xcf:
      uVar3 = randomGetRange(0,0xfa);
      local_90 = -(f32)(s32)(uVar3);
      uStack_2c = randomGetRange(0xfffffffb,5);
      local_8c = lbl_803E08A0 + local_90 / lbl_803E08A0 +
                 (f32)(s32)uStack_2c;
      local_88 = -local_90;
      uStack_34 = randomGetRange(0x28,0x50);
      local_84 = lbl_803E08A8 * (f32)(s32)uStack_34;
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xd0:
      uVar3 = randomGetRange(0xfffffff6,10);
      local_90 = lbl_803E08C0 + (f32)(s32)(uVar3);
      uStack_2c = randomGetRange(0xfffffff8,8);
      local_8c = lbl_803E08B0 + (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xfffffff6,10);
      local_88 = lbl_803E08C4 + (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0,10);
      local_98 = lbl_803E08B8 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(0x28,0x50);
      local_84 = lbl_803E086C * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0,0x14);
      local_c0[2] = (int)(lbl_803E08BC +
                         (f32)(s32)uStack_4c);
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd1:
      uVar3 = randomGetRange(0x46,0x50);
      local_84 = lbl_803E086C * (f32)(s32)(uVar3);
      uVar3 = randomGetRange(0,0xf);
      local_c0[2] = uVar3 + 0x14;
      local_5f = 0;
      local_60 = 0xff;
      local_7c = 0x180210;
      local_7e = 0x159;
      break;
    case 0xd2:
      local_84 = lbl_803E087C;
      local_c0[2] = 0x50;
      local_7c = 0x400000;
      local_7e = 0x159;
      break;
    case 0xd3:
      uVar3 = randomGetRange(0,0xfa);
      local_90 = -(f32)(s32)(uVar3);
      uStack_2c = randomGetRange(0xfffffffb,5);
      local_8c = lbl_803E08C8 + (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xfffffffb,5);
      local_88 = (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0xfffffffb,5);
      local_94 = lbl_803E0864 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(0x28,0x50);
      local_84 = lbl_803E08CC * (f32)(s32)uStack_44;
      local_c0[2] = 0xa0;
      local_60 = 0x7d;
      local_7c = 0x180108;
      local_7e = 0x5c;
      break;
    case 0xd4:
      uVar3 = randomGetRange(0xfffffff6,0x14);
      local_90 = (f32)(s32)(uVar3);
      uStack_2c = randomGetRange(0,0x1c);
      local_8c = (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xffffffec,0x14);
      local_88 = (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0,10);
      local_98 = lbl_803E08D0 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(0x28,0x50);
      local_84 = lbl_803E08D4 * (f32)(s32)uStack_44;
      uStack_4c = randomGetRange(0,0x14);
      local_c0[2] = (int)(lbl_803E08D8 +
                         (f32)(s32)uStack_4c);
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd5:
      local_84 = lbl_803E08DC;
      local_c0[1] = 0xd6;
      local_c0[2] = 100;
      local_60 = 0xff;
      local_7c = 0x80000;
      local_7e = 0x159;
      break;
    case 0xd6:
      local_84 = lbl_803E08DC;
      local_c0[2] = 0x28;
      local_60 = 0xff;
      local_7c = 0x80100;
      local_7e = 0x159;
      break;
    case 0xd7:
      uVar3 = randomGetRange(0xffffff74,0x8c);
      local_90 = lbl_803E08E0 * (f32)(s32)(uVar3);
      uStack_2c = randomGetRange(0xffffffce,10);
      local_8c = lbl_803E08E0 * (f32)(s32)uStack_2c;
      uStack_34 = randomGetRange(0xffffff74,0x8c);
      local_88 = lbl_803E08E0 * (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(0xf,0x23);
      local_98 = lbl_803E08E4 * (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(1,10);
      local_84 = lbl_803E08E8 * (f32)(s32)uStack_44;
      local_c0[2] = 0x8c;
      local_60 = 0xff;
      local_7c = 0x80180100;
      local_7e = 0x5f;
    }
    local_7c = local_7c | param_4;
    if (((local_7c & 1) != 0) && ((param_4 & 2) != 0)) {
      local_7c = local_7c ^ 2;
    }
    if ((local_7c & 1) != 0) {
      if ((param_4 & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) == 0) {
        if (local_c0[0] != 0) {
          local_90 = local_90 + *(float *)(local_c0[0] + 0x18);
          local_8c = local_8c + *(float *)(local_c0[0] + 0x1c);
          local_88 = local_88 + *(float *)(local_c0[0] + 0x20);
        }
      }
      else {
        local_90 = local_90 + local_a8;
        local_8c = local_8c + local_a4;
        local_88 = local_88 + local_a0;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(local_c0,0xffffffff,(int)uVar4,0);
  }
LAB_800bd57c:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3238
 * EN v1.0 Address: 0x800A3238
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800BD594
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3238(void)
{
  double dVar1;
  
  lbl_803DC448 = lbl_803DC448 + lbl_803E0860 * lbl_803DC074;
  if (lbl_803E0868 < lbl_803DC448) {
    lbl_803DC448 = lbl_803E0864;
  }
  lbl_803DC44C = lbl_803DC44C + lbl_803E0860 * lbl_803DC074;
  if (lbl_803E0868 < lbl_803DC44C) {
    lbl_803DC44C = lbl_803E0870;
  }
  DAT_803ddfe0 = DAT_803ddfe0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfe0) {
    DAT_803ddfe0 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFEC = (float)dVar1;
  DAT_803ddfe4 = DAT_803ddfe4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfe4) {
    DAT_803ddfe4 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFE8 = (float)dVar1;
  return;
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
      local_a0 = *(float *)&param_3->sourcePosYBits;
      local_9c = *(float *)&param_3->sourcePosZBits;
      local_98 = *(float *)&param_3->sourcePosWBits;
      local_a4 = param_3->sourcePosXBits;
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
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_b8,0xffffffff,param_2,0);
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800a363c
 * EN v1.0 Address: 0x800A363C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800BE18C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a363c(void)
{
  double dVar1;
  
  lbl_803DC458 = lbl_803DC458 + lbl_803E0900 * lbl_803DC074;
  if (lbl_803E0908 < lbl_803DC458) {
    lbl_803DC458 = lbl_803E0904;
  }
  lbl_803DC45C = lbl_803DC45C + lbl_803E0900 * lbl_803DC074;
  if (lbl_803E0908 < lbl_803DC45C) {
    lbl_803DC45C = lbl_803E0910;
  }
  DAT_803ddff0 = DAT_803ddff0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddff0) {
    DAT_803ddff0 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFFC = (float)dVar1;
  DAT_803ddff4 = DAT_803ddff4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddff4) {
    DAT_803ddff4 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DDFF8 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3730
 * EN v1.0 Address: 0x800A3730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800BE2C0
 * EN v1.1 Size: 6160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3730(undefined4 param_1,undefined4 param_2,ExpgfxAttachedSourceState *param_3,
                 uint param_4,undefined param_5,int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a3734
 * EN v1.0 Address: 0x800A3734
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800BFAD0
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3734(void)
{
  double dVar1;
  
  lbl_803DC468 = lbl_803DC468 + lbl_803E0958 * lbl_803DC074;
  if (lbl_803E0960 < lbl_803DC468) {
    lbl_803DC468 = lbl_803E095C;
  }
  lbl_803DC46C = lbl_803DC46C + lbl_803E0958 * lbl_803DC074;
  if (lbl_803E0960 < lbl_803DC46C) {
    lbl_803DC46C = lbl_803E0968;
  }
  DAT_803de000 = DAT_803de000 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de000) {
    DAT_803de000 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE00C = (float)dVar1;
  DAT_803de004 = DAT_803de004 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de004) {
    DAT_803de004 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE008 = (float)dVar1;
  return;
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
 * Function: FUN_800a3830
 * EN v1.0 Address: 0x800A3830
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800C1324
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3830(void)
{
  double dVar1;
  
  lbl_803DC478 = lbl_803DC478 + lbl_803E0A18 * lbl_803DC074;
  if (lbl_803E0A20 < lbl_803DC478) {
    lbl_803DC478 = lbl_803E0A1C;
  }
  lbl_803DC47C = lbl_803DC47C + lbl_803E0A18 * lbl_803DC074;
  if (lbl_803E0A20 < lbl_803DC47C) {
    lbl_803DC47C = lbl_803E0A28;
  }
  DAT_803de010 = DAT_803de010 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de010) {
    DAT_803de010 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE01C = (float)dVar1;
  DAT_803de014 = DAT_803de014 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de014) {
    DAT_803de014 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE018 = (float)dVar1;
  return;
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

/*
 * --INFO--
 *
 * Function: FUN_800a392c
 * EN v1.0 Address: 0x800A392C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800C2A74
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a392c(void)
{
  double dVar1;
  
  lbl_803DC488 = lbl_803DC488 + lbl_803E0AA8 * lbl_803DC074;
  if (lbl_803E0AB0 < lbl_803DC488) {
    lbl_803DC488 = lbl_803E0AAC;
  }
  lbl_803DC48C = lbl_803DC48C + lbl_803E0AA8 * lbl_803DC074;
  if (lbl_803E0AB0 < lbl_803DC48C) {
    lbl_803DC48C = lbl_803E0AB8;
  }
  DAT_803de020 = DAT_803de020 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de020) {
    DAT_803de020 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE02C = (float)dVar1;
  DAT_803de024 = DAT_803de024 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de024) {
    DAT_803de024 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE028 = (float)dVar1;
  return;
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
#pragma scheduling off
#pragma peephole off
s16 dll_0B_func18(void) { return lbl_803DD288; }
void dll_0B_func17(u32 flags) { *(u32 *)(lbl_8039BE98 + 0x54) |= flags; }
void dll_0B_func15(void *params) { memcpy(lbl_8039BE98 + 0x46, params, 0xe); }
void dll_0B_func14(s16 value)
{
  u8 *state = lbl_8039BE98;
  state = state + lbl_803DD28A * 2;
  *(s16 *)(state + 0x46) = value;
}
void dll_0B_func13(s16 x) { lbl_803DD28A = x; }
void dll_0B_func12(void) { lbl_803DD28A++; }
void dll_0B_func11(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10)
{
  u32 sequenceIndex = (u8)lbl_803DD28A;
  lbl_803DD28C->sequenceIndex = sequenceIndex;
  lbl_803DD28C->param14 = param14;
  lbl_803DD28C->param10 = param10;
  lbl_803DD28C->modelOrResource = modelOrResource;
  lbl_803DD28C->posX = posX;
  lbl_803DD28C->posY = posY;
  lbl_803DD28C->posZ = posZ;
  lbl_803DD28C++;
}
void dll_0B_func10(void)
{
  ModgfxPendingSpawn *cursor = lbl_8039BEF8;
  lbl_803DD290 = cursor;
  lbl_803DD28C = cursor;
  lbl_803DD28A = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* OSReport(literal) wrapper. */
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
void projgfx_release_doUnsupported(void) { OSReport(sProjgfxReleaseDoNoLongerSupported); }
#pragma peephole reset
#pragma scheduling reset

/* OSReport-stub returns. */
extern void OSReport(const char *fmt, ...);

#define PROJGFX_UNSUPPORTED_FALSE_RETURN 0

#pragma scheduling off
#pragma peephole off
int projgfx_rayhit_doUnsupported(void) { OSReport(sProjgfxRayhitDoNoLongerSupported); return PROJGFX_UNSUPPORTED_FALSE_RETURN; }
int projgfx_setzscale_doUnsupported(void) { OSReport(sProjgfxSetzscaleDoNoLongerSupported); return PROJGFX_UNSUPPORTED_FALSE_RETURN; }
#pragma peephole reset
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
extern u8 lbl_803DD2C0;
extern void fn_800A1040(s16 a, int b);
extern u16 lbl_8039C2E0[];

void dll_0B_func0B(void) {
    lbl_803DD282 = lbl_803DD282 + 1;
}

#pragma scheduling off
#pragma peephole off
void dll_0B_func06(void) {
    fn_800A1040(0, 1);
}

void dll_0B_release(void) {
    fn_800A1040(0, 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void playerShadow_setMode(u8 v) {
    if (v == 0 || v >= 0xa) {
        gPlayerShadowMode = v;
    }
}
#pragma peephole reset

extern f32 lbl_803DF430;
extern f32 lbl_803DF434;
extern void *lbl_8039C2C0[];
extern void *lbl_803DD2A4;
extern void *lbl_803DD2A8;
extern void mm_free(void *p);
extern void textureFree(void *resource);
extern int *lbl_8039C1F8[];
extern void Obj_FreeObject(void *obj);
#pragma peephole off
#pragma scheduling off
void dll_0B_initialise(void)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        arr[i] = NULL;
    }
}

extern u8 lbl_8039BE98[];
void dll_0B_func0F(int p1, int p2, int p3, int p4, int p5)
{
    u8 *p = lbl_8039BE98;
    f32 fz;
    f32 fz2;
    memset(p, 0, 96);
    p[88] = p2;
    *(int*)(p + 4) = p1;
    *(s16*)(p + 68) = (u8)p2;
    fz = lbl_803DF430;
    *(f32*)(p + 44) = fz;
    *(f32*)(p + 48) = fz;
    *(f32*)(p + 52) = fz;
    *(f32*)(p + 32) = fz;
    *(f32*)(p + 36) = fz;
    *(f32*)(p + 40) = fz;
    fz2 = lbl_803DF434;
    *(f32*)(p + 56) = fz2;
    *(int*)(p + 64) = p4;
    *(int*)(p + 60) = p5;
    p[89] = p3;
    p[90] = 0;
    p[91] = 0;
}

void dll_0B_func0A(s16 *p)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        if (arr[i] != NULL && *p == *(s16*)((char*)arr[i] + 268)) {
            *(u8*)((char*)arr[i] + 314) = 1;
        }
    }
    *p = -1;
}

void dll_0B_func0C(void *p1, char p2)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        if (arr[i] != NULL && *(void**)((char*)arr[i] + 4) == p1) {
            *(char*)((char*)arr[i] + 315) = p2;
        }
    }
}

void dll_0B_func0D(void *p1)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        if (arr[i] != NULL && *(void**)((char*)arr[i] + 4) == p1) {
            *(u8*)((char*)arr[i] + 314) = 1;
        }
    }
}

void dll_0B_func07(void *p1)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        if (arr[i] == NULL) continue;
        if (*(void**)((char*)arr[i] + 4) != p1) continue;
        if (*(void**)arr[i] != NULL) {
            Obj_FreeObject(*(void**)arr[i]);
        }
        *(int*)((char*)arr[i] + 300) = 0;
        if (*(u8*)((char*)arr[i] + 319) == 0 && *(void**)((char*)arr[i] + 152) != NULL) {
            textureFree(*(void**)((char*)arr[i] + 152));
        }
        if (*(u8*)((char*)arr[i] + 319) == 0) {
            *(int*)((char*)arr[i] + 152) = 0;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}

#pragma dont_inline on
void fn_800A1040(s16 p1, int p2)
{
    int **arr = (int**)lbl_8039C1F8;
    int i;
    for (i = 0; i < 50; i++) {
        if (arr[i] == NULL) continue;
        if ((s16)p1 != *(s16*)((char*)arr[i] + 268) && p2 == 0) continue;
        if (*(void**)((char*)arr[i] + 160) != NULL) {
            mm_free(*(void**)((char*)arr[i] + 160));
        }
        if (*(void**)arr[i] != NULL) {
            Obj_FreeObject(*(void**)arr[i]);
        }
        *(int*)((char*)arr[i] + 300) = 0;
        if (*(u8*)((char*)arr[i] + 319) == 0 && *(void**)((char*)arr[i] + 152) != NULL) {
            textureFree(*(void**)((char*)arr[i] + 152));
        }
        if (*(u8*)((char*)arr[i] + 319) == 0) {
            *(int*)((char*)arr[i] + 152) = 0;
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
    p = lbl_8039C2C0;
    zero = NULL;
    do {
        if (*p != NULL) mm_free(*p);
        *p = zero;
        p++;
        i++;
    } while (i < 7);
    if (lbl_803DD2A4 != NULL) textureFree(lbl_803DD2A4);
    if (lbl_803DD2A8 != NULL) textureFree(lbl_803DD2A8);
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
    lbl_8039C2C0[0] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[1] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[2] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[3] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[4] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[5] = mmAlloc(0x140, 0x15, 0);
    lbl_8039C2C0[6] = mmAlloc(0x140, 0x15, 0);
    for (i = 0; i < 7; i++) {
        for (j = 0; j < 20; j++) {
            ((ParticleSlot*)lbl_8039C2C0[i])[j].a = lbl_8030FFE8[j].a;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].b = lbl_8030FFE8[j].b;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].c = lbl_8030FFE8[j].c;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].d = lbl_8030FFE8[j].d;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].e = lbl_8030FFE8[j].e;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].f = lbl_8030FFE8[j].f;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].g = lbl_8030FFE8[j].g;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].h = lbl_8030FFE8[j].h;
            ((ParticleSlot*)lbl_8039C2C0[i])[j].alpha = 0xff;
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

#pragma peephole off
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
    ModgfxVertexData *src = state->vertexBuffers[1 - (u32)state->activeVertexBufferIndex];
    ModgfxVertexData *dst = state->baseVertexData;
    f32 f1;
    f32 f0;
    int i;
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
    f1 = lbl_803DF434;
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
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void partfx_initialise(void) {
    u16 *p;
    int i;
    i = 0x14;
    p = lbl_8039C2E0 + 0x14;
    while ((s8)i != 0) {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    lbl_803DD2C0 = 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void fn_800A081C(int p1, int p2, int mode)
{
  extern void mathFn_80021ac8(void *, f32 *);
  extern f32 lbl_803DD284;
  extern f32 lbl_803DF430;
  extern f32 lbl_803DF434;

  if (mode == 1) {
    if (*(s16 *)((char *)p1 + (s32)*(s16 *)(p1 + 0xfc) * 2 + 0xee) == 0) {
      int flags = *(u32 *)(p1 + 0xa4);
      if ((flags & 0x4) != 0 || (flags & 0x80000) != 0) {
        s16 buf[6];
        f32 *fbuf = (f32 *)&buf[2];
        s16 v = *(s16 *)*(int *)(p1 + 0x4);
        f32 fill = lbl_803DF430;
        fbuf[3] = fill;
        fbuf[2] = fill;
        fbuf[1] = fill;
        fbuf[0] = lbl_803DF434;
        buf[2] = v;
        buf[1] = v;
        buf[0] = v;
        mathFn_80021ac8(buf, (f32 *)(p2 + 0x4));
      }
      *(f32 *)(p1 + 0x24) = *(f32 *)(p2 + 0x4);
      *(f32 *)(p1 + 0x28) = *(f32 *)(p2 + 0x8);
      *(f32 *)(p1 + 0x2c) = *(f32 *)(p2 + 0xc);
    } else {
      *(f32 *)(p1 + 0x24) = *(f32 *)(p2 + 0x4) / (f32)(s32)*(s16 *)(p1 + 0xfe);
      *(f32 *)(p1 + 0x28) = *(f32 *)(p2 + 0x8) / (f32)(s32)*(s16 *)(p1 + 0xfe);
      *(f32 *)(p1 + 0x2c) = *(f32 *)(p2 + 0xc) / (f32)(s32)*(s16 *)(p1 + 0xfe);
    }
    *(f32 *)(p1 + 0x60) = *(f32 *)(p1 + 0x60) + *(f32 *)(p1 + 0x24);
    *(f32 *)(p1 + 0x64) = *(f32 *)(p1 + 0x64) + *(f32 *)(p1 + 0x28);
    *(f32 *)(p1 + 0x68) = *(f32 *)(p1 + 0x68) + *(f32 *)(p1 + 0x2c);
  } else {
    *(f32 *)(p1 + 0x60) = *(f32 *)(p1 + 0x24) * lbl_803DD284 + *(f32 *)(p1 + 0x60);
    *(f32 *)(p1 + 0x64) = *(f32 *)(p1 + 0x28) * lbl_803DD284 + *(f32 *)(p1 + 0x64);
    *(f32 *)(p1 + 0x68) = *(f32 *)(p1 + 0x2c) * lbl_803DD284 + *(f32 *)(p1 + 0x68);
  }
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x800A09C4  size: 240b  fn_800A09C4: integer-vector lerp setup.
 * On mode 1, snap or step-interpolate the s16 triple at obj->_106/_108/_10a
 * toward the rounded params, then advance it by the per-step delta. */
#pragma scheduling off
#pragma peephole off
void fn_800A09C4(int* obj, f32* params, int mode)
{
    if (mode == 1) {
        int tx = (int)params[1];
        int ty = (int)params[2];
        int tz = (int)params[3];
        if (*(s16*)((char*)obj + 0xfe) != 0) {
            *(s16*)((char*)obj + 0x100) = (s16)(((s16)tx - *(s16*)((char*)obj + 0x106)) / *(s16*)((char*)obj + 0xfe));
            *(s16*)((char*)obj + 0x102) = (s16)(((s16)ty - *(s16*)((char*)obj + 0x108)) / *(s16*)((char*)obj + 0xfe));
            *(s16*)((char*)obj + 0x104) = (s16)(((s16)tz - *(s16*)((char*)obj + 0x10a)) / *(s16*)((char*)obj + 0xfe));
        } else {
            *(s16*)((char*)obj + 0x106) = tx;
            *(s16*)((char*)obj + 0x100) = 0;
            *(s16*)((char*)obj + 0x108) = ty;
            *(s16*)((char*)obj + 0x102) = 0;
            *(s16*)((char*)obj + 0x10a) = tz;
            *(s16*)((char*)obj + 0x104) = 0;
        }
    }
    *(s16*)((char*)obj + 0x106) = *(s16*)((char*)obj + 0x106) + *(s16*)((char*)obj + 0x100);
    *(s16*)((char*)obj + 0x108) = *(s16*)((char*)obj + 0x108) + *(s16*)((char*)obj + 0x102);
    *(s16*)((char*)obj + 0x10a) = *(s16*)((char*)obj + 0x10a) + *(s16*)((char*)obj + 0x104);
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
    for (i = 0; i < 50; i++) {
        int* e = lbl_8039C1F8[i];
        int* f;
        if (e != NULL) {
            f = *(int**)((char*)e + 4);
            if (f != NULL && (*(u16*)((char*)f + 0xb0) & 0x800) != 0) {
                *(u8*)((char*)e + 0x13e) = 1;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Resource_Release(void* res);
extern void *lbl_803DD2C8;
extern void *lbl_803DD2CC;
extern void *lbl_803DD2D0;
extern void *lbl_803DD2D4;
extern void *lbl_803DD2D8;
extern void *lbl_803DD2DC;
extern void *lbl_803DD2E0;
extern void *lbl_803DD2E4;
extern void *lbl_803DD2E8;
extern void *lbl_803DD2EC;
extern void *lbl_803DD2F0;
extern void *lbl_803DD2F4;
extern void *lbl_803DD2F8;
extern void *lbl_803DD2FC;
extern void *lbl_803DD300;
extern void *lbl_803DD304;
extern void *lbl_803DD308;
extern void *lbl_803DD30C;
extern void *lbl_803DD310;
extern void *lbl_803DD314;

/* EN v1.0 0x800AF41C  size: 560b  partfx_release: clear the 20-slot
 * effect-id table and free all 20 cached particle resources. */
#pragma scheduling off
#pragma peephole off
void partfx_release(void) {
    u16 *p;
    int i;
    i = 0x14;
    p = lbl_8039C2E0 + 0x14;
    while ((s8)i != 0) {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    if (lbl_803DD2C8 != NULL) Resource_Release(lbl_803DD2C8);
    lbl_803DD2C8 = NULL;
    if (lbl_803DD2CC != NULL) Resource_Release(lbl_803DD2CC);
    lbl_803DD2CC = NULL;
    if (lbl_803DD2D0 != NULL) Resource_Release(lbl_803DD2D0);
    lbl_803DD2D0 = NULL;
    if (lbl_803DD2D4 != NULL) Resource_Release(lbl_803DD2D4);
    lbl_803DD2D4 = NULL;
    if (lbl_803DD2D8 != NULL) Resource_Release(lbl_803DD2D8);
    lbl_803DD2D8 = NULL;
    if (lbl_803DD2DC != NULL) Resource_Release(lbl_803DD2DC);
    lbl_803DD2DC = NULL;
    if (lbl_803DD2E0 != NULL) Resource_Release(lbl_803DD2E0);
    lbl_803DD2E0 = NULL;
    if (lbl_803DD2E4 != NULL) Resource_Release(lbl_803DD2E4);
    lbl_803DD2E4 = NULL;
    if (lbl_803DD2E8 != NULL) Resource_Release(lbl_803DD2E8);
    lbl_803DD2E8 = NULL;
    if (lbl_803DD2EC != NULL) Resource_Release(lbl_803DD2EC);
    lbl_803DD2EC = NULL;
    if (lbl_803DD2F0 != NULL) Resource_Release(lbl_803DD2F0);
    lbl_803DD2F0 = NULL;
    if (lbl_803DD2F4 != NULL) Resource_Release(lbl_803DD2F4);
    lbl_803DD2F4 = NULL;
    if (lbl_803DD2F8 != NULL) Resource_Release(lbl_803DD2F8);
    lbl_803DD2F8 = NULL;
    if (lbl_803DD2FC != NULL) Resource_Release(lbl_803DD2FC);
    lbl_803DD2FC = NULL;
    if (lbl_803DD300 != NULL) Resource_Release(lbl_803DD300);
    lbl_803DD300 = NULL;
    if (lbl_803DD304 != NULL) Resource_Release(lbl_803DD304);
    lbl_803DD304 = NULL;
    if (lbl_803DD308 != NULL) Resource_Release(lbl_803DD308);
    lbl_803DD308 = NULL;
    if (lbl_803DD30C != NULL) Resource_Release(lbl_803DD30C);
    lbl_803DD30C = NULL;
    if (lbl_803DD310 != NULL) Resource_Release(lbl_803DD310);
    lbl_803DD310 = NULL;
    if (lbl_803DD314 != NULL) Resource_Release(lbl_803DD314);
    lbl_803DD314 = NULL;
    lbl_803DD2C0 = 0;
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
extern f32 timeDelta;
extern f32 lbl_803DD284;
extern u8 framesThisStep;
extern f32 fn_80293E80(f32);

#pragma scheduling off
#pragma peephole off
void Effect1_func05(void)
{
  lbl_803DB7B8 = lbl_803DB7B8 + lbl_803DF720 * timeDelta;
  if (lbl_803DB7B8 > lbl_803DF728) {
    lbl_803DB7B8 = lbl_803DF724;
  }
  lbl_803DB7BC = lbl_803DB7BC + lbl_803DF720 * timeDelta;
  if (lbl_803DB7BC > lbl_803DF728) {
    lbl_803DB7BC = lbl_803DF730;
  }
  lbl_803DD328 = lbl_803DD328 + framesThisStep * 0x64;
  if (lbl_803DD328 > 0x7fff) {
    lbl_803DD328 = 0;
  }
  lbl_803DD334 = fn_80293E80(lbl_803DF868 * (f32)(s16)lbl_803DD328 / lbl_803DF86C);
  lbl_803DD32C = lbl_803DD32C + framesThisStep * 0x32;
  if (lbl_803DD32C > 0x7fff) {
    lbl_803DD32C = 0;
  }
  lbl_803DD330 = fn_80293E80(lbl_803DF868 * (f32)(s16)lbl_803DD32C / lbl_803DF86C);
}
#pragma peephole reset
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
  lbl_803DB7C8 = lbl_803DB7C8 + lbl_803DF870 * timeDelta;
  if (lbl_803DB7C8 > lbl_803DF878) {
    lbl_803DB7C8 = lbl_803DF874;
  }
  lbl_803DB7CC = lbl_803DB7CC + lbl_803DF870 * timeDelta;
  if (lbl_803DB7CC > lbl_803DF878) {
    lbl_803DB7CC = lbl_803DF880;
  }
  lbl_803DD338 = lbl_803DD338 + framesThisStep * 0x64;
  if (lbl_803DD338 > 0x7fff) {
    lbl_803DD338 = 0;
  }
  lbl_803DD344 = fn_80293E80(lbl_803DF9C8 * (f32)(s16)lbl_803DD338 / lbl_803DF9CC);
  lbl_803DD33C = lbl_803DD33C + framesThisStep * 0x32;
  if (lbl_803DD33C > 0x7fff) {
    lbl_803DD33C = 0;
  }
  lbl_803DD340 = fn_80293E80(lbl_803DF9C8 * (f32)(s16)lbl_803DD33C / lbl_803DF9CC);
}
void Effect4_func05(void)
{
  lbl_803DB7D8 = lbl_803DB7D8 + lbl_803DFA88 * timeDelta;
  if (lbl_803DB7D8 > lbl_803DFA90) {
    lbl_803DB7D8 = lbl_803DFA8C;
  }
  lbl_803DB7DC = lbl_803DB7DC + lbl_803DFA88 * timeDelta;
  if (lbl_803DB7DC > lbl_803DFA90) {
    lbl_803DB7DC = lbl_803DFA98;
  }
  lbl_803DD350 = lbl_803DD350 + framesThisStep * 0x64;
  if (lbl_803DD350 > 0x7fff) {
    lbl_803DD350 = 0;
  }
  lbl_803DD35C = fn_80293E80(lbl_803DFBD8 * (f32)(s16)lbl_803DD350 / lbl_803DFBDC);
  lbl_803DD354 = lbl_803DD354 + framesThisStep * 0x32;
  if (lbl_803DD354 > 0x7fff) {
    lbl_803DD354 = 0;
  }
  lbl_803DD358 = fn_80293E80(lbl_803DFBD8 * (f32)(s16)lbl_803DD354 / lbl_803DFBDC);
}
void Effect5_func05(void)
{
  lbl_803DB7E8 = lbl_803DB7E8 + lbl_803DFBE0 * timeDelta;
  if (lbl_803DB7E8 > lbl_803DFBE8) {
    lbl_803DB7E8 = lbl_803DFBE4;
  }
  lbl_803DB7EC = lbl_803DB7EC + lbl_803DFBE0 * timeDelta;
  if (lbl_803DB7EC > lbl_803DFBE8) {
    lbl_803DB7EC = lbl_803DFBF0;
  }
  lbl_803DD360 = lbl_803DD360 + framesThisStep * 0x64;
  if (lbl_803DD360 > 0x7fff) {
    lbl_803DD360 = 0;
  }
  lbl_803DD36C = fn_80293E80(lbl_803DFC78 * (f32)(s16)lbl_803DD360 / lbl_803DFC7C);
  lbl_803DD364 = lbl_803DD364 + framesThisStep * 0x32;
  if (lbl_803DD364 > 0x7fff) {
    lbl_803DD364 = 0;
  }
  lbl_803DD368 = fn_80293E80(lbl_803DFC78 * (f32)(s16)lbl_803DD364 / lbl_803DFC7C);
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
    s16 f58;
    s16 f5a;
    s16 f5c;
    u8  f5e;
    u8  f60;
    u8  f61;
    u8  f62;
} PartFxSpawn;

extern int *gExpgfxInterface;
extern void fn_8017FFD0();
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
    if (lbl_803DB7F0 > lbl_803DFC88) lbl_803DB7F0 = lbl_803DFC84;
    lbl_803DB7F4 = lbl_803DB7F4 + lbl_803DFC8C;
    if (lbl_803DB7F4 > lbl_803DFC88) lbl_803DB7F4 = lbl_803DFC90;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
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
        cfg.f60 = (u8)*param_6;
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
        if (randomGetRange(0, 0x28) != 0) {
            cfg.f3c = lbl_803DFC80 * (f32)(s32)randomGetRange(8, 0x14);
            cfg.f08 = randomGetRange(0x5a, 0x78);
        } else {
            cfg.f3c = lbl_803DFC80 * (f32)(s32)randomGetRange(0x15, 0x29);
            cfg.f08 = 0x1cc;
        }
        cfg.f44 = (u32)((u8 *)fn_8017FFD0 + 0x230);
        cfg.f48 = 0x1000020;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x7f;
        cfg.f58 = 0x3fff;
        cfg.f5a = 0x3fff;
        cfg.f5c = 0x3fff;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xffff;
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
        cfg.f54 = cfg.f50 = randomGetRange(0, 0x8000);
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
        cfg.f60 = (u8)*param_6;
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
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
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
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

void Effect6_func05(void)
{
  lbl_803DB7F8 = lbl_803DB7F8 + lbl_803DFC80 * timeDelta;
  if (lbl_803DB7F8 > lbl_803DFC88) {
    lbl_803DB7F8 = lbl_803DFC84;
  }
  lbl_803DB7FC = lbl_803DB7FC + lbl_803DFC80 * timeDelta;
  if (lbl_803DB7FC > lbl_803DFC88) {
    lbl_803DB7FC = lbl_803DFC90;
  }
  lbl_803DD370 = lbl_803DD370 + framesThisStep * 0x64;
  if (lbl_803DD370 > 0x7fff) {
    lbl_803DD370 = 0;
  }
  lbl_803DD37C = fn_80293E80(lbl_803DFCD0 * (f32)(s16)lbl_803DD370 / lbl_803DFCD4);
  lbl_803DD374 = lbl_803DD374 + framesThisStep * 0x32;
  if (lbl_803DD374 > 0x7fff) {
    lbl_803DD374 = 0;
  }
  lbl_803DD378 = fn_80293E80(lbl_803DFCD0 * (f32)(s16)lbl_803DD374 / lbl_803DFCD4);
}
void Effect7_func05(void)
{
  lbl_803DB808 = lbl_803DB808 + lbl_803DFCD8 * timeDelta;
  if (lbl_803DB808 > lbl_803DFCE0) {
    lbl_803DB808 = lbl_803DFCDC;
  }
  lbl_803DB80C = lbl_803DB80C + lbl_803DFCD8 * timeDelta;
  if (lbl_803DB80C > lbl_803DFCE0) {
    lbl_803DB80C = lbl_803DFCE8;
  }
  lbl_803DD380 = lbl_803DD380 + framesThisStep * 0x64;
  if (lbl_803DD380 > 0x7fff) {
    lbl_803DD380 = 0;
  }
  lbl_803DD38C = fn_80293E80(lbl_803DFD90 * (f32)(s16)lbl_803DD380 / lbl_803DFD94);
  lbl_803DD384 = lbl_803DD384 + framesThisStep * 0x32;
  if (lbl_803DD384 > 0x7fff) {
    lbl_803DD384 = 0;
  }
  lbl_803DD388 = fn_80293E80(lbl_803DFD90 * (f32)(s16)lbl_803DD384 / lbl_803DFD94);
}
void Effect8_func05(void)
{
  lbl_803DB818 = lbl_803DB818 + lbl_803DFD98 * timeDelta;
  if (lbl_803DB818 > lbl_803DFDA0) {
    lbl_803DB818 = lbl_803DFD9C;
  }
  lbl_803DB81C = lbl_803DB81C + lbl_803DFD98 * timeDelta;
  if (lbl_803DB81C > lbl_803DFDA0) {
    lbl_803DB81C = lbl_803DFDA8;
  }
  lbl_803DD390 = lbl_803DD390 + framesThisStep * 0x64;
  if (lbl_803DD390 > 0x7fff) {
    lbl_803DD390 = 0;
  }
  lbl_803DD39C = fn_80293E80(lbl_803DFE20 * (f32)(s16)lbl_803DD390 / lbl_803DFE24);
  lbl_803DD394 = lbl_803DD394 + framesThisStep * 0x32;
  if (lbl_803DD394 > 0x7fff) {
    lbl_803DD394 = 0;
  }
  lbl_803DD398 = fn_80293E80(lbl_803DFE20 * (f32)(s16)lbl_803DD394 / lbl_803DFE24);
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
    lbl_8039C398.fc = lbl_803DFE3C;             \
    lbl_8039C398.f10 = lbl_803DFE3C;            \
    lbl_8039C398.f14 = lbl_803DFE3C;            \
    lbl_8039C398.f8 = lbl_803DFE30;             \
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
    if (lbl_803DB820 > lbl_803DFE30) lbl_803DB820 = lbl_803DFE2C;
    lbl_803DB824 = lbl_803DB824 + lbl_803DFE34;
    if (lbl_803DB824 > lbl_803DFE30) lbl_803DB824 = lbl_803DFE38;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFE3C;
    cfg.f34 = lbl_803DFE3C;
    cfg.f38 = lbl_803DFE3C;
    cfg.f24 = lbl_803DFE3C;
    cfg.f28 = lbl_803DFE3C;
    cfg.f2c = lbl_803DFE3C;
    cfg.f3c = lbl_803DFE3C;
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
    case 1:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f38 = *(f32 *)(param_3 + 10);
        } else {
            cfg.f30 = lbl_803DFE3C;
            cfg.f38 = lbl_803DFE3C;
        }
        cfg.f34 = lbl_803DFE3C;
        cfg.f28 = lbl_803DFE40 * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.f3c = lbl_803DFE44 * (f32)(s32)randomGetRange(6, 0xa);
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = (u32)((u8 *)fn_8017FFD0 + 0x130);
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
        }
        cfg.f3c = lbl_803DFE58;
        cfg.f08 = 0x96;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8000201;
        cfg.f42 = 0x62;
        break;
    case 5:
        if (param_3 == 0) FILL9();
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
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
        if (param_3 != 0) cfg.f34 = *(f32 *)(param_3 + 8);
        if (param_3 != 0) cfg.f3c = lbl_803DFE7C * *(f32 *)(param_3 + 4);
        else cfg.f3c = lbl_803DFE80;
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f38 = *(f32 *)(param_3 + 10);
        } else {
            cfg.f30 = lbl_803DFE3C;
            cfg.f38 = lbl_803DFE3C;
        }
        cfg.f34 = lbl_803DFE3C;
        cfg.f3c = lbl_803DFE44 * (f32)(s32)randomGetRange(6, 0x14);
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = (u32)((u8 *)fn_8017FFD0 + 0x138);
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f38 = *(f32 *)(param_3 + 10);
        } else {
            cfg.f30 = lbl_803DFE3C;
            cfg.f38 = lbl_803DFE3C;
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
        if (randomGetRange(0, 3) == 3) {
            cfg.f3c = lbl_803DFE8C * (f32)(s32)randomGetRange(1, 4);
            cfg.f44 = cfg.f44 | 0x100100;
            cfg.f42 = 0x2b;
            cfg.f60 = 0x9b;
            param_2 = 0x3c1;
        }
        break;
    case 17:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f24 = *(f32 *)(param_3 + 6);
            cfg.f28 = *(f32 *)(param_3 + 8);
            cfg.f2c = *(f32 *)(param_3 + 10);
        } else {
            cfg.f24 = lbl_803DFE28 * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f28 = lbl_803DFE74 * (f32)(s32)randomGetRange(5, 0x64);
            cfg.f2c = lbl_803DFE28 * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f34 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f38 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.f30 = lbl_803DFE2C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f30 = lbl_803DFE3C;
        cfg.f3c = lbl_803DFE78;
        cfg.f08 = 0x28;
        cfg.f44 = 0x1080006;
        cfg.f42 = 0x60;
        cfg.f60 = 0xa0;
        break;
    case 16:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
        }
        cfg.f3c = lbl_803DFE78;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x8100201;
        cfg.f42 = 0x60;
        break;
    case 15:
        if (param_3 == 0) FILL9();
        cfg.f08 = (s32)(lbl_803DFE48 * *(f32 *)(param_3 + 4) + lbl_803DFE90);
        cfg.f3c = lbl_803DFE94 * (f32)(s32)cfg.f08;
        cfg.f44 = 0xe100200;
        cfg.f42 = 0x57;
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f18 = lbl_803DFE3C;
        cfg.f1c = lbl_803DFE3C;
        cfg.f20 = lbl_803DFE3C;
        cfg.f0c = *param_3;
        cfg.f0e = 0;
        cfg.f10 = 0;
        break;
    case 14:
        if (param_3 == 0) FILL9();
        if (param_3 != 0) {
            cfg.f24 = *(f32 *)(param_3 + 6);
            cfg.f28 = *(f32 *)(param_3 + 8);
            cfg.f2c = *(f32 *)(param_3 + 10);
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
        if (param_3 != 0) cfg.f30 = *(f32 *)(param_3 + 6);
        else cfg.f30 = lbl_803DFE3C;
        if (param_3 != 0) cfg.f34 = *(f32 *)(param_3 + 8);
        else cfg.f34 = lbl_803DFE3C;
        if (param_3 != 0) cfg.f38 = *(f32 *)(param_3 + 10);
        else cfg.f38 = lbl_803DFE3C;
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
        if (param_3 != 0) cfg.f38 = *(f32 *)(param_3 + 10);
        else cfg.f38 = lbl_803DFE3C;
        if (param_3 != 0) cfg.f34 = *(f32 *)(param_3 + 8);
        else cfg.f34 = lbl_803DFEA0;
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
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
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
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}
#undef FILL9

extern FxNode9 lbl_8039C380;
extern void randFn_80080100();
extern f32 lbl_803DB810;
extern f32 lbl_803DB814;
extern f32 lbl_803DFDA0;
extern f32 lbl_803DFDA4;
extern f32 lbl_803DFDA8;
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
    lbl_8039C380.fc = lbl_803DFDAC;             \
    lbl_8039C380.f10 = lbl_803DFDAC;            \
    lbl_8039C380.f14 = lbl_803DFDAC;            \
    lbl_8039C380.f8 = lbl_803DFDA0;             \
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
    if (lbl_803DB810 > lbl_803DFDA0) lbl_803DB810 = lbl_803DFD9C;
    lbl_803DB814 = lbl_803DB814 + lbl_803DFDA4;
    if (lbl_803DB814 > lbl_803DFDA0) lbl_803DB814 = lbl_803DFDA8;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803DFDAC;
    cfg.f34 = lbl_803DFDAC;
    cfg.f38 = lbl_803DFDAC;
    cfg.f24 = lbl_803DFDAC;
    cfg.f28 = lbl_803DFDAC;
    cfg.f2c = lbl_803DFDAC;
    cfg.f3c = lbl_803DFDAC;
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
        cfg.f58 = (u16)((u8)param_3[2] << 8);
        cfg.f5a = (u16)((u8)param_3[1] << 8);
        cfg.f5c = (u16)((u8)param_3[0] << 8);
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
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803DFDB0 * (lbl_803DFDE0 * (f32)(s32)param_3[2]);
        cfg.f08 = 0x3c;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f4c = param_3[2] << 8;
        cfg.f50 = param_3[2] << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x60;
        cfg.f60 = param_3[2];
        cfg.f44 = 0x201;
        cfg.f42 = 0x76;
        break;
    case 0x35b:
        if (param_3 == 0) FILL8();
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803DFD9C;
        cfg.f08 = 0xa;
        cfg.f60 = 0xff;
        cfg.f44 = 0x580101;
        cfg.f42 = 0xc22;
        break;
    case 0x35c:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)param_3[0]));
        cfg.f08 = 0xa;
        cfg.f58 = (u16)(param_3[0] << 8);
        cfg.f5a = (u16)(param_3[0] << 8);
        cfg.f5c = 0xff00;
        cfg.f4c = param_3[0] << 8;
        cfg.f50 = param_3[0] << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x20;
        cfg.f60 = param_3[2];
        cfg.f42 = 0xc9d;
        break;
    case 0x35d:
        if (param_3 == 0) FILL8();
        if (param_3 == 0) return -1;
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)param_3[0]));
        cfg.f08 = 0xa;
        cfg.f58 = 0xff00;
        cfg.f5a = (u16)(param_3[0] << 8);
        cfg.f5c = 0xff00;
        cfg.f4c = 0xff00;
        cfg.f50 = param_3[0] << 8;
        cfg.f54 = 0xff00;
        cfg.f48 = 0x20;
        cfg.f60 = param_3[2];
        cfg.f42 = 0xc9d;
        break;
    case 0x35e:
        if (param_3 == 0) FILL8();
        cfg.f3c = lbl_803DFDEC;
        cfg.f34 = lbl_803DFDF0;
        cfg.f08 = 0x46;
        cfg.f60 = param_3 != 0 ? (u8)param_3[2] : 0xff;
        cfg.f61 = 0;
        cfg.f30 = param_3 != 0 ? *(f32 *)(param_3 + 6) : lbl_803DFDAC;
        cfg.f34 = param_3 != 0 ? *(f32 *)(param_3 + 8) : lbl_803DFDAC;
        cfg.f38 = param_3 != 0 ? *(f32 *)(param_3 + 10) : lbl_803DFDAC;
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
        cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.f5a = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.f5c = 0x3caf;
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = (u16)cfg.f5a;
        cfg.f54 = 0x3caf;
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
        cfg.f58 = (u16)(randomGetRange(0, 0x2710) + 0x63bf);
        cfg.f5a = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
        cfg.f5c = 0x3caf;
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = (u16)cfg.f5a;
        cfg.f54 = 0x3caf;
        cfg.f48 = 0x20;
        cfg.f44 = (u32)randFn_80080100;
        cfg.f42 = 0x62;
        cfg.f60 = 0xa0;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
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
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
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
extern f32 lbl_803DF870;
extern f32 lbl_803DF874;
extern f32 lbl_803DF878;
extern f32 lbl_803DF87C;
extern f32 lbl_803DF880;
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

int Effect2_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                   u8 param_5, s16 *param_6)
{
    int uVar1;
    int i;
    PartFxSpawn cfg;

    lbl_803DB7C0 = lbl_803DB7C0 + lbl_803DF870;
    if (lbl_803DB7C0 > lbl_803DF878) lbl_803DB7C0 = lbl_803DF874;
    lbl_803DB7C4 = lbl_803DB7C4 + lbl_803DF87C;
    if (lbl_803DB7C4 > lbl_803DF878) lbl_803DB7C4 = lbl_803DF880;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
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
    case 0x2b1: {
        EmitterCfg *t = &lbl_80310560;
        cfg.f24 = t->vel[0][0] * (f32)(s32)randomGetRange((s32)t->vel[0][1], (s32)t->vel[0][2]);
        cfg.f28 = t->vel[1][0] * (f32)(s32)randomGetRange((s32)t->vel[1][1], (s32)t->vel[1][2]);
        cfg.f2c = t->vel[2][0] * (f32)(s32)randomGetRange((s32)t->vel[2][1], (s32)t->vel[2][2]);
        cfg.f30 = t->vel[3][0] * (f32)(s32)randomGetRange((s32)t->vel[3][1], (s32)t->vel[3][2]);
        cfg.f34 = t->vel[4][0] * (f32)(s32)randomGetRange((s32)t->vel[4][1], (s32)t->vel[4][2]);
        cfg.f38 = t->vel[5][0] * (f32)(s32)randomGetRange((s32)t->vel[5][1], (s32)t->vel[5][2]);
        cfg.f3c = t->vel[6][0] * (f32)(s32)randomGetRange((s32)t->vel[6][1], (s32)t->vel[6][2]);
        cfg.f08 = randomGetRange((s32)t->g08[1], (s32)t->g08[2]) + (s32)t->g08[0];
        cfg.f58 = t->col[0];
        cfg.f5a = t->col[1];
        cfg.f5c = t->col[2];
        cfg.f4c = t->col[3];
        cfg.f50 = t->col[4];
        cfg.f54 = t->col[5];
        for (i = 0; i < 6; i++) if (t->emit[i] != 0) cfg.f44 |= 1 << (t->emit[i] - 1);
        cfg.f48 = 0x2000000;
        for (i = 0; i < 6; i++) if (t->sub[i] != 0) cfg.f48 |= 1 << (t->sub[i] - 1);
        cfg.f42 = (s32)t->f60;
        cfg.f60 = randomGetRange(t->b_a0, t->b_a1);
        break;
    }
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
        if (randomGetRange(0, 1) != 0) cfg.f44 = 0x810210;
        else cfg.f44 = 0x180210;
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x205;
        break;
    case 0x2ae:
        cfg.f34 = lbl_803DF8B8;
        cfg.f3c = lbl_803DF8B4;
        cfg.f08 = randomGetRange(0xe, 0x32);
        cfg.f44 = 0x8100210;
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
        cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.f4c = (u16)cfg.f58;
        cfg.f5a = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.f50 = (u16)cfg.f5a;
        cfg.f5c = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.f54 = (u16)cfg.f5c;
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
        cfg.f42 = 0xc9d;
        break;
    case 0x29d:
        cfg.f0c = 0x3e8;
        cfg.f18 = lbl_803DF884;
        cfg.f08 = 6;
        cfg.f60 = 0xe1;
        cfg.f44 = 0x4a0010;
        if (randomGetRange(0, 1) != 0) cfg.f48 = 0x202;
        else cfg.f48 = 0x102;
        if (param_3 != 0) cfg.f3c = lbl_803DF87C * (f32)(s32)randomGetRange(0, 3) + lbl_803DF870;
        else cfg.f3c = lbl_803DF87C * (f32)(s32)randomGetRange(0, 3) + lbl_803DF924;
        cfg.f42 = 0xc0f;
        break;
    case 0x29e:
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480010;
        if (param_3 != 0) cfg.f3c = lbl_803DF928;
        else cfg.f3c = lbl_803DF92C;
        cfg.f42 = 0x74;
        cfg.f48 = 2;
        break;
    case 0x29f:
        cfg.f08 = 0x3c;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480010;
        cfg.f48 = 2;
        if (param_3 != 0) {
            cfg.f3c = lbl_803DF8C8;
            cfg.f42 = 0xc22;
        } else {
            cfg.f3c = lbl_803DF930;
            cfg.f42 = 0xdc;
        }
        break;
    case 0x2a0:
        cfg.f08 = 0x1e;
        cfg.f61 = 0;
        cfg.f60 = 0x37;
        cfg.f44 = 0x180010;
        if (param_3 != 0) cfg.f3c = lbl_803DF934 * (f32)(s32)randomGetRange(0x14, 0x32);
        else cfg.f3c = lbl_803DF938 * (f32)(s32)randomGetRange(0x14, 0x32);
        cfg.f42 = 0x73;
        break;
    case 0x2a1:
        cfg.f08 = 0x3c;
        cfg.f61 = 0;
        cfg.f60 = 0x37;
        cfg.f44 = 0x480010;
        cfg.f48 = 2;
        if (param_3 != 0) cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(0x46, 0x50);
        else cfg.f3c = lbl_803DF940 * (f32)(s32)randomGetRange(0x46, 0x50);
        cfg.f42 = 0x73;
        break;
    case 0x297:
        cfg.f24 = lbl_803DF944 * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f28 = lbl_803DF948 * (f32)(s32)randomGetRange(5, 0x10);
        cfg.f2c = lbl_803DF94C * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.f3c = lbl_803DF950;
        cfg.f08 = 0x54;
        cfg.f60 = 0x9b;
        cfg.f42 = 0x1fe;
        break;
    case 0x25b:
        cfg.f3c = lbl_803DF954;
        cfg.f08 = 0x3c;
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
        } else if (param_2 == 0x273) {
            cfg.f42 = 0x202;
        } else if (param_2 == 0x27e) {
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
        if (param_2 == 0x278) cfg.f04 = *(int *)((char *)param_1 + 0xc);
        else cfg.f04 = *(int *)((char *)param_1 - 0x980);
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
        if (param_2 == 0x276) cfg.f04 = *(int *)((char *)param_1 + 0xc);
        else cfg.f04 = *(int *)((char *)param_1 - 0x98c);
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
        if (param_2 == 0x277) cfg.f04 = *(int *)((char *)param_1 + 0xc);
        else cfg.f04 = *(int *)((char *)param_1 - 0x998);
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
        cfg.f42 = 0x1fe;
        break;
    case 0x26e:
        cfg.f3c = lbl_803DF974;
        cfg.f08 = 0x55;
        cfg.f61 = 0x10;
        cfg.f44 = 0x2000200;
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
        cfg.f44 = (u32)((u8 *)getCurSeqNo + 4);
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = lbl_803DF98C + *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
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
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
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
        cfg.f50 = 0x1400;
        cfg.f48 = 0x20;
        break;
    case 0x285:
        if (param_3 == 0) FILL338();
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
        } else {
            cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
            cfg.f34 = (f32)(s32)randomGetRange(1, 0xa);
            cfg.f38 = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.f28 = lbl_803DF998 * (f32)(s32)randomGetRange(2, 4);
        cfg.f2c = lbl_803DF8D0 * (f32)(s32)randomGetRange(2, 4);
        cfg.f3c = lbl_803DF870 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803DF9A8;
        cfg.f08 = randomGetRange(0, 0x32);
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
        cfg.f08 = randomGetRange(0, 0x1e);
        cfg.f60 = 0xff;
        cfg.f44 = 0x88108;
        cfg.f42 = 0x159;
        break;
    case 0x28d:
        cfg.f3c = lbl_803DF93C * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.f08 = randomGetRange(0, 0x14);
        cfg.f60 = 0x7d;
        cfg.f44 = 0x500200;
        cfg.f42 = 0x159;
        break;
    case 0x28e:
        cfg.f30 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.f34 = lbl_803DF874 * (f32)(s32)randomGetRange(0x12c, 0x708);
        cfg.f38 = lbl_803DF874 * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.f24 = lbl_803DF9BC * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f2c = lbl_803DF9BC * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803DF96C;
        cfg.f08 = 0x118;
        cfg.f60 = 0xff;
        cfg.f48 = 0x300020;
        cfg.f58 = 0xffff;
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
        cfg.f18 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f1c = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f20 = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.f48 = 0x20;
        cfg.f44 = 0x86000008;
        cfg.f58 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.f5a = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.f5c = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = (u16)cfg.f5a;
        cfg.f54 = (u16)cfg.f5c;
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
        cfg.f4c = (u16)cfg.f58;
        cfg.f50 = (u16)cfg.f5a;
        cfg.f54 = (u16)cfg.f5c;
        cfg.f42 = param_2 + 0x10f;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
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
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    lbl_803DD348 = lbl_803DD2C4;
    return uVar1;
}
#undef FILL338

void Effect9_func05(void)
{
  lbl_803DB828 = lbl_803DB828 + lbl_803DFE28 * timeDelta;
  if (lbl_803DB828 > lbl_803DFE30) {
    lbl_803DB828 = lbl_803DFE2C;
  }
  lbl_803DB82C = lbl_803DB82C + lbl_803DFE28 * timeDelta;
  if (lbl_803DB82C > lbl_803DFE30) {
    lbl_803DB82C = lbl_803DFE38;
  }
  lbl_803DD3A0 = lbl_803DD3A0 + framesThisStep * 0x64;
  if (lbl_803DD3A0 > 0x7fff) {
    lbl_803DD3A0 = 0;
  }
  lbl_803DD3AC = fn_80293E80(lbl_803DFEB0 * (f32)(s16)lbl_803DD3A0 / lbl_803DFEB4);
  lbl_803DD3A4 = lbl_803DD3A4 + framesThisStep * 0x32;
  if (lbl_803DD3A4 > 0x7fff) {
    lbl_803DD3A4 = 0;
  }
  lbl_803DD3A8 = fn_80293E80(lbl_803DFEB0 * (f32)(s16)lbl_803DD3A4 / lbl_803DFEB4);
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
extern int *gPartfxInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DF4A8;
extern f32 lbl_803DF4B8;

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

typedef void (*BoneSpawnFn)(void *, void *, void *, int, int, void *);

#pragma scheduling off
#pragma peephole off
void boneParticleEffect_spawnAtBones(void *obj, void *arg1, void *arg2, u8 prob, short *src)
{
  void *model;
  int i;
  BoneSpawnData data;

  model = Obj_GetActiveModel();
  for (i = 0; i < *(u8 *)(*(int *)model + 0xf3); i++) {
    if (randomGetRange(1, 0x64) <= prob) {
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
      data.x = data.x - *(f32 *)((char *)obj + 0x18);
      data.y = data.y - *(f32 *)((char *)obj + 0x1c);
      data.z = data.z - *(f32 *)((char *)obj + 0x20);
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
      (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(obj, arg1, &data, 2, -1, arg2);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

extern void *Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32 x);
extern f32 lbl_8030FDE8[];
extern s16 lbl_803DD29A;
extern s16 lbl_803DD29C;
extern f32 lbl_803DF468;
extern f32 lbl_803DF46C;
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
    lbl_803DD29C = *(s16 *)((char *)cam + 2);
    dx = *(f32 *)((char *)cam + 0xc) - *(f32 *)((char *)ctx + 0xc);
    dy = *(f32 *)((char *)cam + 0x10) - *(f32 *)((char *)ctx + 0x10);
    dz = *(f32 *)((char *)cam + 0x14) - *(f32 *)((char *)ctx + 0x14);
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
                p0x = *(f32 *)((char *)ctx + 0xc) + ((f32)*(s16 *)(e + 0x10) - a);
                p0y = (f32)*(s16 *)(e + 0x16);
                p0z = *(f32 *)((char *)ctx + 0x14) + ((f32)*(s16 *)(e + 0x1c) - b);
                p1x = *(f32 *)((char *)ctx + 0xc) + ((f32)*(s16 *)(e + 0x12) - a);
                p1y = (f32)*(s16 *)(e + 0x18);
                p1z = *(f32 *)((char *)ctx + 0x14) + ((f32)*(s16 *)(e + 0x1e) - b);
                p2x = *(f32 *)((char *)ctx + 0xc) + ((f32)*(s16 *)(e + 0x14) - a);
                p2y = (f32)*(s16 *)(e + 0x1a);
                p2z = *(f32 *)((char *)ctx + 0x14) + ((f32)*(s16 *)(e + 0x20) - b);
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
                        (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x72, &data, 0x200001, -1, NULL);
                    }
                } else if (rt == 0x11) {
                    if (randomGetRange(0, 8) == 2) {
                        (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x14) {
                    if (randomGetRange(0, 8) == 2) {
                        (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x15) {
                    if (randomGetRange(0, 8) == 2) {
                        (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x73, &data, 0x111, -1, NULL);
                    }
                } else if (rt == 0x17) {
                    (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x190, &data, 0x111, -1, NULL);
                    (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x190, &data, 0x111, -1, NULL);
                    (*(BoneSpawnFn *)(*(int *)gPartfxInterface + 8))(ctx, (void *)0x190, &data, 0x111, -1, NULL);
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
      if (*(u32 *)((char *)arr[i] + 0xa4) & 0x10000) {
        fn_800A1040(*(s16 *)((char *)arr[i] + 0x10c), 0);
      } else {
        *(f32 *)((char *)arr[i] + 0x18) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x18);
        *(f32 *)((char *)arr[i] + 0x1c) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x1c);
        *(f32 *)((char *)arr[i] + 0x20) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x20);
        *(f32 *)((char *)arr[i] + 0x14) = *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x8);
        *(s16 *)((char *)arr[i] + 0x10) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x4);
        *(s16 *)((char *)arr[i] + 0xe) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x2);
        *(s16 *)((char *)arr[i] + 0xc) = *(s16 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x0);
        if (*(u32 *)((char *)arr[i] + 0xa4) & 0x2) {
          *(f32 *)((char *)arr[i] + 0x6c) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x24);
          *(f32 *)((char *)arr[i] + 0x70) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x28);
          *(f32 *)((char *)arr[i] + 0x74) += *(f32 *)((char *)*(void **)((char *)arr[i] + 0x4) + 0x2c);
        }
        if (!(*(u32 *)((char *)arr[i] + 0xa4) & 0x200000)) {
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
  *(ModgfxPendingSpawn **)lbl_8039BE98 = lbl_8039BEF8;
  *(s8 *)(lbl_8039BE98 + 0x5d) = lbl_803DD28C - lbl_803DD290;
  if (g == NULL && f == 0) {
    *(u32 *)(lbl_8039BE98 + 0x54) |= 0x2000000;
  } else {
    *(u32 *)(lbl_8039BE98 + 0x54) |= 0x4000000;
  }
  if (*(u32 *)(lbl_8039BE98 + 0x54) & 1) {
    if (*(void **)(lbl_8039BE98 + 0x4) != NULL) {
      *(f32 *)(lbl_8039BE98 + 0x2c) += *(f32 *)((char *)*(void **)(lbl_8039BE98 + 0x4) + 0x18);
      *(f32 *)(lbl_8039BE98 + 0x30) += *(f32 *)((char *)*(void **)(lbl_8039BE98 + 0x4) + 0x1c);
      *(f32 *)(lbl_8039BE98 + 0x34) += *(f32 *)((char *)*(void **)(lbl_8039BE98 + 0x4) + 0x20);
    } else {
      *(f32 *)(lbl_8039BE98 + 0x2c) += *(f32 *)((char *)a + 0xc);
      *(f32 *)(lbl_8039BE98 + 0x30) += *(f32 *)((char *)a + 0x10);
      *(f32 *)(lbl_8039BE98 + 0x34) += *(f32 *)((char *)a + 0x14);
    }
  }
  lbl_803DD288 = dll_0B_func04(lbl_8039BE98, 0, (int)c, b, (int)e, d, f, g);
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

    total = 0;
    found = 0;
    for (i = 0; i < 50 && found == 0; i++) {
        if (lbl_8039C1F8[i] == NULL) found = 1;
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
        base0 = e * 3 * 16 + c * 3 * 16;
    }

    lbl_8039C1F8[slot] = (int *)mmAlloc(base0 + n * 0x18 + total * 2 + 0x240, 0x15, 0);
    if (lbl_8039C1F8[slot] == NULL) {
        fn_800A1040(0, 0);
        return -1;
    }

    *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x12c) = ((u8 *)lbl_8039C1F8[slot]) + 0x140;
    {
        u8 *bufp = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x12c);
        if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x84) = bufp;
            bufp += e * 16;
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x88) = bufp;
            bufp += e * 16;
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x8c) = bufp;
            bufp += e * 16;
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x78) = bufp;
            bufp += c * 16;
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x7c) = bufp;
            bufp += c * 16;
            *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x80) = bufp;
            bufp += c * 16;
        }
        *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x90) = bufp;
        *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x94) = bufp + 0x80;
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
            u8 *dstc = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x84 + off);
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

    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0x98) = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x13f] = 0;
    if (g != NULL) {
        *(void **)(((u8 *)lbl_8039C1F8[slot]) + 0x98) = g;
        ((u8 *)lbl_8039C1F8[slot])[0x13f] = 1;
    } else if (f != 0) {
        *(void **)(((u8 *)lbl_8039C1F8[slot]) + 0x98) = textureLoadAsset(f);
        ((u8 *)lbl_8039C1F8[slot])[0x13f] = 0;
    }

    if ((*(u32 *)(st + 0x54) & 0x800) == 0) {
        int k;
        int off;
        for (k = 0, off = 0; k < 3; k++, off += 4) {
            u8 *dstv = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x78 + off);
            int j;
            s16 *sb = (s16 *)b;
            for (j = 0; j < c; j++) {
                *(s16 *)(dstv + 0) = sb[0];
                *(s16 *)(dstv + 2) = sb[1];
                *(s16 *)(dstv + 4) = sb[2];
                if (*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x98) != NULL) {
                    *(s16 *)(dstv + 8) = lbl_803DF460 * ((f32)sb[3] / (f32)*(u16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x98) + 0xa));
                    *(s16 *)(dstv + 0xa) = lbl_803DF460 * ((f32)sb[4] / (f32)*(u16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x98) + 0xc));
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

    ((u8 *)lbl_8039C1F8[slot])[0x139] = st[0x5d];
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0x114) = 0;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0x118) = 0;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0x11c) = 0;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0xa0) = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x13a] = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x13d] = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x110) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x10e) = -1;
    ((u8 *)lbl_8039C1F8[slot])[0x13c] = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xee) = *(s16 *)(st + 0x46);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xf0) = *(s16 *)(st + 0x48);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xf2) = *(s16 *)(st + 0x4a);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xf4) = *(s16 *)(st + 0x4c);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xf6) = *(s16 *)(st + 0x4e);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xf8) = *(s16 *)(st + 0x50);
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xfa) = *(s16 *)(st + 0x52);
    *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x12c) + base0 + 0x100;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 8) = 0;
    if (total != 0) {
        *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 8) = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + *(s8 *)(st + 0x5d) * 0x18;
    }

    {
        u8 *dst = *(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 8);
        int m;
        int off;
        for (m = 0, off = 0; m < *(s8 *)(((u8 *)lbl_8039C1F8[slot]) + 0x139); m++, off += 0x18) {
            (*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c))[off + 0x16] = (*(u8 **)st)[off + 0x16];
            *(s16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x14) = *(s16 *)(*(u8 **)st + off + 0x14);
            *(int *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x10) = 0;
            *(int *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off) = *(int *)(*(u8 **)st + off);
            if ((*(int *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off) & 0xf7fff180) == 0 &&
                *(s16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x14) != 0) {
                int k;
                *(int *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x10) = 0;
                *(u8 **)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x10) = dst;
                dst += *(s16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x14) * 2;
                for (k = 0; k < *(s16 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x14); k++) {
                    *(s16 *)(*(u8 **)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0x10) + k * 2) =
                        *(s16 *)(*(u8 **)(*(u8 **)st + off + 0x10) + k * 2);
                }
            }
            *(f32 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 4) = *(f32 *)(*(u8 **)st + off + 4);
            *(f32 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 8) = *(f32 *)(*(u8 **)st + off + 8);
            *(f32 *)(*(u8 **)(((u8 *)lbl_8039C1F8[slot]) + 0x9c) + off + 0xc) = *(f32 *)(*(u8 **)st + off + 0xc);
        }
    }

    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xfc) = -1;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xfe) = *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xfc) * 2 + 0xee);
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0xa4) = *(int *)(st + 0x54);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x60) = *(f32 *)(st + 0x2c);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x64) = *(f32 *)(st + 0x30);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x68) = *(f32 *)(st + 0x34);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xd4) = *(f32 *)(st + 0x38);
    if (*(int *)(((u8 *)lbl_8039C1F8[slot]) + 0xa4) & 1) {
        *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x18) = *(f32 *)(st + 0x2c);
        *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x1c) = *(f32 *)(st + 0x30);
        *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x20) = *(f32 *)(st + 0x34);
    }
    fz430 = lbl_803DF430;
    fz434 = lbl_803DF434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x24) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x28) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x2c) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x30) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x34) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x38) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x40) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x44) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x3c) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x50) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x48) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x4c) = fz434;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x5c) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x54) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x58) = fz430;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x106) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x108) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x10a) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x120) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x122) = 0;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x124) = 0;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xac) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xb0) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xb4) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xb8) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xbc) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xc0) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xc4) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xc8) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xcc) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0xd0) = fz430;
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x6c) = *(f32 *)(st + 0x20);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x70) = *(f32 *)(st + 0x24);
    *(f32 *)(((u8 *)lbl_8039C1F8[slot]) + 0x74) = *(f32 *)(st + 0x28);
    lbl_803DD280 = lbl_803DD280 + 1;
    if (lbl_803DD280 > 0x4e20) {
        lbl_803DD280 = 0;
    }
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x10c) = lbl_803DD280;
    *(s8 *)(((u8 *)lbl_8039C1F8[slot]) + 0x126) = lbl_803DD282;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xea) = (s16)c;
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xec) = (s16)e;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 4) = *(int *)(st + 4);
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0) = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x135] = st[0x5c];
    ((u8 *)lbl_8039C1F8[slot])[0x136] = *(int *)(st + 0x40);
    ((u8 *)lbl_8039C1F8[slot])[0x137] = *(int *)(st + 0x3c);
    ((u8 *)lbl_8039C1F8[slot])[0x138] = st[0x59];
    *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0xe6) = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x130] = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x13b] = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x13e] = 0;
    ((u8 *)lbl_8039C1F8[slot])[0x132] = st[0x5b];
    if (((u8 *)lbl_8039C1F8[slot])[0x132] != 0) {
        ((u8 *)lbl_8039C1F8[slot])[0x133] = 0x3c / ((u8 *)lbl_8039C1F8[slot])[0x132];
    } else {
        ((u8 *)lbl_8039C1F8[slot])[0x133] = 0;
    }
    if (((u8 *)lbl_8039C1F8[slot])[0x133] != 0) {
        ((u8 *)lbl_8039C1F8[slot])[0x134] = 0xff / ((u8 *)lbl_8039C1F8[slot])[0x133];
    } else {
        ((u8 *)lbl_8039C1F8[slot])[0x134] = 0;
    }
    ((u8 *)lbl_8039C1F8[slot])[0x131] = 0;
    *(int *)(((u8 *)lbl_8039C1F8[slot]) + 0xa8) = *(s16 *)(st + 0x44);
    return *(s16 *)(((u8 *)lbl_8039C1F8[slot]) + 0x10c);
}
#pragma peephole reset
#pragma scheduling reset

extern s16 renderModeSetOrGet(int mode);
extern void *Camera_GetCurrentViewSlot(void);
extern void *Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(void *mtx, int id);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void GXSetCullMode(int mode);
extern void setTextColor(void *ctx, int r, int g, int b, int a);
extern void _textSetColor(void *ctx, int r, int g, int b, int a);
extern void selectTexture(void *tex, int slot);
extern void drawFn_8005cf8c(void *a, void *b, int count);
extern f32 sqrtf(f32 x);
extern int getAngle(f32 dx, f32 dz);
extern void mathFn_80021ac8(void *obj, f32 *vec);
extern void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, s8 yawIndex);
extern void setMatrixFromObjectPos(f32 *mtx, s16 *src);
extern void mtx44Transpose(f32 *src, f32 *dst);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_80079328(void);
extern void fn_80078DFC(void);
extern void fn_80078ED0(void);
extern void geomDrawFn_800796f0(void);
extern void gxTexColorFn_80079254(void);
extern void gxBlendFn_80078b4c(void);
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
                    mathFn_80021ac8(&xf.ang[0], &pos[0]);
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
                dirZ = *(f32 *)((char *)view + 0x4c) - *(f32 *)(*(char **)((char *)*p + 4) + 0x20);
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
                fn_80079328();
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
  u8 *bufB = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
  u8 *bufA = *(u8 **)((char *)state + 0x80);
  int j;

  if (mode == 1) {
    f32 target = *(f32 *)((char *)p + 0x4);
    s16 frames = *(s16 *)((char *)state + 0xfe);
    if (frames != 0) {
      *(f32 *)((char *)state + idx * 8 + 0xac) =
          (target - (f32)(u32)bufA[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xf]) / (f32)frames;
      *(f32 *)((char *)state + idx * 8 + 0xb0) =
          (f32)(u32)bufA[(*(s16 **)((char *)p + 0x10))[0] * 16 + 0xf];
      goto animate;
    }
    {
      int val = (int)target;
      for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
        bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] = val;
        bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] =
            bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf];
      }
    }
    return;
  }
animate:
  *(f32 *)((char *)state + idx * 8 + 0xb0) =
      *(f32 *)((char *)state + idx * 8 + 0xb0) +
      *(f32 *)((char *)state + idx * 8 + 0xac) * lbl_803DD284;
  if (*(f32 *)((char *)state + idx * 8 + 0xb0) < lbl_803DF430) {
    *(f32 *)((char *)state + idx * 8 + 0xb0) = lbl_803DF430;
  } else if (*(f32 *)((char *)state + idx * 8 + 0xb0) > lbl_803DF43C) {
    *(f32 *)((char *)state + idx * 8 + 0xb0) = lbl_803DF43C;
  }
  for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
    bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] = (int)*(f32 *)((char *)state + idx * 8 + 0xb0);
    bufA[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf] =
        bufB[(*(s16 **)((char *)p + 0x10))[j] * 16 + 0xf];
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
    f32 tx = *(f32 *)((char *)p + 0x4);
    f32 ty = *(f32 *)((char *)p + 0x8);
    f32 tz = *(f32 *)((char *)p + 0xc);
    if (*(s16 *)((char *)state + 0xfe) != 0) {
      *(f32 *)(base + 0x3c) = (tx - *(f32 *)(base + 0x30)) / (f32)*(s16 *)((char *)state + 0xfe);
      *(f32 *)(base + 0x40) = (ty - *(f32 *)(base + 0x34)) / (f32)*(s16 *)((char *)state + 0xfe);
      *(f32 *)(base + 0x44) = (tz - *(f32 *)(base + 0x38)) / (f32)*(s16 *)((char *)state + 0xfe);
    } else {
      u8 *buf = *(u8 **)((char *)state + 0x80);
      u8 *buf2 = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
      for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
        s16 v = (*(s16 **)((char *)p + 0x10))[j];
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
    u8 *buf = *(u8 **)((char *)state + 0x80);
    u8 *buf2 = *(u8 **)((char *)state + *(u8 *)((char *)state + 0x130) * 4 + 0x78);
    for (j = 0; j < *(s16 *)((char *)p + 0x14); j++) {
      s16 v = (*(s16 **)((char *)p + 0x10))[j];
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

extern u8 gExpgfxUpdatingActivePools;
extern int Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int size, int type);
extern int *Obj_SetupObject(int *obj, int a, int b, int c, int d);
extern void ObjList_GetObjects(int *idx, int *count);
extern void *Resource_Acquire(int id, int a);
extern void Sfx_StopObjectChannel(void *obj, int ch);
extern void Sfx_PlayFromObject(void *obj, int id);
extern f32 lbl_803DF43C;
extern f32 timeDelta;
extern u8 framesThisStep;

typedef void (*ExpFn2)(void *, int);
typedef void (*ExpFn3)(void *, void *, int);
typedef void (*ExpFn4)(void *, void *, int, int);
typedef void (*ExpSpawn6)(void *, int, void *, int, int, void *);
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
            if (*(s16 *)((char *)eff + 0x10c) == -1) break;
            active = 0;
            *(u8 *)((char *)eff + 0x13e) = 0;
            if (*(s16 *)((char *)eff + 0xfe) < 0 || *(s16 *)((char *)eff + 0xfc) == -1) {
                *(s16 *)((char *)eff + 0xfc) += 1;
                if (*(s16 *)((char *)eff + 0xfc) > 6) {
                    fn_800A1040(*(s16 *)((char *)eff + 0x10c), 0);
                    goto slot_done;
                }
                *(s16 *)((char *)eff + 0xfe) = *(s16 *)((char *)eff + *(s16 *)((char *)eff + 0xfc) * 2 + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            } else if (*(u8 *)((char *)eff + 0x13c) != 0) {
                *(s16 *)((char *)eff + 0xfc) = *(u8 *)((char *)eff + 0x13c);
                *(u8 *)((char *)eff + 0x13c) = 0;
                if (*(s16 *)((char *)eff + 0xfc) > 6) {
                    fn_800A1040(*(s16 *)((char *)eff + 0x10c), 0);
                    goto slot_done;
                }
                *(s16 *)((char *)eff + 0xfe) = *(s16 *)((char *)eff + *(s16 *)((char *)eff + 0xfc) * 2 + 0xee);
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            cntC = 0;
            cntA = 0;
            ((ExpFn3)fn_800A0FD0)(eff, E9 + emIdx * 0x18, active);
            feFlag = 0;
            emIdx = 0;
            emOff = 0;
            for (; emIdx < *(s8 *)((char *)eff + 0x139); emIdx++, emOff += 0x18) {
                int flags;
                if (*(s16 *)((char *)eff + 0xfc) != *(u8 *)(E9 + emOff + 0x16)) continue;
                flags = *(int *)(E9 + emOff);
                if ((flags & 0x1000) && *(f32 *)(E9 + emOff + 0x4) > lbl_803DF430 && *(s16 *)((char *)eff + 0xfc) > 0) {
                    *(s16 *)((char *)eff + 0xfc) = *(s16 *)(E9 + emIdx * 0x18 + 0x14);
                    *(f32 *)(E9 + emIdx * 0x18 + 0x4) = *(f32 *)(E9 + emIdx * 0x18 + 0x4) - lbl_803DF434;
                    *(s16 *)((char *)eff + 0xfe) = -1;
                    break;
                }
                if (flags & 0x2000) {
                    if (*(u8 *)((char *)eff + 0x13a) != 0) {
                        *(u8 *)((char *)eff + 0x13a) = 0;
                        *(int *)(E9 + emIdx * 0x18) = 0;
                        *(int *)(E9 + emIdx * 0x18) = 0x20;
                        *(s16 *)((char *)eff + 0xfe) = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (*(s16 *)((char *)eff + 0xfc) > 0) {
                        feFlag = 1;
                        *(s16 *)((char *)eff + 0xfc) = *(s16 *)(E9 + emIdx * 0x18 + 0x14);
                        *(s16 *)((char *)eff + 0xfe) = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000) {
                    tmpl.x = *(f32 *)((char *)eff + 0x60);
                    tmpl.y = *(f32 *)((char *)eff + 0x64);
                    tmpl.z = *(f32 *)((char *)eff + 0x68);
                    q[1] = lbl_803DF430;
                    q[2] = lbl_803DF430;
                    q[3] = lbl_803DF430;
                    q[0] = lbl_803DF434;
                    if (*(int *)((char *)eff + 0xa4) & 1) {
                        ang[0] = *(s16 *)((char *)eff + 0xc);
                    } else {
                        ang[0] = *(s16 *)(*(int **)((char *)eff + 4));
                    }
                    ang[1] = 0;
                    ang[2] = 0;
                    mathFn_80021ac8(&ang[0], &tmpl.x);
                    if (*(int *)eff == 0) {
                        if (Obj_IsLoadingLocked()) {
                            int *o;
                            if (*(int *)((char *)eff + 0xa4) & 1) {
                                tmpl.x += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x18);
                                tmpl.y += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x1c);
                                tmpl.z += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x20);
                            } else {
                                tmpl.x += *(f32 *)((char *)eff + 0x18);
                                tmpl.y += *(f32 *)((char *)eff + 0x1c);
                                tmpl.z += *(f32 *)((char *)eff + 0x20);
                            }
                            o = Obj_AllocObjectSetup(0x20, 0x66);
                            *(f32 *)((char *)o + 0x8) = tmpl.x;
                            *(f32 *)((char *)o + 0xc) = tmpl.y;
                            *(f32 *)((char *)o + 0x10) = tmpl.z;
                            *(int *)eff = (int)Obj_SetupObject(o, 5, -1, -1, 0);
                            *(int *)(*(int *)eff + 0xf8) = 1;
                        }
                    } else if (*(int *)eff != 0) {
                        if (*(int *)((char *)eff + 0xa4) & 1) {
                            tmpl.x += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x18);
                            tmpl.y += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x1c);
                            tmpl.z += *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x20);
                        } else {
                            tmpl.x += *(f32 *)((char *)eff + 0x18);
                            tmpl.y += *(f32 *)((char *)eff + 0x1c);
                            tmpl.z += *(f32 *)((char *)eff + 0x20);
                        }
                        *(f32 *)(*(int *)eff + 0x18) = tmpl.x;
                        *(f32 *)(*(int *)eff + 0x1c) = tmpl.y;
                        *(f32 *)(*(int *)eff + 0x20) = tmpl.z;
                    }
                    if (*(int *)eff != 0) {
                        int *o = *(int **)eff;
                        int *list = *(int **)((char *)*(int **)((char *)o + 0x54) + 0x50);
                        if (list != NULL) {
                            if (*(s16 *)((char *)list + 0x44) == (int)*(f32 *)(E9 + emOff + 0x4)) {
                                Obj_FreeObject(o);
                                *(int *)eff = 0;
                                *(int *)(E9 + emIdx * 0x18) ^= 0x10000000;
                                if (*(f32 *)(E9 + emIdx * 0x18 + 0xc) >= lbl_803DF430 && *(int **)((char *)eff + 4) != NULL) {
                                    (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(
                                        *(int **)((char *)eff + 4), (int)*(f32 *)(E9 + emIdx * 0x18 + 0xc),
                                        &tmpl, 0x200001, -1, NULL);
                                }
                                *(u8 *)((char *)eff + 0x13c) = (int)*(f32 *)(E9 + emIdx * 0x18 + 0x8);
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
                    *(s16 *)((char *)eff + 0x106) = *(s16 *)((char *)eff + 0x106) + (int)(*(f32 *)(E9 + emOff + 0x4) * lbl_803DD284);
                    *(s16 *)((char *)eff + 0x108) = *(s16 *)((char *)eff + 0x108) + (int)(*(f32 *)(E9 + emOff + 0x8) * lbl_803DD284);
                    *(s16 *)((char *)eff + 0x10a) = *(s16 *)((char *)eff + 0x10a) + (int)(*(f32 *)(E9 + emOff + 0xc) * lbl_803DD284);
                }
                if (*(int *)(E9 + emOff) & 0x80) {
                    ((ExpFn4)fn_800A09C4)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x8000000) {
                    *(f32 *)(E9 + emOff + 0xc) = (f32)randomGetRange(0, 0xffff);
                    ((ExpFn4)fn_800A09C4)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x4000) {
                    ((ExpFn4)fn_800A02DC)(eff, E9 + emOff, active, 0);
                }
                if ((*(int *)(E9 + emOff) & 0x10000) && active != 0) {
                    if (*(s16 *)(E9 + emOff + 0x14) == -1) {
                        Sfx_StopObjectChannel(*(int **)((char *)eff + 4), 0x40);
                    } else {
                        Sfx_PlayFromObject(*(int **)((char *)eff + 4), (u16)*(s16 *)(E9 + emOff + 0x14));
                    }
                }
                if (*(int *)(E9 + emOff) & 0x100000) {
                    if (active == 1) {
                        if (*(s16 *)((char *)eff + 0xfe) != 0) {
                            *(f32 *)((char *)eff + 0xbc) =
                                (*(f32 *)(E9 + emOff + 0x4) - (f32)(u32)*(u8 *)((char *)*(int **)((char *)eff + 4) + 0x36)) /
                                (f32)*(s16 *)((char *)eff + 0xfe);
                            *(f32 *)((char *)eff + 0xc0) = (f32)(u32)*(u8 *)((char *)*(int **)((char *)eff + 4) + 0x36);
                        } else {
                            *(f32 *)((char *)eff + 0xbc) =
                                *(f32 *)(E9 + emOff + 0x4) - (f32)(u32)*(u8 *)((char *)*(int **)((char *)eff + 4) + 0x36);
                            *(f32 *)((char *)eff + 0xc0) = lbl_803DF430;
                        }
                    }
                    *(f32 *)((char *)eff + 0xc0) = *(f32 *)((char *)eff + 0xc0) + *(f32 *)((char *)eff + 0xbc);
                    if (*(f32 *)((char *)eff + 0xc0) > lbl_803DF43C) {
                        *(f32 *)((char *)eff + 0xc0) = lbl_803DF43C;
                    } else if (*(f32 *)((char *)eff + 0xc0) < lbl_803DF430) {
                        *(f32 *)((char *)eff + 0xc0) = lbl_803DF430;
                    }
                    *(u8 *)((char *)*(int **)((char *)eff + 4) + 0x36) = (int)*(f32 *)((char *)eff + 0xc0);
                }
                if (*(int *)(E9 + emOff) & 0x400000) {
                    ((ExpFn4)fn_800A081C)(eff, E9 + emOff, active, 0);
                }
                if (*(int *)(E9 + emOff) & 0x80000000) {
                    *(f32 *)((char *)eff + 0x24) = *(f32 *)(E9 + emOff + 0x4) * lbl_803DD284 + *(f32 *)((char *)eff + 0x24);
                    *(f32 *)((char *)eff + 0x28) = *(f32 *)(E9 + emOff + 0x8) * lbl_803DD284 + *(f32 *)((char *)eff + 0x28);
                    *(f32 *)((char *)eff + 0x2c) = *(f32 *)(E9 + emOff + 0xc) * lbl_803DD284 + *(f32 *)((char *)eff + 0x2c);
                }
                if (*(int *)(E9 + emOff) & 0x800000) {
                    if ((*(int *)(E9 + emOff) & 0x1000000) && lbl_803DF430 == *(f32 *)(E9 + emOff + 0x8)) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (randomGetRange(0, (int)*(f32 *)(E9 + emOff + 0xc)) == 0) {
                                if (*(int *)((char *)eff + 0xa4) & 1) {
                                    (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), NULL, 0x10001, -1, NULL);
                                } else {
                                    (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), NULL, 0x10001, -1, NULL);
                                }
                            }
                        }
                    } else if (lbl_803DF430 == *(f32 *)(E9 + emOff + 0x8)) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (*(int *)((char *)eff + 0xa4) & 1) {
                                (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), (char *)eff + 0xc, 0x10002, -1, NULL);
                            } else {
                                (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), NULL, 0x10002, -1, NULL);
                            }
                        }
                    } else if (lbl_803DF434 == *(f32 *)(E9 + emOff + 0x8)) {
                        if (*(int *)((char *)eff + 0xa4) & 1) {
                            tmpl.x = *(f32 *)((char *)eff + 0x60);
                            tmpl.y = *(f32 *)((char *)eff + 0x64);
                            tmpl.z = *(f32 *)((char *)eff + 0x68);
                            if (*(int **)((char *)eff + 4) != NULL) {
                                (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        } else {
                            tmpl.x = *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x18) + *(f32 *)((char *)eff + 0x60);
                            tmpl.y = *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x1c) + *(f32 *)((char *)eff + 0x64);
                            tmpl.z = *(f32 *)((char *)*(int **)((char *)eff + 4) + 0x20) + *(f32 *)((char *)eff + 0x68);
                            if (*(int **)((char *)eff + 4) != NULL) {
                                (*(ExpSpawn6 *)(*(int *)gPartfxInterface + 8))(*(int **)((char *)eff + 4), *(s16 *)(E9 + emOff + 0x14), &tmpl, 0x10001, -1, NULL);
                            }
                        }
                    }
                }
                if (*(int *)(E9 + emOff) & 0x4000000) {
                    res = Resource_Acquire((u16)(*(s16 *)(E9 + emOff + 0x14) + 0x58), 1);
                    if (*(int *)(E9 + emOff) & 0x1000000) {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (randomGetRange(0, 5) == 0) {
                                if (*(int *)((char *)eff + 0xa4) & 1) {
                                    (*(ExpResFn6 *)(*(int *)res + 4))(NULL, 0, (char *)eff + 0xc, 1, -1, NULL);
                                } else {
                                    (*(ExpResFn6 *)(*(int *)res + 4))(*(int **)((char *)eff + 4), 0, NULL, 1, -1, NULL);
                                }
                            }
                        }
                    } else {
                        for (k = 0; k < (int)*(f32 *)(E9 + emOff + 0x4); k++) {
                            if (*(int *)((char *)eff + 0xa4) & 1) {
                                (*(ExpResFn6 *)(*(int *)res + 4))(NULL, 0, (char *)eff + 0xc, 1, -1, NULL);
                            } else {
                                (*(ExpResFn6 *)(*(int *)res + 4))(*(int **)((char *)eff + 4), 0, NULL, 1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0) {
                *(s16 *)((char *)eff + 0xfe) = *(s16 *)((char *)eff + 0xfe) - framesThisStep;
            }
        }
    slot_done:
        gExpgfxUpdatingActivePools = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
