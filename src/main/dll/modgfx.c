#include "ghidra_import.h"
#include "main/expgfx_internal.h"
#include "main/dll/modgfx.h"

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
extern int FUN_80006714();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d4();
extern undefined4 FUN_80006930();
extern undefined4 FUN_80006974();
extern void* FUN_800069a8();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017704();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern uint FUN_80017830();
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
extern void expgfx_initialise();
extern undefined4 FUN_80135814();
extern undefined4 FUN_802420e0();
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
extern f32 lbl_803E0630;
extern f32 lbl_803E0634;
extern f32 lbl_803E0638;
extern f32 lbl_803E063C;
extern f32 lbl_803E0650;
extern f32 lbl_803E0654;
extern f32 lbl_803E0658;
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
 * Function: modgfx_resetExpgfxState
 * EN v1.0 Address: 0x8009FED0
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x8009FF68
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void modgfx_resetExpgfxState(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                             undefined8 param_4,undefined8 param_5,undefined8 param_6,
                             undefined8 param_7,undefined8 param_8)
{
  undefined *puVar1;
  undefined4 *puVar2;
  undefined *puVar3;
  undefined2 *puVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  piVar7 = &DAT_8039b7b8;
  expgfx_initialise(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  puVar2 = &gExpgfxPoolActiveMasks;
  puVar3 = &gExpgfxPoolActiveCounts;
  puVar4 = &gExpgfxPoolSlotTypeIds;
  puVar1 = &gExpgfxPoolFrameFlags;
  puVar5 = &gExpgfxPoolSourceModes;
  puVar6 = &gExpgfxPoolSourceIds;
  iVar8 = EXPGFX_POOL_GROUP_COUNT;
  do {
    *puVar2 = 0;
    *puVar3 = 0;
    *puVar4 = 0xffff;
    *puVar1 = 0;
    *puVar5 = 0;
    *puVar6 = 0;
    puVar2[1] = 0;
    puVar3[1] = 0;
    puVar4[1] = 0xffff;
    puVar1[1] = 0;
    puVar5[1] = 0;
    puVar6[1] = 0;
    puVar2[2] = 0;
    puVar3[2] = 0;
    puVar4[2] = 0xffff;
    puVar1[2] = 0;
    puVar5[2] = 0;
    puVar6[2] = 0;
    puVar2[3] = 0;
    puVar3[3] = 0;
    puVar4[3] = 0xffff;
    puVar1[3] = 0;
    puVar5[3] = 0;
    puVar6[3] = 0;
    puVar2[4] = 0;
    puVar3[4] = 0;
    puVar4[4] = 0xffff;
    puVar1[4] = 0;
    puVar5[4] = 0;
    puVar6[4] = 0;
    puVar2[5] = 0;
    puVar3[5] = 0;
    puVar4[5] = 0xffff;
    puVar1[5] = 0;
    puVar5[5] = 0;
    puVar6[5] = 0;
    puVar2[6] = 0;
    puVar3[6] = 0;
    puVar4[6] = 0xffff;
    puVar1[6] = 0;
    puVar5[6] = 0;
    puVar6[6] = 0;
    puVar2[7] = 0;
    puVar3[7] = 0;
    puVar4[7] = 0xffff;
    puVar1[7] = 0;
    puVar5[7] = 0;
    puVar6[7] = 0;
    puVar2 = puVar2 + 8;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    puVar5 = puVar5 + 8;
    puVar6 = puVar6 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  DAT_8039c7cc = 0;
  DAT_8039c7c8 = 0;
  DAT_8039c7d4 = 0;
  DAT_8039c7d0 = 0;
  DAT_803dded8 = 1;
  iVar8 = 0;
  do {
    if (*piVar7 != 0) {
      FUN_80053754();
    }
    *piVar7 = 0;
    piVar7[2] = 0;
    piVar7[1] = 0;
    piVar7[3] = 0;
    piVar7 = piVar7 + 4;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 0x20);
  DAT_803dded8 = 0;
  return;
}

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
  
  expgfx_initialise(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
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
  gExpgfxSpawnConfig.velocitySource = (void *)uVar1;
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
  FUN_800a11cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1);
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
        dVar23 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_124 = (int)*(short *)(iVar9 + 0x16) ^ 0x80000000;
        local_128 = 0x43300000;
        dVar22 = (double)(float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803e0100);
        fVar3 = *(float *)(param_5 + 0x14);
        uStack_11c = (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000;
        local_120 = 0x43300000;
        dVar21 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_114 = (int)*(short *)(iVar9 + 0x12) ^ 0x80000000;
        local_118 = 0x43300000;
        dVar20 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_114) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_10c = (int)*(short *)(iVar9 + 0x18) ^ 0x80000000;
        local_110 = 0x43300000;
        dVar19 = (double)(float)((double)CONCAT44(0x43300000,uStack_10c) - DOUBLE_803e0100);
        uStack_104 = (int)*(short *)(iVar9 + 0x1e) ^ 0x80000000;
        local_108 = 0x43300000;
        dVar18 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_104) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_fc = (int)*(short *)(iVar9 + 0x14) ^ 0x80000000;
        local_100 = 0x43300000;
        dVar17 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_f4 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e0100);
        uStack_ec = (int)*(short *)(iVar9 + 0x20) ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar14 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_ec) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_e4 = FUN_80017760(1,1000);
        uStack_e4 = uStack_e4 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar12 = (double)((float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803e0100) /
                         lbl_803E00F4);
        uStack_dc = FUN_80017760(1,1000);
        uStack_dc = uStack_dc ^ 0x80000000;
        local_e0 = 0x43300000;
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
          uVar6 = FUN_80017760(0,0x1e);
          if (uVar6 == 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x72,&local_148,0x200001,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x11') {
          uVar6 = FUN_80017760(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x14') {
          uVar6 = FUN_80017760(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x15') {
          uVar6 = FUN_80017760(0,8);
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
                         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0100)),
                 (double)(*(float *)(param_1 + 0x14) -
                         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0100)),uVar1,
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
  uVar7 = FUN_80017690(0x468);
  if (uVar7 != 0) {
    FUN_80017698(0x468,0);
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
    uVar7 = FUN_80017760(0,1);
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
    uVar3 = FUN_80017760(1,100);
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
      uVar3 = FUN_80017760(0xfffffffa,6);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_58 - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0xfffffffa,6);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(0xfffffffa,6);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(4,8);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E0878 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0x24;
      local_60 = 0x41;
      local_7c = 0x100111;
      local_7e = 0xc10;
      break;
    default:
      goto LAB_800bd57c;
    case 0xca:
      if (param_3 == (ExpgfxAttachedSourceState *)0x0) goto LAB_800bd57c;
      uStack_3c = FUN_80017760(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = lbl_803E087C * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = lbl_803E087C * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = lbl_803E0880 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = lbl_803E0874;
      local_c8 = lbl_803E0874;
      local_c4 = lbl_803E0874;
      local_d0 = lbl_803E0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = param_3->sourceVecX;
      FUN_80017748(local_d8,&local_9c);
      uVar3 = FUN_80017760(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = lbl_803E0884 * (float)(local_58 - DOUBLE_803e08f0);
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
      uStack_3c = FUN_80017760(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = lbl_803E0888 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = lbl_803E088C * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = lbl_803E0888 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = lbl_803E0874;
      local_c8 = lbl_803E0874;
      local_c4 = lbl_803E0874;
      local_d0 = lbl_803E0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = param_3->sourceVecX;
      FUN_80017748(local_d8,&local_9c);
      uVar3 = FUN_80017760(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = lbl_803E0890 * (float)(local_58 - DOUBLE_803e08f0);
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
      uStack_3c = FUN_80017760(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(1,2);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = lbl_803E0894 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80017760(0xfffffff6,10);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = lbl_803E0898 * (float)(local_58 - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = lbl_803E0898 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(4,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = lbl_803E089C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0xff;
      local_7c = 0x80108;
      local_7e = 0x5c;
      break;
    case 0xcd:
      uStack_2c = FUN_80017760(0,0xfa);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E08A0 + local_90 / lbl_803E08A0 +
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_88 = lbl_803E08A4 * local_90;
      uStack_3c = FUN_80017760(0x28,0x50);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E08A8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xce:
      uStack_2c = FUN_80017760(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = lbl_803E08AC + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xfffffff8,8);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E08B0 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = lbl_803E08B4 + (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(0,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = lbl_803E08B8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0x28,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = lbl_803E086C * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80017760(0,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_c0[2] = (int)(lbl_803E08BC + (float)(local_58 - DOUBLE_803e08f0));
      local_28 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xcf:
      uVar3 = FUN_80017760(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E08A0 + local_90 / lbl_803E08A0 +
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_88 = -local_90;
      uStack_34 = FUN_80017760(0x28,0x50);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = lbl_803E08A8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xd0:
      uVar3 = FUN_80017760(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = lbl_803E08C0 + (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(0xfffffff8,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E08B0 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = lbl_803E08C4 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = lbl_803E08B8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = lbl_803E086C * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(lbl_803E08BC +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd1:
      uVar3 = FUN_80017760(0x46,0x50);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = lbl_803E086C * (float)(local_28 - DOUBLE_803e08f0);
      uVar3 = FUN_80017760(0,0xf);
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
      uVar3 = FUN_80017760(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E08C8 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(0xfffffffb,5);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = lbl_803E0864 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = lbl_803E08CC * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      local_c0[2] = 0xa0;
      local_60 = 0x7d;
      local_7c = 0x180108;
      local_7e = 0x5c;
      break;
    case 0xd4:
      uVar3 = FUN_80017760(0xfffffff6,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(0,0x1c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = lbl_803E08D0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = lbl_803E08D4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80017760(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(lbl_803E08D8 +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
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
      uVar3 = FUN_80017760(0xffffff74,0x8c);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = lbl_803E08E0 * (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80017760(0xffffffce,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E08E0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80017760(0xffffff74,0x8c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = lbl_803E08E0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80017760(0xf,0x23);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = lbl_803E08E4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80017760(1,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = lbl_803E08E8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
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
      local_b8[2] = FUN_80017760(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 100;
      local_57 = 0x1e;
      break;
    case 0x423:
      uStack_4c = FUN_80017760(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_44 = FUN_80017760(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_3c = FUN_80017760(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_34 = FUN_80017760(5,0xb);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = lbl_803E0900 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x80110;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x424:
      uStack_34 = FUN_80017760(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80017760(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_44 = FUN_80017760(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = lbl_803E0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_4c = FUN_80017760(0xfffffffb,5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = lbl_803E0904 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_2c = FUN_80017760(3,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = lbl_803E0904 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      uStack_24 = FUN_80017760(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = lbl_803E0904 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_1c = FUN_80017760(5,0xb);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = lbl_803E091C * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x1480200;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x425:
      uStack_1c = FUN_80017760(8,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = lbl_803E0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uVar2 = FUN_80017760(0,0x28);
      if (uVar2 == 0) {
        uStack_1c = FUN_80017760(0x15,0x29);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = lbl_803E0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = 0x1cc;
      }
      else {
        uStack_1c = FUN_80017760(8,0x14);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = lbl_803E0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = FUN_80017760(0x5a,0x78);
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
      uStack_1c = FUN_80017760(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = lbl_803E0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80017760(8,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = lbl_803E0920 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E0920 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
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
      local_68 = FUN_80017760(0,0x8000);
      local_64 = local_68;
      break;
    case 0x427:
      uStack_1c = FUN_80017760(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948) / lbl_803E0928;
      uStack_24 = FUN_80017760(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948) / lbl_803E092C;
      uStack_2c = FUN_80017760(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948) / lbl_803E0928;
      uStack_34 = FUN_80017760(1,4);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = lbl_803E0930 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80017760(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = lbl_803E0938 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948)
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
      local_b8[2] = FUN_80017760(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 0xc7e;
      local_57 = 0x1e;
      break;
    case 0x42c:
      uStack_1c = FUN_80017760(0xfffffff6,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = lbl_803E0940 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80017760(10,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = lbl_803E0918 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80017760(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E0940 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
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
      uStack_1c = FUN_80017760(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = lbl_803E0944 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80017760(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = lbl_803E0944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
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
void fn_800A3AA8(void) {}
void fn_800A3AAC(void) {}
void fn_800A3AB0(void) {}
void projgfx_onMapSetup(void) {}
void projgfx_initialise(void) {}
void fn_800A432C(void) {}
void fn_800A4330(void) {}
void fn_800A4334(void) {}
void fn_800A4338(void) {}
void fn_800A4A20(void) {}
void fn_800A4BA8(void) {}
void fn_800A4BAC(void) {}
void partfx_onMapSetup(void) {}
void fn_800B3190(void) {}
void Effect1_release(void) {}
void Effect1_initialise(void) {}
void fn_800B6EEC(void) {}
void Effect2_release(void) {}
void Effect2_initialise(void) {}
void fn_800B8D6C(void) {}
void fn_800B8D70(void) {}
void Effect3_release(void) {}
void Effect3_initialise(void) {}
void fn_800BC238(void) {}
void Effect4_release(void) {}
void Effect4_initialise(void) {}
void fn_800BD430(void) {}
void Effect5_release(void) {}
void Effect5_initialise(void) {}
void fn_800BE028(void) {}
void Effect6_release(void) {}
void Effect6_initialise(void) {}
void fn_800BF96C(void) {}
void Effect7_release(void) {}
void Effect7_initialise(void) {}
void fn_800C11C0(void) {}
void Effect8_release(void) {}
void Effect8_initialise(void) {}
void fn_800C2910(void) {}
void Effect9_release(void) {}
void Effect9_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_800A3AA0(void) { return 0x0; }

/* sda21 accessors. */
extern s16 lbl_803DD288;
extern s16 lbl_803DD28A;
s16 fn_8009FFF0(void) { return lbl_803DD288; }
void fn_800A01B0(s16 x) { lbl_803DD28A = x; }

/* OSReport(literal) wrapper. */
extern char sProjgfxReleaseDoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
void projgfx_release_doUnsupported(void) { OSReport(sProjgfxReleaseDoNoLongerSupported); }
#pragma peephole reset
#pragma scheduling reset

/* OSReport-stub returns. */
extern void OSReport(const char *fmt, ...);
extern char sProjgfxRayhitDoNoLongerSupported[];
extern char sProjgfxSetzscaleDoNoLongerSupported[];
#pragma scheduling off
#pragma peephole off
int projgfx_rayhit_doUnsupported(void) { OSReport(sProjgfxRayhitDoNoLongerSupported); return 0x0; }
int projgfx_setzscale_doUnsupported(void) { OSReport(sProjgfxSetzscaleDoNoLongerSupported); return 0x0; }
#pragma peephole reset
#pragma scheduling reset

/* Pattern wrappers. */
int fn_800A3AB4(void) { return -0x1; }
