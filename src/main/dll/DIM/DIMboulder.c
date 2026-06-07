#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/resource.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState {
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

/*
 * Per-object extra state for the magiclight proximity light
 * (magiclight_getExtraSize == 0x14 for non-0x172 types).
 */
typedef struct MagicLightState {
    f32 triggerRadius; /* preset by subtype */
    s16 lifetime; /* rand(200,600) at init */
    s16 enterAction; /* L-action when the player enters the radius */
    s16 leaveAction; /* L-action when the player leaves radius + hysteresis */
    u8 pad0A;
    s8 inRange; /* hysteresis latch */
    s8 subtype; /* params+0x1A */
    u8 pad0D[3];
    s16 unk10; /* 301 at init */
    u8 pad12[2];
} MagicLightState;

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */
typedef struct Dll16CState {
    void *linkedObj; /* group-10 object matched by type (364/367) */
    f32 unk04; /* set on anim event 2 */
    f32 snapX; /* path point snapshot taken on anim event 2 */
    f32 snapY;
    f32 snapZ;
    f32 pathPointX; /* path point 1 world position, refreshed in render */
    f32 pathPointY;
    f32 pathPointZ;
    u8 opacity; /* distance fade; 0xFF when unlinked */
    s8 subObjIndex; /* lbl_802C2308 id selector; -1 = clear (anim event 3) */
    s8 subObjIndexApplied;
    u8 pad23;
} Dll16CState;

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/*
 * Per-object extra state for the crrockfall falling rock
 * (crrockfall_getExtraSize == 0x14).
 */
typedef struct CrRockfallCfgEntry {
    f32 unk00;
    s32 landSfx; /* 0 = none */
    f32 restOffsetY; /* scaled by obj scale, added to floorY at rest */
} CrRockfallCfgEntry;

typedef struct CrRockfallState {
    CrRockfallCfgEntry *cfg; /* lbl_803236B8 entry 0, or entry 1 for type 0x600 */
    f32 floorY; /* probed landing height */
    f32 startY; /* obj Y at init; fade fraction reference */
    u8 mode; /* 0 armed, 1 falling, 2 resting, 3 shattered */
    u8 fallStarted;
    u8 floorFound;
    u8 pad0F;
    s16 fallDelay; /* params+0x1E; counts down while the player is in range */
    u8 pad12[2];
} CrRockfallState;

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);


extern undefined4 getLActions();
extern undefined4 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint GameBit_Get(int eventId);
extern undefined8 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800614c4();
extern int FUN_800632f4();
extern undefined8 FUN_80080f14();
extern undefined4 FUN_80080f18();
extern undefined4 FUN_8008112c();
extern int FUN_800e8b98();
extern undefined4 FUN_800ea9b8();
extern undefined4 FUN_801abf38();
extern undefined4 SH_LevelControl_runBloopEvent();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern int FUN_80294dbc();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern undefined4 DAT_80324188;
extern undefined4 DAT_803241c0;
extern undefined4 DAT_803241f8;
extern undefined4 DAT_80324230;
extern undefined4 DAT_803242f8;
extern undefined4 DAT_80324304;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern MapEventInterface **DAT_803dd72c;
extern undefined4 DAT_803de7c0;
extern f64 DOUBLE_803e5390;
extern f64 DOUBLE_803e53c0;
extern f32 lbl_803DC074;
extern f32 lbl_803E536C;
extern f32 lbl_803E5374;
extern f32 lbl_803E5378;
extern f32 lbl_803E5380;
extern f32 lbl_803E5384;
extern f32 lbl_803E5388;
extern f32 lbl_803E5398;
extern f32 lbl_803E539C;
extern f32 lbl_803E53A0;
extern f32 lbl_803E53A4;
extern f32 lbl_803E53A8;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B4;
extern f32 lbl_803E53B8;
extern f32 lbl_803E53C8;
extern f32 lbl_803E53D0;
extern f32 lbl_803E53D8;
extern f32 lbl_803E53DC;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53F0;

/*
 * --INFO--
 *
 * Function: FUN_801ac248
 * EN v1.0 Address: 0x801AC248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AC4FC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac248(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ac24c
 * EN v1.0 Address: 0x801AC24C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801AC5D0
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac24c(int param_1)
{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  GameBit_Set(0x3a3,0);
  GameBit_Set(0x3a2,0);
  iVar1 = FUN_80017a98();
  iVar1 = FUN_80294dbc(iVar1);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x48))();
  }
  uVar2 = FUN_80044404(0x17);
  FUN_80042bec(uVar2,1);
  if (iVar1 == 1) {
    (**(code **)(*DAT_803dd6e8 + 0x40))(1);
    *puVar3 = 5;
    GameBit_Set(0x37b,1);
  }
  else {
    *puVar3 = 6;
    GameBit_Set(0xce,1);
  }
  GameBit_Set(0x378,0);
  GameBit_Set(0x3b9,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac340
 * EN v1.0 Address: 0x801AC340
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x801AC6BC
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac340(int param_1,undefined *param_2)
{
  uint uVar1;
  int iVar2;
  
  (**(code **)(*DAT_803dd6e8 + 0x40))(0);
  uVar1 = GameBit_Get(0x3a3);
  if (uVar1 != 0) {
    GameBit_Set(0x3a3,0);
    GameBit_Set(0x3a2,0);
    GameBit_Set(0x378,0);
    GameBit_Set(0x3b9,0);
    iVar2 = FUN_80017a98();
    iVar2 = FUN_80294dbc(iVar2);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x48))();
    }
    GameBit_Set(0x4e5,1);
    (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_1 + 0xac),1,1);
    if (iVar2 == 1) {
      (**(code **)(*DAT_803dd6e8 + 0x40))(1);
      *param_2 = 5;
      GameBit_Set(0x379,1);
    }
    else {
      *param_2 = 6;
      GameBit_Set(0xcb,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ac490
 * EN v1.0 Address: 0x801AC490
 * EN v1.0 Size: 2148b
 * EN v1.1 Address: 0x801AC7FC
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac490(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  char cVar1;
  uint uVar2;
  int iVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  puVar3 = *(undefined **)(param_9 + 0xb8);
  switch(*puVar3) {
  case 1:
    uVar2 = GameBit_Get(0xadc);
    if ((uVar2 == 0) || (uVar2 = GameBit_Get(0xadd), uVar2 == 0)) {
      uVar2 = GameBit_Get(0x70);
      if (uVar2 != 0) {
        *puVar3 = 2;
        (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),0xb,1);
      }
    }
    else {
      GameBit_Set(0xade,1);
      *puVar3 = 2;
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),0xb,1);
    }
    break;
  case 2:
    uVar2 = GameBit_Get(0x70);
    if (uVar2 != 0) {
      *puVar3 = 3;
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),6,1);
    }
    break;
  case 3:
    uVar2 = GameBit_Get(0x72);
    if (uVar2 != 0) {
      iVar2 = (int)*DAT_803dd72c;
      param_1 = (**(code **)(iVar2 + 0x50))((int)*(char *)(param_9 + 0xac),0,0);
    }
    uVar2 = GameBit_Get(0x3a2);
    if (uVar2 != 0) {
      *puVar3 = 4;
      GameBit_Set(0xe5d,1);
      GameBit_Set(0xe5e,1);
      GameBit_Set(0xe5f,1);
      GameBit_Set(0xe60,1);
      GameBit_Set(0xe61,1);
      GameBit_Set(0xe62,1);
      GameBit_Set(0xe63,1);
      GameBit_Set(0xe64,1);
      GameBit_Set(0xe65,1);
      GameBit_Set(0xe66,1);
      GameBit_Set(0xe67,1);
      GameBit_Set(0xe68,1);
      GameBit_Set(0xe69,1);
      GameBit_Set(0xe6a,1);
      param_1 = GameBit_Set(0xe6b,1);
    }
    if (*(int *)(param_9 + 0xf4) == 0) {
      uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0xa3,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x9e,0,param_13,param_14,param_15,param_16);
      uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x119,0,param_13,param_14,param_15,param_16);
      getLActions(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15b,0,0,0,param_15,param_16);
      getLActions(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x15c,0,0,0,param_15,param_16);
      getLActions(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17c,0,0,0,param_15,param_16);
      getLActions(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x17b,0,0,0,param_15,param_16);
      (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
      *(undefined4 *)(param_9 + 0xf4) = 1;
    }
    break;
  case 4:
    FUN_801ac340(param_9,puVar3);
    break;
  case 5:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),3,0);
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),4,0);
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),6,0);
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),7,0);
      *puVar3 = 0;
      (*DAT_803dd72c)->setMode((int)*(char *)(param_9 + 0xac),2);
    }
    break;
  case 6:
    if ((*(uint *)(puVar3 + 4) & 1) != 0) {
      puVar3[8] = 2;
    }
    if (('\0' < (char)puVar3[8]) && (cVar1 = puVar3[8] + -1, puVar3[8] = cVar1, cVar1 == '\0')) {
      uVar4 = GameBit_Set(0x4e5,0);
      FUN_80053c98(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,'\0',param_11,
                   param_12,param_13,param_14,param_15,param_16);
    }
    break;
  case 7:
    uVar2 = GameBit_Get(0x6e);
    if (uVar2 != 0) {
      *puVar3 = 1;
      (*DAT_803dd72c)->setAnimEvent((int)*(char *)(param_9 + 0xac),2,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801accf4
 * EN v1.0 Address: 0x801ACCF4
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801ACC78
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801accf4(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  *(uint *)(*(int *)(param_1 + 0xb8) + 4) = *(uint *)(*(int *)(param_1 + 0xb8) + 4) | 1;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_3 + iVar1 + 0x81) == '\x02') {
      GameBit_Set(0x378,0);
      GameBit_Set(0x3b9,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801acd7c
 * EN v1.0 Address: 0x801ACD7C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801ACD10
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801acd7c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801acda4
 * EN v1.0 Address: 0x801ACDA4
 * EN v1.0 Size: 1188b
 * EN v1.1 Address: 0x801ACD44
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801acda4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_r4;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_9 + 0xf4) == 0) {
    uVar5 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0xa3,0,param_13,param_14,param_15,param_16);
    uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x9e,0,param_13,param_14,param_15,param_16);
    param_11 = 0x104;
    param_12 = 0;
    FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x104
                 ,0,param_13,param_14,param_15,param_16);
    param_1 = (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
    *(undefined4 *)(param_9 + 0xf4) = 1;
    param_10 = extraout_r4;
  }
  bVar1 = *(byte *)(iVar4 + 0xc);
  if (bVar1 == 2) {
    uVar2 = GameBit_Get(0x3a3);
    if (uVar2 != 0) {
      FUN_801ac24c(param_9);
    }
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    FUN_801ac490(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 param_11,param_12,param_13,param_14,param_15,param_16);
  }
  *(uint *)(iVar4 + 4) = *(uint *)(iVar4 + 4) & ~1;
  if (lbl_803E5374 < *(float *)(iVar4 + 0x10)) {
    uVar5 = FUN_80017484(0xff,0xff,0xff,0xff);
    FUN_80006c88(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x351);
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x10) - lbl_803DC074;
    if (*(float *)(iVar4 + 0x10) < lbl_803E5374) {
      *(float *)(iVar4 + 0x10) = lbl_803E5374;
    }
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(iVar4 + 10) != 0x1a) &&
       (*(undefined2 *)(iVar4 + 10) = 0x1a, (*(uint *)(iVar4 + 4) & 8) != 0)) {
      FUN_800067c0((int *)0x1a,1);
    }
  }
  else if ((*(short *)(iVar4 + 10) != -1) &&
          (*(undefined2 *)(iVar4 + 10) = 0xffff, (*(uint *)(iVar4 + 4) & 8) != 0)) {
    FUN_800067c0((int *)0x1a,0);
  }
  SH_LevelControl_runBloopEvent(iVar4 + 4,2,0x2c1,0x238,0x1ed,(int *)0xb2);
  SH_LevelControl_runBloopEvent(iVar4 + 4,0x10,0x1ba,0x1b9,0x1d6,(int *)0xb4);
  SH_LevelControl_runBloopEvent(iVar4 + 4,4,-1,-1,0x3a0,(int *)0xe9);
  SH_LevelControl_runBloopEvent(iVar4 + 4,8,-1,-1,0x3a1,(int *)(int)*(short *)(iVar4 + 10));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad248
 * EN v1.0 Address: 0x801AD248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801ACF74
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad248(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad24c
 * EN v1.0 Address: 0x801AD24C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801AD2B0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801ad24c(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *local_18 [4];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_800632f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  iVar6 = -1;
  iVar5 = 0;
  puVar4 = local_18[0];
  fVar1 = lbl_803E5398;
  if (0 < iVar3) {
    do {
      fVar2 = *(float *)(param_1 + 0x10) - *(float *)*puVar4;
      if ((lbl_803E539C < fVar2) && (fVar2 < fVar1)) {
        iVar6 = iVar5;
        fVar1 = fVar2;
      }
      puVar4 = puVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (iVar6 == -1) {
    fVar1 = *(float *)(param_1 + 0x10);
  }
  else {
    *(undefined *)(iVar7 + 0xe) = 1;
    fVar1 = *(float *)local_18[0][iVar6];
  }
  return (double)fVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad318
 * EN v1.0 Address: 0x801AD318
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801AD390
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad318(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\x03') && (visible != 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad350
 * EN v1.0 Address: 0x801AD350
 * EN v1.0 Size: 1580b
 * EN v1.1 Address: 0x801AD3D4
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad350(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  ushort uVar5;
  bool bVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int *piVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 local_30;
  
  uVar7 = FUN_8028683c();
  piVar13 = *(int **)(uVar7 + 0xb8);
  iVar12 = *(int *)(uVar7 + 0x54);
  iVar10 = *(int *)(uVar7 + 100);
  iVar11 = *(int *)(uVar7 + 0x4c);
  if (DAT_803de7c0 == 0) {
    DAT_803de7c0 = FUN_80006b14(0x5b);
  }
  if (*(char *)((int)piVar13 + 0xe) == '\0') {
    dVar15 = FUN_801ad24c(uVar7);
    piVar13[1] = (int)(float)dVar15;
    if ((*(char *)((int)piVar13 + 0xe) != '\0') && (iVar10 != 0)) {
      *(int *)(iVar10 + 0x24) = piVar13[1];
      FUN_800614c4();
    }
  }
  else {
    if (iVar10 != 0) {
      fVar3 = (*(float *)(uVar7 + 0x10) - (float)piVar13[1]) /
              ((float)piVar13[2] - (float)piVar13[1]);
      fVar4 = lbl_803E53A0;
      if ((fVar3 <= lbl_803E53A0) && (fVar4 = fVar3, fVar3 < lbl_803E5380)) {
        fVar4 = lbl_803E5380;
      }
      dVar15 = (double)(lbl_803E53A0 - fVar4);
      iVar8 = FUN_80017a98();
      if (iVar8 == 0) {
        dVar14 = (double)lbl_803E53A4;
      }
      else {
        dVar16 = (double)FUN_8001771c((float *)(uVar7 + 0x18),(float *)(iVar8 + 0x18));
        dVar14 = (double)lbl_803E53A4;
        if ((dVar16 <= dVar14) && (dVar14 = dVar16, dVar16 < (double)lbl_803E53A8)) {
          dVar14 = (double)lbl_803E53A8;
        }
      }
      param_3 = (double)(lbl_803E53A0 - (float)(dVar14 - (double)lbl_803E53A8) / lbl_803E53AC)
      ;
      param_2 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(uVar7 + 0x37)) -
                                DOUBLE_803e5390) / lbl_803E53B4);
      *(char *)(iVar10 + 0x40) =
           (char)(int)(param_2 *
                      (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                       (int)((double)lbl_803E53B0
                                                                            * dVar15) + 0x40U ^
                                                                       0x80000000) - DOUBLE_803e53c0
                                                     ) * param_3));
    }
    uVar9 = (uint)*(short *)(iVar11 + 0x1c);
    if ((uVar9 == 0xffffffff) || (uVar9 = GameBit_Get(uVar9), uVar9 != 0)) {
      bVar1 = *(byte *)(piVar13 + 3);
      if (bVar1 == 2) {
        *(undefined4 *)(iVar12 + 0x48) = 0x10;
        *(undefined4 *)(iVar12 + 0x4c) = 0x10;
        *(undefined *)(iVar12 + 0x6f) = 1;
        *(undefined *)(iVar12 + 0x6e) = 0xd;
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          iVar10 = FUN_80017a98();
          if (iVar10 == 0) {
            bVar6 = false;
          }
          else {
            iVar8 = *(int *)(uVar7 + 0x4c);
            dVar15 = (double)FUN_80017710((float *)(uVar7 + 0x18),(float *)(iVar10 + 0x18));
            param_4 = (double)(*(float *)(uVar7 + 0x10) - *(float *)(iVar10 + 0x10));
            if (param_4 < (double)lbl_803E5380) {
              param_4 = (double)lbl_803E5380;
            }
            param_3 = (double)lbl_803E5384;
            local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar8 + 0x1a));
            param_2 = DOUBLE_803e5390;
            if (((double)(float)(param_3 * (double)(float)(local_30 - DOUBLE_803e5390)) <= dVar15)
               || ((double)lbl_803E5388 <= param_4)) {
              bVar6 = false;
            }
            else {
              bVar6 = true;
            }
          }
          if ((bVar6) &&
             (sVar2 = *(short *)(piVar13 + 4), uVar5 = (ushort)DAT_803dc070,
             *(ushort *)(piVar13 + 4) = sVar2 - uVar5, (short)(sVar2 - uVar5) < 1)) {
            *(undefined *)(piVar13 + 3) = 1;
          }
        }
        else {
          if (*(char *)((int)piVar13 + 0xd) == '\0') {
            *(undefined *)((int)piVar13 + 0xd) = 1;
            *(float *)(uVar7 + 0x28) = lbl_803E5380;
            if (*(short *)(uVar7 + 0x46) == 0x67) {
              FUN_80006824(uVar7,SFXwp_sexpl2_c);
            }
            FUN_80006824(uVar7,SFXmv_blockscrape_lp);
            *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) | 1;
          }
          *(undefined4 *)(iVar12 + 0x48) = 0x10;
          *(undefined4 *)(iVar12 + 0x4c) = 0x10;
          *(undefined *)(iVar12 + 0x6f) = 1;
          *(undefined *)(iVar12 + 0x6e) = 0xd;
          *(float *)(uVar7 + 0x28) = lbl_803E53B8 * lbl_803DC074 + *(float *)(uVar7 + 0x28);
          *(float *)(uVar7 + 0x10) =
               *(float *)(uVar7 + 0x28) * lbl_803DC074 + *(float *)(uVar7 + 0x10);
          param_3 = (double)(float)piVar13[1];
          param_2 = (double)*(float *)(*piVar13 + 8);
          if (*(float *)(uVar7 + 0x10) < (float)(param_3 + param_2)) {
            *(float *)(uVar7 + 0x10) = (float)(param_2 * (double)*(float *)(uVar7 + 8) + param_3);
            *(undefined *)(piVar13 + 3) = 2;
            if (*(int *)(*piVar13 + 4) != 0) {
              FUN_80006824(uVar7,(ushort)*(int *)(*piVar13 + 4));
            }
          }
        }
      }
      if (*(int *)(iVar12 + 0x50) != 0) {
        *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) & ~1;
        *(undefined *)(piVar13 + 3) = 3;
        FUN_8000680c(uVar7,8);
        if (*(short *)(uVar7 + 0x46) == 0x67) {
          FUN_80006824(uVar7,SFXwp_simp1_c);
        }
        else {
          FUN_80006824(uVar7,0x3bb);
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar11 + 0x1b));
          FUN_8008112c((double)(float)(local_30 - DOUBLE_803e5390),param_2,param_3,param_4,param_5,
                       param_6,param_7,param_8,uVar7,1,1,0,1,1,1,1);
        }
      }
      fVar3 = lbl_803E5380;
      *(float *)(uVar7 + 0x24) = lbl_803E5380;
      *(float *)(uVar7 + 0x2c) = fVar3;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ad97c
 * EN v1.0 Address: 0x801AD97C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AD838
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad97c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad980
 * EN v1.0 Address: 0x801AD980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AD9B4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ad980(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ad984
 * EN v1.0 Address: 0x801AD984
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801AD9F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801ad984(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  int iVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    pfVar2 = *(float **)(param_9 + 0xb8);
    iVar1 = FUN_80017a98();
    dVar3 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
    dVar4 = (double)*pfVar2;
    if ((dVar4 <= dVar3) || (*(char *)((int)pfVar2 + 0xb) != '\0')) {
      if (((double)(float)((double)lbl_803E53D0 + dVar4) < dVar3) &&
         (*(char *)((int)pfVar2 + 0xb) != '\0')) {
        *(undefined *)((int)pfVar2 + 0xb) = 0;
        getLActions(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                     (uint)*(ushort *)(pfVar2 + 2),0,0,0,in_r9,in_r10);
      }
    }
    else {
      *(undefined *)((int)pfVar2 + 0xb) = 1;
      getLActions(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)((int)pfVar2 + 6),0,0,0,in_r9,in_r10);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801adb28
 * EN v1.0 Address: 0x801ADB28
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801ADB04
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adb28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    if (*(char *)(*(int *)(param_9 + 0xb8) + 0xb) != '\0') {
      getLActions(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)(*(int *)(param_9 + 0xb8) + 8),0,0,0,in_r9,in_r10);
    }
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adbec
 * EN v1.0 Address: 0x801ADBEC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801ADB80
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adbec(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((*(short *)(param_1 + 0x46) == 0x172) && (visible != 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adc20
 * EN v1.0 Address: 0x801ADC20
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x801ADBC0
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adc20(undefined2 *param_1)
{
  if ((param_1[0x23] != 0x172) && (*(int *)(param_1 + 0x7a) == 0)) {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801adc9c
 * EN v1.0 Address: 0x801ADC9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801ADC38
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adc9c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801adca0
 * EN v1.0 Address: 0x801ADCA0
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801ADD98
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adca0(undefined2 *param_1,undefined2 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,char param_7,int param_8,int param_9)
{
  undefined uVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [5];
  
  if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8)) {
    uVar1 = *(undefined *)((int)param_2 + 0x37);
    *(char *)((int)param_2 + 0x37) = (char)param_8;
    (**(code **)(**(int **)(param_2 + 0x34) + 0x10))
              (param_2,param_3,param_4,param_5,param_6,0xffffffff);
    *(undefined *)((int)param_2 + 0x37) = uVar1;
  }
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  (**(code **)(**(int **)(param_2 + 0x34) + 0x28))(param_2,local_20,&local_24,&local_28);
  *(undefined4 *)(param_1 + 6) = local_20[0];
  *(undefined4 *)(param_1 + 8) = local_24;
  *(undefined4 *)(param_1 + 10) = local_28;
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_2 + 0x12);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_2 + 0x16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801addec
 * EN v1.0 Address: 0x801ADDEC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x801ADEE4
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801addec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,uint *param_13,undefined4 param_14,undefined4 param_15
            ,undefined4 param_16)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined2 uStack_2a;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  
  piVar5 = *(int **)(param_9 + 0xb8);
  *(undefined *)(piVar5 + 8) = 0xff;
  iVar6 = *piVar5;
  if (*(char *)(param_11 + 0x80) == '\x03') {
    *(undefined *)((int)piVar5 + 0x21) = 0xff;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  local_28 = DAT_802c2a88;
  local_24 = DAT_802c2a8c;
  local_20 = DAT_802c2a90;
  if (*(char *)((int)piVar5 + 0x21) != *(char *)((int)piVar5 + 0x22)) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
      *(undefined *)(param_9 + 0xeb) = 0;
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) == 0) {
      *(undefined *)((int)piVar5 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar5 + 0x21)) {
        puVar2 = FUN_80017aa4(0x18,(&uStack_2a)[*(char *)((int)piVar5 + 0x21)]);
        param_12 = 0xffffffff;
        param_13 = *(uint **)(param_9 + 0x30);
        uVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,param_13,param_14,param_15,param_16);
        *(undefined4 *)(param_9 + 200) = uVar3;
        *(undefined *)(param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar5 + 0x22) = *(undefined *)((int)piVar5 + 0x21);
    }
  }
  *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
  if ((iVar6 == 0) || (*(char *)(param_11 + 0x80) != '\x02')) {
    if ((iVar6 != 0) && (*(char *)(param_11 + 0x80) == '\x01')) {
      (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,0);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
  else {
    piVar5[1] = (int)lbl_803E53F0;
    piVar5[2] = piVar5[5];
    piVar5[3] = piVar5[6];
    piVar5[4] = piVar5[7];
    (**(code **)(**(int **)(iVar6 + 0x68) + 0x3c))(iVar6,2);
    FUN_800305f8((double)lbl_803E53E0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x100,1,param_12,param_13,param_14,param_15,param_16);
    iVar4 = (int)((GameObject *)param_9)->anim.modelState;
    if (iVar4 != 0) {
      ((GameObject *)param_9)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
    }
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & ~0x4;
    *(undefined *)(param_11 + 0x80) = 0;
  }
  if ((iVar6 != 0) && (iVar6 = (**(code **)(**(int **)(iVar6 + 0x68) + 0x38))(iVar6), iVar6 == 2)) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
  }
  return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void imicemountain_free(void) {}
void imicemountain_hitDetect(void) {}

extern MapEventInterface **gMapEventInterface;
extern void gameBitFn_800ea2e0(int idx);
extern void unlockLevel(int a, int b, int c);
extern f32 lbl_803E46E0;

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMode((a))

/* EN v1.0 0x801AC9C0  size: 828b  imicemountain_init: clear the ice-mountain
 * gamebit block, arm the map-event triggers, then branch on the queried level
 * state to set the boulder's start state and fire the appropriate triggers. */
#pragma scheduling off
void imicemountain_init(int* obj)
{
    IMIceMountainState* sub = ((GameObject *)obj)->extra;
    int i;
    ((GameObject *)obj)->animEventCallback = (void *)IMIceMountain_SeqFn;
    for (i = 1; (u8)i <= 0xd; i++) {
        gameBitFn_800ea2e0(i);
    }
    sub->warningTextTimer = lbl_803E46E0;
    MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 1, 0);
    MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 5, 1);
    unlockLevel(0, 0, 1);
    if (GameBit_Get(0x379) != 0) {
        MEVT_SET(*(s8*)((char*)obj + 0xac), 2);
    }
    sub->mapEventState = MEVT_QUERY(*(s8*)((char*)obj + 0xac));
    switch (sub->mapEventState) {
    case 1:
        if (GameBit_Get(0x72) != 0) {
            if (GameBit_Get(0x379) != 0) {
                sub->eventState = 5;
            } else {
                GameBit_Set(0x3a3, 0);
                GameBit_Set(0x3a2, 0);
                GameBit_Set(0xcb, 0);
                GameBit_Set(0x379, 0);
                sub->eventState = 3;
            }
        } else {
            MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 0, 1);
            if (GameBit_Get(0xadc) != 0 && GameBit_Get(0xadd) != 0) {
                MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 0xb, 1);
            }
            if (GameBit_Get(0x6e) != 0) {
                sub->eventState = 1;
            } else {
                MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 2, 1);
                sub->eventState = 7;
            }
        }
        MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 3, 1);
        MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 4, 1);
        MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 7, 1);
        break;
    case 2:
        GameBit_Set(0x3a3, 0);
        GameBit_Set(0x3a2, 0);
        GameBit_Set(0xce, 0);
        GameBit_Set(0x37b, 0);
        GameBit_Set(0xc8, 0);
        GameBit_Set(0x374, 0);
        GameBit_Set(0x37c, 0);
        MEVT_TRIGGER(*(s8*)((char*)obj + 0xac), 2, 0);
        break;
    case 5:
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY
void crrockfall_free(void) {}
void crrockfall_hitDetect(void) {}
void magiclight_hitDetect(void) {}
void magiclight_release(void) {}
void magiclight_initialise(void) {}

extern u32 randomGetRange(int min, int max);
extern f32 lbl_803E4740;
extern f32 lbl_803E4744;

/* EN v1.0 0x801AD684  size: 344b  magiclight_init: seed header + update fn;
 * for the non-172 variants pick a random lifetime and, for type 0x16b, map
 * the spawn subtype to a light-pair / intensity preset. */
#pragma scheduling off
#pragma peephole off
void magiclight_init(int* obj, u8* params)
{
    MagicLightState* sub;
    *(int*)((char*)obj + 0xf4) = 0;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject *)obj)->animEventCallback = (void *)magiclight_SeqFn;
    if (*(s16*)((char*)obj + 0x46) == 0x172) {
        return;
    }
    sub = *(MagicLightState**)((char*)obj + 0xb8);
    sub->lifetime = (s16)randomGetRange(0xc8, 0x258);
    sub->subtype = (s8)*(s16*)(params + 0x1a);
    sub->inRange = 0;
    if (*(s16*)((char*)obj + 0x46) == 0x16b) {
        switch (sub->subtype) {
        case 0:
            sub->enterAction = 0x90;
            sub->leaveAction = 0x91;
            sub->triggerRadius = lbl_803E4740;
            break;
        case 1:
            sub->enterAction = 0x92;
            sub->leaveAction = 0x93;
            sub->triggerRadius = lbl_803E4740;
            break;
        default:
            sub->enterAction = 0x94;
            sub->leaveAction = 0x95;
            sub->triggerRadius = lbl_803E4744;
            break;
        case 3:
            sub->enterAction = 0x187;
            sub->leaveAction = 0x5;
            sub->triggerRadius = lbl_803E4740;
            break;
        }
        sub->unk10 = 0x12d;
    } else {
        sub->unk10 = 0x12d;
    }
}
#pragma peephole reset
#pragma scheduling reset
void dll_16C_release(void) {}
void dll_16C_initialise(void) {}
void imicepillar_free(void) {}

/* 8b "li r3, N; blr" returners. */
int imicemountain_getExtraSize(void) { return 0x14; }
int imicemountain_getObjectTypeId(void) { return 0x0; }
int crrockfall_getExtraSize(void) { return 0x14; }
int crrockfall_getObjectTypeId(void) { return 0x0; }
int magiclight_getObjectTypeId(void) { return 0x0; }
int dll_16C_getExtraSize(void) { return 0x24; }
int dll_16C_getObjectTypeId(void) { return 0x3; }
int imicepillar_getExtraSize(void) { return 0x4; }
int imicepillar_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
extern void *lbl_803DDB40;
void crrockfall_initialise(void) { lbl_803DDB40 = NULL; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E46D8;
extern f32 lbl_803E4708;
extern f32 lbl_803E473C;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void imicemountain_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E46D8); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    CrRockfallState *inner = *(CrRockfallState **)(obj + 0xb8);
    if (inner->mode != 3 && visible != 0) {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4708);
    }
}
void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    if (((GameObject *)obj)->anim.seqId == 0x172 && visible != 0) {
        objRenderFn_8003b8f4(lbl_803E473C);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern unsigned int *gObjectTriggerInterface;
extern EffectInterface **gExpgfxInterface;
#pragma scheduling off
#pragma peephole off
extern int hitDetectFn_80065e50(int obj, int **listOut, int p3, int p4, f32 x, f32 y, f32 z);
extern f32 lbl_803E4700;
extern f32 lbl_803E4704;
#pragma dont_inline on
f32 fn_801ACCFC(int obj) {
    CrRockfallState *state = *(CrRockfallState **)((char *)obj + 0xB8);
    int *list;
    int count;
    int i;
    int bestIdx;
    f32 bestDist;
    f32 limit;
    count = hitDetectFn_80065e50(obj, &list, 0, 0,
                                  ((GameObject *)obj)->anim.localPosX,
                                  ((GameObject *)obj)->anim.localPosY,
                                  ((GameObject *)obj)->anim.localPosZ);
    bestDist = lbl_803E4700;
    bestIdx = -1;
    limit = lbl_803E4704;
    for (i = 0; i < count; i++) {
        f32 dy = ((GameObject *)obj)->anim.localPosY - *(f32 *)list[i];
        if (dy > limit && dy < bestDist) {
            bestDist = dy;
            bestIdx = i;
        }
    }
    if (bestIdx != -1) {
        state->floorFound = 1;
        return *(f32 *)list[bestIdx];
    }
    return ((GameObject *)obj)->anim.localPosY;
}
#pragma dont_inline reset

void magiclight_free(int obj) {
    MagicLightState *inner = *(MagicLightState **)(obj + 0xb8);
    if (((GameObject *)obj)->anim.seqId != 0x172) {
        if ((s8)inner->inRange != 0) {
            getLActions(obj, obj, (u16)inner->leaveAction, 0, 0, 0);
        }
        (*gExpgfxInterface)->freeObject((void *)obj);
    }
}
void magiclight_update(int obj) {
    if (((GameObject *)obj)->anim.seqId != 0x172 && ((GameObject *)obj)->unkF4 == 0) {
        *(s16 *)obj = 0;
        ((GameObject *)obj)->anim.rotY = 0;
        ((GameObject *)obj)->anim.rotZ = 0;
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        ((GameObject *)obj)->unkF4 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int magiclight_getExtraSize(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x172) return 0x0; return 0x14; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

extern void Obj_FreeObject(int*);
#pragma scheduling off
#pragma peephole off
void dll_16C_free(int *obj) { int *p = (int*)obj[0xc8/4]; if (p != NULL) Obj_FreeObject(p); }
#pragma peephole reset
#pragma scheduling reset

/* conditional init/free pair. */
#pragma scheduling off
#pragma peephole off
void crrockfall_release(void) {
    if (lbl_803DDB40 != NULL) {
        Resource_Release(lbl_803DDB40);
    }
    lbl_803DDB40 = NULL;
}
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_hitDetect: if extra->p && vtable(p,0x38)()==2, sync its transform into obj. */
extern void dll_16C_syncSubObjectTransform(void *a, void *b, int c, int d, int e, int f, int g, int h, int i);
#pragma scheduling off
#pragma peephole off
void dll_16C_hitDetect(void *obj) {
    Dll16CState *extra = *(Dll16CState **)((char *)obj + 0xb8);
    void *p = extra->linkedObj;
    if (p != NULL) {
        if ((*(int (**)(void *))(**(int **)((char *)p + 0x68) + 0x38))(p) == 2) {
            dll_16C_syncSubObjectTransform(obj, extra->linkedObj, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int objUpdateOpacity(int *obj);
extern void ObjPath_GetPointWorldPosition(int *obj, int idx, f32 *x, f32 *y, f32 *z, int e);
extern f32 lbl_803E4758;
#pragma scheduling off
#pragma peephole off
void dll_16C_render(int *obj, int p1, int p2, int p3, int p4, s8 visible) {
    Dll16CState *extra;
    int *p;
    int hit;

    if (((GameObject *)obj)->anim.seqId != 883) {
        if (GameBit_Get(110) != 0) {
            if (GameBit_Get(898) == 0) return;
        }
        extra = *(Dll16CState **)((char *)obj + 0xb8);
        p = (int *)extra->linkedObj;
        hit = 0;
        if (p != NULL) {
            if ((*(int (**)(int *))(**(int **)((char *)p + 0x68) + 0x38))(p) == 2) {
                hit = 1;
            }
        }
        if (hit != 0) {
            ((GameObject *)obj)->anim.flags |= 8;
            visible = (s8)objUpdateOpacity(p);
            dll_16C_syncSubObjectTransform(obj, p, p1, p2, p3, p4, visible, extra->opacity, 1);
        } else {
            ((GameObject *)obj)->anim.flags &= ~8;
        }
        if ((s8)visible != 0 && extra->opacity != 0) {
            u8 saved = *(u8 *)((char *)obj + 0x37);
            if (hit != 0) {
                *(u8 *)((char *)obj + 0x37) = extra->opacity;
            }
            ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4758);
            ObjPath_GetPointWorldPosition(obj, 1, &extra->pathPointX, &extra->pathPointY, &extra->pathPointZ, 0);
            *(u8 *)((char *)obj + 0x37) = saved;
        }
    } else {
        ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4758);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* IMIceMountain_SeqFn: set extra bit-0; scan arr for value==2 and clear two GameBits. */
#pragma scheduling off
#pragma peephole off
int IMIceMountain_SeqFn(void *obj, int arg2, u8 *arg3) {
    int i;
    *(u32 *)((char *)((GameObject *)obj)->extra + 4) |= 1;
    for (i = 0; i < arg3[0x8b]; i++) {
        if (arg3[i + 0x81] == 2) {
            GameBit_Set(888, 0);
            GameBit_Set(953, 0);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_init: install callback, configure sub-obj, init extra fields from arg. */
#pragma scheduling off
#pragma peephole off
void dll_16C_init(void *obj, void *arg2) {
    Dll16CState *extra;
    ((GameObject *)obj)->animEventCallback = (void *)dll_16C_SeqFn;
    if (((GameObject *)obj)->anim.modelState != NULL) {
        ((GameObject *)obj)->anim.modelState->flags |= 0x4000;
        ((GameObject *)obj)->anim.modelState->shadowTintA = 100;
        ((GameObject *)obj)->anim.modelState->shadowTintB = 150;
    }
    extra = *(Dll16CState **)((char *)obj + 0xb8);
    extra->linkedObj = NULL;
    *(u8 *)&extra->subObjIndex = *(u8 *)((char *)arg2 + 0x27);
    extra->opacity = 0xff;
}
#pragma peephole reset
#pragma scheduling reset

extern float Vec_distance(float *a, float *b);
extern f32 lbl_803E4738;
#pragma scheduling off
#pragma peephole off
int magiclight_SeqFn(int *obj) {
    MagicLightState *state;
    int *player;
    f32 dist;

    if (((GameObject *)obj)->anim.seqId == 370) return 0;

    state = *(MagicLightState **)((char *)obj + 0xb8);
    player = (int *)Obj_GetPlayerObject();
    dist = Vec_distance((f32 *)((char *)player + 0x18), (f32 *)((char *)obj + 0x18));

    if (dist < state->triggerRadius && state->inRange == 0) {
        state->inRange = 1;
        getLActions(obj, obj, (u16)state->enterAction, 0, 0, 0);
    } else if (dist > lbl_803E4738 + state->triggerRadius && state->inRange != 0) {
        state->inRange = 0;
        getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void getEnvfxAct(int *obj, int *target, int id, int p);
extern void fn_801AC108(int *obj, int *extra);
extern CloudActionInterface **gCloudActionInterface;
extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#pragma scheduling off
#pragma peephole off
void imicemountain_updateEventState(int *obj)
{
    IMIceMountainState *extra = *(IMIceMountainState **)((char *)obj + 0xb8);
    switch (extra->eventState) {
    case 7:
        if (GameBit_Get(0x6e) != 0) {
            extra->eventState = 1;
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 2, 0);
        }
        break;
    case 1:
        if (GameBit_Get(0xadc) != 0 && GameBit_Get(0xadd) != 0) {
            GameBit_Set(0xade, 1);
            extra->eventState = 2;
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 11, 1);
        } else if (GameBit_Get(0x70) != 0) {
            extra->eventState = 2;
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 11, 1);
        }
        break;
    case 2:
        if (GameBit_Get(0x70) != 0) {
            extra->eventState = 3;
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 6, 1);
        }
        break;
    case 3:
        if (GameBit_Get(0x72) != 0) {
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 0, 0);
        }
        if (GameBit_Get(0x3a2) != 0) {
            extra->eventState = 4;
            GameBit_Set(0xe5d, 1);
            GameBit_Set(0xe5e, 1);
            GameBit_Set(0xe5f, 1);
            GameBit_Set(0xe60, 1);
            GameBit_Set(0xe61, 1);
            GameBit_Set(0xe62, 1);
            GameBit_Set(0xe63, 1);
            GameBit_Set(0xe64, 1);
            GameBit_Set(0xe65, 1);
            GameBit_Set(0xe66, 1);
            GameBit_Set(0xe67, 1);
            GameBit_Set(0xe68, 1);
            GameBit_Set(0xe69, 1);
            GameBit_Set(0xe6a, 1);
            GameBit_Set(0xe6b, 1);
        }
        if (((GameObject *)obj)->unkF4 == 0) {
            getEnvfxAct(obj, obj, 0xa3, 0);
            getEnvfxAct(obj, obj, 0x9e, 0);
            getEnvfxAct(obj, obj, 0x119, 0);
            getLActions(obj, obj, 0x15b, 0, 0, 0);
            getLActions(obj, obj, 0x15c, 0, 0, 0);
            getLActions(obj, obj, 0x17c, 0, 0, 0);
            getLActions(obj, obj, 0x17b, 0, 0, 0);
            (*gCloudActionInterface)->func09Nop(1);
            ((GameObject *)obj)->unkF4 = 1;
        }
        break;
    case 4:
        fn_801AC108(obj, (int *)extra);
        break;
    case 5:
        if ((extra->latchFlags & 1) != 0) {
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 3, 0);
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 4, 0);
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 6, 0);
            MEVT_TRIGGER(*(s8 *)((char *)obj + 0xac), 7, 0);
            extra->eventState = 0;
            MEVT_SET(*(s8 *)((char *)obj + 0xac), 2);
        }
        break;
    case 6:
        if ((extra->latchFlags & 1) != 0) {
            extra->warpCountdown = 2;
        }
        if (extra->warpCountdown > 0) {
            s8 cnt = extra->warpCountdown - 1;
            extra->warpCountdown = cnt;
            if (cnt == 0) {
                GameBit_Set(0x4e5, 0);
                warpToMap(0x1a, 0);
            }
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern f32 lbl_803E4748;
extern u8 lbl_802C2308[];

typedef struct { s16 v[5]; } Blob10;

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
#pragma scheduling off
#pragma peephole off
int dll_16C_SeqFn(int *obj, int arg2, u8 *arg3)
{
    int *p;
    int *extra = ((GameObject *)obj)->extra;
    s16 ids[5];

    *(u8 *)((char *)extra + 0x20) = 0xff;
    p = (int *)*extra;
    if (arg3[0x80] == 3) {
        *(s8 *)((char *)extra + 0x21) = -1;
        arg3[0x80] = 0;
    }
    *(Blob10 *)ids = *(Blob10 *)lbl_802C2308;

    if (*(s8 *)((char *)extra + 0x21) != *(s8 *)((char *)extra + 0x22)) {
        if (((GameObject *)obj)->unkC8 != NULL) {
            Obj_FreeObject(((GameObject *)obj)->unkC8);
            *(int *)((char *)obj + 0xc8) = 0;
            ((GameObject *)obj)->unkEB = 0;
        }
        if (Obj_IsLoadingLocked()) {
            s8 idx = *(s8 *)((char *)extra + 0x21);
            if (idx > 0) {
                *(int *)((char *)obj + 0xc8) =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int *)((char *)obj + 0x30));
                ((GameObject *)obj)->unkEB = 1;
            }
            *(s8 *)((char *)extra + 0x22) = *(s8 *)((char *)extra + 0x21);
        } else {
            *(s8 *)((char *)extra + 0x22) = 0;
        }
    }

    *(s16 *)((char *)arg3 + 0x6e) = *(s16 *)((char *)arg3 + 0x70);

    if (p != NULL && arg3[0x80] == 2) {
        *(f32 *)((char *)extra + 4) = lbl_803E4758;
        *(f32 *)((char *)extra + 8) = *(f32 *)((char *)extra + 0x14);
        *(f32 *)((char *)extra + 0xc) = *(f32 *)((char *)extra + 0x18);
        *(f32 *)((char *)extra + 0x10) = *(f32 *)((char *)extra + 0x1c);
        (*(void (**)(int *, int))(**(int **)((char *)p + 0x68) + 0x3c))(p, 2);
        ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 1);
        if (((GameObject *)obj)->anim.modelState != NULL) {
            ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        *(s16 *)((char *)arg3 + 0x6e) &= ~4;
        arg3[0x80] = 0;
    } else if (p != NULL && arg3[0x80] == 1) {
        (*(void (**)(int *, int))(**(int **)((char *)p + 0x68) + 0x3c))(p, 0);
        arg3[0x80] = 0;
    }

    if (p != NULL) {
        if ((*(int (**)(int *))(**(int **)((char *)p + 0x68) + 0x38))(p) == 2) {
            *(s16 *)((char *)arg3 + 0x6e) &= ~3;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
#pragma scheduling off
#pragma peephole off
void dll_16C_syncSubObjectTransform(void *a, void *b, int c, int d, int e, int f, int g, int h, int i)
{
    if (i != 0 && (s8)g != 0 && h > 0) {
        u8 saved = *(u8 *)((char *)b + 0x37);
        *(u8 *)((char *)b + 0x37) = h;
        (*(void (**)(void *, int, int, int, int, int))(**(int **)((char *)b + 0x68) + 0x10))(b, c, d, e, f, -1);
        *(u8 *)((char *)b + 0x37) = saved;
    }
    *(f32 *)((char *)a + 0x8c) = *(f32 *)((char *)a + 0x18);
    *(f32 *)((char *)a + 0x90) = *(f32 *)((char *)a + 0x1c);
    *(f32 *)((char *)a + 0x94) = *(f32 *)((char *)a + 0x20);
    *(f32 *)((char *)a + 0x80) = *(f32 *)((char *)a + 0xc);
    *(f32 *)((char *)a + 0x84) = *(f32 *)((char *)a + 0x10);
    *(f32 *)((char *)a + 0x88) = *(f32 *)((char *)a + 0x14);
    {
        f32 x, y, z;
        (*(void (**)(void *, f32 *, f32 *, f32 *))(**(int **)((char *)b + 0x68) + 0x28))(b, &x, &y, &z);
        *(f32 *)((char *)a + 0xc) = x;
        *(f32 *)((char *)a + 0x10) = y;
        *(f32 *)((char *)a + 0x14) = z;
    }
    *(s16 *)((char *)a + 0) = *(s16 *)((char *)b + 0);
    *(s16 *)((char *)a + 2) = *(s16 *)((char *)b + 2);
    *(s16 *)((char *)a + 4) = *(s16 *)((char *)b + 4);
    *(f32 *)((char *)a + 0x18) = *(f32 *)((char *)a + 0xc);
    *(f32 *)((char *)a + 0x1c) = *(f32 *)((char *)a + 0x10);
    *(f32 *)((char *)a + 0x20) = *(f32 *)((char *)a + 0x14);
    *(f32 *)((char *)a + 0x24) = *(f32 *)((char *)b + 0x24);
    *(f32 *)((char *)a + 0x28) = *(f32 *)((char *)b + 0x28);
    *(f32 *)((char *)a + 0x2c) = *(f32 *)((char *)b + 0x2c);
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_801AC01C(int *obj);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void *state, int mask, int a, int b, int c, int d);
extern int *gSHthorntailAnimationInterface;
extern f32 timeDelta;
extern f32 lbl_803E46DC;

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */
#pragma scheduling off
void imicemountain_update(int *obj)
{
    IMIceMountainState *extra = *(IMIceMountainState **)((char *)obj + 0xb8);
    if (((GameObject *)obj)->unkF4 == 0) {
        getEnvfxAct(obj, obj, 0xa3, 0);
        getEnvfxAct(obj, obj, 0x9e, 0);
        getEnvfxAct(obj, obj, 0x104, 0);
        (*gCloudActionInterface)->func09Nop(1);
        ((GameObject *)obj)->unkF4 = 1;
    }
    switch (extra->mapEventState) {
    case 1:
        imicemountain_updateEventState(obj);
        break;
    case 2:
        if (GameBit_Get(0x3a3) != 0) {
            fn_801AC01C(obj);
        }
        break;
    case 5:
        break;
    }
    extra->latchFlags &= ~1;
    if (extra->warningTextTimer > lbl_803E46DC) {
        gameTextSetColor(255, 255, 255, 255);
        gameTextShow(0x351);
        extra->warningTextTimer = extra->warningTextTimer - timeDelta;
        if (extra->warningTextTimer < lbl_803E46DC) {
            extra->warningTextTimer = lbl_803E46DC;
        }
    }
    if (((int (*)(int))((int *)*gSHthorntailAnimationInterface)[0x24 / 4])(0) != 0) {
        if (extra->musicTrack != -1) {
            extra->musicTrack = -1;
            if ((extra->latchFlags & 8) != 0) {
                Music_Trigger(26, 0);
            }
        }
    } else {
        if (extra->musicTrack != 26) {
            extra->musicTrack = 26;
            if ((extra->latchFlags & 8) != 0) {
                Music_Trigger(26, 1);
            }
        }
    }
    SCGameBitLatch_Update((char *)extra + 4, 2, 705, 568, 493, 178);
    SCGameBitLatch_Update((char *)extra + 4, 16, 442, 441, 470, 180);
    SCGameBitLatch_Update((char *)extra + 4, 4, -1, -1, 928, 233);
    SCGameBitLatch_Update((char *)extra + 4, 8, -1, -1, 929, extra->musicTrack);
}
#pragma peephole reset
#pragma scheduling reset

extern int *ObjGroup_GetObjects(int group, int *countOut);
extern u8 framesThisStep;
extern f32 lbl_803E474C;
extern f32 lbl_803E475C;
extern f32 lbl_803E4760;
extern f32 lbl_803E4764;

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
#pragma scheduling off
#pragma peephole off
void dll_16C_update(int *obj)
{
    Dll16CState *extra = *(Dll16CState **)((char *)obj + 0xb8);
    s16 ids[5];

    *(Blob10 *)ids = *(Blob10 *)lbl_802C2308;
    if (extra->subObjIndex != extra->subObjIndexApplied) {
        if (((GameObject *)obj)->unkC8 != NULL) {
            Obj_FreeObject(((GameObject *)obj)->unkC8);
            *(int *)((char *)obj + 0xc8) = 0;
            ((GameObject *)obj)->unkEB = 0;
        }
        if (Obj_IsLoadingLocked()) {
            s8 idx = extra->subObjIndex;
            if (idx > 0) {
                *(int *)((char *)obj + 0xc8) =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int *)((char *)obj + 0x30));
                ((GameObject *)obj)->unkEB = 1;
            }
            extra->subObjIndexApplied = extra->subObjIndex;
        } else {
            extra->subObjIndexApplied = 0;
        }
    }

    if (extra->linkedObj == NULL) {
        int *objs;
        int count;
        int i;
        int sel;
        objs = ObjGroup_GetObjects(10, &count);
        switch (((GameObject *)obj)->anim.seqId) {
        case 365:
        case 883:
        default:
            sel = 364;
            break;
        case 368:
            sel = 367;
            break;
        }
        for (i = 0; i < count; i++) {
            if (sel == *(s16 *)((char *)objs[i] + 0x46)) {
                extra->linkedObj = (void *)objs[i];
                i = count;
            }
        }
    }

    if (((GameObject *)obj)->anim.seqId == 883 || GameBit_Get(0x3a2) != 0) {
        int *sub = (int *)extra->linkedObj;
        f32 blend;
        f32 a, b;
        if (((GameObject *)obj)->anim.currentMove != 0x100) {
            ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 0);
        }
        (*(void (**)(int *, f32 *))(**(int **)((char *)sub + 0x68) + 0x44))(sub, &blend);
        blend = lbl_803E474C;
        (*(void (**)(int *, f32 *, f32 *))(**(int **)((char *)sub + 0x68) + 0x40))(sub, &a, &b);
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)obj, blend, (f32)(u32)framesThisStep, NULL);
        if (extra->linkedObj != NULL) {
            f32 t;
            int *player = (int *)Obj_GetPlayerObject();
            t = Vec_distance((f32 *)((char *)extra->linkedObj + 0x18), (f32 *)((char *)player + 0x18));
            t = (t - lbl_803E475C) / lbl_803E4760;
            if (t < lbl_803E4748) {
                t = lbl_803E4748;
            } else if (t > lbl_803E4758) {
                t = lbl_803E4758;
            }
            extra->opacity = (int)(lbl_803E4764 * (lbl_803E4758 - t));
            if (((GameObject *)obj)->anim.modelState != NULL) {
                ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        } else {
            extra->opacity = 0xff;
            if (((GameObject *)obj)->anim.modelState != NULL) {
                ((GameObject *)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803236B8[];
extern f32 lbl_803E4730;

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */
#pragma scheduling off
#pragma peephole off
void crrockfall_init(int *obj, u8 *params)
{
    CrRockfallState *extra = *(CrRockfallState **)((char *)obj + 0xb8);
    int *sub;
    ObjModelState *modelState;

    extra->mode = 0;
    extra->startY = ((GameObject *)obj)->anim.localPosY;
    extra->fallDelay = *(s16 *)((char *)params + 0x1e);
    ((GameObject *)obj)->anim.rootMotionScale = (f32)(u32)params[0x1b] / lbl_803E4730;

    sub = *(int **)((char *)obj + 0x54);
    if (sub != NULL) {
        f32 scale = ((GameObject *)obj)->anim.rootMotionScale;
        ObjHitbox_SetCapsuleBounds(obj,
                                   (int)((f32)*(s16 *)((char *)sub + 0x5a) * scale),
                                   (int)((f32)*(s16 *)((char *)sub + 0x5c) * scale),
                                   (int)((f32)*(s16 *)((char *)sub + 0x5e) * scale));
        ObjHits_DisableObject(obj);
    }

    modelState = ((GameObject *)obj)->anim.modelState;
    if (modelState != NULL) {
        modelState->flags |= 0xb0;
        modelState->flags |= 0xc00;
        modelState->overrideWorldPosX = ((GameObject *)obj)->anim.localPosX;
        modelState->overrideWorldPosZ = ((GameObject *)obj)->anim.localPosZ;
        modelState->shadowScale = modelState->shadowScale * ((GameObject *)obj)->anim.rootMotionScale;
    }

    if (((GameObject *)obj)->anim.seqId == 1536) {
        extra->cfg = (CrRockfallCfgEntry *)&lbl_803236B8[0xc];
    } else {
        extra->cfg = (CrRockfallCfgEntry *)lbl_803236B8;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_800628CC(int *obj);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern void Sfx_PlayFromObject(int *obj, int sfx);
extern void Sfx_StopObjectChannel(int *obj, int channel);
extern void spawnExplosion(int *obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E46E8;
extern f32 lbl_803E46EC;
extern f32 lbl_803E46F0;
extern f32 lbl_803E470C;
extern f32 lbl_803E4710;
extern f32 lbl_803E4714;
extern f32 lbl_803E4718;
extern f32 lbl_803E471C;
extern f32 lbl_803E4720;

/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */
#pragma scheduling off
#pragma peephole off
void crrockfall_update(int *obj)
{
    CrRockfallState *ex = *(CrRockfallState **)((char *)obj + 0xb8);
    int *s54 = *(int **)((char *)obj + 0x54);
    ObjModelState *modelState = ((GameObject *)obj)->anim.modelState;
    int *p4c = *(int **)((char *)obj + 0x4c);

    if (lbl_803DDB40 == NULL) {
        lbl_803DDB40 = Resource_Acquire(91, 1);
    }

    if (ex->floorFound == 0) {
        ex->floorY = fn_801ACCFC((int)obj);
        if (ex->floorFound != 0 && modelState != NULL) {
            modelState->overrideWorldPosY = ex->floorY;
            fn_800628CC(obj);
        }
    } else {
        if (modelState != NULL) {
            f32 frac;
            f32 height;
            f32 dist;
            int n;
            int *player;
            frac = (((GameObject *)obj)->anim.localPosY - ex->floorY) /
                   (ex->startY - ex->floorY);
            if (frac > lbl_803E4708) {
                frac = lbl_803E4708;
            } else if (frac < lbl_803E46E8) {
                frac = lbl_803E46E8;
            }
            height = lbl_803E4708 - frac;
            player = (int *)Obj_GetPlayerObject();
            if (player != NULL) {
                dist = Vec_distance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18));
                if (dist > lbl_803E470C) {
                    dist = lbl_803E470C;
                } else if (dist < lbl_803E4710) {
                    dist = lbl_803E4710;
                }
            } else {
                dist = lbl_803E470C;
            }
            dist = (dist - lbl_803E4710) / lbl_803E4714;
            n = (int)(lbl_803E4718 * height) + 0x40;
            modelState->shadowAlpha =
                (int)(((f32)(u32)*(u8 *)((char *)obj + 0x37) / lbl_803E471C) *
                       ((f32)n * (lbl_803E4708 - dist)));
        }

        if (*(s16 *)((char *)p4c + 0x1c) == -1 ||
            GameBit_Get(*(s16 *)((char *)p4c + 0x1c)) != 0) {
            switch (ex->mode) {
            case 0: {
                int cond;
                int *player = (int *)Obj_GetPlayerObject();
                if (player == NULL) {
                    cond = 0;
                } else {
                    int *def = *(int **)((char *)obj + 0x4c);
                    f32 xz = Vec_xzDistance((f32 *)((char *)obj + 0x18),
                                            (f32 *)((char *)player + 0x18));
                    f32 dy = ((GameObject *)obj)->anim.localPosY - *(f32 *)((char *)player + 0x10);
                    if (dy < lbl_803E46E8) {
                        dy = lbl_803E46E8;
                    }
                    if (xz < lbl_803E46EC * (f32)(u32)*(u8 *)((char *)def + 0x1a) &&
                        dy < lbl_803E46F0) {
                        cond = 1;
                    } else {
                        cond = 0;
                    }
                }
                if (cond != 0) {
                    s16 timer = ex->fallDelay - framesThisStep;
                    ex->fallDelay = timer;
                    if (timer <= 0) {
                        ex->mode = 1;
                    }
                }
                break;
            }
            case 1:
                if (ex->fallStarted == 0) {
                    ex->fallStarted = 1;
                    ((GameObject *)obj)->anim.velocityY = lbl_803E46E8;
                    if (((GameObject *)obj)->anim.seqId == 103) {
                        Sfx_PlayFromObject(obj, SFXwp_sexpl2_c);
                    }
                    Sfx_PlayFromObject(obj, SFXmv_blockscrape_lp);
                    *(s16 *)((char *)s54 + 0x60) |= 1;
                }
                *(int *)((char *)s54 + 0x48) = 16;
                *(int *)((char *)s54 + 0x4c) = 16;
                *(u8 *)((char *)s54 + 0x6f) = 1;
                *(u8 *)((char *)s54 + 0x6e) = 13;
                ((GameObject *)obj)->anim.velocityY =
                    lbl_803E4720 * timeDelta + ((GameObject *)obj)->anim.velocityY;
                ((GameObject *)obj)->anim.localPosY =
                    ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
                if (((GameObject *)obj)->anim.localPosY <
                    ex->floorY + ex->cfg->restOffsetY) {
                    ((GameObject *)obj)->anim.localPosY =
                        ex->cfg->restOffsetY * ((GameObject *)obj)->anim.rootMotionScale +
                        ex->floorY;
                    ex->mode = 2;
                    if (ex->cfg->landSfx != 0) {
                        Sfx_PlayFromObject(obj, (u16)ex->cfg->landSfx);
                    }
                }
                break;
            case 2:
                *(int *)((char *)s54 + 0x48) = 16;
                *(int *)((char *)s54 + 0x4c) = 16;
                *(u8 *)((char *)s54 + 0x6f) = 1;
                *(u8 *)((char *)s54 + 0x6e) = 13;
                break;
            case 4:
                break;
            }

            if (*(void **)((char *)s54 + 0x50) != NULL) {
                *(s16 *)((char *)s54 + 0x60) &= ~1;
                ex->mode = 3;
                Sfx_StopObjectChannel(obj, 8);
                if (((GameObject *)obj)->anim.seqId == 103) {
                    Sfx_PlayFromObject(obj, SFXwp_simp1_c);
                } else {
                    Sfx_PlayFromObject(obj, 955);
                    spawnExplosion(obj, (f32)(u32)*(u8 *)((char *)p4c + 0x1b),
                                   1, 1, 0, 1, 1, 1, 1);
                }
            }
        }
    }

    {
        f32 z = lbl_803E46E8;
        ((GameObject *)obj)->anim.velocityX = z;
        ((GameObject *)obj)->anim.velocityZ = z;
    }
}
#pragma peephole reset
#pragma scheduling reset
