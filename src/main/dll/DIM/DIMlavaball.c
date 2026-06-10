#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavaball.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/mapEventTypes.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/objhits_types.h"

/*
 * Per-object extra state for the MoonSeedBush plant spot
 * (MoonSeedBush_getExtraSize == 0x2).
 */
typedef struct MoonSeedBushState {
    u8 seedState; /* gamebit value: 0 unplanted, 2 grown (SeqFn) */
    u8 flags; /* bit 1 = pending update */
} MoonSeedBushState;

STATIC_ASSERT(sizeof(MoonSeedBushState) == 0x2);

/*
 * Per-object extra state for the mmp asteroid set piece
 * (mmp_asteroid_re_getExtraSize == 0x1C).
 */
typedef struct MmpAsteroidReState {
    u8 eventFlags; /* 1/8/0x10/0x20 fx bursts, 0x40 periodic fx, 0x80 seq-ran latch */
    u8 phase; /* gamebit 0x87B value 0..3 */
    u8 intensity; /* gamebit 0x88C / 0xD52; scales rise height + sfx volume */
    u8 pad03;
    f32 stateTimer; /* counts down; clears gamebit 0x88B on expiry */
    f32 periodicFxTimer; /* rand(10,60); flag 0x40 fx cadence */
    f32 baseY; /* obj Y at init */
    f32 baseY2;
    u16 bobPhase; /* angle accumulators for the float wobble */
    u16 rollPhase;
    u16 pitchPhase;
    u8 pad1A[2];
} MmpAsteroidReState;

STATIC_ASSERT(sizeof(MmpAsteroidReState) == 0x1C);

/*
 * Per-object extra state for the mmp trench fx emitter
 * (mmp_trenchfx_getExtraSize == 0x30).
 */
typedef struct MmpTrenchfxState {
    s16 enableBit; /* data+0x24 gamebit gate, -1 = always on */
    u16 extentX; /* data[0x1C..0x1E] << 2 random offset half-extents */
    u16 extentZ;
    u16 extentY;
    s16 emitAngles[3]; /* roll/pitch/yaw presets, mirrored to obj+4/2/0 */
    u8 pad0E[2];
    u32 fxUnk10; /* embedded partfx args record (state+0x10 passed to spawn) */
    u32 fxUnk14;
    f32 fxScale;
    f32 fxX;
    f32 fxY;
    f32 fxZ;
    f32 emitCooldown; /* rand(100,200) frames between bursts */
    f32 emitTimer; /* rand(50,100); spawns effect 0x71F while > 0 */
} MmpTrenchfxState;

STATIC_ASSERT(sizeof(MmpTrenchfxState) == 0x30);

/*
 * Per-object extra state for the mmp moonrock carryable
 * (mmp_moonrock_getExtraSize == 0x30). The leading bytes belong to the
 * gCarryableInterface record (the state pointer itself is handed to it).
 */
typedef struct MmpMoonrockState {
    u8 carryable[0xC];
    f32 baseY; /* lava base height */
    f32 baseY2;
    f32 respawnTimer; /* counts down while flag 0x200 (sunk/reset) */
    f32 homeX; /* spawn position for the reset */
    f32 homeY;
    f32 homeZ;
    u16 flags; /* 1 drop, 2 armed, 4 held?, 8 grab-frame, 0x10/0x20 icon kind, 0x40 thrown, 0x200 respawning, 0x400 placed */
    u16 bobPhase; /* angle accumulators for the float wobble */
    u16 rollPhase;
    u16 pitchPhase;
    u8 pad2C[2];
    u8 kind; /* gamebit-derived 0..6 */
    u8 raised; /* gamebit 0x894 while placed */
} MmpMoonrockState;

STATIC_ASSERT(sizeof(MmpMoonrockState) == 0x30);


extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006c88();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern int FUN_80017b00();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern int FUN_8005b024();
extern int FUN_8005b398();
extern undefined4 FUN_8005d0ac();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined4 FUN_80080f14();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_800e8630();
extern int FUN_800e8b98();
extern undefined4 FUN_8011e868();
extern undefined4 SH_LevelControl_runBloopEvent();
extern ulonglong FUN_80286830();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern uint FUN_80294db4();

extern undefined4 DAT_803ad560;
extern undefined4 DAT_803ad568;
extern undefined4 DAT_803ad56c;
extern undefined4 DAT_803ad570;
extern undefined4 DAT_803ad574;
extern undefined4 DAT_803ad578;
extern undefined4 DAT_803ad580;
extern undefined4 DAT_803ad584;
extern undefined4 DAT_803ad588;
extern undefined4 DAT_803ad58c;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd740;
extern undefined4 DAT_803de7ac;
extern undefined4 DAT_803de7b0;
extern undefined4 DAT_803e50f8;
extern undefined4 DAT_803e50fc;
extern f32 timeDelta;
extern f64 DOUBLE_803e5120;
extern f64 DOUBLE_803e5178;
extern f64 DOUBLE_803e5188;
extern f64 DOUBLE_803e51d8;
extern f64 DOUBLE_803e5240;
extern f32 lbl_803DC074;
extern f32 lbl_803DE7A8;
extern f32 lbl_803E5100;
extern f32 lbl_803E5114;
extern f32 lbl_803E5150;
extern f32 lbl_803E5158;
extern f32 lbl_803E5160;
extern f32 lbl_803E5168;
extern f32 lbl_803E516C;
extern f32 lbl_803E5170;
extern f32 lbl_803E5180;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;
extern f32 lbl_803E51A4;
extern f32 lbl_803E51A8;
extern f32 lbl_803E51AC;
extern f32 lbl_803E51B0;
extern f32 lbl_803E51B4;
extern f32 lbl_803E51BC;
extern f32 lbl_803E51C0;
extern f32 lbl_803E51C4;
extern f32 lbl_803E51C8;
extern f32 lbl_803E51CC;
extern f32 lbl_803E51D0;
extern f32 lbl_803E51D4;
extern f32 lbl_803E51E0;
extern f32 lbl_803E51E4;
extern f32 lbl_803E51E8;
extern f32 lbl_803E51EC;
extern f32 lbl_803E51F0;
extern f32 lbl_803E51F4;
extern f32 lbl_803E51F8;
extern f32 lbl_803E51FC;
extern f32 lbl_803E5200;
extern f32 lbl_803E5204;
extern f32 lbl_803E5208;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;
extern f32 lbl_803E5214;
extern f32 lbl_803E5218;
extern f32 lbl_803E521C;
extern f32 lbl_803E5220;
extern f32 lbl_803E5224;
extern f32 lbl_803E5228;
extern f32 lbl_803E522C;
extern f32 lbl_803E5238;
extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;
extern f32 lbl_803E44C0;

extern void *Obj_GetPlayerObject(void);
extern void gameTextShow(int textId);
extern void envFxActFn_800887f8(int value);
extern void skyFn_80088c94(int flags, int mode);
extern int getEnvfxActImmediately(int obj, int target, int actId, int flags);
extern int getEnvfxAct(int obj, int target, int actId, int flags);
extern int coordsToMapCell(f32 x, f32 z);
extern void Music_Trigger(int id, int mode);
extern void SCGameBitLatch_Update(void *latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int setBit, int textId);

/*
 * --INFO--
 *
 * Function: MMP_levelcontrol_update
 * EN v1.0 Address: 0x801A6778
 * EN v1.0 Size: 972b
 * EN v1.1 Address: 0x801A6AD0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void MMP_levelcontrol_update(int obj)
{
  int playerForMap;
  int playerForFx;

  playerForMap = (int)Obj_GetPlayerObject();
  playerForFx = (int)Obj_GetPlayerObject();

  if (lbl_803DDB28 > lbl_803E44C0) {
    gameTextShow(0x34f);
    {
      f32 t = lbl_803DDB28 - timeDelta;
      lbl_803DDB28 = t;
      if (t < lbl_803E44C0) {
        lbl_803DDB28 = lbl_803E44C0;
      }
    }
  }

  if (((GameObject *)obj)->unkF4 != 0) {
    envFxActFn_800887f8(0);
    if (GameBit_Get(0xd47) != 0) {
      skyFn_80088c94(7, 1);
      if (((GameObject *)obj)->unkF4 == 2) {
        getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x234, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x235, 0);
      } else {
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x234, 0);
        getEnvfxAct(obj, playerForFx, 0x235, 0);
      }
      ((GameObject *)obj)->unkF8 = 0;
    } else if (GameBit_Get(0xf33) != 0) {
      skyFn_80088c94(7, 1);
      if (((GameObject *)obj)->unkF4 == 2) {
        getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x10c, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x10d, 0);
      } else {
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x10c, 0);
        getEnvfxAct(obj, playerForFx, 0x10d, 0);
      }
      ((GameObject *)obj)->unkF8 = 1;
    } else if (coordsToMapCell(*(f32 *)(playerForMap + 0xc), *(f32 *)(playerForMap + 0x14)) == 0x12) {
      skyFn_80088c94(7, 0);
      if (((GameObject *)obj)->unkF4 == 2) {
        getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x138, 0);
        getEnvfxActImmediately(obj, playerForFx, 0x139, 0);
      } else {
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x138, 0);
        getEnvfxAct(obj, playerForFx, 0x139, 0);
      }
      ((GameObject *)obj)->unkF8 = 0;
    }
    Music_Trigger(0x31, 1);
    ((GameObject *)obj)->unkF4 = 0;
  }

  if (((GameObject *)obj)->unkF8 != 0 && GameBit_Get(0xf33) == 0) {
    skyFn_80088c94(7, 0);
    getEnvfxAct(obj, playerForFx, 0x13a, 0);
    getEnvfxAct(obj, playerForFx, 0x138, 0);
    getEnvfxAct(obj, playerForFx, 0x139, 0);
    ((GameObject *)obj)->unkF8 = 0;
  } else if (((GameObject *)obj)->unkF8 == 0 && GameBit_Get(0xf33) != 0) {
    skyFn_80088c94(7, 1);
    getEnvfxAct(obj, playerForFx, 0x13a, 0);
    getEnvfxAct(obj, playerForFx, 0x10c, 0);
    getEnvfxAct(obj, playerForFx, 0x10d, 0);
    ((GameObject *)obj)->unkF8 = 1;
  }

  SCGameBitLatch_Update(&lbl_803DDB2C, 1, -1, -1, 0x389, 0xd5);
  SCGameBitLatch_Update(&lbl_803DDB2C, 2, -1, -1, 0xcbb, 0xc4);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801a68b8
 * EN v1.0 Address: 0x801A68B8
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801A6BEC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a68b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,ObjAnimUpdateState *animUpdate,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = FUN_80017a98();
  animUpdate->sequenceEventActive = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1) {
    bVar1 = animUpdate->eventIds[iVar3];
    if (bVar1 == 2) {
      param_1 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x138,0,param_13,param_14,param_15,param_16);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      param_1 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x13b,0,param_13,param_14,param_15,param_16);
    }
  }
  FUN_801a6b10(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6ab0
 * EN v1.0 Address: 0x801A6AB0
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801A6CC0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6ab0(void)
{
  lbl_803DE7A8 = lbl_803E5158;
  DAT_803de7ac = 0;
  FUN_800067c0((int *)0xd5,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6ae8
 * EN v1.0 Address: 0x801A6AE8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A6CF8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6ae8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6b10
 * EN v1.0 Address: 0x801A6B10
 * EN v1.0 Size: 2872b
 * EN v1.1 Address: 0x801A6D2C
 * EN v1.1 Size: 972b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6b10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  undefined8 uVar5;
  
  iVar1 = FUN_80017a98();
  uVar2 = FUN_80017a98();
  dVar4 = (double)lbl_803DE7A8;
  if ((double)lbl_803E5158 < dVar4) {
    FUN_80006c88(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x34f);
    lbl_803DE7A8 = lbl_803DE7A8 - lbl_803DC074;
    dVar4 = (double)lbl_803DE7A8;
    if (dVar4 < (double)lbl_803E5158) {
      lbl_803DE7A8 = lbl_803E5158;
    }
  }
  if (((GameObject *)param_9)->unkF4 != 0) {
    FUN_80080f14(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    uVar3 = GameBit_Get(0xd47);
    if (uVar3 == 0) {
      uVar3 = GameBit_Get(0xf33);
      if (uVar3 == 0) {
        param_2 = (double)*(float *)(iVar1 + 0x14);
        iVar1 = FUN_8005b024();
        if (iVar1 == 0x12) {
          uVar5 = FUN_80080f28(7,'\0');
          if (((GameObject *)param_9)->unkF4 == 2) {
            uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          else {
            uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          *(undefined4 *)(param_9 + 0xf8) = 0;
        }
      }
      else {
        uVar5 = FUN_80080f28(7,'\x01');
        if (((GameObject *)param_9)->unkF4 == 2) {
          uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        *(undefined4 *)(param_9 + 0xf8) = 1;
      }
    }
    else {
      uVar5 = FUN_80080f28(7,'\x01');
      if (((GameObject *)param_9)->unkF4 == 2) {
        uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0;
    }
    FUN_800067c0((int *)0x31,1);
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  if ((((GameObject *)param_9)->unkF8 == 0) || (uVar3 = GameBit_Get(0xf33), uVar3 != 0)) {
    if ((((GameObject *)param_9)->unkF8 == 0) && (uVar3 = GameBit_Get(0xf33), uVar3 != 0)) {
      uVar5 = FUN_80080f28(7,'\x01');
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x10d
                   ,0,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(param_9 + 0xf8) = 1;
    }
  }
  else {
    uVar5 = FUN_80080f28(7,'\0');
    uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x13a,0,in_r7,in_r8,in_r9,in_r10);
    uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x138,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x139,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xf8) = 0;
  }
  SH_LevelControl_runBloopEvent(&DAT_803de7ac,1,-1,-1,0x389,(int *)0xd5);
  SH_LevelControl_runBloopEvent(&DAT_803de7ac,2,-1,-1,0xcbb,(int *)0xc4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7648
 * EN v1.0 Address: 0x801A7648
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A70F8
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7648(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a764c
 * EN v1.0 Address: 0x801A764C
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801A71DC
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a764c(undefined4 param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  
  iVar2 = FUN_8028683c();
  pcVar7 = *(char **)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  if ((*pcVar7 == '\0') && (uVar3 = GameBit_Get((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
    *pcVar7 = '\x02';
  }
  for (iVar5 = 0; iVar5 < (int)(uint)animUpdate->eventCount; iVar5 = iVar5 + 1) {
    bVar1 = animUpdate->eventIds[iVar5];
    if (bVar1 == 2) {
      (*gPartfxInterface)->spawnObject((void *)iVar2, 0x70b, NULL, 2, -1, NULL);
      iVar4 = 0;
      do {
        (*gPartfxInterface)->spawnObject((void *)iVar2, 0x70c, NULL, 2, -1, NULL);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *pcVar7 = '\x01';
      uVar3 = (uint)*(short *)(iVar6 + 0x1a);
      if (uVar3 != 0xffffffff) {
        GameBit_Set(uVar3,1);
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a777c
 * EN v1.0 Address: 0x801A777C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A7324
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a777c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a77a4
 * EN v1.0 Address: 0x801A77A4
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801A7358
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a77a4(int param_1)
{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = ((GameObject *)param_1)->extra;
  iVar2 = *(int *)&((GameObject *)param_1)->anim.placementData;
  if ((pcVar3[1] & 1U) != 0) {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*pcVar3 == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = (uint)*(byte *)(iVar2 + 0x20);
      (*gObjectTriggerInterface)->preempt(param_1, *(s16 *)(iVar2 + 0x1c));
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (*gObjectTriggerInterface)->runSequence((int)*(char *)(iVar2 + 0x1e), (void *)param_1, uVar1);
    }
    pcVar3[1] = pcVar3[1] & 0xfe;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7870
 * EN v1.0 Address: 0x801A7870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A7424
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7870(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a7874
 * EN v1.0 Address: 0x801A7874
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801A7500
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a7874(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,ObjAnimUpdateState *animUpdate)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = ((GameObject *)param_9)->extra;
  animUpdate->sequenceEventActive = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1) {
    bVar1 = animUpdate->eventIds[iVar3];
    if (bVar1 == 2) {
      *pbVar4 = *pbVar4 & 0xf6;
      *pbVar4 = *pbVar4 | 0x30;
      ((ObjAnimComponent *)param_9)->bankIndex = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        param_1 = FUN_8005d0ac(0);
      }
      else {
        *pbVar4 = 0xd;
        pbVar4[1] = 1;
        param_1 = GameBit_Set(0x87b,(uint)pbVar4[1]);
        ((GameObject *)param_9)->anim.alpha = 0xff;
      }
    }
    else if (bVar1 == 4) {
      *(float *)(pbVar4 + 4) = lbl_803E5180;
      param_1 = FUN_8005d0ac(1);
    }
    else if (bVar1 < 4) {
      *pbVar4 = *pbVar4 & 0xdf;
      *pbVar4 = *pbVar4 | 0x50;
      uVar2 = randomGetRange(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (f32)(s32)(uVar2);
      pbVar4[1] = 1;
      param_1 = GameBit_Set(0x87b,(uint)pbVar4[1]);
    }
  }
  *pbVar4 = *pbVar4 | 0x80;
  FUN_801a7a94(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7a6c
 * EN v1.0 Address: 0x801A7A6C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A76A4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7a6c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a7a94
 * EN v1.0 Address: 0x801A7A94
 * EN v1.0 Size: 1744b
 * EN v1.1 Address: 0x801A76D8
 * EN v1.1 Size: 1660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a7a94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  double dVar5;
  undefined8 local_38;
  
  pbVar4 = ((GameObject *)param_9)->extra;
  if ((*pbVar4 & 0x80) == 0) {
    uVar2 = GameBit_Get(0xd52);
    if (uVar2 == 0) {
      uVar2 = GameBit_Get(0x88c);
      pbVar4[2] = (byte)uVar2;
    }
    else {
      pbVar4[2] = 1;
    }
    pbVar4[1] = 2;
    FUN_800068c4(param_9,0x107);
    uVar2 = (uint)pbVar4[2] * 0x20 + 0x20;
    if (0x7f < uVar2) {
      uVar2 = 0x7f;
    }
    FUN_80006814((double)lbl_803E5194,param_9,0x40,(byte)uVar2);
    if (pbVar4[2] != 0) {
      fVar1 = ((GameObject *)param_9)->anim.velocityY;
      if (lbl_803E5198 *
          ((*(float *)(pbVar4 + 0xc) + *(float *)((uint)pbVar4[2] * 4 + -0x7fcdc1f0)) -
          ((GameObject *)param_9)->anim.localPosY) <= fVar1) {
        ((GameObject *)param_9)->anim.velocityY = -(lbl_803E51A0 * lbl_803DC074 - fVar1);
      }
      else {
        ((GameObject *)param_9)->anim.velocityY = lbl_803E519C * lbl_803DC074 + fVar1;
      }
      dVar5 = DOUBLE_803e51d8;
      *(short *)(pbVar4 + 0x14) =
           (short)(int)(lbl_803E51A4 * lbl_803DC074 +
                       (f32)(u32)*(ushort *)(pbVar4 + 0x14));
      *(short *)(pbVar4 + 0x16) =
           (short)(int)(lbl_803E51A8 * lbl_803DC074 + (f32)(u32)*(ushort *)(pbVar4 + 0x16));
      *(short *)(pbVar4 + 0x18) =
           (short)(int)(lbl_803E51AC * lbl_803DC074 + (f32)(u32)*(ushort *)(pbVar4 + 0x18));
      param_3 = (double)lbl_803E51B0;
      FUN_80017a88(param_3,(double)(((GameObject *)param_9)->anim.velocityY * lbl_803DC074),param_3,param_9);
      dVar5 = (double)FUN_80293f90();
      ((GameObject *)param_9)->anim.localPosY = (float)((double)((GameObject *)param_9)->anim.localPosY + dVar5);
      if (((GameObject *)param_9)->anim.localPosY < *(float *)(pbVar4 + 0xc)) {
        ((GameObject *)param_9)->anim.localPosY = *(float *)(pbVar4 + 0xc);
      }
      dVar5 = (double)FUN_80293f90();
      ((GameObject *)param_9)->anim.rotZ =
           ((GameObject *)param_9)->anim.rotZ + (short)(int)((double)lbl_803E51BC * dVar5);
      param_2 = (double)lbl_803E51B4;
      dVar5 = (double)FUN_80293f90();
      ((GameObject *)param_9)->anim.rotY =
           ((GameObject *)param_9)->anim.rotY + (short)(int)((double)lbl_803E51BC * dVar5);
      DAT_803ad568 = lbl_803E5190;
      DAT_803ad56c = *(undefined4 *)(param_9 + 0xc);
      DAT_803ad570 = *(float *)(pbVar4 + 0xc) - lbl_803E51C0;
      DAT_803ad574 = *(undefined4 *)(param_9 + 0x14);
      DAT_803de7b0 = (int)(((GameObject *)param_9)->anim.localPosY - *(float *)(pbVar4 + 0xc));
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x722, NULL, 2, -1, &DAT_803de7b0);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x723, &DAT_803ad560, 0x200001, -1,
                                       &DAT_803de7b0);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x723, &DAT_803ad560, 0x200001, -1,
                                       &DAT_803de7b0);
    }
  }
  if (*pbVar4 != 0) {
    if ((*pbVar4 & 1) != 0) {
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x716, NULL, 1, -1, NULL);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x716, NULL, 1, -1, NULL);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x716, NULL, 1, -1, NULL);
    }
    if ((*pbVar4 & 8) != 0) {
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x71a, NULL, 2, -1, NULL);
    }
    if ((*pbVar4 & 0x10) != 0) {
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x71b, NULL, 1, -1, NULL);
      iVar3 = 0x28;
      do {
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x71c, NULL, 1, -1, NULL);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      FUN_8008112c((double)lbl_803E51C4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,1,0,1,0,1,0);
      FUN_8000691c((double)lbl_803E51C8,(double)lbl_803E51CC,(double)lbl_803E51D0);
      FUN_80006b94((double)lbl_803E51D4);
      *pbVar4 = *pbVar4 & 0xef;
    }
    if ((*pbVar4 & 0x20) != 0) {
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x71d, NULL, 1, -1, NULL);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x71d, NULL, 1, -1, NULL);
    }
    if (((*pbVar4 & 0x40) != 0) &&
       (*(float *)(pbVar4 + 8) = *(float *)(pbVar4 + 8) - lbl_803DC074,
       *(float *)(pbVar4 + 8) < lbl_803E51B0)) {
      uVar2 = randomGetRange(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (f32)(s32)(uVar2);
      (*gPartfxInterface)->spawnObject((void *)param_9, 0x71e, NULL, 1, -1, NULL);
    }
  }
  fVar1 = lbl_803E51B0;
  if (lbl_803E51B0 < *(float *)(pbVar4 + 4)) {
    *(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) - lbl_803DC074;
    if (*(float *)(pbVar4 + 4) <= fVar1) {
      GameBit_Set(0x88b,0);
    }
  }
  *pbVar4 = *pbVar4 & 0x7f;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8164
 * EN v1.0 Address: 0x801A8164
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A7D54
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8164(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a8168
 * EN v1.0 Address: 0x801A8168
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x801A7E7C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801a8168(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7)
{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  double dVar5;
  undefined4 *local_38 [4];
  
  iVar2 = FUN_800632f4(param_1,param_2,param_3,param_5,local_38,0,1);
  *param_6 = (float)param_2;
  *param_7 = 0;
  iVar4 = 0;
  iVar1 = iVar2 + -1;
  puVar3 = local_38[0];
  if (0 < iVar2) {
    do {
      if (((*(char *)((float *)*puVar3 + 5) != '\x0e') &&
          (dVar5 = (double)*(float *)*puVar3, param_2 < dVar5)) &&
         ((dVar5 < param_4 || (iVar4 == iVar1)))) {
        *param_7 = *(undefined4 *)(local_38[0][iVar4] + 0x10);
        *param_6 = *(float *)local_38[0][iVar4];
        return 1 - ((int)((uint)(byte)((*(float *)(local_38[0][iVar4] + 8) < lbl_803E51E0) << 3)
                         << 0x1c) >> 0x1f);
      }
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8284
 * EN v1.0 Address: 0x801A8284
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x801A7F94
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8284(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)
{
  int iVar1;
  int iVar2;
  undefined4 uStack_60;
  int aiStack_5c [21];
  
  iVar2 = param_9[0x2e];
  iVar1 = ObjHits_GetPriorityHit((int)param_9,&uStack_60,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0) {
    iVar1 = FUN_800620e8(param_9 + 0x20,param_9 + 3,(float *)0x1,aiStack_5c,param_9,1,0xffffffff,
                         0xff,0);
  }
  if ((iVar1 != 0) ||
     (((*(char *)(param_9[0x15] + 0xad) != '\0' && ((*(ushort *)(iVar2 + 0x24) & 0x40) != 0)) ||
      ((*(ushort *)(iVar2 + 0x24) & 0x100) != 0)))) {
    param_9[4] = (int)((float)param_9[4] + lbl_803E51E8);
    FUN_8008112c((double)lbl_803E51EC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,1,0,0,0,1,0);
    *(ushort *)(iVar2 + 0x24) = *(ushort *)(iVar2 + 0x24) | 0x200;
    *(float *)(iVar2 + 0x14) = lbl_803E51F0;
    ((GameObject *)param_9)->anim.alpha = 0;
    param_9[3] = *(int *)(iVar2 + 0x18);
    param_9[4] = *(int *)(iVar2 + 0x1c);
    param_9[5] = *(int *)(iVar2 + 0x20);
    FUN_800e8630((int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8454
 * EN v1.0 Address: 0x801A8454
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801A80C4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8454(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float local_18;
  undefined4 auStack_14 [3];
  
  iVar4 = *(int *)&((GameObject *)param_1)->extra;
  iVar3 = FUN_8005b398((double)((GameObject *)param_1)->anim.localPosX,(double)((GameObject *)param_1)->anim.localPosY);
  if (iVar3 != -1) {
    ObjHits_SetHitVolumeSlot(param_1,0xe,1,0);
    ObjHits_EnableObject(param_1);
    ((GameObject *)param_1)->anim.velocityY = -(lbl_803E51F4 * lbl_803DC074 - ((GameObject *)param_1)->anim.velocityY);
    fVar1 = ((GameObject *)param_1)->anim.velocityX;
    fVar2 = (fVar1 < lbl_803E51F8) ? lbl_803E51F8 : ((fVar1 > lbl_803E51FC) ? lbl_803E51FC : fVar1);
    ((GameObject *)param_1)->anim.velocityX = fVar2;
    fVar1 = ((GameObject *)param_1)->anim.velocityY;
    fVar2 = (fVar1 < lbl_803E51F8) ? lbl_803E51F8 : ((fVar1 > lbl_803E51FC) ? lbl_803E51FC : fVar1);
    ((GameObject *)param_1)->anim.velocityY = fVar2;
    fVar1 = ((GameObject *)param_1)->anim.velocityX;
    fVar2 = (fVar1 < lbl_803E51F8) ? lbl_803E51F8 : ((fVar1 > lbl_803E51FC) ? lbl_803E51FC : fVar1);
    ((GameObject *)param_1)->anim.velocityX = fVar2;
    FUN_80017a88((double)(((GameObject *)param_1)->anim.velocityX * lbl_803DC074),
                 (double)(((GameObject *)param_1)->anim.velocityY * lbl_803DC074),
                 (double)(((GameObject *)param_1)->anim.velocityZ * lbl_803DC074),param_1);
    *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) & ~0x80;
    iVar3 = FUN_801a8168((double)((GameObject *)param_1)->anim.localPosX,(double)((GameObject *)param_1)->anim.localPosY,
                         (double)((GameObject *)param_1)->anim.localPosZ,
                         (double)(float)((double)lbl_803E5200 + (double)((GameObject *)param_1)->anim.localPosY
                                        ),param_1,&local_18,auStack_14);
    if (iVar3 != 0) {
      if (iVar3 == 2) {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x100;
        fVar1 = lbl_803E51EC;
        ((GameObject *)param_1)->anim.velocityX = lbl_803E51EC;
        ((GameObject *)param_1)->anim.velocityY = fVar1;
        ((GameObject *)param_1)->anim.velocityZ = fVar1;
      }
      else {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x180;
        ((GameObject *)param_1)->anim.localPosY = local_18;
        fVar1 = lbl_803E51EC;
        ((GameObject *)param_1)->anim.velocityX = lbl_803E51EC;
        ((GameObject *)param_1)->anim.velocityY = fVar1;
        ((GameObject *)param_1)->anim.velocityZ = fVar1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a86b0
 * EN v1.0 Address: 0x801A86B0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801A8278
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a86b0(int param_1)
{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  puVar1 = (ushort *)FUN_80017a98();
  local_1c = lbl_803E51EC;
  iVar2 = *(int *)(puVar1 + 0x5c);
  ((GameObject *)param_1)->anim.velocityX = lbl_803E51EC;
  ((GameObject *)param_1)->anim.velocityY = lbl_803E5208 * *(float *)(iVar2 + 0x298) + lbl_803E5204;
  ((GameObject *)param_1)->anim.velocityZ = lbl_803E5210 * *(float *)(iVar2 + 0x298) + lbl_803E520C;
  local_18 = local_1c;
  local_14 = local_1c;
  local_20 = lbl_803E5214;
  local_28[2] = 0;
  local_28[1] = 0;
  local_28[0] = *puVar1;
  FUN_80017748(local_28,(float *)&((GameObject *)param_1)->anim.velocityX);
  *(ushort *)(iVar3 + 0x24) = *(ushort *)(iVar3 + 0x24) | 0x40;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8748
 * EN v1.0 Address: 0x801A8748
 * EN v1.0 Size: 928b
 * EN v1.1 Address: 0x801A8328
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8748(undefined4 param_1,undefined4 param_2,uint param_3)
{
  char cVar1;
  undefined4 uVar2;
  char cVar4;
  ushort uVar3;
  int iVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  ulonglong uVar13;
  int local_38;
  int local_34 [13];
  
  uVar13 = FUN_80286830();
  iVar5 = (int)(uVar13 >> 0x20);
  iVar11 = *(int *)(iVar5 + 0xb8);
  iVar6 = FUN_80017b00(local_34,&local_38);
  for (; local_34[0] < local_38; local_34[0] = local_34[0] + 1) {
    iVar9 = *(int *)(iVar6 + local_34[0] * 4);
    if (((iVar9 != iVar5) && (*(short *)(iVar9 + 0x46) == 0x518)) &&
       (dVar12 = (double)FUN_8001771c((float *)(iVar5 + 0x18),(float *)(iVar9 + 0x18)),
       dVar12 < (double)lbl_803E5218)) {
      iVar10 = *(int *)(*(int *)(iVar6 + local_34[0] * 4) + 0x4c);
      iVar9 = *(int *)(iVar5 + 0x4c);
      uVar7 = GameBit_Get(0x88c);
      cVar4 = (char)uVar7;
      uVar7 = GameBit_Get(0x894);
      cVar8 = (char)uVar7;
      if ((uVar13 & 0xff) == 0) {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,1);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          GameBit_Set((int)*(short *)(iVar10 + 0x1e),0);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          cVar4 = cVar4 + -1;
        }
        else {
          cVar8 = cVar8 + -1;
        }
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          GameBit_Set(uVar7,0);
          *(undefined *)(iVar11 + 0x2e) = 0;
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) & 0xfbff;
        *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar11 + 0x18);
        *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar11 + 0x1c);
        *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar11 + 0x20);
        FUN_800e8630(iVar5);
      }
      else {
        (**(code **)(*DAT_803dd740 + 0x20))(iVar11,0);
        if ((int)*(short *)(iVar10 + 0x1e) != 0xffffffff) {
          GameBit_Set((int)*(short *)(iVar10 + 0x1e),1);
        }
        if ((param_3 & 0xff) == 0) {
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0xc);
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x10);
          *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(*(int *)(iVar6 + local_34[0] * 4) + 0x14);
          FUN_800e8630(iVar5);
        }
        uVar2 = *(undefined4 *)(iVar5 + 0x10);
        *(undefined4 *)(iVar11 + 0xc) = uVar2;
        *(undefined4 *)(iVar11 + 0x10) = uVar2;
        uVar7 = (uint)*(short *)(iVar9 + 0x1a);
        if (uVar7 != 0xffffffff) {
          GameBit_Set(uVar7,(int)*(short *)(iVar10 + 0x1a));
          *(char *)(iVar11 + 0x2e) = (char)*(undefined2 *)(iVar10 + 0x1a);
        }
        cVar1 = *(char *)(iVar11 + 0x2e);
        if (((cVar1 == '\x03') || (cVar1 == '\x04')) || (cVar1 == '\x06')) {
          if ((param_3 & 0xff) != 2) {
            cVar4 = cVar4 + '\x01';
          }
          if ((param_3 & 0xff) == 0) {
            if (cVar4 < '\x03') {
              uVar3 = 0x109;
            }
            else {
              uVar3 = 0x7e;
            }
            FUN_80006824(0,uVar3);
            GameBit_Set(0x9ae,1);
          }
          *(ushort *)(iVar11 + 0x24) = *(ushort *)(iVar11 + 0x24) | 0x400;
          FUN_8011e868(0);
        }
        else if ((param_3 & 0xff) != 2) {
          cVar8 = cVar8 + '\x01';
        }
      }
      if (cVar4 < '\x03') {
        GameBit_Set(0x89b,0);
      }
      else {
        GameBit_Set(0x89b,1);
      }
      if (cVar4 < '\x04') {
        if (cVar4 < '\0') {
          cVar4 = '\0';
        }
      }
      else {
        cVar4 = '\x03';
      }
      if (cVar8 < '\x04') {
        if (cVar8 < '\0') {
          cVar8 = '\0';
        }
      }
      else {
        cVar8 = '\x03';
      }
      GameBit_Set(0x88c,(int)cVar4);
      GameBit_Set(0x894,(int)cVar8);
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8ae8
 * EN v1.0 Address: 0x801A8AE8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801A8678
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8ae8(double param_1,double param_2,double param_3,int param_4)
{
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  FUN_800e8630(param_4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8b20
 * EN v1.0 Address: 0x801A8B20
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A86A4
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8b20(int param_1,char param_2)
{
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_1)->extra;
  if (param_2 != '\0') {
    *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) | 4;
    *(byte *)&((GameObject *)param_1)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_1)->anim.resetHitboxMode | 8;
    return;
  }
  *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) & ~0x4;
  *(byte *)&((GameObject *)param_1)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_1)->anim.resetHitboxMode & 0xf7;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8b64
 * EN v1.0 Address: 0x801A8B64
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801A870C
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8b64(int param_1)
{
  ObjGroup_RemoveObject(param_1,4);
  (**(code **)(*DAT_803dd740 + 0x10))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8bb0
 * EN v1.0 Address: 0x801A8BB0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801A8754
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8bb0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80286840();
  iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)visible);
  if (iVar2 != 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8c14
 * EN v1.0 Address: 0x801A8C14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A87D4
 * EN v1.1 Size: 1736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8c14(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a8c18
 * EN v1.0 Address: 0x801A8C18
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x801A8E9C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8c18(int param_1,int param_2)
{
  char cVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)&((GameObject *)param_1)->extra;
  ((GameObject *)param_1)->objectFlags = ((GameObject *)param_1)->objectFlags | 0x2000;
  *(undefined2 *)(iVar4 + 0x24) = 0;
  uVar3 = GameBit_Get((int)*(short *)(param_2 + 0x1a));
  *(char *)(iVar4 + 0x2e) = (char)uVar3;
  cVar1 = *(char *)(iVar4 + 0x2e);
  if (cVar1 == '\0') {
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,1);
  }
  else {
    if (((byte)(cVar1 - 3U) < 2) || (cVar1 == '\x06')) {
      *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x400;
    }
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,0);
  }
  uVar2 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0xc) = uVar2;
  *(undefined4 *)(iVar4 + 0x10) = uVar2;
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0xb8),0x32);
  (**(code **)(*DAT_803dd740 + 0x2c))(iVar4,1);
  ObjGroup_AddObject(param_1,4);
  *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(param_1 + 0x14);
  ObjHits_DisableObject(param_1);
  FUN_801a8748(param_1,1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a8d70
 * EN v1.0 Address: 0x801A8D70
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801A9004
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8d70(int obj)
{
  (*gExpgfxInterface)->freeSource2((u32)obj);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void MMP_levelcontrol_release(void) {}
void MMP_levelcontrol_initialise(void) {}
void MoonSeedBush_free(void) {}
void MoonSeedBush_hitDetect(void) {}
void MoonSeedBush_release(void) {}
void MoonSeedBush_initialise(void) {}
void mmp_asteroid_re_free(void) {}
void mmp_asteroid_re_hitDetect(void) {}
void mmp_asteroid_re_release(void) {}
void mmp_asteroid_re_initialise(void) {}
void mmp_moonrock_hitDetect(void) {}
void mmp_moonrock_release(void) {}
void mmp_moonrock_initialise(void) {}
void mmp_trenchfx_hitDetect(void) {}
void mmp_trenchfx_release(void) {}
void mmp_trenchfx_initialise(void) {}
void mmp_gyservent_free(void) {}
void mmp_gyservent_render(void) {}
void mmp_gyservent_hitDetect(void) {}
void mmp_gyservent_release(void) {}
void mmp_gyservent_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int MoonSeedBush_getExtraSize(void) { return 0x2; }
int MoonSeedBush_getObjectTypeId(void) { return 0x0; }
int mmp_asteroid_re_getExtraSize(void) { return 0x1c; }
int mmp_asteroid_re_getObjectTypeId(void) { return 0x0; }
int mmp_moonrock_getExtraSize(void) { return 0x30; }
int mmp_moonrock_getObjectTypeId(void) { return 0x0; }
int mmp_trenchfx_getExtraSize(void) { return 0x30; }
int mmp_trenchfx_getObjectTypeId(void) { return 0x0; }
int mmp_gyservent_getExtraSize(void) { return 0x0; }
int mmp_gyservent_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E44D0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E44F8;
#pragma peephole off
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E44D0); }
void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E44F8); }
#pragma peephole reset

extern f32 lbl_803E44D4;
extern f32 lbl_803E44D8;

#pragma scheduling off
#pragma peephole off
void MoonSeedBush_update(int obj) {
    MoonSeedBushState *state = ((GameObject *)obj)->extra;
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    int v;
    if ((state->flags & 1) == 0) return;
    if (*(s16 *)(def + 0x1C) != 0 && state->seedState != 0) {
        v = *(u8 *)(def + 0x20);
        (*gObjectTriggerInterface)->preempt(obj, *(s16 *)(def + 0x1C));
    } else {
        v = -1;
    }
    {
        s32 idx = (s32)(s8)*(u8 *)(def + 0x1E);
        if (idx != -1) {
            (*gObjectTriggerInterface)->runSequence(idx, (void *)obj, v);
        }
    }
    state->flags &= ~1;
}
#pragma peephole reset
#pragma scheduling reset

extern int getSaveGameLoadStatus(void);
extern int mapGetDirIdx(int);
extern void unlockLevel(int, int, int);
extern f32 lbl_803E44C8;
extern u8 framesThisStep;
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
#pragma scheduling off
#pragma peephole off
void mmp_gyservent_update(int obj) {
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    if (GameBit_Get(*(s16 *)(def + 0x1E)) != 0) return;
    ((GameObject *)obj)->unkF4 -= framesThisStep;
    if (((GameObject *)obj)->unkF4 < 0) {
        ((GameObject *)obj)->unkF4 = randomGetRange(0x46, 0xF0);
        ((GameObject *)obj)->unkF8 = randomGetRange(0x1E, 0x3C);
    }
    if (((GameObject *)obj)->unkF8 == 0) return;
    ((GameObject *)obj)->unkF8 -= framesThisStep;
    if (((GameObject *)obj)->unkF8 <= 0) {
        ((GameObject *)obj)->unkF8 = 0;
    } else {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x724, NULL, 2, -1, NULL);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x450);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    MoonSeedBushState *state = ((GameObject *)obj)->extra;
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    int i;
    int j;
    if (state->seedState == 0) {
        if (GameBit_Get(*(s16 *)(def + 0x18)) != 0) {
            state->seedState = 2;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch ((s32)animUpdate->eventIds[i]) {
        case 1:
            state->seedState = 1;
            if (*(s16 *)(def + 0x1A) != -1) {
                GameBit_Set(*(s16 *)(def + 0x1A), 1);
            }
            break;
        case 2:
            (*gPartfxInterface)->spawnObject((void *)obj, 0x70B, NULL, 2, -1, NULL);
            for (j = 0; j < 0x28; j++) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x70C, NULL, 2, -1, NULL);
            }
            break;
        }
    }
    return state->seedState != 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MMP_levelcontrol_init(int obj) {
    ((GameObject *)obj)->objectFlags |= 0x6000;
    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }
    *(u32 *)&((GameObject *)obj)->unkF8 = GameBit_Get(0xF33);
    ((GameObject *)obj)->animEventCallback = (void *)MMP_LevelControl_SeqFn;
    unlockLevel(mapGetDirIdx(0x12), 0, 0);
    lbl_803DDB28 = lbl_803E44C8;
    lbl_803DDB2C = 0;
    Music_Trigger(0xCC, 0);
    Music_Trigger(0xDB, 0);
    Music_Trigger(0xF2, 0);
    Music_Trigger(0xCE, 0);
    Music_Trigger(0xC2, 0);
    GameBit_Set(0xDCF, 0);
}
#pragma peephole reset
#pragma scheduling reset

extern void setDrawLights(int v);
extern f32 lbl_803E44E8;

extern int objPosToMapBlockIdx(double x, double y, double z);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32 *out1, int *out2);
extern f32 lbl_803E4554;
extern f32 lbl_803E455C;
extern f32 lbl_803E4560;
extern f32 lbl_803E4564;
extern f32 lbl_803E4568;

#pragma scheduling off
#pragma peephole off
void fn_801A7B10(int obj) {
    extern int fn_801A78C8(int obj, f32 x, f32 y, f32 z, f32 y2, f32 *out1, int *out2);
    MmpMoonrockState *state = ((GameObject *)obj)->extra;
    int auStack_14[1];
    f32 local_18;
    int idx;
    f32 v;
    int ret;
    idx = objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ);
    if (idx == -1) return;
    ObjHits_SetHitVolumeSlot(obj, 14, 1, 0);
    ObjHits_EnableObject(obj);
    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY - lbl_803E455C * timeDelta;
    {
        f32 v1 = ((GameObject *)obj)->anim.velocityX;
        f32 v2;
        if (v1 < lbl_803E4560) {
            v2 = lbl_803E4560;
        } else if (v1 > lbl_803E4564) {
            v2 = lbl_803E4564;
        } else {
            v2 = v1;
        }
        ((GameObject *)obj)->anim.velocityX = v2;
    }
    {
        f32 v1 = ((GameObject *)obj)->anim.velocityY;
        f32 v2;
        if (v1 < lbl_803E4560) {
            v2 = lbl_803E4560;
        } else if (v1 > lbl_803E4564) {
            v2 = lbl_803E4564;
        } else {
            v2 = v1;
        }
        ((GameObject *)obj)->anim.velocityY = v2;
    }
    {
        f32 v1 = ((GameObject *)obj)->anim.velocityX;
        f32 v2;
        if (v1 < lbl_803E4560) {
            v2 = lbl_803E4560;
        } else if (v1 > lbl_803E4564) {
            v2 = lbl_803E4564;
        } else {
            v2 = v1;
        }
        ((GameObject *)obj)->anim.velocityX = v2;
    }
    objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
    state->flags &= ~0x80;
    v = ((GameObject *)obj)->anim.localPosY;
    ret = fn_801A78C8(obj, ((GameObject *)obj)->anim.localPosX, v, ((GameObject *)obj)->anim.localPosZ, lbl_803E4568 + v, &local_18, auStack_14);
    if (ret == 0) return;
    if (ret == 2) {
        f32 c;
        state->flags |= 0x100;
        c = lbl_803E4554;
        ((GameObject *)obj)->anim.velocityX = c;
        ((GameObject *)obj)->anim.velocityY = c;
        ((GameObject *)obj)->anim.velocityZ = c;
    } else {
        f32 c;
        state->flags |= 0x180;
        ((GameObject *)obj)->anim.localPosY = local_18;
        c = lbl_803E4554;
        ((GameObject *)obj)->anim.velocityX = c;
        ((GameObject *)obj)->anim.velocityY = c;
        ((GameObject *)obj)->anim.velocityZ = c;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801A6F4C(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    MmpAsteroidReState *state = ((GameObject *)obj)->extra;
    int i;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)animUpdate->eventCount; i++) {
        u8 type = animUpdate->eventIds[i];
        switch (type) {
        case 0:
            setDrawLights(0);
            break;
        case 1:
            state->eventFlags = 13;
            state->phase = 1;
            GameBit_Set(0x87b, state->phase);
            ((GameObject *)obj)->anim.alpha = 0xff;
            break;
        case 2:
            state->eventFlags = state->eventFlags & ~9;
            state->eventFlags = state->eventFlags | 0x30;
            ((ObjAnimComponent *)obj)->bankIndex = 1;
            break;
        case 3: {
            int r;
            state->eventFlags = state->eventFlags & ~0x20;
            state->eventFlags = state->eventFlags | 0x50;
            r = (int)randomGetRange(10, 60);
            state->periodicFxTimer = (f32)r;
            state->phase = 1;
            GameBit_Set(0x87b, state->phase);
            break;
        }
        case 4:
            state->stateTimer = lbl_803E44E8;
            setDrawLights(1);
            break;
        }
    }
    state->eventFlags |= 0x80;
    mmp_asteroid_re_update(obj);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mmp_asteroid_re_init(int obj) {
    MmpAsteroidReState *state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->objectFlags |= 0x6000;
    ((GameObject *)obj)->animEventCallback = (void *)fn_801A6F4C;
    state->eventFlags = 0;
    state->intensity = (u8)GameBit_Get(0x88C);
    state->phase = (u8)GameBit_Get(0x87B);
    switch ((s32)state->phase) {
    case 0:
        ((GameObject *)obj)->anim.alpha = 0;
        *(u8 *)&((GameObject *)obj)->anim.bankIndex = 0;
        break;
    case 1:
        ((GameObject *)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8 *)&((GameObject *)obj)->anim.bankIndex = 1;
        state->eventFlags |= 0x40;
        break;
    case 2:
        ((GameObject *)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8 *)&((GameObject *)obj)->anim.bankIndex = 1;
        break;
    case 3:
        ((GameObject *)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8 *)&((GameObject *)obj)->anim.bankIndex = 1;
        break;
    }
    {
        f32 v = ((GameObject *)obj)->anim.localPosY;
        state->baseY = v;
        state->baseY2 = v;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MoonSeedBush_init(int obj, int data) {
    MoonSeedBushState *state = ((GameObject *)obj)->extra;
    state->flags = 1;
    *(s16 *)obj = (s16)((*(u8 *)(data + 0x1F)) << 8);
    ((GameObject *)obj)->animEventCallback = (void *)MoonSeedBush_SeqFn;
    ((GameObject *)obj)->objectFlags |= 0x2000;
    ((GameObject *)obj)->anim.rootMotionScale = (f32)(u32)(*(u8 *)(data + 0x21)) * lbl_803E44D4;
    if (((GameObject *)obj)->anim.rootMotionScale == lbl_803E44D8) {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E44D0;
    }
    ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    if (*(s16 *)(data + 0x1a) != -1) {
        state->seedState = (u8)GameBit_Get(*(s16 *)(data + 0x1a));
    } else {
        state->seedState = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void saveGame_saveObjectPos(int obj);

extern int objBboxFn_800640cc(int *from, int *to, f32 radius, int mode, void *hit, int obj, int p7, int p8, int p9, int p10);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 lbl_803E454C;
extern f32 lbl_803E4550;
extern f32 lbl_803E4558;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801A79E0(int obj) {
    int auStack_14[21];
    int local_18;
    MmpMoonrockState *state;
    int ret;
    state = ((GameObject *)obj)->extra;
    ret = ObjHits_GetPriorityHit(obj, &local_18, (int *)0, (int *)0);
    if (ret == 0) {
        ret = objBboxFn_800640cc((int *)&((GameObject *)obj)->anim.previousLocalPosX, (int *)&((GameObject *)obj)->anim.localPosX, lbl_803E454C, 1, auStack_14, obj, 1, -1, 0xff, 0);
    }
    if ((ret != 0) ||
        (((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactFlags != 0 && (state->flags & 0x40) != 0) ||
         (state->flags & 0x100) != 0)) {
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + lbl_803E4550;
        spawnExplosion(obj, lbl_803E4554, 1, 1, 0, 0, 0, 1, 0);
        state->flags |= 0x200;
        state->respawnTimer = lbl_803E4558;
        ((GameObject *)obj)->anim.alpha = 0;
        ((GameObject *)obj)->anim.localPosX = state->homeX;
        ((GameObject *)obj)->anim.localPosY = state->homeY;
        ((GameObject *)obj)->anim.localPosZ = state->homeZ;
        saveGame_saveObjectPos(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

void fn_801A80C4(int obj, f32 x, f32 y, f32 z) {
    ((GameObject *)obj)->anim.localPosX = x;
    ((GameObject *)obj)->anim.localPosY = y;
    ((GameObject *)obj)->anim.localPosZ = z;
    saveGame_saveObjectPos(obj);
}

/* mmp_trenchfx_free: expgfx interface freeObject callback. */
void mmp_trenchfx_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

extern f32 lbl_803E45C0;
#pragma peephole off
void mmp_trenchfx_init(int obj, int data) {
    MmpTrenchfxState *state = ((GameObject *)obj)->extra;
    s16 v;
    state->enableBit = *(s16 *)(data + 0x24);
    state->extentX = (u16)((*(u8 *)(data + 0x1C)) << 2);
    state->extentZ = (u16)((*(u8 *)(data + 0x1D)) << 2);
    state->extentY = (u16)((*(u8 *)(data + 0x1E)) << 2);
    v = (s16)(((s32)*(s8 *)(data + 0x19)) << 8);
    state->emitAngles[2] = v;
    ((GameObject *)obj)->anim.rotZ = v;
    v = (s16)(((s32)*(s8 *)(data + 0x1A)) << 8);
    state->emitAngles[1] = v;
    ((GameObject *)obj)->anim.rotY = v;
    v = (s16)(((s32)*(s8 *)(data + 0x1B)) << 8);
    state->emitAngles[0] = v;
    *(s16 *)obj = v;
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E45C0;
}
#pragma peephole reset

/* ObjGroup_RemoveObject + vtable[4] tail-call. */
extern int *lbl_803DCAC0;
#define gCarryableInterface lbl_803DCAC0
#pragma scheduling off
void mmp_moonrock_free(int obj) {
    ObjGroup_RemoveObject((uint)obj, 4);
    (*(void (*)(int))(*(int *)(*gCarryableInterface + 0x10)))(obj);
}
#pragma scheduling reset

extern f32 lbl_803E457C;
#pragma scheduling off
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    if ((*(int (*)(int, int))(*(int *)(*gCarryableInterface + 0xC)))(obj, (s32)visible) != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (obj, p2, p3, p4, p5, lbl_803E457C);
    }
}
#pragma scheduling reset

extern void vecRotateZXY(void *in, void *out);
extern f32 lbl_803E456C;
extern f32 lbl_803E4570;
extern f32 lbl_803E4574;
extern f32 lbl_803E4578;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801A7CC4(int obj) {
    MmpMoonrockState *state = ((GameObject *)obj)->extra;
    struct {
        s16 a;
        s16 b;
        s16 c;
        s16 _pad;
        f32 d;
        f32 e;
        f32 f;
        f32 g;
    } stk;
    int *player = (int *)Obj_GetPlayerObject();
    int *playerState = *(int **)((char *)player + 0xB8);
    f32 c1 = lbl_803E4554;
    ((GameObject *)obj)->anim.velocityX = c1;
    ((GameObject *)obj)->anim.velocityY = lbl_803E4570 * *(f32 *)((char *)playerState + 0x298) + lbl_803E456C;
    ((GameObject *)obj)->anim.velocityZ = lbl_803E4578 * *(f32 *)((char *)playerState + 0x298) + lbl_803E4574;
    stk.e = c1;
    stk.f = c1;
    stk.g = c1;
    stk.d = lbl_803E457C;
    stk.c = 0;
    stk.b = 0;
    stk.a = *(s16 *)player;
    vecRotateZXY(&stk, (void *)(obj + 0x24));
    state->flags |= 0x40;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_801A80F0(int obj, u8 flag) {
    MmpMoonrockState *state = ((GameObject *)obj)->extra;
    if (flag != 0) {
        state->flags |= 0x4;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
    } else {
        state->flags &= ~0x4;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mmp_gyservent_init(int obj) {
    ((GameObject *)obj)->objectFlags |= 0x6000;
    *(u32 *)&((GameObject *)obj)->unkF4 = randomGetRange(0xa, 0xc8);
    ((GameObject *)obj)->anim.alpha = 0;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
}

void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset
#pragma scheduling reset

extern void fn_801A7D74(int obj, u8 a, u8 b);

extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, f32 ***out, int a, int b);
extern f32 lbl_803E4548;

#pragma scheduling off
#pragma peephole off
int fn_801A78C8(f32 x, f32 y, f32 z, f32 y2, int obj, f32 *out1, int *out2) {
    f32 **results;
    f32 *e;
    int i;
    int count;

    count = hitDetectFn_80065e50(obj, x, y, z, &results, 0, 1);
    *out1 = y;
    *out2 = 0;
    for (i = 0; i < count; i++) {
        e = results[i];
        if (*(s8 *)((u8 *)e + 0x14) != 0xE && y < e[0] && (y2 > e[0] || i == count - 1)) {
            *out2 = *(int *)((u8 *)results[i] + 0x10);
            *out1 = results[i][0];
            return (results[i][2] < lbl_803E4548) + 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void mmp_moonrock_init(int obj, int param2)
{
    MmpMoonrockState *state = ((GameObject *)obj)->extra;
    u8 kind;
    ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x2000;
    *(s16 *)&state->flags = 0;
    state->kind = (u8)GameBit_Get(*(s16 *)(param2 + 0x1a));
    kind = state->kind;
    if (kind != 0) {
        if ((u8)(kind - 3) <= 1 || kind == 6) {
            state->flags = state->flags | 0x400;
        }
        (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x20))((int)state, 0);
    } else {
        (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x20))((int)state, 1);
    }
    {
        f32 z = ((GameObject *)obj)->anim.localPosY;
        state->baseY = z;
        state->baseY2 = z;
    }
    (*(int (**)(int, int, int))(*(int *)lbl_803DCAC0 + 0x4))(obj, *(int *)&((GameObject *)obj)->extra, 0x32);
    (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x2c))((int)state, 1);
    ObjGroup_AddObject(obj, 4);
    state->homeX = ((GameObject *)obj)->anim.localPosX;
    state->homeY = ((GameObject *)obj)->anim.localPosY;
    state->homeZ = ((GameObject *)obj)->anim.localPosZ;
    ObjHits_DisableObject(obj);
    fn_801A7D74(obj, 1, 2);
}
#pragma peephole reset
#pragma scheduling reset

extern int *ObjList_GetObjects(int *idx, int *count);
extern f32 Vec_distance(void *a, void *b);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void setAButtonIcon(int icon);
extern f32 lbl_803E4580;

#pragma scheduling off
#pragma peephole off
void fn_801A7D74(int obj, u8 a, u8 b) {
    int i;
    int count;
    int *list;
    MmpMoonrockState *state;
    int odef;
    int mydef;
    s8 g1;
    s8 g2;

    state = ((GameObject *)obj)->extra;
    list = ObjList_GetObjects(&i, &count);
    for (; i < count; i++) {
        u32 o = (u32)list[i];
        if (o != (u32)obj && *(s16 *)(o + 0x46) == 0x518 &&
            Vec_distance((void *)(obj + 0x18), (void *)(o + 0x18)) < lbl_803E4580) {
            u32 c;
            odef = *(int *)(list[i] + 0x4C);
            mydef = *(int *)&((GameObject *)obj)->anim.placementData;
            g1 = GameBit_Get(0x88C);
            g2 = GameBit_Get(0x894);
            if (a == 0) {
                (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x20))((int)state, 1);
                if (*(s16 *)(odef + 0x1E) != -1) {
                    GameBit_Set(*(s16 *)(odef + 0x1E), 0);
                }
                c = state->kind;
                if (c == 3) goto dec;
                if (c == 4) goto dec;
                if (c == 6) {
                dec:
                    g1 -= 1;
                } else {
                    g2 -= 1;
                }
                if (*(s16 *)(mydef + 0x1A) != -1) {
                    GameBit_Set(*(s16 *)(mydef + 0x1A), 0);
                    state->kind = 0;
                }
                {
                    f32 y = ((GameObject *)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                state->flags &= ~0x400;
                ((GameObject *)obj)->anim.localPosX = state->homeX;
                ((GameObject *)obj)->anim.localPosY = state->homeY;
                ((GameObject *)obj)->anim.localPosZ = state->homeZ;
                saveGame_saveObjectPos(obj);
            } else {
                (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x20))((int)state, 0);
                if (*(s16 *)(odef + 0x1E) != -1) {
                    GameBit_Set(*(s16 *)(odef + 0x1E), 1);
                }
                if (b == 0) {
                    ((GameObject *)obj)->anim.localPosX = *(f32 *)(list[i] + 0xC);
                    ((GameObject *)obj)->anim.localPosY = *(f32 *)(list[i] + 0x10);
                    ((GameObject *)obj)->anim.localPosZ = *(f32 *)(list[i] + 0x14);
                    saveGame_saveObjectPos(obj);
                }
                {
                    f32 y = ((GameObject *)obj)->anim.localPosY;
                    state->baseY = y;
                    state->baseY2 = y;
                }
                if (*(s16 *)(mydef + 0x1A) != -1) {
                    GameBit_Set(*(s16 *)(mydef + 0x1A), *(s16 *)(odef + 0x1A));
                    state->kind = *(s16 *)(odef + 0x1A);
                }
                c = state->kind;
                if (c == 3) goto held;
                if (c == 4) goto held;
                if (c == 6) {
                held:
                    if (b != 2) {
                        g1 = g1 + 1;
                    }
                    if (b == 0) {
                        Sfx_PlayFromObject(0, g1 < 3 ? 0x109 : 0x7E);
                        GameBit_Set(0x9AE, 1);
                    }
                    state->flags |= 0x400;
                    setAButtonIcon(0);
                } else if (b != 2) {
                    g2 += 1;
                }
            }
            if (g1 >= 3) {
                GameBit_Set(0x89B, 1);
            } else {
                GameBit_Set(0x89B, 0);
            }
            if (g1 > 3) {
                g1 = 3;
            } else if (g1 < 0) {
                g1 = 0;
            }
            if (g2 > 3) {
                g2 = 3;
            } else if (g2 < 0) {
                g2 = 0;
            }
            GameBit_Set(0x88C, g1);
            GameBit_Set(0x894, g2);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern char lbl_803AC930[];
extern f32 lbl_803E45B0;
extern f32 lbl_803E45B4;

#pragma scheduling off
#pragma peephole off
void mmp_trenchfx_update(int obj) {
    MmpTrenchfxState *state = ((GameObject *)obj)->extra;
    if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0) {
        state->emitCooldown -= timeDelta;
        if (state->emitCooldown < lbl_803E45B0) {
            state->fxScale = lbl_803E45B4;
            state->fxX = (f32)(int)randomGetRange(-(int)state->extentX, state->extentX);
            state->fxY = (f32)(int)randomGetRange(-(int)state->extentY, state->extentY);
            state->fxZ = (f32)(int)randomGetRange(-(int)state->extentZ, state->extentZ);
            vecRotateZXY((void *)state->emitAngles, (void *)&state->fxX);
            state->fxX += ((GameObject *)obj)->anim.localPosX;
            state->fxY += ((GameObject *)obj)->anim.localPosY;
            state->fxZ += ((GameObject *)obj)->anim.localPosZ;
            state->emitCooldown = (f32)(int)randomGetRange(0x64, 0xC8);
            state->emitTimer = (f32)(int)randomGetRange(0x32, 0x64);
        }
        state->emitTimer -= timeDelta;
        if (state->emitTimer > lbl_803E45B0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x71F, &state->fxUnk10, 0x200001,
                                             -1, NULL);
        }
        *(f32 *)(lbl_803AC930 + 8) = lbl_803E45B4;
        *(f32 *)(lbl_803AC930 + 0xC) = (f32)(int)randomGetRange(-(int)state->extentX, state->extentX);
        *(f32 *)(lbl_803AC930 + 0x10) = (f32)(int)randomGetRange(-(int)state->extentY, state->extentY);
        *(f32 *)(lbl_803AC930 + 0x14) = (f32)(int)randomGetRange(-(int)state->extentZ, state->extentZ);
        vecRotateZXY((void *)state->emitAngles, (void *)(lbl_803AC930 + 0xC));
        *(f32 *)(lbl_803AC930 + 0xC) += ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(lbl_803AC930 + 0x10) += ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(lbl_803AC930 + 0x14) += ((GameObject *)obj)->anim.localPosZ;
        (*gPartfxInterface)->spawnObject((void *)obj, 0x720, lbl_803AC930, 0x200001, -1,
                                         NULL);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 volume, f32 scale);
extern f32 mathSinf(f32);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void doRumble(f32 duration);
extern char lbl_803231D0[];
extern char lbl_803AC900[];
extern int lbl_803DDB30;
extern f32 lbl_803E44FC;
extern f32 lbl_803E4500;
extern f32 lbl_803E4504;
extern f32 lbl_803E4508;
extern f32 lbl_803E450C;
extern f32 lbl_803E4510;
extern f32 lbl_803E4514;
extern f32 lbl_803E4518;
extern f32 lbl_803E451C;
extern f32 lbl_803E4520;
extern f32 lbl_803E4524;
extern f32 lbl_803E4528;
extern f32 lbl_803E452C;
extern f32 lbl_803E4530;
extern f32 lbl_803E4534;
extern f32 lbl_803E4538;
extern f32 lbl_803E453C;

#pragma scheduling off
#pragma peephole off
void mmp_asteroid_re_update(int obj) {
    MmpAsteroidReState *state = ((GameObject *)obj)->extra;
    if ((state->eventFlags & 0x80) == 0) {
        if (GameBit_Get(0xD52) != 0) {
            state->intensity = 1;
        } else {
            state->intensity = GameBit_Get(0x88C);
        }
        state->phase = 2;
        Sfx_KeepAliveLoopedObjectSound(obj, 0x107);
        {
            int vol = state->intensity * 0x20 + 0x20;
            if (vol > 0x7F) {
                vol = 0x7F;
            }
            Sfx_SetObjectChannelVolume(obj, 0x40, vol, lbl_803E44FC);
        }
        if (state->intensity != 0) {
            f32 speed = ((GameObject *)obj)->anim.velocityY;
            if (speed < lbl_803E4500 * ((state->baseY + *(f32 *)(lbl_803231D0 + state->intensity * 4)) - ((GameObject *)obj)->anim.localPosY)) {
                ((GameObject *)obj)->anim.velocityY = lbl_803E4504 * timeDelta + speed;
            } else {
                ((GameObject *)obj)->anim.velocityY = -(lbl_803E4508 * timeDelta - speed);
            }
            *(s16 *)&state->bobPhase = lbl_803E450C * timeDelta + (f32)state->bobPhase;
            *(s16 *)&state->rollPhase = lbl_803E4510 * timeDelta + (f32)state->rollPhase;
            *(s16 *)&state->pitchPhase = lbl_803E4514 * timeDelta + (f32)state->pitchPhase;
            ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4518, ((GameObject *)obj)->anim.velocityY * timeDelta, lbl_803E4518);
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + mathSinf((lbl_803E451C * (f32)state->bobPhase) / lbl_803E4520);
            if (((GameObject *)obj)->anim.localPosY < state->baseY) {
                ((GameObject *)obj)->anim.localPosY = state->baseY;
            }
            ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ + (int)(lbl_803E4524 * mathSinf((lbl_803E451C * (f32)state->rollPhase) / lbl_803E4520)));
            ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY + (int)(lbl_803E4524 * mathSinf((lbl_803E451C * (f32)state->pitchPhase) / lbl_803E4520)));
            *(f32 *)(lbl_803AC900 + 8) = lbl_803E44F8;
            *(f32 *)(lbl_803AC900 + 0xC) = ((GameObject *)obj)->anim.localPosX;
            *(f32 *)(lbl_803AC900 + 0x10) = state->baseY - lbl_803E4528;
            *(f32 *)(lbl_803AC900 + 0x14) = ((GameObject *)obj)->anim.localPosZ;
            lbl_803DDB30 = (int)(((GameObject *)obj)->anim.localPosY - state->baseY);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x722, NULL, 2, -1, &lbl_803DDB30);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x723, lbl_803AC900, 0x200001, -1,
                                             &lbl_803DDB30);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x723, lbl_803AC900, 0x200001, -1,
                                             &lbl_803DDB30);
        }
    }
    if (state->eventFlags != 0) {
        if ((state->eventFlags & 1) != 0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x716, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 8) != 0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x71A, NULL, 2, -1, NULL);
        }
        if ((state->eventFlags & 0x10) != 0) {
            int n;
            (*gPartfxInterface)->spawnObject((void *)obj, 0x71B, NULL, 1, -1, NULL);
            n = 0x28;
            do {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x71C, NULL, 1, -1, NULL);
                n--;
            } while (n != 0);
            spawnExplosion(obj, lbl_803E452C, 1, 1, 0, 1, 0, 1, 0);
            CameraShake_Start(lbl_803E4530, lbl_803E4534, lbl_803E4538);
            doRumble(lbl_803E453C);
            state->eventFlags &= ~0x10;
        }
        if ((state->eventFlags & 0x20) != 0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x71D, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void *)obj, 0x71D, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 0x40) != 0) {
            state->periodicFxTimer -= timeDelta;
            if (state->periodicFxTimer < lbl_803E4518) {
                state->periodicFxTimer = (f32)(int)randomGetRange(10, 0x3C);
                (*gPartfxInterface)->spawnObject((void *)obj, 0x71E, NULL, 1, -1, NULL);
            }
        }
    }
    {
        f32 v = state->stateTimer;
        f32 k = lbl_803E4518;
        if (v > k) {
            state->stateTimer = v - timeDelta;
            if (state->stateTimer <= k) {
                GameBit_Set(0x88B, 0);
            }
        }
    }
    state->eventFlags &= ~0x80;
}
#pragma peephole reset
#pragma scheduling reset

extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern void objParticleFn_80099d84(int obj, f32 a, int c, f32 b, int d);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern u32 playerGetStateFlag310(int player);
extern MapEventInterface **gMapEventInterface;
extern char lbl_803AC918[];
extern f32 lbl_803E4584;
extern f32 lbl_803E4588;
extern f32 lbl_803E458C;
extern f32 lbl_803E4590;
extern f32 lbl_803E4594;
extern f32 lbl_803E4598;
extern f32 lbl_803E459C;
extern f32 lbl_803E45A0;

#pragma scheduling off
#pragma peephole off
void mmp_moonrock_update(int obj) {
    MmpMoonrockState *state = ((GameObject *)obj)->extra;
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    u8 grabbed;
    int d;
    int count;
    if (objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ) == -1) {
        return;
    }
    if ((state->flags & 4) != 0) {
        return;
    }
    if ((state->flags & 0x200) != 0) {
        f32 v = state->respawnTimer;
        f32 k = lbl_803E4554;
        if (v > k) {
            state->respawnTimer = v - timeDelta;
            if (state->respawnTimer <= k) {
                *(s16 *)&state->flags = 0;
                ((GameObject *)obj)->anim.alpha = 0xFF;
                ObjHits_DisableObject(obj);
                fn_801A7D74(obj, 1, 1);
            } else {
                ((GameObject *)obj)->anim.alpha =
                    (u8)(int)(lbl_803E4584 * (lbl_803E457C - state->respawnTimer / lbl_803E4558));
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / lbl_803E4558, 0);
                objParticleFn_80099d84(obj, lbl_803E4588, 2, lbl_803E457C - state->respawnTimer / lbl_803E4558, 0);
            }
        }
        return;
    }
    objfx_spawnDirectionalBurst(obj, 1, lbl_803E457C, 5, 1, 0xA, lbl_803E454C, 0, 0);
    objfx_spawnDirectionalBurst(obj, 5, lbl_803E457C, 5, 1, 0x14, lbl_803E454C, 0, 0);
    if ((state->flags & 0x40) != 0) {
        fn_801A7B10(obj);
        fn_801A79E0(obj);
        return;
    }
    grabbed = 0;
    if ((state->flags & 8) != 0 &&
        (*gMapEventInterface)->getAnimEvent(0x12, 6) == 0) {
        state->flags |= 1;
    } else if ((state->flags & 0x400) == 0) {
        if (*(s16 *)(def + 0x20) != -1 && GameBit_Get(*(s16 *)(def + 0x20)) == 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        } else if ((*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x8))(obj, *(int *)&((GameObject *)obj)->extra) != 0) {
            grabbed = 1;
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
    state->flags &= ~0x8;
    if (grabbed != 0) {
        int stateCopy;
        int i;
        int *list;
        u8 found;
        if ((playerGetStateFlag310((int)Obj_GetPlayerObject()) & 0x4000) != 0) {
            setAButtonIcon(5);
            state->flags |= 0x18;
            state->flags &= ~0x20;
        } else {
            setAButtonIcon(4);
            state->flags |= 0x28;
            state->flags &= ~0x10;
        }
        stateCopy = *(int *)&((GameObject *)obj)->extra;
        (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x24))(stateCopy, 0);
        list = (int *)ObjGroup_GetObjects(0x10, &count);
        {
            f32 k = lbl_803E4580;
            for (i = 0; i < count; i++) {
                u32 o = (u32)*list;
                if (o != (u32)obj && *(s16 *)(o + 0x46) == 0x519 &&
                    Vec_xzDistance((f32 *)(obj + 0x18), (f32 *)(o + 0x18)) < k) {
                    (*(int (**)(int, int))(*(int *)lbl_803DCAC0 + 0x24))(stateCopy, 1);
                    found = 0;
                    goto checked;
                }
                list++;
            }
        }
        found = 1;
    checked:
        if (found != 0) {
            state->flags |= 1;
        }
        if ((state->flags & 2) != 0) {
            fn_801A7D74(obj, 0, 0);
            state->flags &= ~0x2;
        }
        return;
    }
    {
        u16 flags = state->flags;
        if ((flags & 0x400) == 0 && (flags & 1) != 0) {
            if ((flags & 0x20) != 0) {
                fn_801A7CC4(obj);
            } else {
                fn_801A7D74(obj, 1, 0);
            }
            state->flags &= ~0x1;
        }
    }
    state->flags |= 2;
    if (state->kind == 0) {
        return;
    }
    if ((state->flags & 0x400) != 0) {
        state->raised = GameBit_Get(0x894);
    } else {
        state->raised = 0;
    }
    Sfx_PlayFromObject(obj, 0x108);
    Sfx_SetObjectChannelVolume(obj, 0x40, state->raised * 0x20 + 0x20, lbl_803E4588);
    {
        f32 speed = ((GameObject *)obj)->anim.velocityY;
        if (speed < lbl_803E458C * ((lbl_803E4568 * (f32)state->raised + state->baseY) - ((GameObject *)obj)->anim.localPosY)) {
            ((GameObject *)obj)->anim.velocityY = speed + lbl_803E4590;
        } else {
            ((GameObject *)obj)->anim.velocityY = speed - lbl_803E4594;
        }
    }
    state->bobPhase += 0x1000;
    state->rollPhase += 0xDAC;
    state->pitchPhase += 0x800;
    ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4554, ((GameObject *)obj)->anim.velocityY * timeDelta, lbl_803E4554);
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + mathSinf((lbl_803E4598 * (f32)state->bobPhase) / lbl_803E459C);
    if (((GameObject *)obj)->anim.localPosY < state->baseY) {
        ((GameObject *)obj)->anim.localPosY = state->baseY;
    }
    ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ + (int)(lbl_803E45A0 * mathSinf((lbl_803E4598 * (f32)state->rollPhase) / lbl_803E459C)));
    ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY + (int)(lbl_803E45A0 * mathSinf((lbl_803E4598 * (f32)state->pitchPhase) / lbl_803E459C)));
    *(f32 *)(lbl_803AC918 + 8) = lbl_803E457C;
    *(f32 *)(lbl_803AC918 + 0xC) = ((GameObject *)obj)->anim.localPosX;
    *(f32 *)(lbl_803AC918 + 0x10) = state->baseY;
    *(f32 *)(lbl_803AC918 + 0x14) = ((GameObject *)obj)->anim.localPosZ;
    d = (int)(((GameObject *)obj)->anim.localPosY - state->baseY);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x723, lbl_803AC918, 0x200001, -1, &d);
}
#pragma peephole reset
#pragma scheduling reset
