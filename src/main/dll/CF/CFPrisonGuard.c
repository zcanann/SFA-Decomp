#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/CF/CFPrisonGuard.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b94();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 FUN_80039520();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void doRumble(f32 strength);
extern int Obj_GetPlayerObject(void);
extern int getTrickyObject(void);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int objectId);
extern int Obj_SetupObject(int setup, int mode, int mapLayer, int objIndex, int parent);
extern void trickyImpress(int obj);
extern f32 sqrtf(f32 value);
extern void vecRotateZXY(void *rotation, void *vec);
extern u16 getAngle(f32 x, f32 z);

extern f64 DOUBLE_803e4868;
extern f64 lbl_803E3BD0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4850;
extern f32 FLOAT_803e4854;
extern f32 FLOAT_803e4858;
extern f32 FLOAT_803e485c;
extern f32 FLOAT_803e4860;
extern f32 FLOAT_803e4864;
extern f32 timeDelta;
extern const f32 lbl_803E3BBC;
extern const f32 lbl_803E3BC4;
extern f32 lbl_803E3BC8;
extern f32 lbl_803E3BCC;
extern f32 lbl_803E3BD8;
extern const f32 lbl_803E3BDC;
extern const f32 lbl_803E3BE0;
extern f64 lbl_803E3BE8;
extern s16 lbl_803DBDE0[4];
extern MapEventInterface **gMapEventInterface;

#define STAFFACTIVATED_ACTIVE 0x80
#define STAFFACTIVATED_LOCKED 0x40

/*
 * --INFO--
 *
 * Function: staffactivated_updateLiftHeight
 * EN v1.0 Address: 0x801899B4
 * EN v1.0 Size: 560b
 */
#pragma peephole off
#pragma scheduling off
void staffactivated_updateLiftHeight(int obj, int state)
{
  u32 flags;
  s32 prevHeight;
  s32 rumbleStrength;

  flags = *(u8 *)(state + 0x1d);
  if ((flags >> 7 & 1) != 0) {
    if ((flags >> 6 & 1) == 0) {
      if (*(u8 *)(state + 0x1c) == 0) {
        *(s32 *)(state + 0xc) =
            (s32)-(lbl_803E3BC8 * timeDelta - (f32)*(s32 *)(state + 0xc));
        *(s32 *)(state + 0x14) =
            (s32)((f32)*(s32 *)(state + 0xc) * timeDelta + (f32)*(s32 *)(state + 0x14));
        if (*(s32 *)(state + 0x14) > *(s32 *)(state + 0x18)) {
          *(s32 *)(state + 0x18) = *(s32 *)(state + 0x14);
        }
        if (*(s32 *)(state + 0x10) == 0x800 && *(s32 *)(state + 0x14) < 0x800) {
          Sfx_PlayFromObject(obj, 0x374);
        }
        if (*(s32 *)(state + 0x14) < 0) {
          if (*(s32 *)(state + 0x10) > 0) {
            Sfx_PlayFromObject(obj, SFXmn_dimraw36);
            rumbleStrength = *(s32 *)(state + 0x18) / 200;
            if (rumbleStrength > 0) {
              doRumble((f32)rumbleStrength);
            }
          }
          *(s32 *)(state + 0xc) = 0;
          *(s32 *)(state + 0x14) = 0;
        }
      } else {
        *(u8 *)(state + 0x1c) = 0;
        *(s32 *)(state + 0x18) = 0;
      }

      prevHeight = *(s32 *)(state + 0x10);
      if ((prevHeight < 0x40 && *(s32 *)(state + 0x14) >= 0x40) ||
          (prevHeight >= 0x40 && *(s32 *)(state + 0x14) < 0x40)) {
        Sfx_PlayFromObject(obj, 0x374);
      }
      ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                (f32 *)(state + 0x20));
      *(s32 *)(state + 0x10) = *(s32 *)(state + 0x14);
      ObjAnim_SetMoveProgress((f32)*(s32 *)(state + 0x14) / lbl_803E3BCC,
                              (ObjAnimComponent *)obj);
    } else {
      goto done;
    }
  }
done:;
}
#pragma scheduling reset
#pragma peephole reset

typedef struct PrisonGuardStateFlags {
    u8 pad[0x1d];
    u8 active : 1;
    u8 locked : 1;
    u8 mirror : 1;
} PrisonGuardStateFlags;

/*
 * --INFO--
 *
 * Function: cfPrisonGuard_setGameBitMirror
 * EN v1.0 Address: 0x80189BE4
 * EN v1.0 Size: 116b
 */
#pragma peephole off
#pragma scheduling off
void cfPrisonGuard_setGameBitMirror(int obj, u8 flag)
{
    register int s = *(int *)&((GameObject *)obj)->anim.placementData;
    register int t = *(int *)&((GameObject *)obj)->extra;
    if (flag != 0) {
        GameBit_Set((int)*(short *)(s + 0x24), 1);
        ((PrisonGuardStateFlags *)t)->mirror = 1;
    } else {
        GameBit_Set((int)*(short *)(s + 0x24), 0);
        ((PrisonGuardStateFlags *)t)->mirror = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

u32 cfPrisonGuard_isGameBitMirrorSet(int *obj) { return (*((u8*)((int**)obj)[0xb8/4] + 0x1d) >> 5) & 1; }

typedef struct PrisonGuardRotationWork {
  s16 y;
  s16 x;
  s16 z;
  s16 pad;
  f32 scale;
  f32 tx;
  f32 ty;
  f32 tz;
} PrisonGuardRotationWork;

/*
 * --INFO--
 *
 * Function: staffactivated_spawnMapEventDebris
 * EN v1.0 Address: 0x80189C68
 * EN v1.0 Size: 732b
 */
#pragma peephole off
#pragma scheduling off
void staffactivated_spawnMapEventDebris(int obj)
{
  int i;
  int setup;
  int player;
  u32 tricky;
  int state;
  int spawnedSetup;
  int spawnedObj;
  f32 lenSq;
  f32 len;
  s32 yawDelta;
  PrisonGuardRotationWork rotate;

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  player = Obj_GetPlayerObject();
  tricky = getTrickyObject();
  state = *(int *)&((GameObject *)obj)->extra;

  if ((*gMapEventInterface)->isTimedEventActive(*(int *)(setup + 0x14)) != 0 &&
      Obj_IsLoadingLocked() != 0) {
    (*gMapEventInterface)->startTimedEvent(*(int *)(setup + 0x14),
                                           lbl_803E3BD8 * (f32)*(u8 *)(setup + 0x20));
    if (tricky != 0) {
      trickyImpress(tricky);
    }

    i = 0;
    while (i < *(u8 *)(setup + 0x1f)) {
      spawnedSetup = Obj_AllocObjectSetup(0x24, lbl_803DBDE0[*(u8 *)(setup + 0x1e)]);
      *(f32 *)(spawnedSetup + 8) = *(f32 *)state;
      *(f32 *)(spawnedSetup + 0xc) = ((GameObject *)obj)->anim.localPosY;
      *(f32 *)(spawnedSetup + 0x10) = *(f32 *)(state + 4);
      *(s16 *)(spawnedSetup + 0x1a) = 0x190;

      spawnedObj = Obj_SetupObject(spawnedSetup, 5, *(s8 *)(obj + 0xac), -1, *(int *)&((GameObject *)obj)->anim.parent);
      *(f32 *)(spawnedObj + 0x24) = ((GameObject *)obj)->anim.localPosX - *(f32 *)(player + 0xc);
      *(f32 *)(spawnedObj + 0x2c) = ((GameObject *)obj)->anim.localPosZ - *(f32 *)(player + 0x14);

      lenSq = (*(f32 *)(spawnedObj + 0x24) * *(f32 *)(spawnedObj + 0x24)) +
              (*(f32 *)(spawnedObj + 0x2c) * *(f32 *)(spawnedObj + 0x2c));
      if (lenSq != lbl_803E3BDC) {
        len = sqrtf(lenSq);
        *(f32 *)(spawnedObj + 0x24) = *(f32 *)(spawnedObj + 0x24) / len;
        *(f32 *)(spawnedObj + 0x2c) = *(f32 *)(spawnedObj + 0x2c) / len;
      }

      *(f32 *)(spawnedObj + 0x24) =
          *(f32 *)(spawnedObj + 0x24) *
          (lbl_803E3BBC - (lbl_803E3BC4 * (f32)(int)randomGetRange(0, 0x19)));
      *(f32 *)(spawnedObj + 0x2c) =
          *(f32 *)(spawnedObj + 0x2c) *
          (lbl_803E3BBC - (lbl_803E3BC4 * (f32)(int)randomGetRange(0, 0x19)));
      *(f32 *)(spawnedObj + 0x28) = lbl_803E3BE0;

      rotate.tx = lbl_803E3BDC;
      rotate.ty = lbl_803E3BDC;
      rotate.tz = lbl_803E3BDC;
      rotate.scale = lbl_803E3BBC;
      rotate.z = 0;
      rotate.x = 0;
      rotate.y = (s16)randomGetRange(-10000, 10000);
      vecRotateZXY(&rotate, (void *)(spawnedObj + 0x24));

      yawDelta = *(s16 *)spawnedObj -
                 (u16)getAngle(*(f32 *)(spawnedObj + 0x24), -*(f32 *)(spawnedObj + 0x2c));
      if (yawDelta > 0x8000) {
        yawDelta -= 0xffff;
      }
      if (yawDelta < -0x8000) {
        yawDelta += 0xffff;
      }
      *(s16 *)spawnedObj = (s16)yawDelta;
      i++;
    }
  }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80189cc4
 * EN v1.0 Address: 0x80189CC4
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80189DB0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189cc4(int param_1,int param_2)
{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x24) != 0xffffffff) {
    uVar2 = GameBit_Get((int)*(short *)(iVar4 + 0x24));
    *(byte *)(param_2 + 0x1d) =
         (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(param_2 + 0x1d) & 0xdf;
    bVar1 = *(byte *)(param_2 + 0x1d) >> 5 & 1;
    if ((bVar1 == 0) || (*(char *)(iVar4 + 0x1c) != '\x05')) {
      if (bVar1 == 0) {
        *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf;
      }
    }
    else {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0xbf | 0x40;
    }
  }
  if (*(char *)(param_2 + 0x1d) < '\0') {
    if (((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
       (uVar2 = GameBit_Get((int)*(short *)(iVar4 + 0x22)), uVar2 == 0)) {
      *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f;
    }
  }
  else if (((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
          (uVar2 = GameBit_Get((int)*(short *)(iVar4 + 0x22)), uVar2 != 0)) {
    *(byte *)(param_2 + 0x1d) = *(byte *)(param_2 + 0x1d) & 0x7f | 0x80;
  }
  puVar3 = (undefined4 *)FUN_80039520(param_1,0);
  if (puVar3 != (undefined4 *)0x0) {
    if ((char)*(byte *)(param_2 + 0x1d) < '\0') {
      if ((*(byte *)(param_2 + 0x1d) >> 5 & 1) == 0) {
        *puVar3 = 0x100;
      }
      else {
        *puVar3 = 0x200;
      }
    }
    else {
      *puVar3 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189e0c
 * EN v1.0 Address: 0x80189E0C
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x80189F0C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189e0c(uint param_1,int param_2)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined8 local_18;
  
  dVar1 = DOUBLE_803e4868;
  if (((char)*(byte *)(param_2 + 0x1d) < '\0') && ((*(byte *)(param_2 + 0x1d) >> 6 & 1) == 0)) {
    if (*(char *)(param_2 + 0x1c) == '\0') {
      *(int *)(param_2 + 0xc) =
           (int)-(FLOAT_803e4860 * FLOAT_803dc074 -
                 (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) -
                        DOUBLE_803e4868));
      *(int *)(param_2 + 0x14) =
           (int)((float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) - dVar1)
                 * FLOAT_803dc074 +
                (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000) - dVar1)
                );
      if (*(int *)(param_2 + 0x18) < *(int *)(param_2 + 0x14)) {
        *(int *)(param_2 + 0x18) = *(int *)(param_2 + 0x14);
      }
      if ((*(int *)(param_2 + 0x10) == 0x800) && (*(int *)(param_2 + 0x14) < 0x800)) {
        FUN_80006824(param_1,0x374);
      }
      if (*(int *)(param_2 + 0x14) < 0) {
        if (0 < *(int *)(param_2 + 0x10)) {
          FUN_80006824(param_1,SFXmn_dimraw36);
          iVar2 = *(int *)(param_2 + 0x18) / 200 + (*(int *)(param_2 + 0x18) >> 0x1f);
          uVar3 = iVar2 - (iVar2 >> 0x1f);
          if (0 < (int)uVar3) {
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            FUN_80006b94((double)(float)(local_18 - DOUBLE_803e4868));
          }
        }
        *(undefined4 *)(param_2 + 0xc) = 0;
        *(undefined4 *)(param_2 + 0x14) = 0;
      }
    }
    else {
      *(undefined *)(param_2 + 0x1c) = 0;
      *(undefined4 *)(param_2 + 0x18) = 0;
    }
    if (((*(int *)(param_2 + 0x10) < 0x40) && (0x3f < *(int *)(param_2 + 0x14))) ||
       ((0x3f < *(int *)(param_2 + 0x10) && (*(int *)(param_2 + 0x14) < 0x40)))) {
      FUN_80006824(param_1,0x374);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(param_1,8,0xb4,0xf0,0xff,0x6f,(float *)(param_2 + 0x20));
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_2 + 0x14);
    local_18 = (double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000);
    FUN_800305c4((double)((float)(local_18 - DOUBLE_803e4868) / FLOAT_803e4864),param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a060
 * EN v1.0 Address: 0x8018A060
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x8018A13C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018a060(int param_1,char param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    GameBit_Set((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),0);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf;
  }
  else {
    GameBit_Set((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),1);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf | 0x20;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018a0d0
 * EN v1.0 Address: 0x8018A0D0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8018A1B0
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8018a0d0(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x1d) >> 5 & 1;
}

/*
 * --INFO--
 *
 * Function: cfPrisonGuard_getPullRateMode
 * EN v1.0 Address: 0x80189F44
 * EN v1.0 Size: 24b
 */
u32 cfPrisonGuard_getPullRateMode(int obj) {
    u32 v;
    v = *(u8 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x1d);
    if (v > 2) v = 2;
    return v;
}
