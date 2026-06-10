#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
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
void staffactivated_updateLiftHeight(int obj, StaffActivatedState *state)
{
  u32 flags;
  s32 prevHeight;
  s32 rumbleStrength;

  flags = state->flags;
  if ((flags >> 7 & 1) != 0) {
    if ((flags >> 6 & 1) == 0) {
      if (state->liftReset == 0) {
        state->liftVelocity = (s32)-(lbl_803E3BC8 * timeDelta - (f32)state->liftVelocity);
        state->liftHeight =
            (s32)((f32)state->liftVelocity * timeDelta + (f32)state->liftHeight);
        if (state->liftHeight > state->peakLiftHeight) {
          state->peakLiftHeight = state->liftHeight;
        }
        if (state->previousLiftHeight == 0x800 && state->liftHeight < 0x800) {
          Sfx_PlayFromObject(obj, 0x374);
        }
        if (state->liftHeight < 0) {
          if (state->previousLiftHeight > 0) {
            Sfx_PlayFromObject(obj, SFXmn_dimraw36);
            rumbleStrength = state->peakLiftHeight / 200;
            if (rumbleStrength > 0) {
              doRumble((f32)rumbleStrength);
            }
          }
          state->liftVelocity = 0;
          state->liftHeight = 0;
        }
      } else {
        state->liftReset = 0;
        state->peakLiftHeight = 0;
      }

      prevHeight = state->previousLiftHeight;
      if ((prevHeight < 0x40 && state->liftHeight >= 0x40) ||
          (prevHeight >= 0x40 && state->liftHeight < 0x40)) {
        Sfx_PlayFromObject(obj, 0x374);
      }
      ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                &state->hitCooldown);
      state->previousLiftHeight = state->liftHeight;
      ObjAnim_SetMoveProgress((f32)state->liftHeight / lbl_803E3BCC, (ObjAnimComponent *)obj);
    } else {
      goto done;
    }
  }
done:;
}

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
void cfPrisonGuard_setGameBitMirror(int obj, u8 flag)
{
    register StaffActivatedSetup *setup = (StaffActivatedSetup *)((GameObject *)obj)->anim.placementData;
    register StaffActivatedState *state = ((GameObject *)obj)->extra;
    if (flag != 0) {
        GameBit_Set(setup->lockGameBit, 1);
        ((PrisonGuardStateFlags *)state)->mirror = 1;
    } else {
        GameBit_Set(setup->lockGameBit, 0);
        ((PrisonGuardStateFlags *)state)->mirror = 0;
    }
}

u32 cfPrisonGuard_isGameBitMirrorSet(int *obj) { return (((StaffActivatedState *)((GameObject *)obj)->extra)->flags >> 5) & 1; }

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
void staffactivated_spawnMapEventDebris(int obj)
{
  int i;
  StaffActivatedSetup *setup;
  int player;
  u32 tricky;
  StaffActivatedState *state;
  int spawnedSetup;
  int spawnedObj;
  ObjPlacement *spawnedPlacement;
  f32 lenSq;
  f32 len;
  s32 yawDelta;
  PrisonGuardRotationWork rotate;

  setup = (StaffActivatedSetup *)((GameObject *)obj)->anim.placementData;
  player = Obj_GetPlayerObject();
  tricky = getTrickyObject();
  state = ((GameObject *)obj)->extra;

  if ((*gMapEventInterface)->isTimedEventActive(setup->base.mapId) != 0 &&
      Obj_IsLoadingLocked() != 0) {
    (*gMapEventInterface)->startTimedEvent(setup->base.mapId,
                                           lbl_803E3BD8 * (f32)setup->timedEventSeconds);
    if (tricky != 0) {
      trickyImpress(tricky);
    }

    i = 0;
    while (i < setup->debrisCount) {
      spawnedSetup = Obj_AllocObjectSetup(0x24, lbl_803DBDE0[setup->debrisObjectSet]);
      spawnedPlacement = (ObjPlacement *)spawnedSetup;
      spawnedPlacement->posX = state->targetX;
      spawnedPlacement->posY = ((GameObject *)obj)->anim.localPosY;
      spawnedPlacement->posZ = state->targetZ;
      *(s16 *)(spawnedSetup + 0x1a) = 0x190;

      spawnedObj = Obj_SetupObject(spawnedSetup, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
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
#pragma scheduling on
#pragma peephole on
void FUN_80189cc4(int obj, StaffActivatedState *state)
{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  StaffActivatedSetup *setup;
  
  setup = (StaffActivatedSetup *)((GameObject *)obj)->anim.placementData;
  if (setup->lockGameBit != -1) {
    uVar2 = GameBit_Get(setup->lockGameBit);
    state->flags = (byte)((uVar2 & 0xff) << 5) & 0x20 | state->flags & 0xdf;
    bVar1 = state->flags >> 5 & 1;
    if ((bVar1 == 0) || (setup->mode != 5)) {
      if (bVar1 == 0) {
        state->flags = state->flags & 0xbf;
      }
    }
    else {
      state->flags = state->flags & 0xbf | 0x40;
    }
  }
  if ((s8)state->flags < 0) {
    if ((setup->activeGameBit != -1) && (uVar2 = GameBit_Get(setup->activeGameBit), uVar2 == 0)) {
      state->flags = state->flags & 0x7f;
    }
  }
  else if ((setup->activeGameBit != -1) && (uVar2 = GameBit_Get(setup->activeGameBit), uVar2 != 0)) {
    state->flags = state->flags & 0x7f | 0x80;
  }
  puVar3 = (undefined4 *)FUN_80039520(obj,0);
  if (puVar3 != (undefined4 *)0x0) {
    if ((s8)state->flags < 0) {
      if ((state->flags >> 5 & 1) == 0) {
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
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling on
#pragma peephole on
void FUN_80189e0c(uint obj, StaffActivatedState *state)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined8 local_18;
  
  dVar1 = DOUBLE_803e4868;
  if (((s8)state->flags < 0) && ((state->flags >> 6 & 1) == 0)) {
    if (state->liftReset == 0) {
      state->liftVelocity =
           (int)-(FLOAT_803e4860 * FLOAT_803dc074 -
                 (float)((double)CONCAT44(0x43300000,state->liftVelocity ^ 0x80000000) -
                        DOUBLE_803e4868));
      state->liftHeight =
           (int)((float)((double)CONCAT44(0x43300000,state->liftVelocity ^ 0x80000000) - dVar1)
                 * FLOAT_803dc074 +
                (float)((double)CONCAT44(0x43300000,state->liftHeight ^ 0x80000000) - dVar1)
                );
      if (state->peakLiftHeight < state->liftHeight) {
        state->peakLiftHeight = state->liftHeight;
      }
      if ((state->previousLiftHeight == 0x800) && (state->liftHeight < 0x800)) {
        FUN_80006824(obj,0x374);
      }
      if (state->liftHeight < 0) {
        if (0 < state->previousLiftHeight) {
          FUN_80006824(obj,SFXmn_dimraw36);
          iVar2 = state->peakLiftHeight / 200 + (state->peakLiftHeight >> 0x1f);
          uVar3 = iVar2 - (iVar2 >> 0x1f);
          if (0 < (int)uVar3) {
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            FUN_80006b94((double)(float)(local_18 - DOUBLE_803e4868));
          }
        }
        state->liftVelocity = 0;
        state->liftHeight = 0;
      }
    }
    else {
      state->liftReset = 0;
      state->peakLiftHeight = 0;
    }
    if (((state->previousLiftHeight < 0x40) && (0x3f < state->liftHeight)) ||
       ((0x3f < state->previousLiftHeight && (state->liftHeight < 0x40)))) {
      FUN_80006824(obj,0x374);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj,8,0xb4,0xf0,0xff,0x6f,&state->hitCooldown);
    state->previousLiftHeight = state->liftHeight;
    local_18 = (double)CONCAT44(0x43300000,state->liftHeight ^ 0x80000000);
    FUN_800305c4((double)((float)(local_18 - DOUBLE_803e4868) / FLOAT_803e4864),obj);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling on
#pragma peephole on
void FUN_8018a060(int obj,char enabled)
{
  StaffActivatedSetup *setup;
  StaffActivatedState *state;
  
  setup = (StaffActivatedSetup *)((GameObject *)obj)->anim.placementData;
  state = ((GameObject *)obj)->extra;
  if (enabled == '\0') {
    GameBit_Set(setup->lockGameBit,0);
    state->flags = state->flags & 0xdf;
  }
  else {
    GameBit_Set(setup->lockGameBit,1);
    state->flags = state->flags & 0xdf | 0x20;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
byte FUN_8018a0d0(int obj)
{
  return ((StaffActivatedState *)((GameObject *)obj)->extra)->flags >> 5 & 1;
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
    v = ((StaffActivatedSetup *)((GameObject *)obj)->anim.placementData)->size;
    if (v > 2) v = 2;
    return v;
}
