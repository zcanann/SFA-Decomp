#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/dim_bossgut.h"
#include "main/dll/SH/SHkillermushroom.h"
#include "main/objanim.h"
#include "main/objseq.h"

#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern void ModelLightStruct_free(void *light);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017714();
extern int randomGetRange(int min, int max);
extern undefined4 FUN_80017a28();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RefreshObjectState();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_8013651c();
extern u32 GameBit_Get(int eventId);
extern void fn_801D2B70(void *obj, void *stateEntry, void *state);
extern void *Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32 *p1, f32 *p2);
extern void Sfx_PlayFromObject(void *obj, int sndId);
extern void Sfx_KeepAliveLoopedObjectSound(void *obj, int sndId);
extern void Obj_StartModelFadeIn(void *obj, int duration);
extern void objLightFn_8009a1dc(void *obj, f32 *pos, int a, int b, f32 intensity);
extern void Obj_SetModelColorFadeRecursive(void *obj, int a, int b, int c, int d, int e);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern f32 lbl_803E5358;
extern f32 lbl_803E535C;
extern f64 lbl_803E5360;
extern f32 lbl_803E5368;
extern f32 lbl_803E536C;
extern f32 lbl_803E537C;
extern f32 lbl_803E5380;

extern u8 lbl_80326D20[];
extern EffectInterface **gPartfxInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern undefined4 DAT_80327960;
extern undefined4 DAT_80327964;
extern undefined4 DAT_80327968;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f64 DOUBLE_803e5ff8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e5ff0;
extern f32 FLOAT_803e5ff4;
extern f32 FLOAT_803e6000;
extern f32 FLOAT_803e6004;
extern f32 FLOAT_803e6010;
extern f32 FLOAT_803e6014;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E5398;
extern f32 lbl_803E539C;
extern f64 lbl_803E53A0;
extern f32 lbl_803E53A8;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B4;

/*
 * --INFO--
 *
 * Function: bombplantspore_getExtraSize
 * EN v1.0 Address: 0x801D3378
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplantspore_getExtraSize(void)
{
  return 0x2b4;
}

/*
 * --INFO--
 *
 * Function: bombplantspore_free
 * EN v1.0 Address: 0x801D3380
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801D3970
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplantspore_free(void *obj)
{
  void *state;
  void *light;

  state = ((GameObject *)obj)->extra;
  (*gExpgfxInterface)->freeSource((u32)obj);
  light = ((BombPlantSporeState *)state)->light;
  if (light != NULL) {
    ModelLightStruct_free(light);
    ((BombPlantSporeState *)state)->light = NULL;
  }
}

/*
 * --INFO--
 *
 * Function: bombplantspore_startDriftBurst
 * EN v1.0 Address: 0x801D33D4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplantspore_startDriftBurst(void *obj, void *state)
{
  s16 baseAngle;
  void *params;
  s32 angleDelta;

  params = ((GameObject *)obj)->anim.placementData;
  baseAngle = *(s16 *)((u8 *)params + 0x1c);

  ((BombPlantSporeState *)state)->unk298 = (f32)(int)randomGetRange(0x1e, 0x2d);

  ((BombPlantSporeState *)state)->unk284 =
      ((BombPlantSporeState *)state)->unk298 + (f32)(int)randomGetRange(0x78, 0xb4);

  ((BombPlantSporeState *)state)->burstAngle =
      ((BombPlantSporeState *)state)->driftAngle + (s16)randomGetRange(-2000, 2000);
  angleDelta = (s32)((BombPlantSporeState *)state)->burstAngle - (u16)baseAngle;
  if (0x8000 < angleDelta) {
    angleDelta -= 0xffff;
  }
  if (angleDelta < -0x8000) {
    angleDelta += 0xffff;
  }
  if (*(s16 *)((u8 *)params + 0x1a) < angleDelta) {
    ((BombPlantSporeState *)state)->burstAngle = (s16)(baseAngle + *(s16 *)((u8 *)params + 0x1a));
  }
  if (angleDelta < -(s32)*(s16 *)((u8 *)params + 0x1a)) {
    ((BombPlantSporeState *)state)->burstAngle = (s16)(baseAngle - *(s16 *)((u8 *)params + 0x1a));
  }

  ((BombPlantSporeState *)state)->unk29c = (f32)(int)randomGetRange(900, 0x514) / lbl_803E5390;
  ((BombPlantSporeState *)state)->driftRadiusRate = lbl_803E5394;

  ((BombPlantSporeState *)state)->burstSin =
      mathSinf((lbl_803E5398 * (f32)((BombPlantSporeState *)state)->burstAngle) / lbl_803E539C);
  ((BombPlantSporeState *)state)->burstCos =
      mathCosf((lbl_803E5398 * (f32)((BombPlantSporeState *)state)->burstAngle) / lbl_803E539C);
}

/*
 * --INFO--
 *
 * Function: bombplantspore_updateDrift
 * EN v1.0 Address: 0x801D359C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplantspore_updateDrift(void *obj, void *state)
{
  s16 baseAngle;
  void *params;
  s32 angleDelta;

  params = ((GameObject *)obj)->anim.placementData;
  baseAngle = *(s16 *)((u8 *)params + 0x1c);

  if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState *)state)->unk2a0 <= lbl_803E5394) {
    ((BombPlantSporeState *)state)->driftAngleStep = (s16)randomGetRange(2000, 4000);
    if (randomGetRange(0, 1) != 0) {
      ((BombPlantSporeState *)state)->driftAngleStep = -((BombPlantSporeState *)state)->driftAngleStep;
    }
    ((BombPlantSporeState *)state)->driftAngleStep =
        ((BombPlantSporeState *)state)->driftAngleStep + ((BombPlantSporeState *)state)->driftAngle;
    angleDelta = (s32)((BombPlantSporeState *)state)->driftAngleStep - (u16)baseAngle;
    if (0x8000 < angleDelta) {
      angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
      angleDelta += 0xffff;
    }
    if (*(s16 *)((u8 *)params + 0x1a) < angleDelta) {
      ((BombPlantSporeState *)state)->driftAngleStep = (s16)(baseAngle + *(s16 *)((u8 *)params + 0x1a));
    }
    if (angleDelta < -(s32)*(s16 *)((u8 *)params + 0x1a)) {
      ((BombPlantSporeState *)state)->driftAngleStep = (s16)(baseAngle - *(s16 *)((u8 *)params + 0x1a));
    }
    ((BombPlantSporeState *)state)->unk2a0 = lbl_803E53A8;
  }

  if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState *)state)->unk2a0 <= lbl_803E5394) {
    ((BombPlantSporeState *)state)->driftRadiusTarget =
        ((BombPlantSporeState *)state)->driftRadius + (f32)(int)randomGetRange(-200, 200) / lbl_803E5390;
    if (((BombPlantSporeState *)state)->driftRadiusTarget < lbl_803E53AC) {
      ((BombPlantSporeState *)state)->driftRadiusTarget = lbl_803E53AC;
    } else if (lbl_803E53B0 < ((BombPlantSporeState *)state)->driftRadiusTarget) {
      ((BombPlantSporeState *)state)->driftRadiusTarget = lbl_803E53B0;
    }
  }

  angleDelta = (s32)((BombPlantSporeState *)state)->driftAngleStep - (u16)((BombPlantSporeState *)state)->driftAngle;
  if (0x8000 < angleDelta) {
    angleDelta -= 0xffff;
  }
  if (angleDelta < -0x8000) {
    angleDelta += 0xffff;
  }
  ((BombPlantSporeState *)state)->driftAngle += (s16)((angleDelta * (s32)framesThisStep) >> 4);
  ((BombPlantSporeState *)state)->driftRadius =
      lbl_803E53B4 * (((BombPlantSporeState *)state)->driftRadiusTarget - ((BombPlantSporeState *)state)->driftRadius) *
          timeDelta +
      ((BombPlantSporeState *)state)->driftRadius;

  ((BombPlantSporeState *)state)->driftSin =
      ((BombPlantSporeState *)state)->driftRadius *
      mathSinf((lbl_803E5398 * (f32)((BombPlantSporeState *)state)->driftAngle) / lbl_803E539C);
  ((BombPlantSporeState *)state)->driftCos =
      ((BombPlantSporeState *)state)->driftRadius *
      mathCosf((lbl_803E5398 * (f32)((BombPlantSporeState *)state)->driftAngle) / lbl_803E539C);
}

/*
 * --INFO--
 *
 * Function: bombplant_init
 * EN v1.0 Address: 0x801D3238
 * EN v1.0 Size: 320b
 */
void bombplant_init(void *obj, void *param, int flag)
{
  void *state;
  void *p4c;
  s16 bitId;

  state = ((GameObject *)obj)->extra;
  *(s16 *)obj = (s16)((s32)(s8) * ((u8 *)param + 0x1f) << 8);
  ((GameObject *)obj)->objectFlags |= 0x2000;
  ((GameObject *)obj)->animEventCallback = (void *)bombplant_SeqFn;
  ((BombPlantSporeState *)state)->fadeTarget = ((GameObject *)obj)->anim.rootMotionScale;

  if (flag != 0) {
    return;
  }

  bitId = *(s16 *)((u8 *)param + 0x1c);
  if (bitId != -1 && GameBit_Get(bitId) == 0) {
    p4c = ((GameObject *)obj)->anim.placementData;
    ((GameObject *)obj)->anim.alpha = 0xff;
    ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ((GameObject *)obj)->anim.localPosX = *(f32 *)((u8 *)p4c + 0x8);
    ((GameObject *)obj)->anim.localPosY = *(f32 *)((u8 *)p4c + 0xc);
    ((GameObject *)obj)->anim.localPosZ = *(f32 *)((u8 *)p4c + 0x10);
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E5358;
    ((BombPlantSporeState *)state)->fadeTime = lbl_803E535C;
    ((BombPlantSporeState *)state)->fadeFrom = ((BombPlantSporeState *)state)->fadeTarget;
    ((BombPlantSporeState *)state)->fadeRate =
        ((BombPlantSporeState *)state)->fadeFrom / ((BombPlantSporeState *)state)->fadeTime;
    ((BombPlantSporeState *)state)->fadeValue = ((BombPlantSporeState *)state)->fadeTime;
    ObjHits_RefreshObjectState(obj);
    ((BombPlantSporeState *)state)->stateIndex = 1;
  } else {
    p4c = ((GameObject *)obj)->anim.placementData;
    ((GameObject *)obj)->anim.alpha = 0xff;
    ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ((GameObject *)obj)->anim.localPosX = *(f32 *)((u8 *)p4c + 0x8);
    ((GameObject *)obj)->anim.localPosY = *(f32 *)((u8 *)p4c + 0xc);
    ((GameObject *)obj)->anim.localPosZ = *(f32 *)((u8 *)p4c + 0x10);
    ObjHits_RefreshObjectState(obj);
  }
}

/*
 * --INFO--
 *
 * Function: bombplant_update
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 1508b
 */
void bombplant_update(void *obj)
{
  void *state;
  u8 *entry;
  void *param;
  void *p4c;
  void *plr;
  void *p50;
  f32 dist;
  s16 bitId;
  int hitType;
  int outA;
  int outB;
  int outC;
  f32 hitX;
  f32 hitY;
  f32 hitZ;
  f32 lightVec[3];

  Obj_GetPlayerObject();
  if (objIsFrozen(obj) != 0) {
    goto epilogue;
  }

  state = ((GameObject *)obj)->extra;
  entry = &lbl_80326D20[((BombPlantSporeState *)state)->stateIndex * 0xc];

  switch (((BombPlantSporeState *)state)->stateIndex) {
  case 1:
    param = ((GameObject *)obj)->anim.placementData;
    if ((((BombPlantSporeState *)state)->flags & 0x2) != 0) {
      ((BombPlantSporeState *)state)->flags &= ~0x2;
      ((BombPlantSporeState *)state)->fadeValue = (f32)(int)*(s16 *)((u8 *)param + 0x18);
    }
    bitId = *(s16 *)((u8 *)param + 0x1c);
    if (bitId != -1) {
      if (GameBit_Get(bitId) != 0) {
        plr = Obj_GetPlayerObject();
        dist =
            vec3f_distanceSquared((f32 *)((u8 *)obj + 0x18), (f32 *)((u8 *)plr + 0x18));
        if (dist > lbl_803E5368) {
          ((BombPlantSporeState *)state)->stateIndex = 2;
          ((BombPlantSporeState *)state)->flags |= 0x2;
        }
      }
    } else {
      f32 t = ((BombPlantSporeState *)state)->fadeValue - timeDelta;
      ((BombPlantSporeState *)state)->fadeValue = t;
      if (t <= lbl_803E536C) {
        plr = Obj_GetPlayerObject();
        dist =
            vec3f_distanceSquared((f32 *)((u8 *)obj + 0x18), (f32 *)((u8 *)plr + 0x18));
        if (dist > lbl_803E5368) {
          ((BombPlantSporeState *)state)->stateIndex = 2;
          ((BombPlantSporeState *)state)->flags |= 0x2;
        }
        ((BombPlantSporeState *)state)->fadeValue = lbl_803E536C;
      }
    }
    break;

  case 2:
    if ((((BombPlantSporeState *)state)->flags & 0x2) != 0) {
      Sfx_PlayFromObject(obj, SFXmv_sliftloop11);
      ((BombPlantSporeState *)state)->flags &= ~0x2;
      p4c = ((GameObject *)obj)->anim.placementData;
      ((GameObject *)obj)->anim.alpha = 0xff;
      ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
      ((GameObject *)obj)->anim.localPosX = *(f32 *)((u8 *)p4c + 0x8);
      ((GameObject *)obj)->anim.localPosY = *(f32 *)((u8 *)p4c + 0xc);
      ((GameObject *)obj)->anim.localPosZ = *(f32 *)((u8 *)p4c + 0x10);
      ((GameObject *)obj)->anim.rootMotionScale = lbl_803E5358;
      ((BombPlantSporeState *)state)->fadeTime = lbl_803E535C;
      ((BombPlantSporeState *)state)->fadeFrom = ((BombPlantSporeState *)state)->fadeTarget;
      ((BombPlantSporeState *)state)->fadeRate =
          ((BombPlantSporeState *)state)->fadeFrom / ((BombPlantSporeState *)state)->fadeTime;
      ((BombPlantSporeState *)state)->fadeValue = ((BombPlantSporeState *)state)->fadeTime;
      ObjHits_RefreshObjectState(obj);
    }
    if (((GameObject *)obj)->anim.rootMotionScale > ((BombPlantSporeState *)state)->fadeFrom) {
      ((BombPlantSporeState *)state)->fadeRate = ((BombPlantSporeState *)state)->fadeRate / lbl_803E537C;
    }
    if (((BombPlantSporeState *)state)->fadeRate < lbl_803E5358) {
      ((BombPlantSporeState *)state)->fadeRate = lbl_803E536C;
    }
    ((GameObject *)obj)->anim.rootMotionScale =
        ((BombPlantSporeState *)state)->fadeRate * timeDelta + ((GameObject *)obj)->anim.rootMotionScale;
    {
      f32 t = ((BombPlantSporeState *)state)->fadeValue - timeDelta;
      ((BombPlantSporeState *)state)->fadeValue = t;
      if (t < lbl_803E536C) {
        ((BombPlantSporeState *)state)->stateIndex = 0;
        ((BombPlantSporeState *)state)->flags |= 0x2;
      }
    }
    break;

  case 4:
    fn_801D2B70(obj, entry, state);
    break;

  case 0:
    Sfx_KeepAliveLoopedObjectSound(obj, 0x3fd);
    /* fallthrough */
  default:
    param = ((GameObject *)obj)->anim.placementData;
    if ((((BombPlantSporeState *)state)->flags & 0x2) != 0) {
      ((BombPlantSporeState *)state)->flags &= ~0x2;
      ((BombPlantSporeState *)state)->fadeValue =
          (f32)(int)(*(s16 *)((u8 *)param + 0x1a) + randomGetRange(-0x32, 0x32));
    }
    if ((((GameObject *)obj)->objectFlags & 0x800) != 0) {
      (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
    }
    break;
  }

  if ((entry[8] & 0x1) != 0) {
    hitType = ObjHits_GetPriorityHitWithPosition(obj, &outA, &outB, &outC, &hitX,
                                                 &hitY, &hitZ);
    if (hitType != 0 && outC != 0) {
      if (hitType == 0x10) {
        Obj_StartModelFadeIn(obj, 0x12c);
      } else if (hitType - 0xe <= 1 || hitType == 0x11) {
        Sfx_PlayFromObject(obj, SFXmv_curtainloop16);
        hitX = hitX + playerMapOffsetX;
        hitZ = hitZ + playerMapOffsetZ;
        objLightFn_8009a1dc(obj, lightVec, 1, 0, lbl_803E5380);
        Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        ((BombPlantSporeState *)state)->stateIndex = 4;
        ((BombPlantSporeState *)state)->flags |= 0x2;
        p50 = ((GameObject *)obj)->anim.modelInstance;
        ObjHitbox_SetCapsuleBounds(obj, (s16)(*(u8 *)((u8 *)p50 + 0x62) + 0x50),
                                   (s16)(*(s16 *)((u8 *)p50 + 0x68) - 0x50),
                                   (s16)(*(s16 *)((u8 *)p50 + 0x6a) + 0x50));
        ObjHits_MarkObjectPositionDirty(obj);
      }
    }
  }

  if ((entry[8] & 0x8) != 0) {
    ObjHits_EnableObject(obj);
  } else {
    ObjHits_DisableObject(obj);
  }

  if ((entry[8] & 0x10) != 0) {
    ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
  } else {
    ObjHits_ClearHitVolumes(obj);
  }

  if ((entry[8] & 0x2) != 0) {
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x4) != 0 && GameBit_Get(0x189) == 0) {
      (*gObjectTriggerInterface)->runSequence(0, obj, -1);
      GameBit_Set(0x189, 1);
    }
  } else {
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
  }

  if ((entry[8] & 0x4) != 0) {
    ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
  } else {
    ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
  }

  if (((GameObject *)obj)->anim.currentMove != *(s16 *)entry) {
    ObjAnim_SetCurrentMove((int)obj, *(s16 *)entry, lbl_803E536C, 0);
  }

  if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
          (int)obj, *(f32 *)(entry + 0x4), timeDelta, NULL) != 0) {
    ((BombPlantSporeState *)state)->flags |= 0x1;
  } else {
    ((BombPlantSporeState *)state)->flags &= ~0x1;
  }

epilogue:
  return;
}
