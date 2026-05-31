#include "ghidra_import.h"
#include "main/dll/SH/SHkillermushroom.h"

#define SFXmv_curtainloop16 157
#define SFXmv_sliftloop11 161
#define SFXmv_curtainrustle 163

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
extern undefined4 FUN_801d2db8();
extern u32 GameBit_Get(int eventId);
extern void fn_801D286C(void);
extern void fn_801D2B70(void *obj, void *stateEntry, void *state);
extern void *Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32 *p1, f32 *p2);
extern void Sfx_PlayFromObject(void *obj, int sndId);
extern void Sfx_KeepAliveLoopedObjectSound(void *obj, int sndId);
extern void Obj_StartModelFadeIn(void *obj, int duration);
extern void objLightFn_8009a1dc(void *obj, f32 *pos, int a, int b, f32 intensity);
extern void Obj_SetModelColorFadeRecursive(void *obj, int a, int b, int c, int d, int e);
extern void ObjAnim_SetCurrentMove(void *obj, s16 animId, int a, f32 startTime);
extern int ObjAnim_AdvanceCurrentMove(void *obj, int mode, f32 ts1, f32 ts2);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);

extern f32 lbl_803E5358;
extern f32 lbl_803E535C;
extern f64 lbl_803E5360;
extern f32 lbl_803E5368;
extern f32 lbl_803E536C;
extern f32 lbl_803E537C;
extern f32 lbl_803E5380;

extern u8 lbl_80326D20[];
extern void *gPartfxInterface;
extern void *gObjectTriggerInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern undefined4 DAT_80327960;
extern undefined4 DAT_80327964;
extern undefined4 DAT_80327968;
extern u8 framesThisStep;
extern undefined4* DAT_803dd6d4;
extern void *gExpgfxInterface;
extern undefined4* DAT_803dd708;
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
 * Function: SHkillermushroom_free
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801D3138
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHkillermushroom_free(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

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
 * Function: FUN_801d2c74
 * EN v1.0 Address: 0x801D2C74
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801D3160
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2c74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x26);
  iVar1 = FUN_80017a90();
  if (iVar1 != 0) {
    FUN_8013651c(iVar1);
  }
  FUN_80006824((uint)param_9,SFXmv_curtainrustle);
  *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 0x40
  ;
  FUN_8008112c((double)FLOAT_803e6010,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,1,1,1,0,1,0);
  *(undefined *)(param_11 + 0x14) = 1;
  *(byte *)(param_11 + 0x15) = *(byte *)(param_11 + 0x15) | 2;
  if ((int)*(short *)(iVar2 + 0x1c) == 0xffffffff) {
    iVar1 = 0;
    do {
      FUN_801d2db8(param_9);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  else {
    GameBit_Set((int)*(short *)(iVar2 + 0x1c),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2dd0
 * EN v1.0 Address: 0x801D2DD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D3244
 * EN v1.1 Size: 1508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2dd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,uint *param_12,
                 float *param_13,undefined4 *param_14,float *param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d2dd4
 * EN v1.0 Address: 0x801D2DD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D3828
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2dd4(undefined2 *param_1,int param_2,int param_3)
{
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
#pragma scheduling off
void bombplantspore_free(void *obj)
{
  void *state;
  void *light;

  state = *(void **)((u8 *)obj + 0xb8);
  (*(void (***)(void *))gExpgfxInterface)[5](obj);
  light = *(void **)((u8 *)state + 0x270);
  if (light != NULL) {
    ModelLightStruct_free(light);
    *(void **)((u8 *)state + 0x270) = NULL;
  }
}
#pragma scheduling reset

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

  params = *(void **)((u8 *)obj + 0x4c);
  baseAngle = *(s16 *)((u8 *)params + 0x1c);

  *(f32 *)((u8 *)state + 0x298) = (f32)(int)randomGetRange(0x1e, 0x2d);

  *(f32 *)((u8 *)state + 0x284) =
      *(f32 *)((u8 *)state + 0x298) + (f32)(int)randomGetRange(0x78, 0xb4);

  *(s16 *)((u8 *)state + 0x2aa) =
      *(s16 *)((u8 *)state + 0x2a8) + (s16)randomGetRange(-2000, 2000);
  angleDelta = (s32)*(s16 *)((u8 *)state + 0x2aa) - (u16)baseAngle;
  if (0x8000 < angleDelta) {
    angleDelta -= 0xffff;
  }
  if (angleDelta < -0x8000) {
    angleDelta += 0xffff;
  }
  if (*(s16 *)((u8 *)params + 0x1a) < angleDelta) {
    *(s16 *)((u8 *)state + 0x2aa) = (s16)(baseAngle + *(s16 *)((u8 *)params + 0x1a));
  }
  if (angleDelta < -(s32)*(s16 *)((u8 *)params + 0x1a)) {
    *(s16 *)((u8 *)state + 0x2aa) = (s16)(baseAngle - *(s16 *)((u8 *)params + 0x1a));
  }

  *(f32 *)((u8 *)state + 0x29c) = (f32)(int)randomGetRange(900, 0x514) / lbl_803E5390;
  *(f32 *)((u8 *)state + 0x27c) = lbl_803E5394;

  *(f32 *)((u8 *)state + 0x290) =
      fn_80293E80((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2aa)) / lbl_803E539C);
  *(f32 *)((u8 *)state + 0x294) =
      sin((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2aa)) / lbl_803E539C);
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

  params = *(void **)((u8 *)obj + 0x4c);
  baseAngle = *(s16 *)((u8 *)params + 0x1c);

  if (randomGetRange(0, 100) < 10 && *(f32 *)((u8 *)state + 0x2a0) <= lbl_803E5394) {
    *(s16 *)((u8 *)state + 0x2ac) = (s16)randomGetRange(2000, 4000);
    if (randomGetRange(0, 1) != 0) {
      *(s16 *)((u8 *)state + 0x2ac) = -*(s16 *)((u8 *)state + 0x2ac);
    }
    *(s16 *)((u8 *)state + 0x2ac) =
        *(s16 *)((u8 *)state + 0x2ac) + *(s16 *)((u8 *)state + 0x2a8);
    angleDelta = (s32)*(s16 *)((u8 *)state + 0x2ac) - (u16)baseAngle;
    if (0x8000 < angleDelta) {
      angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
      angleDelta += 0xffff;
    }
    if (*(s16 *)((u8 *)params + 0x1a) < angleDelta) {
      *(s16 *)((u8 *)state + 0x2ac) = (s16)(baseAngle + *(s16 *)((u8 *)params + 0x1a));
    }
    if (angleDelta < -(s32)*(s16 *)((u8 *)params + 0x1a)) {
      *(s16 *)((u8 *)state + 0x2ac) = (s16)(baseAngle - *(s16 *)((u8 *)params + 0x1a));
    }
    *(f32 *)((u8 *)state + 0x2a0) = lbl_803E53A8;
  }

  if (randomGetRange(0, 100) < 10 && *(f32 *)((u8 *)state + 0x2a0) <= lbl_803E5394) {
    *(f32 *)((u8 *)state + 0x280) =
        *(f32 *)((u8 *)state + 0x278) + (f32)(int)randomGetRange(-200, 200) / lbl_803E5390;
    if (*(f32 *)((u8 *)state + 0x280) < lbl_803E53AC) {
      *(f32 *)((u8 *)state + 0x280) = lbl_803E53AC;
    } else if (lbl_803E53B0 < *(f32 *)((u8 *)state + 0x280)) {
      *(f32 *)((u8 *)state + 0x280) = lbl_803E53B0;
    }
  }

  angleDelta = (s32)*(s16 *)((u8 *)state + 0x2ac) - (u16)*(s16 *)((u8 *)state + 0x2a8);
  if (0x8000 < angleDelta) {
    angleDelta -= 0xffff;
  }
  if (angleDelta < -0x8000) {
    angleDelta += 0xffff;
  }
  *(s16 *)((u8 *)state + 0x2a8) += (s16)((angleDelta * (s32)framesThisStep) >> 4);
  *(f32 *)((u8 *)state + 0x278) =
      lbl_803E53B4 * (*(f32 *)((u8 *)state + 0x280) - *(f32 *)((u8 *)state + 0x278)) *
          timeDelta +
      *(f32 *)((u8 *)state + 0x278);

  *(f32 *)((u8 *)state + 0x288) =
      *(f32 *)((u8 *)state + 0x278) *
      fn_80293E80((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2a8)) / lbl_803E539C);
  *(f32 *)((u8 *)state + 0x28c) =
      *(f32 *)((u8 *)state + 0x278) *
      sin((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2a8)) / lbl_803E539C);
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

  state = *(void **)((u8 *)obj + 0xb8);
  *(s16 *)obj = (s16)((s32)(s8) * ((u8 *)param + 0x1f) << 8);
  *(u16 *)((u8 *)obj + 0xb0) |= 0x2000;
  *(void **)((u8 *)obj + 0xbc) = (void *)fn_801D286C;
  *(f32 *)((u8 *)state + 0xc) = *(f32 *)((u8 *)obj + 0x8);

  if (flag != 0) {
    return;
  }

  bitId = *(s16 *)((u8 *)param + 0x1c);
  if (bitId != -1 && GameBit_Get(bitId) == 0) {
    p4c = *(void **)((u8 *)obj + 0x4c);
    *(u8 *)((u8 *)obj + 0x36) = 0xff;
    *(s16 *)((u8 *)obj + 0x6) &= ~0x4000;
    *(f32 *)((u8 *)obj + 0xc) = *(f32 *)((u8 *)p4c + 0x8);
    *(f32 *)((u8 *)obj + 0x10) = *(f32 *)((u8 *)p4c + 0xc);
    *(f32 *)((u8 *)obj + 0x14) = *(f32 *)((u8 *)p4c + 0x10);
    *(f32 *)((u8 *)obj + 0x8) = lbl_803E5358;
    *(f32 *)((u8 *)state + 0x8) = lbl_803E535C;
    *(f32 *)((u8 *)state + 0x4) = *(f32 *)((u8 *)state + 0xc);
    *(f32 *)((u8 *)state + 0x10) =
        *(f32 *)((u8 *)state + 0x4) / *(f32 *)((u8 *)state + 0x8);
    *(f32 *)state = *(f32 *)((u8 *)state + 0x8);
    ObjHits_RefreshObjectState(obj);
    *(u8 *)((u8 *)state + 0x14) = 1;
  } else {
    p4c = *(void **)((u8 *)obj + 0x4c);
    *(u8 *)((u8 *)obj + 0x36) = 0xff;
    *(s16 *)((u8 *)obj + 0x6) &= ~0x4000;
    *(f32 *)((u8 *)obj + 0xc) = *(f32 *)((u8 *)p4c + 0x8);
    *(f32 *)((u8 *)obj + 0x10) = *(f32 *)((u8 *)p4c + 0xc);
    *(f32 *)((u8 *)obj + 0x14) = *(f32 *)((u8 *)p4c + 0x10);
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

  state = *(void **)((u8 *)obj + 0xb8);
  entry = &lbl_80326D20[*(u8 *)((u8 *)state + 0x14) * 0xc];

  switch (*(u8 *)((u8 *)state + 0x14)) {
  case 1:
    param = *(void **)((u8 *)obj + 0x4c);
    if ((*(u8 *)((u8 *)state + 0x15) & 0x2) != 0) {
      *(u8 *)((u8 *)state + 0x15) &= ~0x2;
      *(f32 *)state = (f32)(int)*(s16 *)((u8 *)param + 0x18);
    }
    bitId = *(s16 *)((u8 *)param + 0x1c);
    if (bitId != -1) {
      if (GameBit_Get(bitId) != 0) {
        plr = Obj_GetPlayerObject();
        dist =
            vec3f_distanceSquared((f32 *)((u8 *)obj + 0x18), (f32 *)((u8 *)plr + 0x18));
        if (dist > lbl_803E5368) {
          *(u8 *)((u8 *)state + 0x14) = 2;
          *(u8 *)((u8 *)state + 0x15) |= 0x2;
        }
      }
    } else {
      f32 t = *(f32 *)state - timeDelta;
      *(f32 *)state = t;
      if (t <= lbl_803E536C) {
        plr = Obj_GetPlayerObject();
        dist =
            vec3f_distanceSquared((f32 *)((u8 *)obj + 0x18), (f32 *)((u8 *)plr + 0x18));
        if (dist > lbl_803E5368) {
          *(u8 *)((u8 *)state + 0x14) = 2;
          *(u8 *)((u8 *)state + 0x15) |= 0x2;
        }
        *(f32 *)state = lbl_803E536C;
      }
    }
    break;

  case 2:
    if ((*(u8 *)((u8 *)state + 0x15) & 0x2) != 0) {
      Sfx_PlayFromObject(obj, SFXmv_sliftloop11);
      *(u8 *)((u8 *)state + 0x15) &= ~0x2;
      p4c = *(void **)((u8 *)obj + 0x4c);
      *(u8 *)((u8 *)obj + 0x36) = 0xff;
      *(s16 *)((u8 *)obj + 0x6) &= ~0x4000;
      *(f32 *)((u8 *)obj + 0xc) = *(f32 *)((u8 *)p4c + 0x8);
      *(f32 *)((u8 *)obj + 0x10) = *(f32 *)((u8 *)p4c + 0xc);
      *(f32 *)((u8 *)obj + 0x14) = *(f32 *)((u8 *)p4c + 0x10);
      *(f32 *)((u8 *)obj + 0x8) = lbl_803E5358;
      *(f32 *)((u8 *)state + 0x8) = lbl_803E535C;
      *(f32 *)((u8 *)state + 0x4) = *(f32 *)((u8 *)state + 0xc);
      *(f32 *)((u8 *)state + 0x10) =
          *(f32 *)((u8 *)state + 0x4) / *(f32 *)((u8 *)state + 0x8);
      *(f32 *)state = *(f32 *)((u8 *)state + 0x8);
      ObjHits_RefreshObjectState(obj);
    }
    if (*(f32 *)((u8 *)obj + 0x8) > *(f32 *)((u8 *)state + 0x4)) {
      *(f32 *)((u8 *)state + 0x10) = *(f32 *)((u8 *)state + 0x10) / lbl_803E537C;
    }
    if (*(f32 *)((u8 *)state + 0x10) < lbl_803E5358) {
      *(f32 *)((u8 *)state + 0x10) = lbl_803E536C;
    }
    *(f32 *)((u8 *)obj + 0x8) =
        *(f32 *)((u8 *)state + 0x10) * timeDelta + *(f32 *)((u8 *)obj + 0x8);
    {
      f32 t = *(f32 *)state - timeDelta;
      *(f32 *)state = t;
      if (t < lbl_803E536C) {
        *(u8 *)((u8 *)state + 0x14) = 0;
        *(u8 *)((u8 *)state + 0x15) |= 0x2;
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
    param = *(void **)((u8 *)obj + 0x4c);
    if ((*(u8 *)((u8 *)state + 0x15) & 0x2) != 0) {
      *(u8 *)((u8 *)state + 0x15) &= ~0x2;
      *(f32 *)state =
          (f32)(int)(*(s16 *)((u8 *)param + 0x1a) + randomGetRange(-0x32, 0x32));
    }
    if ((*(u16 *)((u8 *)obj + 0xb0) & 0x800) != 0) {
      (*(void (***)(void *, int, int, int, int, int))gPartfxInterface)[2](
          obj, 0x7f1, 0, 2, -1, 0);
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
        *(u8 *)((u8 *)state + 0x14) = 4;
        *(u8 *)((u8 *)state + 0x15) |= 0x2;
        p50 = *(void **)((u8 *)obj + 0x50);
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
    *(u8 *)((u8 *)obj + 0xaf) &= ~0x8;
    if ((*(u8 *)((u8 *)obj + 0xaf) & 0x4) != 0 && GameBit_Get(0x189) == 0) {
      (*(void (***)(int, void *, int))gObjectTriggerInterface)[18](0, obj, -1);
      GameBit_Set(0x189, 1);
    }
  } else {
    *(u8 *)((u8 *)obj + 0xaf) |= 0x8;
  }

  if ((entry[8] & 0x4) != 0) {
    *(s16 *)((u8 *)obj + 0x6) |= 0x4000;
  } else {
    *(s16 *)((u8 *)obj + 0x6) &= ~0x4000;
  }

  if (*(s16 *)((u8 *)obj + 0xa0) != *(s16 *)entry) {
    ObjAnim_SetCurrentMove(obj, *(s16 *)entry, 0, lbl_803E536C);
  }

  if (ObjAnim_AdvanceCurrentMove(obj, 0, *(f32 *)(entry + 0x4), timeDelta) != 0) {
    *(u8 *)((u8 *)state + 0x15) |= 0x1;
  } else {
    *(u8 *)((u8 *)state + 0x15) &= ~0x1;
  }

epilogue:
  return;
}
