#include "ghidra_import.h"
#include "main/dll/SH/SHkillermushroom.h"

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
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);

extern undefined4 DAT_80327960;
extern undefined4 DAT_80327964;
extern undefined4 DAT_80327968;
extern u8 framesThisStep;
extern undefined4* DAT_803dd6d4;
extern void *lbl_803DCA78;
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
  FUN_80006824((uint)param_9,0xa3);
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
void bombplantspore_free(void *obj)
{
  void *state;
  void *light;
  
  state = *(void **)((u8 *)obj + 0xb8);
  (*(void (***)(void *))lbl_803DCA78)[5](obj);
  light = *(void **)((u8 *)state + 0x270);
  if (light != NULL) {
    ModelLightStruct_free(light);
    *(void **)((u8 *)state + 0x270) = NULL;
  }
}

/*
 * --INFO--
 *
 * Function: fn_801D33D4
 * EN v1.0 Address: 0x801D33D4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801D33D4(void *obj, void *state)
{
  void *params;
  s16 baseAngle;
  u32 randAsDouble[2];
  s32 angleDelta;
  
  params = *(void **)((u8 *)obj + 0x4c);
  baseAngle = *(s16 *)((u8 *)params + 0x1c);

  randAsDouble[0] = 0x43300000;
  randAsDouble[1] = randomGetRange(0x1e, 0x2d) ^ 0x80000000;
  *(f32 *)((u8 *)state + 0x298) = *(f64 *)randAsDouble - lbl_803E53A0;

  randAsDouble[0] = 0x43300000;
  randAsDouble[1] = randomGetRange(0x78, 0xb4) ^ 0x80000000;
  *(f32 *)((u8 *)state + 0x284) =
      *(f32 *)((u8 *)state + 0x298) + (*(f64 *)randAsDouble - lbl_803E53A0);

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

  randAsDouble[0] = 0x43300000;
  randAsDouble[1] = randomGetRange(900, 0x514) ^ 0x80000000;
  *(f32 *)((u8 *)state + 0x29c) = (*(f64 *)randAsDouble - lbl_803E53A0) / lbl_803E5390;
  *(f32 *)((u8 *)state + 0x27c) = lbl_803E5394;

  *(f32 *)((u8 *)state + 0x290) =
      fn_80293E80((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2aa)) / lbl_803E539C);
  *(f32 *)((u8 *)state + 0x294) =
      sin((lbl_803E5398 * (f32)*(s16 *)((u8 *)state + 0x2aa)) / lbl_803E539C);
}

/*
 * --INFO--
 *
 * Function: fn_801D359C
 * EN v1.0 Address: 0x801D359C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801D359C(void *obj, void *state)
{
  void *params;
  s16 baseAngle;
  s32 angleDelta;
  u32 randAsDouble[2];
  
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
    randAsDouble[0] = 0x43300000;
    randAsDouble[1] = randomGetRange(-200, 200) ^ 0x80000000;
    *(f32 *)((u8 *)state + 0x280) =
        *(f32 *)((u8 *)state + 0x278) + (*(f64 *)randAsDouble - lbl_803E53A0) / lbl_803E5390;
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
  *(s16 *)((u8 *)state + 0x2a8) =
      *(s16 *)((u8 *)state + 0x2a8) + (s16)((angleDelta * (s32)framesThisStep) >> 4);
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
