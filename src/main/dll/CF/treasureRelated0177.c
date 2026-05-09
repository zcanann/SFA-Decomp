#include "ghidra_import.h"
#include "main/dll/CF/treasureRelated0177.h"

extern undefined8 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern void* FUN_800069a8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern undefined4 FUN_80017664();
extern undefined4 FUN_800176c8();
extern double FUN_800176f4();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern void ModelLightStruct_free(void *effect);
extern u32 GameBit_Get(int bit);
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnimArg,
                                             void *animEvents);
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_80053bf0();
extern undefined8 FUN_8005d1e8();
extern undefined4 FUN_8005fe14();
extern void queueGlowRender(void *effect);
extern undefined4 FUN_80081110();
extern undefined4 FUN_800d7780();
extern undefined4 FUN_8011daf8();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294d90();
extern undefined4 FUN_80294d98();
extern void* SUB42();

extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6f8;
extern undefined4* lbl_803DCA78;
extern u8 framesThisStep;
extern f64 DOUBLE_803e4a08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e49b0;
extern f32 FLOAT_803e49b4;
extern f32 FLOAT_803e49b8;
extern f32 FLOAT_803e49bc;
extern f32 FLOAT_803e49c0;
extern f32 FLOAT_803e49c4;
extern f32 FLOAT_803e49d0;
extern f32 FLOAT_803e49dc;
extern f32 FLOAT_803e49e0;
extern f32 FLOAT_803e49f0;
extern f32 FLOAT_803e49fc;
extern f32 FLOAT_803e4a00;
extern f32 FLOAT_803e4a10;
extern f32 FLOAT_803e4a14;
extern f32 FLOAT_803e4a18;
extern f32 timeDelta;
extern f32 lbl_803E3D64;
extern f32 lbl_803E3D68;
extern f64 lbl_803E3D70;
extern f32 lbl_803E3D78;
extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;
extern f64 lbl_803E3DB8;

/*
 * --INFO--
 *
 * Function: dll_127_update
 * EN v1.0 Address: 0x8018CDAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018CDAC
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dll_127_update(int obj)
{
  int timer;
  int flags;

  if (*(void **)(obj + 0x54) == 0) {
    return;
  }
  timer = *(short *)(obj + 0xf8);
  if (timer > 0) {
    *(short *)(obj + 0xf8) = timer - framesThisStep;
  }
  flags = *(short *)(*(int *)(obj + 0x54) + 0x60) & 8;
  if (flags == 0) {
    return;
  }
  if (*(short *)(obj + 0xf8) > 0) {
    return;
  }
  *(short *)(obj + 0xf8) = 100;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8018cdb0
 * EN v1.0 Address: 0x8018CDB0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8018D208
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cdb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short *psVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  psVar2 = FUN_800069a8();
  FUN_800d7780(1);
  (**(code **)(*DAT_803dd6cc + 8))(1,1);
  FUN_800305f8((double)FLOAT_803e49b4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0x8e,0,param_12,param_13,param_14,param_15,param_16);
  *pfVar3 = FLOAT_803e49f0;
  pfVar3[1] = *(float *)(psVar2 + 6);
  pfVar3[2] = *(float *)(psVar2 + 8);
  pfVar3[3] = *(float *)(psVar2 + 10);
  pfVar3[6] = (float)(int)*psVar2;
  pfVar3[7] = (float)(int)psVar2[1];
  fVar1 = FLOAT_803e49c4;
  pfVar3[4] = FLOAT_803e49c4;
  pfVar3[5] = fVar1;
  FUN_80017664(param_9);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x400;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018cf58
 * EN v1.0 Address: 0x8018CF58
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8018D2F4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cf58(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dll_127_init
 * EN v1.0 Address: 0x8018CF80
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8018D378
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dll_127_init(short *param_1,int param_2)
{
  float fVar1;
  double dVar2;
  uint uVar2;
  uint local_18[2];
  uint local_10[2];
  
  param_1[3] = param_1[3] | 2;
  uVar2 = *(byte *)(param_2 + 0x19) ^ 0x80000000;
  dVar2 = lbl_803E3D70;
  local_18[1] = uVar2;
  local_18[0] = 0x43300000;
  fVar1 = (float)(*(double *)local_18 - dVar2);
  local_10[1] = uVar2;
  local_10[0] = 0x43300000;
  if ((float)(*(double *)local_10 - dVar2) < lbl_803E3D64) {
    fVar1 = lbl_803E3D64;
  }
  fVar1 = fVar1 * lbl_803E3D68;
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  if (*(float **)(param_1 + 0x32) != (float *)0x0) {
    **(float **)(param_1 + 0x32) = **(float **)(param_1 + 0x28) * fVar1;
  }
  *(char *)((int)param_1 + 0xad) = *(char *)(param_2 + 0x18);
  uVar2 = *(byte *)(param_2 + 0x1a) & 0x3f;
  *param_1 = (short)(uVar2 << 10);
  if (*(char *)((int)param_1 + 0xad) >= *(char *)(*(int *)(param_1 + 0x28) + 0x55)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8018d064
 * EN v1.0 Address: 0x8018D064
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8018D470
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d064(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*puVar1 != 0) {
    FUN_80017620(*puVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d0b4
 * EN v1.0 Address: 0x8018D0B4
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8018D4BC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d0b4(int param_1)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
    iVar1 = *piVar2;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_8005fe14(iVar1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d110
 * EN v1.0 Address: 0x8018D110
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x8018D520
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d110(void)
{
  bool bVar1;
  float fVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined4 uVar8;
  int *piVar9;
  undefined auStack_28 [4];
  float local_24;
  float local_20;
  float local_1c;
  
  uVar4 = FUN_80286840();
  piVar9 = *(int **)(uVar4 + 0xb8);
  FUN_80017a98();
  iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
  if (iVar5 == 0) {
    if (*piVar9 != 0) {
      FUN_800175cc((double)FLOAT_803e4a10,*piVar9,'\0');
    }
    ObjHits_ClearHitVolumes(uVar4);
    piVar9[1] = (int)((float)piVar9[1] - FLOAT_803dc074);
    if (FLOAT_803e4a14 < (float)piVar9[1]) {
      uVar7 = 0;
    }
    else {
      uVar7 = 3;
      piVar9[1] = (int)((float)piVar9[1] + FLOAT_803e4a18);
    }
    uVar8 = 0;
    uVar6 = 0;
    if (*(char *)((int)piVar9 + 0x12) != '\0') {
      FUN_800068cc();
      *(undefined *)((int)piVar9 + 0x12) = 0;
    }
  }
  else {
    if (*piVar9 != 0) {
      FUN_800175cc((double)FLOAT_803e4a10,*piVar9,'\x01');
    }
    ObjHits_SetHitVolumeSlot(uVar4,0x1f,1,0);
    piVar9[2] = (int)((float)piVar9[2] - FLOAT_803dc074);
    fVar2 = (float)piVar9[2];
    bVar1 = fVar2 <= FLOAT_803e4a14;
    if (bVar1) {
      piVar9[2] = (int)(fVar2 + FLOAT_803e4a10);
    }
    uVar6 = (uint)bVar1;
    uVar8 = 2;
    uVar7 = 0;
    if (*(char *)((int)piVar9 + 0x12) == '\0') {
      FUN_800068d0(uVar4,0x9e);
      *(undefined *)((int)piVar9 + 0x12) = 1;
    }
  }
  local_24 = FLOAT_803e4a14;
  local_20 = FLOAT_803e4a18;
  local_1c = FLOAT_803e4a14;
  FUN_80081110(uVar4,uVar8,uVar7,uVar6,&local_24);
  iVar5 = *piVar9;
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    uVar4 = FUN_80017760(0xffffffe7,0x19);
    iVar5 = *piVar9;
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa) + (short)uVar4;
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xff < sVar3) {
      sVar3 = 0xff;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    *(char *)(*piVar9 + 0x2f9) = (char)sVar3;
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8018CEDC(void) {}
void fn_8018CEE0(void) {}

#pragma scheduling off
void campfire_free(int obj)
{
  void **state;
  void *effect;

  state = *(void ***)(obj + 0xb8);
  (*(void (*)(int))(*(int *)(*lbl_803DCA78 + 0x18)))(obj);
  effect = *state;
  if (effect != 0) {
    ModelLightStruct_free(effect);
  }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void campfire_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  void **state;
  void *effect;
  s32 isVisible;

  state = *(void ***)(obj + 0xb8);
  isVisible = visible;
  if (isVisible != 0) {
    objRenderFn_8003b8f4(lbl_803E3D78);
    effect = *state;
    if (((effect != 0) && (*(u8 *)((int)effect + 0x2f8) != 0)) &&
        (*(u8 *)((int)effect + 0x4c) != 0)) {
      queueGlowRender(effect);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

void kt_torch_free(void) {}
void kt_torch_hitDetect(void) {}
void kt_torch_release(void) {}
void kt_torch_initialise(void) {}

#pragma scheduling off
void kt_torch_update(int obj)
{
  int mapData;
  int bit;
  uint local_18[2];

  mapData = *(int *)(obj + 0x4c);
  local_18[1] = *(u8 *)(mapData + 0x1b);
  local_18[0] = 0x43300000;
  ObjAnim_AdvanceCurrentMove((double)((float)(*(double *)local_18 - lbl_803E3DB8) /
                                      lbl_803E3DB4),
                             (double)timeDelta,obj,0);
  bit = *(short *)(mapData + 0x20);
  if (bit != -1) {
    if (GameBit_Get(bit) != 0) {
      *(u8 *)(obj + 0x36) = 0xff;
    }
    else {
      *(u8 *)(obj + 0x36) = 0;
    }
  }
}
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int campfire_getExtraSize(void) { return 0x14; }
int campfire_func08(void) { return 0x1; }
int kt_torch_getExtraSize(void) { return 0x0; }
int kt_torch_func08(void) { return 0x0; }
int cfccrate_getExtraSize(void) { return 0x4c; }
int cfccrate_func08(void) { return 0x1; }

#pragma scheduling off
void cfccrate_free(int obj)
{
  (*(void (*)(int))(*(int *)(*lbl_803DCA78 + 0x18)))(obj);
}
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off
void kt_torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3DB0); }
#pragma peephole reset
