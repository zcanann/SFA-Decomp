#include "ghidra_import.h"
#include "main/dll/cannonball.h"

extern bool FUN_8000b598();
extern double FUN_80021730();
extern undefined4 FUN_80022264();
extern undefined4 FUN_800394f0();
extern undefined4 FUN_800da4c8();
extern undefined4 FUN_800dabb4();
extern undefined4 FUN_800dac0c();
extern int FUN_800dbf88();
extern undefined4 FUN_80139bbc();
extern undefined4 FUN_80139e14();
extern undefined4 FUN_8013b6f0();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();

extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e30f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e30ac;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e3198;
extern f32 FLOAT_803e319c;

/*
 * --INFO--
 *
 * Function: FUN_80141618
 * EN v1.0 Address: 0x80141290
 * EN v1.0 Size: 1996b
 * EN v1.1 Address: 0x80141618
 * EN v1.1 Size: 1520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80141618(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float fVar2;
  bool bVar5;
  int iVar3;
  float fVar4;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  float fVar11;
  double dVar12;
  double dVar13;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar14;
  int local_48 [16];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar14 = FUN_80286838();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  iVar6 = (int)uVar14;
  iVar8 = 0;
  if (*(char *)(iVar6 + 10) == '\0') {
    FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 iVar3,iVar6,param_11,param_12,(byte)param_13,param_14,param_15,param_16);
    iVar8 = FUN_800dbf88((float *)(*(int *)(iVar6 + 0x700) + 8),(undefined *)0x0);
    iVar3 = FUN_800dbf88((float *)(iVar3 + 0x18),(undefined *)0x0);
    if (iVar3 == iVar8) {
      fVar11 = *(float *)(iVar6 + 0x700);
      (**(code **)(*DAT_803dd71c + 0x54))(fVar11,0);
      fVar2 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x60))(fVar11,0);
      fVar1 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      dVar13 = FUN_80021730((float *)(*(int *)(iVar6 + 4) + 0x18),(float *)((int)fVar2 + 8));
      dVar12 = FUN_80021730((float *)(*(int *)(iVar6 + 4) + 0x18),(float *)((int)fVar1 + 8));
      if (dVar13 <= dVar12) {
        (**(code **)(*DAT_803dd71c + 0x60))(fVar1,0);
        fVar4 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
        *(undefined4 *)(iVar6 + 0x4a0) = 1;
        uVar14 = extraout_f1_00;
      }
      else {
        (**(code **)(*DAT_803dd71c + 0x54))(fVar2,0);
        fVar4 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
        *(undefined4 *)(iVar6 + 0x4a0) = 0;
        fVar1 = fVar2;
        uVar14 = extraout_f1;
      }
      FUN_800dac0c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (float *)(iVar6 + 0x420),fVar11,fVar1,fVar4,param_13,param_14,param_15,param_16);
      if (*(int *)(iVar6 + 0x4a0) == 0) {
        FUN_800dabb4((double)FLOAT_803e3070,(float *)(iVar6 + 0x420));
      }
      else {
        FUN_800dabb4((double)FLOAT_803e319c,(float *)(iVar6 + 0x420));
      }
      *(float *)(iVar6 + 0x708) = FLOAT_803e306c;
      *(undefined *)(iVar6 + 10) = 1;
    }
  }
  else {
    if (*(int *)(iVar6 + 0x4a0) == 0) {
      if (*(int *)(iVar6 + 0x430) != 0) {
        param_11 = *(int *)(iVar6 + 0x4c4);
        if ((-1 < *(int *)(param_11 + 0x1c)) && ((*(byte *)(param_11 + 0x1b) & 1) == 0)) {
          iVar8 = 1;
          local_48[0] = *(int *)(param_11 + 0x1c);
        }
        iVar9 = iVar8;
        if ((-1 < *(int *)(param_11 + 0x20)) && ((*(byte *)(param_11 + 0x1b) & 2) == 0)) {
          iVar9 = iVar8 + 1;
          local_48[iVar8] = *(int *)(param_11 + 0x20);
        }
        iVar8 = iVar9;
        if ((-1 < *(int *)(param_11 + 0x24)) && ((*(byte *)(param_11 + 0x1b) & 4) == 0)) {
          iVar8 = iVar9 + 1;
          local_48[iVar9] = *(int *)(param_11 + 0x24);
        }
        param_12 = 8;
        if ((-1 < *(int *)(param_11 + 0x28)) && ((*(byte *)(param_11 + 0x1b) & 8) == 0)) {
          local_48[iVar8] = *(int *)(param_11 + 0x28);
          iVar8 = iVar8 + 1;
        }
      }
    }
    else if (*(int *)(iVar6 + 0x430) == 0) {
      param_11 = *(int *)(iVar6 + 0x4c4);
      if ((-1 < *(int *)(param_11 + 0x1c)) && ((*(byte *)(param_11 + 0x1b) & 1) != 0)) {
        iVar8 = 1;
        local_48[0] = *(int *)(param_11 + 0x1c);
      }
      iVar9 = iVar8;
      if ((-1 < *(int *)(param_11 + 0x20)) && ((*(byte *)(param_11 + 0x1b) & 2) != 0)) {
        iVar9 = iVar8 + 1;
        local_48[iVar8] = *(int *)(param_11 + 0x20);
      }
      iVar10 = iVar9;
      if ((-1 < *(int *)(param_11 + 0x24)) && ((*(byte *)(param_11 + 0x1b) & 4) != 0)) {
        iVar10 = iVar9 + 1;
        local_48[iVar9] = *(int *)(param_11 + 0x24);
      }
      param_12 = 8;
      iVar8 = iVar10;
      if ((-1 < *(int *)(param_11 + 0x28)) && ((*(byte *)(param_11 + 0x1b) & 8) != 0)) {
        iVar8 = iVar10 + 1;
        local_48[iVar10] = *(int *)(param_11 + 0x28);
      }
    }
    if (iVar8 != 0) {
      fVar1 = (float)(**(code **)(*DAT_803dd71c + 0x1c))(local_48[0]);
      dVar12 = FUN_80021730((float *)(*(int *)(iVar6 + 0x24) + 0x18),(float *)((int)fVar1 + 8));
      piVar7 = local_48;
      dVar13 = dVar12;
      for (iVar9 = 1; piVar7 = piVar7 + 1, iVar9 < iVar8; iVar9 = iVar9 + 1) {
        fVar2 = (float)(**(code **)(*DAT_803dd71c + 0x1c))(*piVar7);
        dVar12 = FUN_80021730((float *)(*(int *)(iVar6 + 0x24) + 0x18),(float *)((int)fVar2 + 8));
        if (dVar12 < dVar13) {
          fVar1 = fVar2;
          dVar13 = dVar12;
        }
      }
      FUN_800da4c8(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (float *)(iVar6 + 0x420),fVar1,param_11,param_12,param_13,param_14,param_15,
                   param_16);
    }
    fVar1 = *(float *)(iVar6 + 0x14);
    if (fVar1 <= FLOAT_803e3198) {
      fVar1 = FLOAT_803e30b0 * FLOAT_803dc074 + fVar1;
      if (FLOAT_803e3198 < fVar1) {
        fVar1 = FLOAT_803e3198;
      }
    }
    else {
      fVar1 = FLOAT_803e30ac * FLOAT_803dc074 + fVar1;
      if (fVar1 < FLOAT_803e3198) {
        fVar1 = FLOAT_803e3198;
      }
    }
    *(float *)(iVar6 + 0x14) = fVar1;
    FUN_80139bbc((double)*(float *)(iVar6 + 0x14),iVar3,(float *)(iVar6 + 0x420));
    FUN_80139e14();
    iVar8 = FUN_800dbf88((float *)(iVar3 + 0x18),(undefined *)0x0);
    if (iVar8 == 0) {
      *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    }
    else {
      *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xffffffef;
    }
    *(float *)(iVar6 + 0x708) = *(float *)(iVar6 + 0x708) - FLOAT_803dc074;
    if (*(float *)(iVar6 + 0x708) < FLOAT_803e306c) {
      local_48[5] = FUN_80022264(200,600);
      local_48[5] = local_48[5] ^ 0x80000000;
      local_48[4] = 0x43300000;
      *(float *)(iVar6 + 0x708) =
           (float)((double)CONCAT44(0x43300000,local_48[5]) - DOUBLE_803e30f0);
      iVar8 = *(int *)(iVar3 + 0xb8);
      if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar3 + 0xa0) || (*(short *)(iVar3 + 0xa0) < 0x29)) &&
          (bVar5 = FUN_8000b598(iVar3,0x10), !bVar5)))) {
        FUN_800394f0(iVar3,iVar8 + 0x3a8,0x29b,0x1000,0xffffffff,0);
      }
    }
  }
  FUN_80286884();
  return;
}
