#include "ghidra_import.h"
#include "main/dll/DF/dll_196.h"

extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern f64 DOUBLE_803e5a88;
extern f32 FLOAT_803e5a94;
extern f32 FLOAT_803e5ab0;
extern f32 FLOAT_803e5ab4;

/*
 * --INFO--
 *
 * Function: FUN_801c1bf0
 * EN v1.0 Address: 0x801C1BF0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801C1C4C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801c1bf0(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,float *param_7,float *param_8,float *param_9)
{
  double dVar1;
  double dVar2;
  double dVar3;
  
  dVar2 = (double)(float)(param_4 - param_1);
  dVar3 = (double)(float)(param_6 - param_3);
  dVar1 = (double)FLOAT_803e5a94;
  if ((dVar1 != dVar2) || (dVar1 != dVar3)) {
    dVar1 = (double)((float)(dVar2 * (double)(float)((double)*param_7 - param_1) +
                            (double)(float)(dVar3 * (double)(float)((double)*param_9 - param_3))) /
                    (float)(dVar2 * dVar2 + (double)(float)(dVar3 * dVar3)));
  }
  if ((double)FLOAT_803e5a94 <= dVar1) {
    if (dVar1 < (double)FLOAT_803e5ab0) {
      *param_7 = (float)(dVar1 * dVar2 + param_1);
      *param_8 = (float)(dVar1 * (double)(float)(param_5 - param_2) + param_2);
      *param_9 = (float)(dVar1 * dVar3 + param_3);
    }
    else {
      *param_7 = (float)param_4;
      *param_8 = (float)param_5;
      *param_9 = (float)param_6;
    }
  }
  else {
    *param_7 = (float)param_1;
    *param_8 = (float)param_2;
    *param_9 = (float)param_3;
  }
  return dVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801c1cd8
 * EN v1.0 Address: 0x801C1CD8
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x801C1CF4
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c1cd8(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,float *param_6,undefined *param_7)
{
  float *pfVar1;
  float *pfVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  double extraout_f1;
  double dVar7;
  double dVar8;
  double in_f27;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_88;
  float local_84;
  float local_80 [2];
  undefined4 local_78;
  uint uStack_74;
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
  uVar13 = FUN_80286838();
  iVar4 = (int)((ulonglong)uVar13 >> 0x20);
  pfVar1 = (float *)uVar13;
  piVar6 = *(int **)(iVar4 + 0xb8);
  if ((((((*(byte *)(*(int *)(iVar4 + 0x4c) + 0x18) & 1) != 0) && (*piVar6 != 0)) &&
       ((double)(float)piVar6[1] <= extraout_f1)) &&
      ((extraout_f1 <= (double)(float)piVar6[2] && ((double)(float)piVar6[3] <= param_3)))) &&
     (param_3 <= (double)(float)piVar6[4])) {
    *pfVar1 = FLOAT_803e5ab4;
    dVar10 = (double)(float)(extraout_f1 - (double)*(float *)(iVar4 + 0xc));
    dVar11 = (double)(float)(param_2 - (double)*(float *)(iVar4 + 0x10));
    dVar12 = (double)(float)(param_3 - (double)*(float *)(iVar4 + 0x14));
    iVar5 = 0;
    iVar4 = 0;
    dVar9 = (double)FLOAT_803e5a94;
    for (uVar3 = 0; (int)uVar3 < (int)(*(byte *)(piVar6[0xb] + 8) - 1); uVar3 = uVar3 + 1) {
      local_80[0] = (float)dVar10;
      local_84 = (float)dVar11;
      local_88 = (float)dVar12;
      pfVar2 = (float *)(*(int *)piVar6[0xb] + iVar4);
      dVar7 = FUN_801c1bf0((double)*pfVar2,(double)pfVar2[1],(double)pfVar2[2],(double)pfVar2[0xd],
                           (double)pfVar2[0xe],(double)pfVar2[0xf],local_80,&local_84,&local_88);
      if (((dVar9 <= dVar7) && (dVar7 < (double)FLOAT_803e5ab0)) &&
         (dVar8 = FUN_80293900((double)((float)((double)local_88 - dVar12) *
                                        (float)((double)local_88 - dVar12) +
                                       (float)((double)local_80[0] - dVar10) *
                                       (float)((double)local_80[0] - dVar10) +
                                       (float)((double)local_84 - dVar11) *
                                       (float)((double)local_84 - dVar11))), dVar8 < (double)*pfVar1
         )) {
        iVar5 = uVar3 + 1;
        *pfVar1 = (float)dVar8;
        uStack_74 = uVar3 ^ 0x80000000;
        local_78 = 0x43300000;
        *param_6 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e5a88)
                          + dVar7);
      }
      iVar4 = iVar4 + 0x34;
    }
    if (iVar5 != 0) {
      if ((int)(uint)*(byte *)(piVar6[0xb] + 8) >> 1 < iVar5 + -1) {
        *param_7 = 1;
      }
      else {
        *param_7 = 0;
      }
    }
  }
  FUN_80286884();
  return;
}
