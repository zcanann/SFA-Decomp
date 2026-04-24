#include "ghidra_import.h"
#include "main/dll/CAM/attentioncam.h"

extern double FUN_80293900();

extern undefined4* DAT_803dd71c;
extern f32 FLOAT_803e2508;
extern f32 FLOAT_803e2528;

/*
 * --INFO--
 *
 * Function: FUN_8010aee4
 * EN v1.0 Address: 0x8010AEA8
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x8010AEE4
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_8010aee4(double param_1,undefined8 param_2,double param_3,undefined4 *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  int local_98 [7];
  
  iVar6 = 0;
  piVar7 = local_98;
  do {
    iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(*param_4);
    *piVar7 = iVar5;
    param_4 = param_4 + 1;
    piVar7 = piVar7 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  dVar13 = (double)(*(float *)(local_98[2] + 8) - *(float *)(local_98[1] + 8));
  dVar12 = (double)(*(float *)(local_98[2] + 0x10) - *(float *)(local_98[1] + 0x10));
  dVar8 = dVar12;
  dVar9 = dVar13;
  if (local_98[0] != 0) {
    dVar8 = (double)(*(float *)(local_98[1] + 0x10) - *(float *)(local_98[0] + 0x10));
    dVar9 = (double)(*(float *)(local_98[1] + 8) - *(float *)(local_98[0] + 8));
  }
  dVar10 = (double)(FLOAT_803e2528 * (float)(dVar9 + dVar13));
  dVar9 = (double)(FLOAT_803e2528 * (float)(dVar8 + dVar12));
  dVar8 = FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
  if ((double)FLOAT_803e2508 != dVar8) {
    dVar10 = (double)(float)(dVar10 / dVar8);
    dVar9 = (double)(float)(dVar9 / dVar8);
  }
  dVar8 = (double)(float)(dVar10 * dVar13 + (double)(float)(dVar9 * dVar12));
  if ((double)FLOAT_803e2508 != dVar8) {
    dVar8 = (double)(float)(-(double)(-(float)(dVar10 * (double)*(float *)(local_98[1] + 8) +
                                              (double)(float)(dVar9 * (double)*(float *)(local_98[1]
                                                                                        + 0x10))) +
                                     (float)(dVar10 * param_1 + (double)(float)(dVar9 * param_3))) /
                           dVar8);
  }
  fVar1 = (float)((double)*(float *)(local_98[2] + 8) - (double)*(float *)(local_98[1] + 8));
  fVar2 = (float)((double)*(float *)(local_98[2] + 0x10) - (double)*(float *)(local_98[1] + 0x10));
  fVar3 = fVar1;
  fVar4 = fVar2;
  if (local_98[3] != 0) {
    fVar3 = (float)((double)*(float *)(local_98[3] + 8) - (double)*(float *)(local_98[2] + 8));
    fVar4 = (float)((double)*(float *)(local_98[3] + 0x10) - (double)*(float *)(local_98[2] + 0x10))
    ;
  }
  dVar11 = (double)(FLOAT_803e2528 * (fVar3 + fVar1));
  dVar10 = (double)(FLOAT_803e2528 * (fVar4 + fVar2));
  dVar9 = FUN_80293900((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10)));
  if ((double)FLOAT_803e2508 != dVar9) {
    dVar11 = (double)(float)(dVar11 / dVar9);
    dVar10 = (double)(float)(dVar10 / dVar9);
  }
  dVar9 = (double)(float)(dVar11 * dVar13 + (double)(float)(dVar10 * dVar12));
  if ((double)FLOAT_803e2508 != dVar9) {
    dVar9 = (double)(float)(-(double)(-(float)(dVar11 * (double)*(float *)(local_98[2] + 8) +
                                              (double)(float)(dVar10 * (double)*(float *)(local_98[2
                                                  ] + 0x10))) +
                                     (float)(dVar11 * param_1 + (double)(float)(dVar10 * param_3)))
                           / dVar9);
  }
  return (double)(float)(-dVar8 / (double)(float)(dVar9 - dVar8));
}
