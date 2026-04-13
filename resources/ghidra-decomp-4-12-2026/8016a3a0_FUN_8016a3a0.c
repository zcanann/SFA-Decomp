// Function: FUN_8016a3a0
// Entry: 8016a3a0
// Size: 356 bytes

/* WARNING: Removing unreachable block (ram,0x8016a4e0) */
/* WARNING: Removing unreachable block (ram,0x8016a4d8) */
/* WARNING: Removing unreachable block (ram,0x8016a4d0) */
/* WARNING: Removing unreachable block (ram,0x8016a4c8) */
/* WARNING: Removing unreachable block (ram,0x8016a3c8) */
/* WARNING: Removing unreachable block (ram,0x8016a3c0) */
/* WARNING: Removing unreachable block (ram,0x8016a3b8) */
/* WARNING: Removing unreachable block (ram,0x8016a3b0) */

int FUN_8016a3a0(double param_1,double param_2,float *param_3,float *param_4,char param_5)

{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar2 = FUN_80293900((double)((*param_3 - *param_4) * (*param_3 - *param_4) +
                               (param_3[2] - param_4[2]) * (param_3[2] - param_4[2])));
  dVar3 = (double)(param_3[1] - param_4[1]);
  dVar5 = (double)(float)(dVar2 * (double)FLOAT_803e3da8);
  dVar2 = (double)(float)((double)(float)((double)FLOAT_803e3dac * param_2) * param_2);
  dVar6 = (double)(float)(param_1 * param_1);
  dVar4 = (double)(float)(-(double)(float)(param_2 * dVar3) - dVar6);
  dVar3 = (double)(float)(dVar4 * dVar4 -
                         (double)((float)((double)FLOAT_803e3db0 * dVar2) *
                                 (float)(dVar3 * dVar3 + (double)(float)(dVar5 * dVar5))));
  if (dVar3 < (double)FLOAT_803e3db4) {
    iVar1 = 0x2000;
  }
  else {
    if (param_5 == '\0') {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(FLOAT_803e3db8 * (float)(-dVar4 - dVar3)) / dVar2;
    }
    else {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(FLOAT_803e3db8 * (float)(-dVar4 + dVar3)) / dVar2;
    }
    dVar2 = FUN_80293900((double)(float)dVar2);
    FUN_80293900(-(double)(float)((double)(float)(dVar5 / dVar2) * (double)(float)(dVar5 / dVar2) -
                                 dVar6));
    iVar1 = FUN_80021884();
  }
  return iVar1;
}

