// Function: FUN_80189f5c
// Entry: 80189f5c
// Size: 676 bytes

void FUN_80189f5c(short *param_1,float *param_2,float *param_3)

{
  byte bVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  bVar1 = *(byte *)(*(int *)(param_1 + 0x26) + 0x1c);
  if (bVar1 == 2) {
    dVar3 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    *param_2 = -(float)((double)FLOAT_803e3bf0 * dVar3 - (double)*pfVar2);
    dVar3 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    *param_3 = -(float)((double)FLOAT_803e3bf0 * dVar3 - (double)pfVar2[1]);
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        dVar3 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       (int)*param_1 ^ 0x80000000) -
                                                     DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
        *param_2 = (float)((double)FLOAT_803e3bfc * dVar3 + (double)*(float *)(param_1 + 6));
        dVar3 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       (int)*param_1 ^ 0x80000000) -
                                                     DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
        *param_3 = (float)((double)FLOAT_803e3bfc * dVar3 + (double)*(float *)(param_1 + 10));
        return;
      }
    }
    else if (bVar1 < 4) {
      dVar3 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
      *param_2 = (float)((double)FLOAT_803e3bf0 * dVar3 + (double)*pfVar2);
      dVar3 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
      *param_3 = (float)((double)FLOAT_803e3bf0 * dVar3 + (double)pfVar2[1]);
      return;
    }
    dVar3 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    *param_2 = (float)((double)FLOAT_803e3bf0 * dVar3 + (double)*(float *)(param_1 + 6));
    dVar3 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    *param_3 = (float)((double)FLOAT_803e3bf0 * dVar3 + (double)*(float *)(param_1 + 10));
  }
  return;
}

