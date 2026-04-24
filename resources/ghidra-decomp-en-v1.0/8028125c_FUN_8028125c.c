// Function: FUN_8028125c
// Entry: 8028125c
// Size: 180 bytes

void FUN_8028125c(float *param_1)

{
  double dVar1;
  double dVar2;
  
  dVar1 = (double)(param_1[2] * param_1[2] + *param_1 * *param_1 + param_1[1] * param_1[1]);
  if ((double)FLOAT_803e78c8 < dVar1) {
    dVar2 = 1.0 / SQRT(dVar1);
    dVar2 = DOUBLE_803e78d0 * dVar2 * (DOUBLE_803e78d8 - dVar1 * dVar2 * dVar2);
    dVar2 = DOUBLE_803e78d0 * dVar2 * (DOUBLE_803e78d8 - dVar1 * dVar2 * dVar2);
    dVar1 = (double)(float)(dVar1 * DOUBLE_803e78d0 * dVar2 *
                                    (DOUBLE_803e78d8 - dVar1 * dVar2 * dVar2));
  }
  *param_1 = (float)((double)*param_1 / dVar1);
  param_1[1] = (float)((double)param_1[1] / dVar1);
  param_1[2] = (float)((double)param_1[2] / dVar1);
  return;
}

