// Function: FUN_802819c0
// Entry: 802819c0
// Size: 180 bytes

void FUN_802819c0(float *param_1)

{
  double dVar1;
  double dVar2;
  
  dVar1 = (double)(param_1[2] * param_1[2] + *param_1 * *param_1 + param_1[1] * param_1[1]);
  if ((double)FLOAT_803e8560 < dVar1) {
    dVar2 = 1.0 / SQRT(dVar1);
    dVar2 = DOUBLE_803e8568 * dVar2 * (DOUBLE_803e8570 - dVar1 * dVar2 * dVar2);
    dVar2 = DOUBLE_803e8568 * dVar2 * (DOUBLE_803e8570 - dVar1 * dVar2 * dVar2);
    dVar1 = (double)(float)(dVar1 * DOUBLE_803e8568 * dVar2 *
                                    (DOUBLE_803e8570 - dVar1 * dVar2 * dVar2));
  }
  *param_1 = (float)((double)*param_1 / dVar1);
  param_1[1] = (float)((double)param_1[1] / dVar1);
  param_1[2] = (float)((double)param_1[2] / dVar1);
  return;
}

