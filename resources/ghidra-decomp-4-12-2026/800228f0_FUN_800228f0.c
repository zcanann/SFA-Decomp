// Function: FUN_800228f0
// Entry: 800228f0
// Size: 132 bytes

void FUN_800228f0(float *param_1)

{
  float fVar1;
  double dVar2;
  
  dVar2 = FUN_80293900((double)(param_1[2] * param_1[2] +
                               *param_1 * *param_1 + param_1[1] * param_1[1]));
  if ((double)FLOAT_803df488 != dVar2) {
    fVar1 = (float)((double)FLOAT_803df490 / dVar2);
    *param_1 = *param_1 * fVar1;
    param_1[1] = param_1[1] * fVar1;
    param_1[2] = param_1[2] * fVar1;
  }
  return;
}

