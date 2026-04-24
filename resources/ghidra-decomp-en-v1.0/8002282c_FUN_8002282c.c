// Function: FUN_8002282c
// Entry: 8002282c
// Size: 132 bytes

void FUN_8002282c(float *param_1)

{
  float fVar1;
  double dVar2;
  
  dVar2 = (double)FUN_802931a0((double)(param_1[2] * param_1[2] +
                                       *param_1 * *param_1 + param_1[1] * param_1[1]));
  if ((double)FLOAT_803de808 != dVar2) {
    fVar1 = (float)((double)FLOAT_803de810 / dVar2);
    *param_1 = *param_1 * fVar1;
    param_1[1] = param_1[1] * fVar1;
    param_1[2] = param_1[2] * fVar1;
  }
  return;
}

