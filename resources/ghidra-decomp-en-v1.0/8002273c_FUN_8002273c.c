// Function: FUN_8002273c
// Entry: 8002273c
// Size: 188 bytes

void FUN_8002273c(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  
  fVar1 = param_1[2] * param_2[2] + *param_1 * *param_2 + param_1[1] * param_2[1];
  if (FLOAT_803de808 < fVar1) {
    *param_3 = *param_2;
    param_3[1] = param_2[1];
    param_3[2] = param_2[2];
    return;
  }
  fVar1 = fVar1 * FLOAT_803de80c;
  *param_3 = *param_1;
  param_3[1] = param_1[1];
  param_3[2] = param_1[2];
  *param_3 = *param_3 * fVar1;
  param_3[1] = param_3[1] * fVar1;
  param_3[2] = param_3[2] * fVar1;
  *param_3 = *param_3 + *param_2;
  param_3[1] = param_3[1] + param_2[1];
  param_3[2] = param_3[2] + param_2[2];
  return;
}

