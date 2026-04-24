// Function: FUN_80188798
// Entry: 80188798
// Size: 124 bytes

void FUN_80188798(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  
  fVar1 = *param_1;
  if (fVar1 <= *param_2) {
    if (fVar1 < *param_3) {
      *param_3 = fVar1;
    }
  }
  else {
    *param_2 = fVar1;
  }
  fVar1 = param_1[1];
  if (fVar1 <= param_2[1]) {
    if (fVar1 < param_3[1]) {
      param_3[1] = fVar1;
    }
  }
  else {
    param_2[1] = fVar1;
  }
  fVar1 = param_1[2];
  if (param_2[2] < fVar1) {
    param_2[2] = fVar1;
    return;
  }
  if (param_3[2] <= fVar1) {
    return;
  }
  param_3[2] = fVar1;
  return;
}

