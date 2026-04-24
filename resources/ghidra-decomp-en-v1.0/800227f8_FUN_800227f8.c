// Function: FUN_800227f8
// Entry: 800227f8
// Size: 52 bytes

void FUN_800227f8(double param_1,float *param_2,float *param_3,float *param_4)

{
  *param_4 = (float)(param_1 * (double)*param_3 + (double)*param_2);
  param_4[1] = (float)(param_1 * (double)param_3[1] + (double)param_2[1]);
  param_4[2] = (float)(param_1 * (double)param_3[2] + (double)param_2[2]);
  return;
}

