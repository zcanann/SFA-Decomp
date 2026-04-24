// Function: FUN_802933d4
// Entry: 802933d4
// Size: 40 bytes

void FUN_802933d4(double param_1,float *param_2,float *param_3)

{
  *param_3 = (float)((double)*param_2 * param_1);
  param_3[1] = (float)((double)param_2[1] * param_1);
  param_3[2] = (float)((double)param_2[2] * param_1);
  return;
}

