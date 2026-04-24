// Function: FUN_8000dd94
// Entry: 8000dd94
// Size: 116 bytes

void FUN_8000dd94(float *param_1,float *param_2,char param_3)

{
  if (param_3 < 0) {
    *param_2 = *param_1;
    param_2[1] = param_1[1];
    param_2[2] = param_1[2];
  }
  else {
    FUN_80022790((double)*param_1,(double)param_1[1],(double)param_1[2],
                 (float *)(param_3 * 0x40 + -0x7fcc7b90),param_2,param_2 + 1,param_2 + 2);
  }
  return;
}

