// Function: FUN_8000e12c
// Entry: 8000e12c
// Size: 116 bytes

void FUN_8000e12c(int param_1,float *param_2,float *param_3,float *param_4)

{
  if (*(int *)(param_1 + 0x30) == 0) {
    *param_2 = *(float *)(param_1 + 0xc);
    *param_3 = *(float *)(param_1 + 0x10);
    *param_4 = *(float *)(param_1 + 0x14);
  }
  else {
    FUN_80022790((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),
                 (float *)(*(char *)(*(int *)(param_1 + 0x30) + 0x35) * 0x40 + -0x7fcc7b90),param_2,
                 param_3,param_4);
  }
  return;
}

