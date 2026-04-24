// Function: FUN_8026c644
// Entry: 8026c644
// Size: 60 bytes

void FUN_8026c644(int *param_1,int param_2)

{
  *param_1 = param_2;
  param_1[1] = 2;
  *(byte *)(param_1 + 2) = *(byte *)*param_1 >> 4 & 7;
  *(byte *)((int)param_1 + 9) = *(byte *)*param_1 & 0xf;
  *param_1 = *param_1 + 1;
  return;
}

