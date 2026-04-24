// Function: FUN_8029697c
// Entry: 8029697c
// Size: 116 bytes

void FUN_8029697c(int param_1,undefined2 *param_2,undefined2 *param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = (short)(int)(FLOAT_803e7ee4 * *(float *)(iVar1 + 0x7b8));
  if (*(int *)(iVar1 + 0x7f0) == 0) {
    *param_3 = (short)(int)(FLOAT_803e7eec * *(float *)(iVar1 + 0x7bc));
  }
  else {
    *param_3 = (short)(int)(FLOAT_803e7ee8 * *(float *)(iVar1 + 0x7bc));
  }
  return;
}

