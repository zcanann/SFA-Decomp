// Function: FUN_80233a98
// Entry: 80233a98
// Size: 108 bytes

void FUN_80233a98(undefined2 *param_1,int param_2)

{
  *param_1 = 0x8000;
  param_1[2] = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_802338f0;
  **(undefined **)(param_1 + 0x5c) = *(undefined *)(param_2 + 0x19);
  param_1[3] = param_1[3] | 0x4000;
  *(undefined *)(param_1 + 0x1b) = 0;
  FUN_80035f00();
  return;
}

