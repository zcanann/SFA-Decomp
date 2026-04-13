// Function: FUN_8023415c
// Entry: 8023415c
// Size: 108 bytes

void FUN_8023415c(undefined2 *param_1,int param_2)

{
  *param_1 = 0x8000;
  param_1[2] = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_80233fb4;
  **(undefined **)(param_1 + 0x5c) = *(undefined *)(param_2 + 0x19);
  param_1[3] = param_1[3] | 0x4000;
  *(undefined *)(param_1 + 0x1b) = 0;
  FUN_80035ff8((int)param_1);
  return;
}

