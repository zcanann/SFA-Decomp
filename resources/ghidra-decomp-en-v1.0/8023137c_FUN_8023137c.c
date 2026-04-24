// Function: FUN_8023137c
// Entry: 8023137c
// Size: 28 bytes

void FUN_8023137c(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0x24) = *param_2;
  *(undefined4 *)(param_1 + 0x28) = param_2[1];
  *(undefined4 *)(param_1 + 0x2c) = param_2[2];
  return;
}

