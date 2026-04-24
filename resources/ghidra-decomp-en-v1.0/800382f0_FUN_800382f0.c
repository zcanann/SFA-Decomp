// Function: FUN_800382f0
// Entry: 800382f0
// Size: 64 bytes

void FUN_800382f0(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)

{
  param_2 = param_2 * 0x18;
  *param_3 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2);
  *param_4 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2 + 4);
  *param_5 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2 + 8);
  return;
}

