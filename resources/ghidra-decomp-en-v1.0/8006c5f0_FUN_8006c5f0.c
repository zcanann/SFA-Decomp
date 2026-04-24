// Function: FUN_8006c5f0
// Entry: 8006c5f0
// Size: 128 bytes

void FUN_8006c5f0(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4,int *param_5)

{
  *param_2 = (&DAT_8038e1dc)[(DAT_803dcf8c + 1) % 3];
  *param_3 = **(undefined4 **)(param_1 + 100);
  *param_4 = (int)*(float *)(*(int *)(param_1 + 100) + 0x14);
  *param_5 = (int)*(float *)(*(int *)(param_1 + 100) + 0x18);
  return;
}

