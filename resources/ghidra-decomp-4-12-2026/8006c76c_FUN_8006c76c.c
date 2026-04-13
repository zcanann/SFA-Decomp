// Function: FUN_8006c76c
// Entry: 8006c76c
// Size: 128 bytes

void FUN_8006c76c(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4,int *param_5)

{
  *param_2 = (&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3];
  *param_3 = **(undefined4 **)(param_1 + 100);
  *param_4 = (int)*(float *)(*(int *)(param_1 + 100) + 0x14);
  *param_5 = (int)*(float *)(*(int *)(param_1 + 100) + 0x18);
  return;
}

