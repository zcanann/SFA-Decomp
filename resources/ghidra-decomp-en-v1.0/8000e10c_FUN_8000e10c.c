// Function: FUN_8000e10c
// Entry: 8000e10c
// Size: 116 bytes

void FUN_8000e10c(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  if (*(int *)(param_1 + 0x30) == 0) {
    *param_2 = *(undefined4 *)(param_1 + 0xc);
    *param_3 = *(undefined4 *)(param_1 + 0x10);
    *param_4 = *(undefined4 *)(param_1 + 0x14);
  }
  else {
    FUN_800226cc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),
                 *(char *)(*(int *)(param_1 + 0x30) + 0x35) * 0x40 + -0x7fcc87f0);
  }
  return;
}

