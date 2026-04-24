// Function: FUN_802ab5a4
// Entry: 802ab5a4
// Size: 236 bytes

void FUN_802ab5a4(int param_1,int param_2,uint param_3)

{
  if ((param_3 & 1) != 0) {
    FUN_800e67ac(param_1,param_2 + 4);
  }
  if ((param_3 & 2) != 0) {
    FUN_800e64f4(param_1,param_2 + 4);
    *(undefined4 *)(param_2 + 0x24) = *(undefined4 *)(param_1 + 0x18);
    *(float *)(param_2 + 0x28) = FLOAT_803e80ec + *(float *)(param_1 + 0x1c);
    *(undefined4 *)(param_2 + 0x2c) = *(undefined4 *)(param_1 + 0x20);
  }
  if ((param_3 & 4) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x10) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x14) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x18) = *(undefined4 *)(param_1 + 0x14);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x1c) = *(undefined4 *)(param_1 + 0x18);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x20) = *(undefined4 *)(param_1 + 0x1c);
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x24) = *(undefined4 *)(param_1 + 0x20);
  }
  return;
}

