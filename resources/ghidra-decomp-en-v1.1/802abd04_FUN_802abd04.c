// Function: FUN_802abd04
// Entry: 802abd04
// Size: 236 bytes

void FUN_802abd04(int param_1,int param_2,uint param_3)

{
  if ((param_3 & 1) != 0) {
    FUN_800e6a30();
  }
  if ((param_3 & 2) != 0) {
    FUN_800e6778();
    *(undefined4 *)(param_2 + 0x24) = *(undefined4 *)(param_1 + 0x18);
    *(float *)(param_2 + 0x28) = FLOAT_803e8d84 + *(float *)(param_1 + 0x1c);
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

