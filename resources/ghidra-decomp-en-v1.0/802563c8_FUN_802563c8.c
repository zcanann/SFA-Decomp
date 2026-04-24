// Function: FUN_802563c8
// Entry: 802563c8
// Size: 152 bytes

void FUN_802563c8(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  if (param_1 == DAT_803de0b8) {
    *(uint *)(param_1 + 0x18) = (*(uint *)(DAT_803de0a8 + 0x14) & 0xfbffffff) + 0x80000000;
  }
  if (param_1 == DAT_803de0bc) {
    *(int *)(param_1 + 0x14) =
         CONCAT22(*(undefined2 *)(DAT_803de0ac + 0x3a),*(undefined2 *)(DAT_803de0ac + 0x38)) +
         -0x80000000;
    *(uint *)(param_1 + 0x1c) =
         CONCAT22(*(undefined2 *)(DAT_803de0ac + 0x32),*(undefined2 *)(DAT_803de0ac + 0x30));
  }
  else {
    *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x18) - *(int *)(param_1 + 0x14);
    if (*(int *)(param_1 + 0x1c) < 0) {
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + *(int *)(param_1 + 8);
    }
  }
  *param_2 = *(undefined4 *)(param_1 + 0x14);
  *param_3 = *(undefined4 *)(param_1 + 0x18);
  return;
}

