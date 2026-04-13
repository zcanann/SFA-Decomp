// Function: FUN_802597f0
// Entry: 802597f0
// Size: 104 bytes

void FUN_802597f0(undefined *param_1,uint param_2)

{
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = CONCAT11(param_1[3],*param_1) | 0x4f000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(ushort *)(param_1 + 1) | 0x50000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_2 & 0xffffff | 0x51000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

