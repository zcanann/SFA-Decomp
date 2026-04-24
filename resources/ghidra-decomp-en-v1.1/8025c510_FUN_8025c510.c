// Function: FUN_8025c510
// Entry: 8025c510
// Size: 116 bytes

void FUN_8025c510(int param_1,byte *param_2)

{
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (uint)*param_2 | (uint)param_2[3] << 0xc | 0x800000 |
                 (param_1 * 2 + 0xe0) * 0x1000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (uint)param_2[2] | (uint)param_2[1] << 0xc | 0x800000 |
                 (param_1 * 2 + 0xe1) * 0x1000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

