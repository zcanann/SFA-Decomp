// Function: FUN_8025d100
// Entry: 8025d100
// Size: 128 bytes

void FUN_8025d100(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dd210 + 0x7c) =
       *(uint *)(DAT_803dd210 + 0x7c) & 0xffbfffff | (param_2 & 0xff) << 0x16;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x7c);
  FUN_8025bfdc();
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1 & 0xff | 0x68000000;
  FUN_8025bfdc();
  return;
}

