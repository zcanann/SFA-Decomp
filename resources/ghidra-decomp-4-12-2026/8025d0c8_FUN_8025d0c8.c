// Function: FUN_8025d0c8
// Entry: 8025d0c8
// Size: 56 bytes

void FUN_8025d0c8(uint param_1,uint param_2)

{
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_2 & 0xfd | (param_1 & 0xff) << 1 | 0x44000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

