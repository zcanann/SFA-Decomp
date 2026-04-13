// Function: FUN_8025d074
// Entry: 8025d074
// Size: 84 bytes

void FUN_8025d074(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dd210 + 0x1d4) = param_2 & 0xff | *(uint *)(DAT_803dd210 + 0x1d4) & 0xffffff00;
  *(uint *)(DAT_803dd210 + 0x1d4) =
       *(uint *)(DAT_803dd210 + 0x1d4) & 0xfffffeff | (param_1 & 0xff) << 8;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d4);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

