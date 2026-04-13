// Function: FUN_8025d034
// Entry: 8025d034
// Size: 64 bytes

void FUN_8025d034(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x1d0) =
       *(uint *)(DAT_803dd210 + 0x1d0) & 0xfffffffb | (param_1 & 0xff) << 2;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d0);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

