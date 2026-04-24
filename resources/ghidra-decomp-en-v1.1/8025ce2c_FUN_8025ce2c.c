// Function: FUN_8025ce2c
// Entry: 8025ce2c
// Size: 64 bytes

void FUN_8025ce2c(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x1d0) =
       *(uint *)(DAT_803dd210 + 0x1d0) & 0xffffffef | (param_1 & 0xff) << 4;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d0);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

