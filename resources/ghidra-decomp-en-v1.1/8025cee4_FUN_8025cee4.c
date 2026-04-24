// Function: FUN_8025cee4
// Entry: 8025cee4
// Size: 64 bytes

void FUN_8025cee4(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x1dc) =
       *(uint *)(DAT_803dd210 + 0x1dc) & 0xffffffbf | (param_1 & 0xff) << 6;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1dc);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

