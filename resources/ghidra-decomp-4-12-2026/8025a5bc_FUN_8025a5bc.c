// Function: FUN_8025a5bc
// Entry: 8025a5bc
// Size: 76 bytes

void FUN_8025a5bc(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x204) =
       *(uint *)(DAT_803dd210 + 0x204) & 0xffffff8f | (param_1 & 0xff) << 4;
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = 0x1009;
  DAT_cc008000 = param_1 & 0xff;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 4;
  return;
}

