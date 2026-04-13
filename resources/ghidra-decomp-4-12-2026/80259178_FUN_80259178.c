// Function: FUN_80259178
// Entry: 80259178
// Size: 88 bytes

void FUN_80259178(uint param_1,int param_2)

{
  *(uint *)(DAT_803dd210 + 0x7c) = param_1 & 0xff | *(uint *)(DAT_803dd210 + 0x7c) & 0xffffff00;
  *(uint *)(DAT_803dd210 + 0x7c) = *(uint *)(DAT_803dd210 + 0x7c) & 0xfff8ffff | param_2 << 0x10;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x7c);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

