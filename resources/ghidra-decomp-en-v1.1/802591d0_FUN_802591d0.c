// Function: FUN_802591d0
// Entry: 802591d0
// Size: 84 bytes

void FUN_802591d0(uint param_1,int param_2)

{
  *(uint *)(DAT_803dd210 + 0x7c) =
       (param_1 & 0xff) << 8 | *(uint *)(DAT_803dd210 + 0x7c) & 0xffff00ff;
  *(uint *)(DAT_803dd210 + 0x7c) = *(uint *)(DAT_803dd210 + 0x7c) & 0xffc7ffff | param_2 << 0x13;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x7c);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

