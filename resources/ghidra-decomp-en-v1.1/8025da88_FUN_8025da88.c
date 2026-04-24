// Function: FUN_8025da88
// Entry: 8025da88
// Size: 176 bytes

void FUN_8025da88(int param_1,int param_2,int param_3,int param_4)

{
  *(uint *)(DAT_803dd210 + 0xf8) = *(uint *)(DAT_803dd210 + 0xf8) & 0xfffff800 | param_2 + 0x156U;
  *(uint *)(DAT_803dd210 + 0xf8) =
       *(uint *)(DAT_803dd210 + 0xf8) & 0xff800fff | (param_1 + 0x156) * 0x1000;
  *(uint *)(DAT_803dd210 + 0xfc) =
       *(uint *)(DAT_803dd210 + 0xfc) & 0xfffff800 | param_2 + 0x156U + param_4 + -1;
  *(uint *)(DAT_803dd210 + 0xfc) =
       *(uint *)(DAT_803dd210 + 0xfc) & 0xff800fff | (param_1 + 0x156 + param_3 + -1) * 0x1000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0xf8);
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0xfc);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

