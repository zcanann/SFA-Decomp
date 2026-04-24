// Function: FUN_80256de0
// Entry: 80256de0
// Size: 76 bytes

void FUN_80256de0(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffffb | (param_1 & 0xff) << 2;
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffff7 | (param_2 & 0xff) << 3;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  return;
}

