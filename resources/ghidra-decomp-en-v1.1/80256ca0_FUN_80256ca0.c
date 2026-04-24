// Function: FUN_80256ca0
// Entry: 80256ca0
// Size: 100 bytes

void FUN_80256ca0(void)

{
  FUN_80243e74();
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffffd;
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xffffffdf;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  DAT_803ded54 = 0;
  FUN_80243e9c();
  return;
}

