// Function: FUN_80256d50
// Entry: 80256d50
// Size: 40 bytes

void FUN_80256d50(void)

{
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffffe | 1;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  return;
}

