// Function: FUN_80256d78
// Entry: 80256d78
// Size: 36 bytes

void FUN_80256d78(void)

{
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffffe;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  return;
}

