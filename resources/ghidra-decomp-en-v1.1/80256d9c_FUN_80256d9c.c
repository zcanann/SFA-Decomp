// Function: FUN_80256d9c
// Entry: 80256d9c
// Size: 68 bytes

void FUN_80256d9c(char param_1)

{
  *(uint *)(DAT_803dd210 + 8) =
       *(uint *)(DAT_803dd210 + 8) & 0xffffffef | (uint)(param_1 != '\0') << 4;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  return;
}

