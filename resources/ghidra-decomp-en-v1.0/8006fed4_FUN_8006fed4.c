// Function: FUN_8006fed4
// Entry: 8006fed4
// Size: 36 bytes

uint FUN_8006fed4(void)

{
  if (DAT_803dd004 != 0) {
    return DAT_803dd004 | DAT_803dd004 << 0x10;
  }
  return 0x1e00280;
}

