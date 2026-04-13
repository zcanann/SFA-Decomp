// Function: FUN_800581a8
// Entry: 800581a8
// Size: 52 bytes

void FUN_800581a8(void)

{
  DAT_803dda61 = DAT_803dda61 + -1;
  if (DAT_803dda61 < -2) {
    DAT_803dda61 = -2;
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

