// Function: FUN_80014e40
// Entry: 80014e40
// Size: 92 bytes

uint FUN_80014e40(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if (DAT_803dd5d0 != '\0') {
    return 0;
  }
  if (DAT_803dd588 != '\0') {
    return 0xffffffff;
  }
  return (&DAT_8033a530)[param_1] & (&DAT_802c75d0)[param_1];
}

