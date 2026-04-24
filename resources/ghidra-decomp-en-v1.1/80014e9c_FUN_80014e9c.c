// Function: FUN_80014e9c
// Entry: 80014e9c
// Size: 84 bytes

uint FUN_80014e9c(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if ((DAT_803dd588 == '\0') && (DAT_803dd5d0 == '\0')) {
    return (&DAT_8033a540)[param_1] & (&DAT_802c75d0)[param_1];
  }
  return 0;
}

