// Function: FUN_80014f14
// Entry: 80014f14
// Size: 84 bytes

uint FUN_80014f14(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if ((DAT_803dd588 == '\0') && (DAT_803dd5d0 == '\0')) {
    return (&DAT_8033a520)[param_1] & (&DAT_802c75d0)[param_1];
  }
  return 0;
}

