// Function: FUN_80014e14
// Entry: 80014e14
// Size: 92 bytes

uint FUN_80014e14(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if (DAT_803dc950 != '\0') {
    return 0;
  }
  if (DAT_803dc908 != '\0') {
    return 0xffffffff;
  }
  return (&DAT_803398d0)[param_1] & (&DAT_802c6e50)[param_1];
}

