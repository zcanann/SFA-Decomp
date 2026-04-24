// Function: FUN_80014e70
// Entry: 80014e70
// Size: 84 bytes

uint FUN_80014e70(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if ((DAT_803dc908 == '\0') && (DAT_803dc950 == '\0')) {
    return (&DAT_803398e0)[param_1] & (&DAT_802c6e50)[param_1];
  }
  return 0;
}

