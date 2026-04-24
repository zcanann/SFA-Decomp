// Function: FUN_80014bc4
// Entry: 80014bc4
// Size: 84 bytes

undefined FUN_80014bc4(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if ((DAT_803dc908 == '\0') && (DAT_803dc950 == '\0')) {
    return (&DAT_803398f5)[(param_1 + (uint)DAT_803dc94c * 4) * 0xc];
  }
  return 0;
}

