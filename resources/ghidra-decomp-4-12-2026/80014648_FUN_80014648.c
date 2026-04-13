// Function: FUN_80014648
// Entry: 80014648
// Size: 76 bytes

double FUN_80014648(void)

{
  if ((DAT_803dd579 & 1) != 0) {
    return (double)(FLOAT_803df360 * ((FLOAT_803dd57c - FLOAT_803dd580) / FLOAT_803df354));
  }
  return (double)(FLOAT_803df360 * (FLOAT_803dd580 / FLOAT_803df354));
}

