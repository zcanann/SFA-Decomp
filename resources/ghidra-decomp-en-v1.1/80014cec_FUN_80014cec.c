// Function: FUN_80014cec
// Entry: 80014cec
// Size: 84 bytes

undefined FUN_80014cec(int param_1)

{
  if (0 < param_1) {
    return 0;
  }
  if ((DAT_803dd588 == '\0') && (DAT_803dd5d0 == '\0')) {
    return (&DAT_8033a552)[(param_1 + (uint)DAT_803dd5cc * 4) * 0xc];
  }
  return 0;
}

