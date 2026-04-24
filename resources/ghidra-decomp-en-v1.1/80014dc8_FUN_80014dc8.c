// Function: FUN_80014dc8
// Entry: 80014dc8
// Size: 60 bytes

undefined2 FUN_80014dc8(int param_1)

{
  if (0 < param_1) {
    param_1 = 0;
  }
  if ((DAT_803dd588 == '\0') && (DAT_803dd5d0 == '\0')) {
    return *(undefined2 *)(&DAT_803dd5ac + param_1 * 2);
  }
  return 0;
}

