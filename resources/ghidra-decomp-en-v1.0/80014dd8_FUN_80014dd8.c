// Function: FUN_80014dd8
// Entry: 80014dd8
// Size: 60 bytes

undefined2 FUN_80014dd8(int param_1)

{
  if (0 < param_1) {
    param_1 = 0;
  }
  if ((DAT_803dc908 == '\0') && (DAT_803dc950 == '\0')) {
    return *(undefined2 *)(&DAT_803dc91c + param_1 * 2);
  }
  return 0;
}

