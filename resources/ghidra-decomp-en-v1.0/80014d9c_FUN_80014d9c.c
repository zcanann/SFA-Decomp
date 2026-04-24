// Function: FUN_80014d9c
// Entry: 80014d9c
// Size: 60 bytes

undefined2 FUN_80014d9c(int param_1)

{
  if (0 < param_1) {
    param_1 = 0;
  }
  if ((DAT_803dc908 == '\0') && (DAT_803dc950 == '\0')) {
    return *(undefined2 *)(&DAT_803dc92c + param_1 * 2);
  }
  return 0;
}

