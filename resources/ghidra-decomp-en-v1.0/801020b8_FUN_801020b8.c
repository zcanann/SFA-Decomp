// Function: FUN_801020b8
// Entry: 801020b8
// Size: 84 bytes

void FUN_801020b8(int param_1,int param_2)

{
  if (*(char *)(DAT_803dd524 + 0x13b) < param_1) {
    *(char *)(DAT_803dd524 + 0x13b) = (char)param_1;
    *(undefined *)(DAT_803dd524 + 0x13c) = 2;
    if (param_2 != 0) {
      FUN_8000faec((int)(short)param_1);
    }
  }
  return;
}

