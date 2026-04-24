// Function: FUN_8008991c
// Entry: 8008991c
// Size: 84 bytes

void FUN_8008991c(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)

{
  if (DAT_803dd12c == 0) {
    *param_4 = 0xff;
    *param_3 = 0xff;
    *param_2 = 0xff;
    return;
  }
  param_1 = param_1 * 0xa4;
  *param_2 = *(undefined *)(DAT_803dd12c + param_1 + 0x88);
  *param_3 = *(undefined *)(DAT_803dd12c + param_1 + 0x89);
  *param_4 = *(undefined *)(DAT_803dd12c + param_1 + 0x8a);
  return;
}

