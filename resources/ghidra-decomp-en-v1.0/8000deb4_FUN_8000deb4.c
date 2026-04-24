// Function: FUN_8000deb4
// Entry: 8000deb4
// Size: 52 bytes

int FUN_8000deb4(int param_1,short *param_2)

{
  param_1 = param_1 + *param_2;
  if (0x8000 < param_1) {
    param_1 = param_1 + -0xffff;
  }
  if (-0x8001 < param_1) {
    return param_1;
  }
  return param_1 + 0xffff;
}

